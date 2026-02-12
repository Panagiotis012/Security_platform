import { BlockList, isIP } from 'net';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { GatewayConfig } from '../../config/default';
import { getRouteConfig } from '../../config/default';
import { createSecurityLogger } from './request-logger';
import { extractClientIp } from '../utils/client-ip';
import { globalMetrics } from '@zerotrust/shared';

type AccessDecisionReason =
  | 'ip_denylist'
  | 'ip_not_allowlisted'
  | 'country_denylist'
  | 'country_not_allowlisted'
  | 'asn_denylist'
  | 'asn_not_allowlisted';

interface CompiledAccessControlProfile {
  enabled: boolean;
  ipAllowlist: string[];
  ipDenylist: string[];
  ipAllowMatcher: BlockList | null;
  ipDenyMatcher: BlockList | null;
  countryAllowlist: Set<string>;
  countryDenylist: Set<string>;
  asnAllowlist: Set<string>;
  asnDenylist: Set<string>;
}

function normalizeToken(value: string): string {
  return value.trim().toUpperCase();
}

function normalizeIpRules(values: string[] | undefined): string[] {
  if (!Array.isArray(values) || values.length === 0) return [];
  const unique = new Set<string>();
  for (const raw of values) {
    const value = String(raw || '').trim();
    if (!value) continue;
    unique.add(value);
  }
  return [...unique];
}

function normalizeTokens(values: string[] | undefined): Set<string> {
  if (!Array.isArray(values) || values.length === 0) return new Set<string>();
  const unique = new Set<string>();
  for (const raw of values) {
    const value = normalizeToken(String(raw || ''));
    if (value) unique.add(value);
  }
  return unique;
}

function buildIpMatcher(values: string[], label: string): BlockList | null {
  if (values.length === 0) return null;
  const list = new BlockList();

  for (const rawRule of values) {
    const rule = rawRule.trim();
    if (!rule) continue;

    if (rule.includes('/')) {
      const [ipRaw, prefixRaw] = rule.split('/', 2);
      const ip = (ipRaw || '').trim();
      const family = isIP(ip);
      if (!family) {
        throw new Error(`Invalid IP/CIDR rule "${rule}" in ${label}`);
      }

      const prefix = Number.parseInt((prefixRaw || '').trim(), 10);
      const maxPrefix = family === 4 ? 32 : 128;
      if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
        throw new Error(`Invalid CIDR prefix "${rule}" in ${label}`);
      }

      list.addSubnet(ip, prefix, family === 4 ? 'ipv4' : 'ipv6');
      continue;
    }

    const family = isIP(rule);
    if (!family) {
      throw new Error(`Invalid IP rule "${rule}" in ${label}`);
    }
    list.addAddress(rule, family === 4 ? 'ipv4' : 'ipv6');
  }

  return list;
}

function readHeader(req: Request, headerName: string): string {
  const raw = req.headers[headerName.toLowerCase()];
  if (typeof raw === 'string') return raw;
  if (Array.isArray(raw)) return raw.join(',');
  return '';
}

function normalizeCountry(value: string): string {
  const normalized = normalizeToken(value);
  if (!normalized) return '';
  return normalized.slice(0, 3);
}

function normalizeAsn(value: string): string {
  const normalized = normalizeToken(value);
  if (!normalized) return '';
  return normalized.replace(/^AS/i, '');
}

function checkIpMatch(matcher: BlockList | null, ip: string): boolean {
  if (!matcher) return false;
  const family = isIP(ip);
  if (!family) return false;
  return matcher.check(ip, family === 4 ? 'ipv4' : 'ipv6');
}

function compileProfile(
  policy: GatewayConfig['accessControl']['policy'] | Partial<GatewayConfig['accessControl']['policy']>,
  label: string,
): CompiledAccessControlProfile {
  const ipAllowlist = normalizeIpRules(policy.ipAllowlist as string[] | undefined);
  const ipDenylist = normalizeIpRules(policy.ipDenylist as string[] | undefined);
  return {
    enabled: policy.enabled !== false,
    ipAllowlist,
    ipDenylist,
    ipAllowMatcher: buildIpMatcher(ipAllowlist, `${label}.ipAllowlist`),
    ipDenyMatcher: buildIpMatcher(ipDenylist, `${label}.ipDenylist`),
    countryAllowlist: normalizeTokens(policy.countryAllowlist as string[] | undefined),
    countryDenylist: normalizeTokens(policy.countryDenylist as string[] | undefined),
    asnAllowlist: normalizeTokens(policy.asnAllowlist as string[] | undefined),
    asnDenylist: normalizeTokens(policy.asnDenylist as string[] | undefined),
  };
}

function mergeProfile(
  base: CompiledAccessControlProfile,
  override: Partial<GatewayConfig['accessControl']['policy']>,
  label: string,
): CompiledAccessControlProfile {
  const merged = {
    enabled: override.enabled ?? base.enabled,
    ipAllowlist: override.ipAllowlist ?? base.ipAllowlist,
    ipDenylist: override.ipDenylist ?? base.ipDenylist,
    countryAllowlist: override.countryAllowlist ?? [...base.countryAllowlist],
    countryDenylist: override.countryDenylist ?? [...base.countryDenylist],
    asnAllowlist: override.asnAllowlist ?? [...base.asnAllowlist],
    asnDenylist: override.asnDenylist ?? [...base.asnDenylist],
  };

  return compileProfile(
    {
      enabled: merged.enabled,
      ipAllowlist: merged.ipAllowlist,
      ipDenylist: merged.ipDenylist,
      countryAllowlist: merged.countryAllowlist,
      countryDenylist: merged.countryDenylist,
      asnAllowlist: merged.asnAllowlist,
      asnDenylist: merged.asnDenylist,
    },
    label,
  );
}

function recordDenied(reason: AccessDecisionReason, profileName: string): void {
  try {
    globalMetrics.recordCounter('access_control_denied_total', 1, {
      service: 'gateway',
      reason,
      profile: profileName,
    });
  } catch {
    // Metrics must never block requests.
  }
}

export function createAccessControlMiddleware(config: GatewayConfig): RequestHandler {
  const securityLog = createSecurityLogger(config);
  const trustedProxies = new Set(config.rateLimit.trustedProxies);
  const maxXffDepth = config.rateLimit.xForwardedForMaxDepth;

  let compiledSignature = '';
  let defaultProfile = compileProfile(config.accessControl.policy, 'accessControl.policy');
  let profileMap = new Map<string, CompiledAccessControlProfile>();

  const refreshCompiledProfiles = (): void => {
    const nextSignature = JSON.stringify(config.accessControl);
    if (nextSignature === compiledSignature) return;

    defaultProfile = compileProfile(config.accessControl.policy, 'accessControl.policy');
    const nextProfileMap = new Map<string, CompiledAccessControlProfile>();
    for (const [name, profile] of Object.entries(config.accessControl.profiles)) {
      nextProfileMap.set(name, mergeProfile(defaultProfile, profile, `accessControl.profiles.${name}`));
    }
    profileMap = nextProfileMap;
    compiledSignature = nextSignature;
  };

  const deny = (
    req: Request,
    res: Response,
    reason: AccessDecisionReason,
    profileName: string,
    clientIp: string,
    country: string,
    asn: string,
  ): void => {
    recordDenied(reason, profileName);
    securityLog.warn({
      event: 'access_control_denied',
      reason,
      profile: profileName,
      ip: clientIp,
      country: country || undefined,
      asn: asn || undefined,
      path: req.path,
      method: req.method,
      correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
    });
    res.status(403).json({
      error: 'access_denied',
      reason,
    });
  };

  return (req: Request, res: Response, next: NextFunction): void => {
    if (!config.accessControl.enabled) {
      next();
      return;
    }

    try {
      refreshCompiledProfiles();
    } catch (err) {
      securityLog.error({
        event: 'access_control_config_error',
        error: err instanceof Error ? err.message : String(err),
        path: req.path,
        method: req.method,
        correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
      });
      res.status(503).json({ error: 'access_control_unavailable' });
      return;
    }

    if (config.accessControl.bypassInternal && req.path.startsWith('/internal/')) {
      next();
      return;
    }

    const route = getRouteConfig(config, req.path, req.method);
    const profileName = route?.accessControlProfile ?? 'default';
    const profile = route?.accessControlProfile
      ? profileMap.get(route.accessControlProfile) ?? defaultProfile
      : defaultProfile;

    if (!profile.enabled) {
      next();
      return;
    }

    const clientIp = extractClientIp(req, maxXffDepth, trustedProxies);
    const country = normalizeCountry(readHeader(req, config.accessControl.countryHeader));
    const asn = normalizeAsn(readHeader(req, config.accessControl.asnHeader));

    if (checkIpMatch(profile.ipDenyMatcher, clientIp)) {
      deny(req, res, 'ip_denylist', profileName, clientIp, country, asn);
      return;
    }

    if (profile.ipAllowlist.length > 0 && !checkIpMatch(profile.ipAllowMatcher, clientIp)) {
      deny(req, res, 'ip_not_allowlisted', profileName, clientIp, country, asn);
      return;
    }

    if (country && profile.countryDenylist.has(country)) {
      deny(req, res, 'country_denylist', profileName, clientIp, country, asn);
      return;
    }

    if (profile.countryAllowlist.size > 0 && !profile.countryAllowlist.has(country)) {
      deny(req, res, 'country_not_allowlisted', profileName, clientIp, country, asn);
      return;
    }

    if (asn && profile.asnDenylist.has(asn)) {
      deny(req, res, 'asn_denylist', profileName, clientIp, country, asn);
      return;
    }

    if (profile.asnAllowlist.size > 0 && !profile.asnAllowlist.has(asn)) {
      deny(req, res, 'asn_not_allowlisted', profileName, clientIp, country, asn);
      return;
    }

    next();
  };
}
