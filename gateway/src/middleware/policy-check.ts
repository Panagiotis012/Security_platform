import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { GatewayConfig} from '../../config/default';
import { getRouteConfig } from '../../config/default';
import { createSecurityLogger } from './request-logger';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import { computeInternalAuthHeaders, globalMetrics, recordPolicyDecision } from '@zerotrust/shared';
import fs from 'fs';
import http from 'http';
import https from 'https';
import { URL } from 'url';

/**
 * Policy Decision Point (PDP) middleware.
 *
 * For every request: call the external PDP service to authorize.
 * FAIL-CLOSED: if PDP is unreachable or errors, DENY.
 *
 * - Sends: actor identity, action (HTTP method), resource (path), context attributes
 * - Caches positive decisions briefly (configurable TTL, default 30s)
 * - Logs every allow/deny as audit event with policy_id and reason
 * - Supports emergency break-glass with mandatory audit trail
 */

// ─── Decision Cache ──────────────────────────────────────────────────────────

interface CachedDecision {
  allowed: boolean;
  policyId: string;
  reason: string;
  timestamp: number;
  decisionId: string;
}

class PolicyDecisionCache {
  private cache = new Map<string, CachedDecision>();
  private cleanupInterval: ReturnType<typeof setInterval>;
  private maxEntries: number;
  private ttlMs: number;

  constructor(ttlMs: number, maxEntries: number) {
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.cleanupInterval = setInterval(() => this.cleanup(), Math.min(ttlMs, 30_000));
    this.cleanupInterval.unref();
  }

  /**
   * Build a cache key from the request attributes.
   * The key includes identity + method + path to scope decisions properly.
   */
  static buildKey(
    identity: { sub: string; jti?: string; stepUpLevel: number; roles: string[]; permissions: string[] },
    method: string,
    path: string
  ): string {
    // Security: cache keys must include all inputs that could change authorization.
    // If roles/permissions/step-up level change, we must not reuse an old "allow".
    const roles = [...identity.roles].sort().join(',');
    const perms = [...identity.permissions].sort().join(',');
    const fingerprint = crypto
      .createHash('sha256')
      .update(`${identity.sub}|${identity.jti ?? ''}|${identity.stepUpLevel}|${roles}|${perms}`, 'utf8')
      .digest('hex');

    return `${method}:${path}:${fingerprint}`;
  }

  get(key: string): CachedDecision | null {
    const entry = this.cache.get(key);
    if (!entry) return null;

    // Check TTL
    if (Date.now() - entry.timestamp > this.ttlMs) {
      this.cache.delete(key);
      return null;
    }

    // Only cache positive decisions
    if (!entry.allowed) {
      this.cache.delete(key);
      return null;
    }

    return entry;
  }

  set(key: string, decision: CachedDecision): void {
    // Only cache positive decisions
    if (!decision.allowed) return;

    // Evict oldest entries if at capacity
    if (this.cache.size >= this.maxEntries) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }

    this.cache.set(key, decision);
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache.entries()) {
      if (now - entry.timestamp > this.ttlMs) {
        this.cache.delete(key);
      }
    }
  }

  destroy(): void {
    clearInterval(this.cleanupInterval);
    this.cache.clear();
  }
}

// ─── PDP Client ──────────────────────────────────────────────────────────────

/**
 * PDP request/response contract.
 *
 * This gateway calls the Policy Engine's `/v1/evaluate` endpoint.
 * The policy engine keys policies on:
 *   - `action` (string)
 *   - `resource.type:resource.id` (string)
 */
interface PdpRequest {
  actor: {
    id: string;
    roles: string[];
    attributes: Record<string, unknown>;
  };
  action: string;
  resource: {
    type: string;
    id: string;
    attributes: Record<string, unknown>;
  };
  environment?: {
    ip?: string;
    time?: string;
    stepUpLevel?: number;
    custom?: Record<string, unknown>;
  };
  correlationId?: string;
}

interface PdpResponse {
  decision: 'ALLOW' | 'DENY';
  policyId: string | null;
  reason: string;
}

let _pdpTlsCacheKey: string | null = null;
let _pdpTlsOptions: { ca?: Buffer; cert?: Buffer; key?: Buffer; rejectUnauthorized?: boolean } | null = null;

function getPdpTlsOptions(config: GatewayConfig): typeof _pdpTlsOptions | undefined {
  const mtls = config.pdp.mtls;
  if (!mtls?.enabled) return undefined;

  const key = `${mtls.caPath ?? ''}|${mtls.certPath ?? ''}|${mtls.keyPath ?? ''}|${mtls.rejectUnauthorized !== false}`;
  if (_pdpTlsOptions && _pdpTlsCacheKey === key) return _pdpTlsOptions;

  _pdpTlsOptions = {
    ca: mtls.caPath ? fs.readFileSync(mtls.caPath) : undefined,
    cert: mtls.certPath ? fs.readFileSync(mtls.certPath) : undefined,
    key: mtls.keyPath ? fs.readFileSync(mtls.keyPath) : undefined,
    rejectUnauthorized: mtls.rejectUnauthorized !== false,
  };
  _pdpTlsCacheKey = key;
  return _pdpTlsOptions;
}

async function postJson(
  url: URL,
  headers: Record<string, string>,
  body: string,
  timeoutMs: number,
  tlsOptions?: { ca?: Buffer; cert?: Buffer; key?: Buffer; rejectUnauthorized?: boolean },
): Promise<unknown> {
  const isHttps = url.protocol === 'https:';
  const transport = isHttps ? https : http;

  const requestOptions: https.RequestOptions = {
    protocol: url.protocol,
    hostname: url.hostname,
    port: url.port ? Number(url.port) : (isHttps ? 443 : 80),
    path: url.pathname + url.search,
    method: 'POST',
    headers: {
      ...headers,
      'Content-Length': Buffer.byteLength(body, 'utf8'),
    },
    ...tlsOptions,
  };

  return await new Promise((resolve, reject) => {
    const req = transport.request(requestOptions, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        const status = res.statusCode ?? 0;
        if (status < 200 || status >= 300) {
          return reject(new Error(`PDP returned status ${status}`));
        }
        try {
          resolve(JSON.parse(data));
        } catch {
          reject(new Error('PDP returned invalid JSON'));
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error('PDP request timed out'));
    });

    req.write(body);
    req.end();
  });
}

async function callPdp(
  config: GatewayConfig,
  pdpRequest: PdpRequest,
  correlationId: string
): Promise<{ allowed: boolean; policyId: string; reason: string }> {
  try {
    const bodyStr = JSON.stringify(pdpRequest);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'X-Correlation-Id': correlationId,
    };

    // Internal auth (HMAC) for gateway -> PDP calls.
    if (config.internalAuth.enabled) {
      const internal = computeInternalAuthHeaders(
        { method: 'POST', path: '/v1/evaluate', rawBody: Buffer.from(bodyStr, 'utf8') },
        config.internalAuth.callerSecret || config.internalAuth.secret!,
        undefined,
        undefined,
        config.internalAuth.callerId,
        config.pdp.internalAudience,
        config.internalAuth.callerKeyId,
      );
      Object.assign(headers, internal);
    }

    const url = new URL('/v1/evaluate', config.pdp.url);
    const body = await postJson(url, headers, bodyStr, config.pdp.timeoutMs, getPdpTlsOptions(config) ?? undefined) as PdpResponse;
    if (body.decision !== 'ALLOW' && body.decision !== 'DENY') {
      throw new Error('PDP response missing/invalid "decision" field');
    }

    return {
      allowed: body.decision === 'ALLOW',
      policyId: body.policyId ?? 'unknown',
      reason: body.reason ?? 'no reason provided',
    };
  } finally {
  }
}

// ─── Break-Glass Validation ──────────────────────────────────────────────────

function validateBreakGlass(
  req: Request,
  config: GatewayConfig,
  securityLog: ReturnType<typeof createSecurityLogger>,
  correlationId: string
): boolean {
  if (!config.pdp.breakGlassEnabled) return false;

  const breakGlassHeader = req.headers[config.pdp.breakGlassHeader.toLowerCase()] as string | undefined;
  if (!breakGlassHeader) return false;

  // Validate break-glass secret
  if (!config.pdp.breakGlassSecret) return false;

  // Guardrails: require mTLS-bound identity for break-glass usage.
  if (!req.identity?.tokenBindingHash) {
    securityLog.error({
      event: 'break_glass_denied',
      correlationId,
      ip: req.ip,
      path: req.path,
      method: req.method,
      identity: req.identity?.sub,
      reason: 'Break-glass requires token binding (mTLS)',
    });
    return false;
  }

  // Guardrails: source IP must be allowlisted.
  const clientIp = normalizeIp(req.ip ?? '');
  const allowedIps = new Set(config.pdp.breakGlassAllowedIps.map(normalizeIp));
  if (!allowedIps.has(clientIp)) {
    securityLog.error({
      event: 'break_glass_denied',
      correlationId,
      ip: clientIp,
      path: req.path,
      method: req.method,
      identity: req.identity?.sub,
      reason: 'Source IP not allowlisted for break-glass',
    });
    return false;
  }

  // Guardrails: path must be allowlisted (supports globs).
  const allowed = config.pdp.breakGlassAllowedPaths.some((p) => matchGlob(p, req.path));
  if (!allowed) {
    securityLog.error({
      event: 'break_glass_denied',
      correlationId,
      ip: clientIp,
      path: req.path,
      method: req.method,
      identity: req.identity?.sub,
      reason: 'Path not allowlisted for break-glass',
    });
    return false;
  }

  // Constant-time comparison to prevent timing attacks.
  const expected = Buffer.from(config.pdp.breakGlassSecret, 'utf8');
  const actual = Buffer.from(breakGlassHeader, 'utf8');
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    securityLog.error({
      event: 'break_glass_invalid',
      correlationId,
      ip: clientIp,
      path: req.path,
      method: req.method,
      identity: req.identity?.sub,
      reason: 'Invalid break-glass credential',
    });
    return false;
  }

  // CRITICAL: Log break-glass usage as a high-severity security event
  securityLog.error({
    event: 'break_glass_activated',
    correlationId,
    ip: req.ip,
    path: req.path,
    method: req.method,
    identity: req.identity?.sub,
    roles: req.identity?.roles,
    userAgent: req.headers['user-agent'],
    reason: 'Emergency break-glass override activated',
    severity: 'CRITICAL',
  });

  return true;
}

function normalizeIp(ip: string): string {
  const trimmed = (ip || '').trim().toLowerCase();
  if (trimmed.startsWith('::ffff:')) return trimmed.slice('::ffff:'.length);
  return trimmed;
}

function matchGlob(pattern: string, value: string): boolean {
  if (!pattern.includes('*')) return pattern === value;
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const tokenized = escaped.replace(/\*\*/g, '<<DOUBLESTAR>>');
  const singleStar = tokenized.replace(/\*/g, '[^/]*');
  return new RegExp('^' + singleStar.replace(/<<DOUBLESTAR>>/g, '.*') + '$').test(value);
}

// ─── Policy Check Middleware ─────────────────────────────────────────────────

export function createPolicyCheckMiddleware(config: GatewayConfig): RequestHandler {
  const securityLog = createSecurityLogger(config);

  const decisionCache = new PolicyDecisionCache(
    config.pdp.cacheTtlMs,
    config.pdp.cacheMaxEntries
  );

  const recordPdpFailure = (outcome: string): void => {
    try {
      globalMetrics.recordCounter('pdp_failures_total', 1, {
        service: 'gateway',
        outcome,
      });
    } catch {
      // Metrics must never affect request handling.
    }
  };

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const correlationId = (req.headers['x-correlation-id'] as string) || 'unknown';
    const decisionId = uuidv4();
    req.policyDecisionId = decisionId;

    const routeConfig = getRouteConfig(config, req.path, req.method);

    const identity = req.identity;
    if (!identity) {
      // No identity means JWT validation was skipped or failed.
      // Fail closed: DENY.
      recordPolicyDecision('deny', 'gateway');
      securityLog.warn({
        event: 'policy_denied',
        decisionId,
        correlationId,
        ip: req.ip,
        path: req.path,
        method: req.method,
        reason: 'No authenticated identity',
        policyId: 'system:require_identity',
      });
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    // ── Route-level guardrails (defense-in-depth) ────────────────────
    if (routeConfig?.stepUpRequired && identity.stepUpLevel < 1) {
      recordPolicyDecision('deny', 'gateway');
      securityLog.warn({
        event: 'policy_denied',
        decisionId,
        correlationId,
        identity: identity.sub,
        ip: req.ip,
        path: req.path,
        method: req.method,
        reason: 'Step-up authentication required',
        policyId: 'system:step_up_required',
      });
      // Keep behavior consistent with the edge policy engine (Envoy/OPA) so
      // clients can trigger step-up flows when access is denied.
      res.setHeader('x-zt-step-up-required', 'true');
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    if (routeConfig?.requiredScopes && routeConfig.requiredScopes.length > 0) {
      const missing = routeConfig.requiredScopes.filter((s) => !identity.scopes.includes(s));
      if (missing.length > 0) {
        recordPolicyDecision('deny', 'gateway');
        securityLog.warn({
          event: 'policy_denied',
          decisionId,
          correlationId,
          identity: identity.sub,
          ip: req.ip,
          path: req.path,
          method: req.method,
          reason: 'Missing required scopes',
          policyId: 'system:required_scopes',
          missingScopes: missing,
        });
        res.status(403).json({ error: 'Forbidden' });
        return;
      }
    }

    // If the gateway is running behind an edge proxy enforcing authorization
    // (e.g. Envoy + OPA), the in-gateway PDP call can be disabled to avoid
    // redundant checks and policy drift.
    if (config.pdp.enabled === false) {
      recordPolicyDecision('skip', 'gateway');
      next();
      return;
    }

    // ── Check cache first ─────────────────────────────────────────────
    const cacheKey = PolicyDecisionCache.buildKey(identity, req.method, req.path);
    const cached = decisionCache.get(cacheKey);

    if (cached) {
      req.policyDecisionId = cached.decisionId;
      recordPolicyDecision('allow', 'gateway');
      securityLog.info({
        event: 'policy_allowed',
        decisionId: cached.decisionId,
        correlationId,
        identity: identity.sub,
        path: req.path,
        method: req.method,
        policyId: cached.policyId,
        reason: cached.reason,
        cached: true,
      });
      next();
      return;
    }

    // ── Call PDP ──────────────────────────────────────────────────────
    const pdpRequest: PdpRequest = {
      actor: {
        id: identity.sub,
        roles: identity.roles,
        // Keep these as arrays/primitive types so policy-engine ConditionValue can consume them.
        attributes: {
          permissions: identity.permissions,
          scopes: identity.scopes,
        },
      },
      action: req.method.toUpperCase(),
      resource: {
        type: 'http',
        id: req.path,
        attributes: {},
      },
      environment: {
        ip: req.ip || '0.0.0.0',
        time: new Date().toISOString(),
        stepUpLevel: identity.stepUpLevel,
        custom: {
          correlationId,
          wafRiskScore: req.wafRiskScore ?? 0,
        },
      },
      correlationId,
    };

    try {
      const decision = await callPdp(config, pdpRequest, correlationId);

      if (decision.allowed) {
        // Cache the positive decision
        decisionCache.set(cacheKey, {
          allowed: true,
          policyId: decision.policyId,
          reason: decision.reason,
          timestamp: Date.now(),
          decisionId,
        });

        recordPolicyDecision('allow', 'gateway');
        securityLog.info({
          event: 'policy_allowed',
          decisionId,
          correlationId,
          identity: identity.sub,
          path: req.path,
          method: req.method,
          policyId: decision.policyId,
          reason: decision.reason,
          cached: false,
        });

        next();
      } else {
        recordPolicyDecision('deny', 'gateway');
        securityLog.warn({
          event: 'policy_denied',
          decisionId,
          correlationId,
          identity: identity.sub,
          ip: req.ip,
          path: req.path,
          method: req.method,
          policyId: decision.policyId,
          reason: decision.reason,
        });

        res.status(403).json({ error: 'Forbidden' });
      }
    } catch (err) {
      // PDP unreachable or error — FAIL CLOSED

      // Check break-glass before denying
      if (validateBreakGlass(req, config, securityLog, correlationId)) {
        req.policyDecisionId = `break-glass:${decisionId}`;

        recordPdpFailure('break_glass_allow');
        recordPolicyDecision('allow', 'gateway');
        securityLog.error({
          event: 'policy_break_glass_allow',
          decisionId: `break-glass:${decisionId}`,
          correlationId,
          identity: identity.sub,
          ip: req.ip,
          path: req.path,
          method: req.method,
          policyId: 'system:break_glass',
          reason: 'PDP unreachable, break-glass activated',
          pdpError: err instanceof Error ? err.message : 'unknown',
          severity: 'CRITICAL',
        });

        next();
        return;
      }

      if (config.pdp.failClosed) {
        recordPdpFailure('fail_closed_deny');
        recordPolicyDecision('deny', 'gateway');
        securityLog.error({
          event: 'policy_pdp_failure_denied',
          decisionId,
          correlationId,
          identity: identity.sub,
          ip: req.ip,
          path: req.path,
          method: req.method,
          policyId: 'system:fail_closed',
          reason: 'PDP unreachable, fail-closed policy applied',
          pdpError: err instanceof Error ? err.message : 'unknown',
        });

        res.status(503).json({ error: 'Service Unavailable' });
      } else {
        // This should never happen in production — failClosed should always be true.
        // But if someone misconfigures, at least log it loudly.
        recordPdpFailure('fail_open_allow');
        recordPolicyDecision('allow', 'gateway');
        securityLog.error({
          event: 'policy_pdp_failure_allowed',
          decisionId,
          correlationId,
          identity: identity.sub,
          ip: req.ip,
          path: req.path,
          method: req.method,
          policyId: 'system:fail_open_DANGER',
          reason: 'PDP unreachable, FAIL-OPEN (MISCONFIGURATION)',
          pdpError: err instanceof Error ? err.message : 'unknown',
          severity: 'CRITICAL',
        });

        next();
      }
    }
  };
}
