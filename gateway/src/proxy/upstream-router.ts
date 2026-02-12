import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { Options as ProxyOptions } from 'http-proxy-middleware';
import { createProxyMiddleware } from 'http-proxy-middleware';
import * as http from 'http';
import * as https from 'https';
import * as fs from 'fs';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'crypto';
import type { GatewayConfig, RouteConfig, UpstreamService } from '../../config/default';
import { getRouteConfig } from '../../config/default';
import { createSecurityLogger, createAccessLogger } from '../middleware/request-logger';
import { computeInternalAuthHeaders, INTERNAL_AUTH_HEADERS } from '@zerotrust/shared';
import { UpstreamEndpointPool } from './upstream-pool';
import type { UpstreamRoutingPolicyManager } from './upstream-policy-manager';

/**
 * Upstream router with circuit breaker, mTLS, and security header management.
 *
 * - Routes requests to upstream services based on route configuration
 * - Adds internal headers: X-Request-Id, X-Authenticated-User, X-Policy-Decision-Id
 * - Strips external hop-by-hop headers
 * - mTLS to internal services with certificate validation
 * - Circuit breaker pattern to prevent cascade failures
 * - Per-route timeout enforcement
 */

// ─── Hop-by-hop Headers ─────────────────────────────────────────────────────
// These headers must not be forwarded to upstream services.

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailers',
  'transfer-encoding',
  'upgrade',
  'proxy-connection',
]);

// Headers that external clients should never be able to set on internal requests
const INTERNAL_ONLY_HEADERS = new Set([
  'x-authenticated-user',
  'x-authenticated-roles',
  'x-authenticated-permissions',
  'x-policy-decision-id',
  'x-step-up-level',
  'x-internal-request',
  INTERNAL_AUTH_HEADERS.Timestamp,
  INTERNAL_AUTH_HEADERS.ContentSha256,
  INTERNAL_AUTH_HEADERS.Nonce,
  INTERNAL_AUTH_HEADERS.Caller,
  INTERNAL_AUTH_HEADERS.Audience,
  INTERNAL_AUTH_HEADERS.KeyId,
  INTERNAL_AUTH_HEADERS.Signature,
]);

const SELECTED_ENDPOINT_URL = '__ztSelectedUpstreamEndpointUrl';
const SELECTED_ENDPOINT_AFFINITY_KEY = '__ztSelectedUpstreamAffinityKey';
const UPSTREAM_REQUEST_START_MS = '__ztUpstreamRequestStartMs';
const UPSTREAM_RETRY_ATTEMPTS = '__ztUpstreamRetryAttempts';
const SELECTED_CANARY_ROUTE_KEY = '__ztCanaryRouteKey';
const SELECTED_CANARY_USED = '__ztCanaryUsed';
const SELECTED_CANARY_PATH = '__ztCanaryRoutePath';
const SELECTED_CANARY_PRIMARY = '__ztCanaryPrimaryUpstream';
const SELECTED_CANARY_TARGET = '__ztCanaryUpstream';

interface AffinityResolution {
  key?: string;
  setCookieHeader?: string;
  source: 'none' | 'ip' | 'header' | 'cookie';
}

interface RetryBudgetState {
  windowStartMs: number;
  requests: number;
  retries: number;
}

interface CanaryRouteResolution {
  upstreamName: string;
  usedCanary: boolean;
  rolloutPercent: number;
  bucket: number;
  stickinessKey: string;
  rollbackSuppressed?: boolean;
}

export interface CanaryGuardrailsConfig {
  enabled: boolean;
  windowMs: number;
  minRequests: number;
  errorRateThreshold: number;
  latencyThresholdMs: number;
  cooldownMs: number;
  maxRoutes: number;
}

export interface CanaryRouteWindowSummary {
  requests: number;
  failures: number;
  errorRate: number;
  averageLatencyMs: number | null;
}

export interface CanaryRouteMetricsSnapshot {
  routeKey: string;
  routePath: string;
  primaryUpstream: string;
  canaryUpstream: string;
  rolloutPercent: number;
  totalRequests: number;
  canaryRequests: number;
  primaryRequests: number;
  suppressedByRollback: number;
  lastBucket: number | null;
  lastDecisionAt: string | null;
  window: CanaryRouteWindowSummary;
  rollback: {
    active: boolean;
    until: string | null;
    reason: string | null;
    triggeredAt: string | null;
  };
}

function normalizeHeaderName(value: string): string {
  return value.trim().toLowerCase();
}

function headerToString(value: string | string[] | undefined): string {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value[0] ?? '';
  return '';
}

function parseBooleanEnv(value: string | undefined, fallback: boolean): boolean {
  if (!value) return fallback;
  const normalized = value.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

function parseIntegerEnv(value: string | undefined, fallback: number, min: number, max: number): number {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(parsed, max));
}

function parseNumberEnv(value: string | undefined, fallback: number, min: number, max: number): number {
  if (!value) return fallback;
  const parsed = Number.parseFloat(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(parsed, max));
}

function normalizeRolloutPercent(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, value));
}

export function buildRouteCanaryKey(routeConfig: RouteConfig): string {
  const methods = [...routeConfig.methods].map((method) => method.toUpperCase()).sort().join(',');
  const canaryUpstream = String(routeConfig.canary?.upstream ?? '').trim() || '-';
  return `${routeConfig.path}|${methods}|${routeConfig.upstream}|${canaryUpstream}`;
}

export function computeCanaryRolloutBucket(key: string): number {
  const input = key.trim() || 'anonymous';
  const digest = createHash('sha256').update(input, 'utf8').digest();
  const value = digest.readUInt32BE(0);
  const ratio = value / 0xffffffff;
  return Number((ratio * 100).toFixed(6));
}

function resolveCanaryStickinessKey(
  req: Pick<Request, 'headers' | 'ip'> & { identity?: { sub?: string } },
  routeConfig: RouteConfig,
): string {
  const canary = routeConfig.canary;
  if (!canary?.enabled) return String(req.ip || '').trim() || 'ip:unknown';

  if (canary.stickiness === 'header') {
    const headerName = normalizeHeaderName(canary.headerName || 'x-canary-key');
    const headerValue = headerToString(req.headers[headerName] as string | string[] | undefined).trim();
    if (headerValue) return `header:${headerName}:${headerValue.slice(0, 512)}`;
  }

  if (canary.stickiness === 'identity') {
    const identitySub = String(req.identity?.sub ?? '').trim();
    if (identitySub) return `identity:${identitySub.slice(0, 512)}`;
  }

  const ip = String(req.ip || '').trim();
  return ip ? `ip:${ip}` : 'ip:unknown';
}

export function resolveRouteUpstream(
  routeConfig: RouteConfig,
  req: Pick<Request, 'headers' | 'ip'> & { identity?: { sub?: string } },
  options?: { rollbackActive?: boolean },
): CanaryRouteResolution {
  const primary = routeConfig.upstream;
  const canary = routeConfig.canary;
  if (!canary?.enabled) {
    return {
      upstreamName: primary,
      usedCanary: false,
      rolloutPercent: 0,
      bucket: 100,
      stickinessKey: '',
    };
  }

  const canaryUpstream = String(canary.upstream ?? '').trim();
  const rolloutPercent = normalizeRolloutPercent(canary.rolloutPercent);
  if (!canaryUpstream || rolloutPercent <= 0) {
    return {
      upstreamName: primary,
      usedCanary: false,
      rolloutPercent,
      bucket: 100,
      stickinessKey: '',
    };
  }
  if (options?.rollbackActive) {
    return {
      upstreamName: primary,
      usedCanary: false,
      rolloutPercent,
      bucket: 100,
      stickinessKey: '',
      rollbackSuppressed: true,
    };
  }

  const stickinessKey = resolveCanaryStickinessKey(req, routeConfig);
  const bucket = computeCanaryRolloutBucket(`${routeConfig.path}|${stickinessKey}`);
  const useCanary = bucket < rolloutPercent;
  return {
    upstreamName: useCanary ? canaryUpstream : primary,
    usedCanary: useCanary,
    rolloutPercent,
    bucket,
    stickinessKey,
  };
}

export interface CanaryDecisionRecord {
  atMs: number;
  routePath: string;
  primaryUpstream: string;
  canaryUpstream: string;
  selectedUpstream: string;
  usedCanary: boolean;
  rolloutPercent: number;
  bucket: number;
  rollbackSuppressed: boolean;
}

interface CanaryOutcomeRecord {
  atMs: number;
  success: boolean;
  latencyMs: number | null;
}

interface CanaryRollbackState {
  activeUntilMs: number;
  reason: string;
  triggeredAtMs: number;
}

interface CanaryRouteState {
  routePath: string;
  primaryUpstream: string;
  canaryUpstream: string;
  rolloutPercent: number;
  totalRequests: number;
  canaryRequests: number;
  primaryRequests: number;
  suppressedByRollback: number;
  lastBucket: number | null;
  lastDecisionAtMs: number | null;
  decisions: CanaryDecisionRecord[];
  outcomes: CanaryOutcomeRecord[];
  rollback: CanaryRollbackState | null;
}

export class CanaryRouteMonitor {
  private readonly routes = new Map<string, CanaryRouteState>();

  constructor(private readonly config: CanaryGuardrailsConfig) {}

  private pruneState(state: CanaryRouteState, nowMs: number): void {
    const floor = nowMs - this.config.windowMs;
    state.decisions = state.decisions.filter((entry) => entry.atMs >= floor);
    state.outcomes = state.outcomes.filter((entry) => entry.atMs >= floor);
    if (state.rollback && state.rollback.activeUntilMs <= nowMs) {
      state.rollback = null;
    }
  }

  private getOrCreateState(
    routeKey: string,
    decision: CanaryDecisionRecord,
  ): CanaryRouteState {
    let state = this.routes.get(routeKey);
    if (state) return state;

    if (this.routes.size >= this.config.maxRoutes) {
      const firstKey = this.routes.keys().next().value as string | undefined;
      if (firstKey) {
        this.routes.delete(firstKey);
      }
    }

    state = {
      routePath: decision.routePath,
      primaryUpstream: decision.primaryUpstream,
      canaryUpstream: decision.canaryUpstream,
      rolloutPercent: decision.rolloutPercent,
      totalRequests: 0,
      canaryRequests: 0,
      primaryRequests: 0,
      suppressedByRollback: 0,
      lastBucket: null,
      lastDecisionAtMs: null,
      decisions: [],
      outcomes: [],
      rollback: null,
    };
    this.routes.set(routeKey, state);
    return state;
  }

  public isRollbackActive(routeKey: string, nowMs: number = Date.now()): boolean {
    const state = this.routes.get(routeKey);
    if (!state?.rollback) return false;
    if (state.rollback.activeUntilMs <= nowMs) {
      state.rollback = null;
      return false;
    }
    return true;
  }

  public recordDecision(
    routeKey: string,
    decision: CanaryDecisionRecord,
    nowMs: number = Date.now(),
  ): void {
    const state = this.getOrCreateState(routeKey, decision);
    this.pruneState(state, nowMs);
    state.routePath = decision.routePath;
    state.primaryUpstream = decision.primaryUpstream;
    state.canaryUpstream = decision.canaryUpstream;
    state.rolloutPercent = decision.rolloutPercent;
    state.totalRequests += 1;
    if (decision.usedCanary) {
      state.canaryRequests += 1;
    } else {
      state.primaryRequests += 1;
    }
    if (decision.rollbackSuppressed) {
      state.suppressedByRollback += 1;
    }
    state.lastBucket = decision.bucket;
    state.lastDecisionAtMs = decision.atMs;
    state.decisions.push(decision);
  }

  public recordOutcome(
    routeKey: string,
    input: {
      success: boolean;
      latencyMs?: number | null;
      nowMs?: number;
      reason?: string;
    },
  ): { rollbackActivated: boolean; rollbackReason?: string; rollbackUntil?: string } {
    const nowMs = input.nowMs ?? Date.now();
    const state = this.routes.get(routeKey);
    if (!state) return { rollbackActivated: false };
    this.pruneState(state, nowMs);
    const rollbackWasActive = Boolean(state.rollback && state.rollback.activeUntilMs > nowMs);
    state.outcomes.push({
      atMs: nowMs,
      success: input.success,
      latencyMs: Number.isFinite(input.latencyMs ?? NaN)
        ? Math.max(0, Number(input.latencyMs))
        : null,
    });
    this.evaluateRollback(routeKey, state, nowMs, input.reason);
    const rollbackIsActive = Boolean(state.rollback && state.rollback.activeUntilMs > nowMs);
    if (!rollbackWasActive && rollbackIsActive && state.rollback) {
      return {
        rollbackActivated: true,
        rollbackReason: state.rollback.reason,
        rollbackUntil: new Date(state.rollback.activeUntilMs).toISOString(),
      };
    }
    return { rollbackActivated: false };
  }

  private evaluateRollback(
    routeKey: string,
    state: CanaryRouteState,
    nowMs: number,
    overrideReason?: string,
  ): void {
    if (!this.config.enabled || state.rollback) return;
    if (state.outcomes.length < this.config.minRequests) return;
    const failures = state.outcomes.filter((entry) => !entry.success).length;
    const errorRate = failures / state.outcomes.length;
    const latencies = state.outcomes
      .map((entry) => entry.latencyMs)
      .filter((value): value is number => typeof value === 'number');
    const averageLatencyMs = latencies.length > 0
      ? latencies.reduce((sum, value) => sum + value, 0) / latencies.length
      : 0;

    const errorTriggered = errorRate >= this.config.errorRateThreshold;
    const latencyTriggered =
      averageLatencyMs > 0 && averageLatencyMs >= this.config.latencyThresholdMs;
    if (!errorTriggered && !latencyTriggered) return;

    const reason = overrideReason ??
      (errorTriggered
        ? `error_rate:${errorRate.toFixed(4)}`
        : `latency_avg_ms:${Math.round(averageLatencyMs)}`);
    state.rollback = {
      activeUntilMs: nowMs + this.config.cooldownMs,
      reason,
      triggeredAtMs: nowMs,
    };
    this.routes.set(routeKey, state);
  }

  public getSnapshot(routePath?: string, nowMs: number = Date.now()): {
    generatedAt: string;
    guardrails: CanaryGuardrailsConfig;
    routeCount: number;
    routes: CanaryRouteMetricsSnapshot[];
  } {
    const routes: CanaryRouteMetricsSnapshot[] = [];
    for (const [routeKey, state] of this.routes.entries()) {
      this.pruneState(state, nowMs);
      if (routePath && state.routePath !== routePath) continue;
      const failures = state.outcomes.filter((entry) => !entry.success).length;
      const latencies = state.outcomes
        .map((entry) => entry.latencyMs)
        .filter((value): value is number => typeof value === 'number');
      const averageLatencyMs = latencies.length > 0
        ? latencies.reduce((sum, value) => sum + value, 0) / latencies.length
        : null;
      const errorRate = state.outcomes.length > 0 ? failures / state.outcomes.length : 0;
      routes.push({
        routeKey,
        routePath: state.routePath,
        primaryUpstream: state.primaryUpstream,
        canaryUpstream: state.canaryUpstream,
        rolloutPercent: state.rolloutPercent,
        totalRequests: state.totalRequests,
        canaryRequests: state.canaryRequests,
        primaryRequests: state.primaryRequests,
        suppressedByRollback: state.suppressedByRollback,
        lastBucket: state.lastBucket,
        lastDecisionAt: state.lastDecisionAtMs ? new Date(state.lastDecisionAtMs).toISOString() : null,
        window: {
          requests: state.outcomes.length,
          failures,
          errorRate,
          averageLatencyMs,
        },
        rollback: {
          active: Boolean(state.rollback && state.rollback.activeUntilMs > nowMs),
          until: state.rollback ? new Date(state.rollback.activeUntilMs).toISOString() : null,
          reason: state.rollback?.reason ?? null,
          triggeredAt: state.rollback ? new Date(state.rollback.triggeredAtMs).toISOString() : null,
        },
      });
    }
    return {
      generatedAt: new Date(nowMs).toISOString(),
      guardrails: this.config,
      routeCount: routes.length,
      routes,
    };
  }
}

function readCookie(req: Request, cookieName: string): string | undefined {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const parsed = (req as any).cookies as Record<string, unknown> | undefined;
  if (parsed && typeof parsed[cookieName] === 'string') {
    return parsed[cookieName] as string;
  }

  const rawCookie = headerToString(req.headers['cookie'] as string | string[] | undefined);
  if (!rawCookie) return undefined;
  const segments = rawCookie.split(';');
  for (const segment of segments) {
    const [rawName, ...rawValue] = segment.trim().split('=');
    if (!rawName || rawValue.length === 0) continue;
    if (rawName !== cookieName) continue;
    try {
      return decodeURIComponent(rawValue.join('='));
    } catch {
      return rawValue.join('=');
    }
  }
  return undefined;
}

function hmacAffinitySignature(payloadB64: string, secret: string): string {
  return createHmac('sha256', secret).update(`v1.${payloadB64}`).digest('base64url');
}

function constantTimeEquals(a: string, b: string): boolean {
  const aa = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (aa.length !== bb.length) return false;
  try {
    return timingSafeEqual(aa, bb);
  } catch {
    return false;
  }
}

function issueAffinityToken(key: string, ttlSeconds: number, secret: string): string {
  const payloadB64 = Buffer.from(
    JSON.stringify({
      k: key,
      exp: Date.now() + Math.max(1, Math.floor(ttlSeconds)) * 1000,
    }),
    'utf8',
  ).toString('base64url');
  const signature = hmacAffinitySignature(payloadB64, secret);
  return `v1.${payloadB64}.${signature}`;
}

function verifyAffinityToken(
  token: string,
  secrets: string[],
): { key: string; needsRotation: boolean } | null {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') return null;

  const payloadB64 = parts[1] || '';
  const signature = parts[2] || '';
  if (!payloadB64 || !signature) return null;

  let payload: { k?: unknown; exp?: unknown } | null = null;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8')) as { k?: unknown; exp?: unknown };
  } catch {
    return null;
  }
  if (!payload || typeof payload.k !== 'string' || typeof payload.exp !== 'number') return null;
  if (!payload.k || payload.k.length > 256) return null;
  if (!Number.isFinite(payload.exp) || payload.exp <= Date.now()) return null;

  for (let i = 0; i < secrets.length; i += 1) {
    const secret = secrets[i];
    if (!secret) continue;
    const expected = hmacAffinitySignature(payloadB64, secret);
    if (constantTimeEquals(expected, signature)) {
      return {
        key: payload.k,
        needsRotation: i > 0,
      };
    }
  }

  return null;
}

function serializeCookie(
  name: string,
  value: string,
  options: {
    maxAgeSeconds: number;
    path: string;
    domain?: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite: 'lax' | 'strict' | 'none';
  },
): string {
  const sameSite = options.sameSite.charAt(0).toUpperCase() + options.sameSite.slice(1).toLowerCase();
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    `Max-Age=${Math.max(1, Math.floor(options.maxAgeSeconds))}`,
    `Path=${options.path || '/'}`,
    `SameSite=${sameSite}`,
  ];
  if (options.domain) parts.push(`Domain=${options.domain}`);
  if (options.secure) parts.push('Secure');
  if (options.httpOnly) parts.push('HttpOnly');
  return parts.join('; ');
}

function appendSetCookie(res: Response, cookieHeader: string): void {
  const existing = res.getHeader('set-cookie');
  if (!existing) {
    res.setHeader('set-cookie', [cookieHeader]);
    return;
  }
  if (Array.isArray(existing)) {
    res.setHeader('set-cookie', [...existing.map((v) => String(v)), cookieHeader]);
    return;
  }
  res.setHeader('set-cookie', [String(existing), cookieHeader]);
}

function shouldRetryRequestMethod(method: string): boolean {
  const normalized = method.toUpperCase();
  return normalized === 'GET' || normalized === 'HEAD' || normalized === 'OPTIONS';
}

function retryBackoffMs(attempt: number): number {
  const base = 25;
  return Math.min(500, base * Math.max(1, attempt));
}

function resolveAffinity(req: Request, upstream: UpstreamService): AffinityResolution {
  const affinity = upstream.pool?.sessionAffinity;
  if (!affinity?.enabled) return { source: 'none' };

  if (affinity.source === 'header') {
    const headerName = normalizeHeaderName(affinity.headerName || 'x-zt-affinity-key');
    const raw = headerToString(req.headers[headerName] as string | string[] | undefined).trim();
    if (!raw) return { source: 'none' };
    return {
      key: raw.slice(0, 256),
      source: 'header',
    };
  }

  if (affinity.source === 'cookie') {
    const cookieCfg = affinity.cookie;
    const cookieName = cookieCfg.name || '__zt_upstream_affinity';
    const primarySecret = cookieCfg.secret?.trim() || '';
    const previousSecrets = cookieCfg.previousSecrets.map((s) => s.trim()).filter(Boolean);
    const secrets = [primarySecret, ...previousSecrets].filter(Boolean);
    const rawCookie = readCookie(req, cookieName);

    if (rawCookie && secrets.length > 0) {
      const verified = verifyAffinityToken(rawCookie, secrets);
      if (verified) {
        const setCookieHeader = verified.needsRotation
          ? serializeCookie(
              cookieName,
              issueAffinityToken(verified.key, cookieCfg.ttlSeconds, secrets[0]!),
              {
                maxAgeSeconds: cookieCfg.ttlSeconds,
                path: cookieCfg.path,
                domain: cookieCfg.domain,
                secure: cookieCfg.secure,
                httpOnly: cookieCfg.httpOnly,
                sameSite: cookieCfg.sameSite,
              },
            )
          : undefined;
        return {
          key: verified.key,
          source: 'cookie',
          setCookieHeader,
        };
      }
    }

    if (secrets.length > 0) {
      const newKey = `ck:${randomBytes(16).toString('hex')}`;
      return {
        key: newKey,
        source: 'cookie',
        setCookieHeader: serializeCookie(
          cookieName,
          issueAffinityToken(newKey, cookieCfg.ttlSeconds, secrets[0]!),
          {
            maxAgeSeconds: cookieCfg.ttlSeconds,
            path: cookieCfg.path,
            domain: cookieCfg.domain,
            secure: cookieCfg.secure,
            httpOnly: cookieCfg.httpOnly,
            sameSite: cookieCfg.sameSite,
          },
        ),
      };
    }

    if (!affinity.fallbackToIp) {
      return { source: 'none' };
    }
  }

  const ip = String(req.ip || '').trim();
  if (!ip) return { source: 'none' };
  return {
    key: `ip:${ip}`,
    source: 'ip',
  };
}

// ─── Circuit Breaker ─────────────────────────────────────────────────────────

enum CircuitState {
  CLOSED = 'closed',       // Normal operation
  OPEN = 'open',           // Failing, reject requests
  HALF_OPEN = 'half_open', // Testing if service recovered
}

interface CircuitBreakerState {
  state: CircuitState;
  failureCount: number;
  lastFailureTime: number;
  halfOpenRequests: number;
  lastStateChange: number;
}

class CircuitBreaker {
  private circuits = new Map<string, CircuitBreakerState>();

  private getOrCreate(service: string): CircuitBreakerState {
    let cb = this.circuits.get(service);
    if (!cb) {
      cb = {
        state: CircuitState.CLOSED,
        failureCount: 0,
        lastFailureTime: 0,
        halfOpenRequests: 0,
        lastStateChange: Date.now(),
      };
      this.circuits.set(service, cb);
    }
    return cb;
  }

  canRequest(service: string, config: UpstreamService): boolean {
    if (!config.circuitBreaker.enabled) return true;

    const cb = this.getOrCreate(service);
    const now = Date.now();

    switch (cb.state) {
      case CircuitState.CLOSED:
        return true;

      case CircuitState.OPEN:
        // Check if reset timeout has elapsed
        if (now - cb.lastStateChange >= config.circuitBreaker.resetTimeoutMs) {
          cb.state = CircuitState.HALF_OPEN;
          cb.halfOpenRequests = 1;
          cb.lastStateChange = now;
          return true;
        }
        return false;

      case CircuitState.HALF_OPEN:
        // Allow limited requests through
        if (cb.halfOpenRequests >= config.circuitBreaker.halfOpenMaxRequests) {
          return false;
        }
        cb.halfOpenRequests += 1;
        return true;
    }
  }

  recordSuccess(service: string, config: UpstreamService): void {
    if (!config.circuitBreaker.enabled) return;

    const cb = this.getOrCreate(service);
    if (cb.state === CircuitState.HALF_OPEN) {
      // Service recovered — close the circuit
      cb.state = CircuitState.CLOSED;
      cb.failureCount = 0;
      cb.halfOpenRequests = 0;
      cb.lastStateChange = Date.now();
    } else if (cb.state === CircuitState.CLOSED) {
      // Reset failure count on success
      cb.failureCount = 0;
    }
  }

  recordFailure(service: string, config: UpstreamService): void {
    if (!config.circuitBreaker.enabled) return;

    const cb = this.getOrCreate(service);
    cb.failureCount++;
    cb.lastFailureTime = Date.now();

    if (cb.state === CircuitState.HALF_OPEN) {
      // Failed during recovery — re-open
      cb.state = CircuitState.OPEN;
      cb.lastStateChange = Date.now();
    } else if (cb.state === CircuitState.CLOSED) {
      if (cb.failureCount >= config.circuitBreaker.failureThreshold) {
        cb.state = CircuitState.OPEN;
        cb.lastStateChange = Date.now();
      }
    }
  }

  getState(service: string): CircuitState {
    return this.getOrCreate(service).state;
  }

  getDetails(service: string): CircuitBreakerState {
    const cb = this.getOrCreate(service);
    return {
      state: cb.state,
      failureCount: cb.failureCount,
      lastFailureTime: cb.lastFailureTime,
      halfOpenRequests: cb.halfOpenRequests,
      lastStateChange: cb.lastStateChange,
    };
  }
}

class RetryBudgetManager {
  private readonly budgets = new Map<string, RetryBudgetState>();

  private getOrCreate(upstream: string): RetryBudgetState {
    let state = this.budgets.get(upstream);
    if (!state) {
      state = {
        windowStartMs: Date.now(),
        requests: 0,
        retries: 0,
      };
      this.budgets.set(upstream, state);
    }
    return state;
  }

  private maybeRotateWindow(
    state: RetryBudgetState,
    windowMs: number,
    nowMs: number,
  ): void {
    if (nowMs - state.windowStartMs < windowMs) return;
    state.windowStartMs = nowMs;
    state.requests = 0;
    state.retries = 0;
  }

  public recordRequest(upstream: string, config: UpstreamService, nowMs: number = Date.now()): void {
    const budget = config.retryBudget;
    if (!budget.enabled) return;
    const state = this.getOrCreate(upstream);
    this.maybeRotateWindow(state, budget.windowMs, nowMs);
    state.requests += 1;
  }

  public canRetry(upstream: string, config: UpstreamService, nowMs: number = Date.now()): boolean {
    const budget = config.retryBudget;
    if (!budget.enabled) return true;
    const state = this.getOrCreate(upstream);
    this.maybeRotateWindow(state, budget.windowMs, nowMs);

    const allowedRetries = Math.max(
      budget.minRetryTokens,
      Math.floor(state.requests * budget.ratio),
    );
    return state.retries < allowedRetries;
  }

  public consumeRetry(upstream: string, config: UpstreamService, nowMs: number = Date.now()): void {
    const budget = config.retryBudget;
    if (!budget.enabled) return;
    const state = this.getOrCreate(upstream);
    this.maybeRotateWindow(state, budget.windowMs, nowMs);
    state.retries += 1;
  }

  public getDetails(upstream: string, config: UpstreamService, nowMs: number = Date.now()): {
    enabled: boolean;
    windowStartMs: number;
    windowMs: number;
    requests: number;
    retries: number;
    allowedRetries: number;
    remainingRetries: number;
    ratio: number;
    minRetryTokens: number;
  } {
    const budget = config.retryBudget;
    if (!budget.enabled) {
      return {
        enabled: false,
        windowStartMs: nowMs,
        windowMs: budget.windowMs,
        requests: 0,
        retries: 0,
        allowedRetries: 0,
        remainingRetries: 0,
        ratio: budget.ratio,
        minRetryTokens: budget.minRetryTokens,
      };
    }

    const state = this.getOrCreate(upstream);
    this.maybeRotateWindow(state, budget.windowMs, nowMs);
    const allowedRetries = Math.max(
      budget.minRetryTokens,
      Math.floor(state.requests * budget.ratio),
    );
    return {
      enabled: true,
      windowStartMs: state.windowStartMs,
      windowMs: budget.windowMs,
      requests: state.requests,
      retries: state.retries,
      allowedRetries,
      remainingRetries: Math.max(0, allowedRetries - state.retries),
      ratio: budget.ratio,
      minRetryTokens: budget.minRetryTokens,
    };
  }
}

// ─── mTLS Agent Cache ────────────────────────────────────────────────────────

const agentCache = new Map<string, https.Agent>();

function getMtlsAgent(upstream: UpstreamService): https.Agent | undefined {
  if (!upstream.mtls?.enabled) return undefined;

  const cacheKey = `${upstream.name}:${upstream.mtls.certPath}:${upstream.mtls.keyPath}:${upstream.mtls.caPath}`;
  let agent = agentCache.get(cacheKey);

  if (!agent) {
    const options: https.AgentOptions = {
      rejectUnauthorized: upstream.mtls.rejectUnauthorized,
    };

    if (upstream.mtls.certPath) {
      options.cert = fs.readFileSync(upstream.mtls.certPath);
    }
    if (upstream.mtls.keyPath) {
      options.key = fs.readFileSync(upstream.mtls.keyPath);
    }
    if (upstream.mtls.caPath) {
      options.ca = fs.readFileSync(upstream.mtls.caPath);
    }

    agent = new https.Agent(options);
    agentCache.set(cacheKey, agent);
  }

  return agent;
}

async function probeEndpoint(
  endpointUrl: string,
  healthPath: string,
  timeoutMs: number,
  expectedStatusMin: number,
  expectedStatusMax: number,
): Promise<boolean> {
  return await new Promise<boolean>((resolve) => {
    try {
      const target = new URL(endpointUrl);
      const normalizedHealthPath = `${healthPath.startsWith('/') ? healthPath : '/' + healthPath}`;
      const basePath = target.pathname && target.pathname !== '/' ? target.pathname.replace(/\/$/, '') : '';
      const requestPath = `${basePath}${normalizedHealthPath}`;
      const isHttps = target.protocol === 'https:';

      const req = (isHttps ? https : http).request({
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (isHttps ? 443 : 80),
        method: 'GET',
        path: requestPath,
        timeout: timeoutMs,
      }, (res: http.IncomingMessage) => {
        const status = res.statusCode || 0;
        res.resume();
        resolve(status >= expectedStatusMin && status <= expectedStatusMax);
      });

      req.on('timeout', () => {
        req.destroy();
        resolve(false);
      });
      req.on('error', () => resolve(false));
      req.end();
    } catch {
      resolve(false);
    }
  });
}

function startActiveHealthChecks(
  config: GatewayConfig,
  pools: Map<string, UpstreamEndpointPool>,
  securityLog: ReturnType<typeof createSecurityLogger>,
): void {
  for (const name of Object.keys(config.upstreams)) {
    const initial = config.upstreams[name];
    if (!initial?.pool?.enabled || !initial.pool.activeHealthChecks?.enabled) continue;
    const intervalMs = Math.max(1_000, initial.pool.activeHealthChecks.intervalMs);

    const tick = async (): Promise<void> => {
      const upstream = config.upstreams[name];
      if (!upstream?.pool?.enabled || !upstream.pool.activeHealthChecks?.enabled) {
        return;
      }
      const pool = pools.get(name);
      if (!pool) return;
      const checkConfig = upstream.pool.activeHealthChecks;
      const snapshot = pool.getSnapshot();
      for (const endpoint of snapshot) {
        const healthy = await probeEndpoint(
          endpoint.url,
          checkConfig.path,
          checkConfig.timeoutMs,
          checkConfig.expectedStatusMin,
          checkConfig.expectedStatusMax,
        );
        if (healthy) {
          pool.recordSuccess(endpoint.url);
        } else {
          const ejected = pool.recordFailure(endpoint.url);
          if (ejected) {
            securityLog.warn({
              event: 'upstream_endpoint_ejected_by_active_probe',
              upstream: name,
              endpointUrl: endpoint.url,
              pool: pool.getSnapshot(),
            });
          }
        }
      }
    };

    void tick();
    const timer = setInterval(() => {
      void tick();
    }, intervalMs);
    if (typeof timer === 'object' && 'unref' in timer) {
      timer.unref();
    }
  }
}

// ─── Upstream Router Middleware ───────────────────────────────────────────────

export interface UpstreamRouterOptions {
  upstreamPolicyManager?: UpstreamRoutingPolicyManager;
}

function createEndpointPool(name: string, upstream: UpstreamService): UpstreamEndpointPool {
  return new UpstreamEndpointPool(
    name,
    upstream.url,
    upstream.pool?.enabled ? upstream.pool.endpoints : undefined,
    upstream.pool?.outlierEjection ?? {
      enabled: false,
      consecutiveFailuresThreshold: 5,
      ejectionDurationMs: 30_000,
      maxEjectionPercent: 50,
    },
    upstream.pool?.steering ?? {
      policy: 'weighted_random',
      latencyEwmaAlpha: 0.2,
      defaultLatencyMs: 100,
    },
  );
}

export function createUpstreamRouter(
  config: GatewayConfig,
  options?: UpstreamRouterOptions,
): RequestHandler {
  const securityLog = createSecurityLogger(config);
  const accessLog = createAccessLogger(config);
  const circuitBreaker = new CircuitBreaker();
  const retryBudgetManager = new RetryBudgetManager();
  const policyManager = options?.upstreamPolicyManager;
  let knownPolicyRevision = policyManager?.getRevision() ?? null;
  const canaryMonitor = new CanaryRouteMonitor({
    enabled: parseBooleanEnv(process.env['ROUTE_CANARY_AUTO_ROLLBACK_ENABLED'], false),
    windowMs: parseIntegerEnv(
      process.env['ROUTE_CANARY_AUTO_ROLLBACK_WINDOW_MS'],
      60_000,
      10_000,
      60 * 60 * 1000,
    ),
    minRequests: parseIntegerEnv(
      process.env['ROUTE_CANARY_AUTO_ROLLBACK_MIN_REQUESTS'],
      25,
      1,
      10_000,
    ),
    errorRateThreshold: parseNumberEnv(
      process.env['ROUTE_CANARY_AUTO_ROLLBACK_ERROR_RATE_THRESHOLD'],
      0.25,
      0.01,
      1,
    ),
    latencyThresholdMs: parseIntegerEnv(
      process.env['ROUTE_CANARY_AUTO_ROLLBACK_LATENCY_THRESHOLD_MS'],
      1_500,
      10,
      120_000,
    ),
    cooldownMs: parseIntegerEnv(
      process.env['ROUTE_CANARY_AUTO_ROLLBACK_COOLDOWN_MS'],
      300_000,
      1_000,
      24 * 60 * 60 * 1000,
    ),
    maxRoutes: parseIntegerEnv(
      process.env['ROUTE_CANARY_METRICS_MAX_ROUTES'],
      2_000,
      10,
      100_000,
    ),
  });

  // Pre-build proxy middleware for each upstream service
  const proxyMiddlewares = new Map<string, RequestHandler>();
  const endpointPools = new Map<string, UpstreamEndpointPool>();

  const resolveRuntimeUpstream = (name: string, fallback: UpstreamService): UpstreamService => (
    config.upstreams[name] ?? fallback
  );

  const resolveEndpointPool = (name: string, fallback: UpstreamService): UpstreamEndpointPool => {
    const existing = endpointPools.get(name);
    if (existing) return existing;
    const created = createEndpointPool(name, resolveRuntimeUpstream(name, fallback));
    endpointPools.set(name, created);
    return created;
  };

  const refreshEndpointPoolsIfNeeded = (): void => {
    if (!policyManager) return;
    const revision = policyManager.getRevision();
    if (revision === knownPolicyRevision) return;
    knownPolicyRevision = revision;

    for (const upstreamName of Array.from(endpointPools.keys())) {
      if (!config.upstreams[upstreamName]) {
        endpointPools.delete(upstreamName);
      }
    }

    for (const [upstreamName, upstream] of Object.entries(config.upstreams)) {
      endpointPools.set(upstreamName, createEndpointPool(upstreamName, upstream));
    }
  };

  for (const [name, upstream] of Object.entries(config.upstreams)) {
    const agent = getMtlsAgent(upstream);
    endpointPools.set(name, createEndpointPool(name, upstream));
    let middlewareRef: RequestHandler | null = null;
    const proxyOptions: ProxyOptions = {
      target: upstream.url,
      changeOrigin: true,
      secure: upstream.mtls?.rejectUnauthorized !== false,
      timeout: Math.max(120_000, upstream.timeoutMs),
      proxyTimeout: Math.max(120_000, upstream.timeoutMs),
      followRedirects: false, // Never follow redirects — let the client handle them
      router: (req: Request): string => {
        refreshEndpointPoolsIfNeeded();
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const affinityKey = (req as any)[SELECTED_ENDPOINT_AFFINITY_KEY] as string | undefined;
        const runtimeUpstream = resolveRuntimeUpstream(name, upstream);
        const pool = resolveEndpointPool(name, runtimeUpstream);
        const selected = pool.selectEndpoint(Date.now(), Math.random(), affinityKey);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (req as any)[SELECTED_ENDPOINT_URL] = selected.url;
        return selected.url;
      },

      // Add internal headers and strip dangerous external ones
      onProxyReq: (proxyReq, req: Request) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (req as any)[UPSTREAM_REQUEST_START_MS] = Date.now();
        const correlationId = (req.headers['x-correlation-id'] as string) || 'unknown';
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const rawBody = (req as any).rawBody as Buffer | undefined;
        const pathForSig = req.originalUrl || req.url || req.path;

        // ── Strip hop-by-hop headers ─────────────────────────────────
        for (const header of HOP_BY_HOP_HEADERS) {
          proxyReq.removeHeader(header);
        }

        // ── Strip external attempts to set internal-only headers ─────
        for (const header of INTERNAL_ONLY_HEADERS) {
          proxyReq.removeHeader(header);
        }

        // ── Strip any route-specific blacklisted headers ─────────────
        const routeConfig = getRouteConfig(config, req.path, req.method);
        if (routeConfig?.stripRequestHeaders) {
          for (const header of routeConfig.stripRequestHeaders) {
            proxyReq.removeHeader(header.toLowerCase());
          }
        }

        // ── Add internal security headers ────────────────────────────
        proxyReq.setHeader('X-Request-Id', correlationId);
        proxyReq.setHeader('X-Internal-Request', 'true');

        // ── Internal service-to-service auth (HMAC) ──────────────────
        // Defense-in-depth against lateral movement if network boundaries are misconfigured.
        if (config.internalAuth.enabled) {
          const runtimeUpstream = resolveRuntimeUpstream(name, upstream);
          const headers = computeInternalAuthHeaders(
            { method: req.method, path: pathForSig, rawBody },
            config.internalAuth.callerSecret || config.internalAuth.secret!,
            undefined,
            undefined,
            config.internalAuth.callerId,
            runtimeUpstream.name,
            config.internalAuth.callerKeyId,
          );
          for (const [k, v] of Object.entries(headers)) {
            proxyReq.setHeader(k, v);
          }
        }

        if (req.identity) {
          proxyReq.setHeader('X-Authenticated-User', req.identity.sub);
          proxyReq.setHeader('X-Authenticated-Roles', req.identity.roles.join(','));
          proxyReq.setHeader('X-Authenticated-Permissions', req.identity.permissions.join(','));
          proxyReq.setHeader('X-Step-Up-Level', String(req.identity.stepUpLevel));
        }

        if (req.policyDecisionId) {
          proxyReq.setHeader('X-Policy-Decision-Id', req.policyDecisionId);
        }

        // ── Re-stream body if it was parsed earlier ──────────────────
        // body-parser consumes the request stream, so the proxy would otherwise forward an empty body.
        const method = req.method.toUpperCase();
        const canHaveBody = !['GET', 'HEAD', 'OPTIONS'].includes(method);
        if (canHaveBody && rawBody && rawBody.length > 0) {
          proxyReq.setHeader('Content-Length', rawBody.length);
          proxyReq.write(rawBody);
        }
      },

      onProxyRes: (_proxyRes, req: Request) => {
        const runtimeUpstream = resolveRuntimeUpstream(name, upstream);
        const pool = resolveEndpointPool(name, runtimeUpstream);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const endpointUrl = ((req as any)[SELECTED_ENDPOINT_URL] as string | undefined) ?? runtimeUpstream.url;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const requestStartedAtMs = (req as any)[UPSTREAM_REQUEST_START_MS] as number | undefined;
        const observedLatencyMs = requestStartedAtMs ? Math.max(1, Date.now() - requestStartedAtMs) : undefined;
        const statusCode = _proxyRes.statusCode || 0;
        if (statusCode >= 500) {
          circuitBreaker.recordFailure(name, runtimeUpstream);
          const ejected = pool.recordFailure(endpointUrl);
          if (ejected) {
            securityLog.warn({
              event: 'upstream_endpoint_ejected',
              upstream: name,
              endpointUrl,
              statusCode,
              pool: pool.getSnapshot(),
            });
          }
        } else {
          circuitBreaker.recordSuccess(name, runtimeUpstream);
          pool.recordSuccess(endpointUrl, observedLatencyMs);
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const routeCanaryKey = (req as any)[SELECTED_CANARY_ROUTE_KEY] as string | undefined;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const routeCanaryUsed = Boolean((req as any)[SELECTED_CANARY_USED]);
        if (routeCanaryKey && routeCanaryUsed) {
          const outcome = canaryMonitor.recordOutcome(routeCanaryKey, {
            success: statusCode < 500,
            latencyMs: observedLatencyMs ?? null,
          });
          if (outcome.rollbackActivated) {
            securityLog.warn({
              event: 'route_canary_auto_rollback_activated',
              routePath:
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                ((req as any)[SELECTED_CANARY_PATH] as string | undefined) ?? req.path,
              primaryUpstream:
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                ((req as any)[SELECTED_CANARY_PRIMARY] as string | undefined) ?? 'unknown',
              canaryUpstream:
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                ((req as any)[SELECTED_CANARY_TARGET] as string | undefined) ?? 'unknown',
              reason: outcome.rollbackReason,
              rollbackUntil: outcome.rollbackUntil,
            });
          }
        }

        accessLog.debug({
          event: 'upstream_response',
          upstream: name,
          endpointUrl,
          observedLatencyMs,
          correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
          status: statusCode,
          path: req.path,
        });
      },

      onError: (err, req: Request, res: Response) => {
        const runtimeUpstream = resolveRuntimeUpstream(name, upstream);
        const pool = resolveEndpointPool(name, runtimeUpstream);
        circuitBreaker.recordFailure(name, runtimeUpstream);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const endpointUrl = ((req as any)[SELECTED_ENDPOINT_URL] as string | undefined) ?? runtimeUpstream.url;
        const ejected = pool.recordFailure(endpointUrl);

        const correlationId = (req.headers['x-correlation-id'] as string) || 'unknown';
        const retryAttempts = (
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (req as any)[UPSTREAM_RETRY_ATTEMPTS] as number | undefined
        ) ?? 0;
        const maxRetries = Math.max(0, Math.floor(runtimeUpstream.retries ?? 0));
        const canRetry =
          !res.headersSent &&
          retryAttempts < maxRetries &&
          shouldRetryRequestMethod(req.method) &&
          retryBudgetManager.canRetry(name, runtimeUpstream);

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const routeCanaryKey = (req as any)[SELECTED_CANARY_ROUTE_KEY] as string | undefined;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const routeCanaryUsed = Boolean((req as any)[SELECTED_CANARY_USED]);
        if (routeCanaryKey && routeCanaryUsed) {
          const outcome = canaryMonitor.recordOutcome(routeCanaryKey, {
            success: false,
            reason: 'proxy_error',
          });
          if (outcome.rollbackActivated) {
            securityLog.warn({
              event: 'route_canary_auto_rollback_activated',
              routePath:
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                ((req as any)[SELECTED_CANARY_PATH] as string | undefined) ?? req.path,
              primaryUpstream:
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                ((req as any)[SELECTED_CANARY_PRIMARY] as string | undefined) ?? 'unknown',
              canaryUpstream:
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                ((req as any)[SELECTED_CANARY_TARGET] as string | undefined) ?? 'unknown',
              reason: outcome.rollbackReason,
              rollbackUntil: outcome.rollbackUntil,
            });
          }
        }

        if (canRetry && middlewareRef) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (req as any)[UPSTREAM_RETRY_ATTEMPTS] = retryAttempts + 1;
          retryBudgetManager.consumeRetry(name, runtimeUpstream);
          const backoffMs = retryBackoffMs(retryAttempts + 1);
          securityLog.warn({
            event: 'upstream_retry_scheduled',
            upstream: name,
            endpointUrl,
            correlationId,
            path: req.path,
            method: req.method,
            attempt: retryAttempts + 1,
            maxRetries,
            backoffMs,
            error: err.message,
            endpointEjected: ejected,
            retryBudget: retryBudgetManager.getDetails(name, runtimeUpstream),
          });
          const timer = setTimeout(() => {
            if (res.headersSent) return;
            middlewareRef?.(req, res, () => undefined);
          }, backoffMs);
          if (typeof timer === 'object' && 'unref' in timer) {
            timer.unref();
          }
          return;
        }

        securityLog.error({
          event: 'upstream_error',
          upstream: name,
          endpointUrl,
          correlationId,
          error: err.message,
          path: req.path,
          method: req.method,
          circuitState: circuitBreaker.getState(name),
          endpointEjected: ejected,
          retryAttempts,
          retryBudget: retryBudgetManager.getDetails(name, runtimeUpstream),
        });

        if (!res.headersSent) {
          res.status(502).json({ error: 'Bad Gateway' });
        }
      },

      // Use custom agent for mTLS if configured
      ...(agent ? {
        agent,
      } : {}),

      logLevel: 'silent', // We handle logging ourselves
    };

    const middleware = createProxyMiddleware(proxyOptions);
    middlewareRef = middleware as RequestHandler;
    proxyMiddlewares.set(name, middleware as RequestHandler);
  }

  startActiveHealthChecks(config, endpointPools, securityLog);

  const buildDiagnostics = (upstreamFilter?: string) => {
    refreshEndpointPoolsIfNeeded();
    const now = Date.now();
    const entries = Object.entries(config.upstreams).filter(([name]) => !upstreamFilter || upstreamFilter === name);
    return {
      generatedAt: new Date(now).toISOString(),
      policyRevision: policyManager?.getRevision() ?? null,
      upstreamCount: entries.length,
      upstreams: entries.map(([name, upstream]) => {
        const pool = endpointPools.get(name);
        const cb = circuitBreaker.getDetails(name);
        return {
          name,
          configuredUrl: upstream.url,
          circuitBreaker: {
            enabled: upstream.circuitBreaker.enabled,
            state: cb.state,
            failureCount: cb.failureCount,
            lastFailureTime: cb.lastFailureTime,
            halfOpenRequests: cb.halfOpenRequests,
            lastStateChange: cb.lastStateChange,
          },
          retryBudget: retryBudgetManager.getDetails(name, upstream, now),
          pool: {
            enabled: upstream.pool?.enabled ?? false,
            steering: upstream.pool?.steering ?? {
              policy: 'weighted_random',
              latencyEwmaAlpha: 0.2,
              defaultLatencyMs: 100,
            },
            sessionAffinity: upstream.pool?.sessionAffinity ?? {
              enabled: false,
              source: 'ip',
              headerName: 'x-zt-affinity-key',
              fallbackToIp: true,
              cookie: {
                name: '__zt_upstream_affinity',
                ttlSeconds: 60 * 60 * 24 * 7,
                secure: true,
                httpOnly: true,
                sameSite: 'lax',
                path: '/',
                previousSecrets: [],
              },
            },
            outlierEjection: upstream.pool?.outlierEjection ?? {
              enabled: false,
              consecutiveFailuresThreshold: 5,
              ejectionDurationMs: 30_000,
              maxEjectionPercent: 50,
            },
            activeHealthChecks: upstream.pool?.activeHealthChecks ?? {
              enabled: false,
              intervalMs: 10_000,
              timeoutMs: 2_000,
              path: '/health',
              expectedStatusMin: 200,
              expectedStatusMax: 399,
            },
            endpointCount: pool?.size ?? 0,
            endpoints: pool?.getSnapshot(now) ?? [],
          },
        };
      }),
    };
  };

  // ── Main routing handler ────────────────────────────────────────────
  return (req: Request, res: Response, next: NextFunction): void => {
    refreshEndpointPoolsIfNeeded();
    const correlationId = (req.headers['x-correlation-id'] as string) || 'unknown';

    if (req.method.toUpperCase() === 'GET' && req.path === '/internal/upstreams/diagnostics') {
      const requestedUpstream = typeof req.query?.['upstream'] === 'string'
        ? req.query['upstream']
        : undefined;

      if (requestedUpstream && !config.upstreams[requestedUpstream]) {
        res.status(404).json({ error: 'upstream_not_found' });
        return;
      }

      res.status(200).json(buildDiagnostics(requestedUpstream));
      return;
    }

    if (req.method.toUpperCase() === 'GET' && req.path === '/internal/routes/canary/metrics') {
      const routePathFilter = typeof req.query?.['routePath'] === 'string'
        ? req.query['routePath']
        : undefined;
      res.status(200).json(canaryMonitor.getSnapshot(routePathFilter));
      return;
    }

    const routeConfig = getRouteConfig(config, req.path, req.method);

    if (!routeConfig) {
      // No route configured for this path — deny by default
      securityLog.warn({
        event: 'upstream_no_route',
        correlationId,
        ip: req.ip,
        path: req.path,
        method: req.method,
        reason: 'No matching route configuration',
      });
      res.status(404).json({ error: 'Not Found' });
      return;
    }

    const routeCanaryKey = buildRouteCanaryKey(routeConfig);
    const rollbackActive = canaryMonitor.isRollbackActive(routeCanaryKey);
    const routeResolution = resolveRouteUpstream(routeConfig, req, { rollbackActive });
    let routeCanaryUsed = routeResolution.usedCanary;
    let upstreamName = routeResolution.upstreamName;
    let upstream = config.upstreams[upstreamName];
    if (!upstream && routeResolution.usedCanary) {
      // Canary targets can become temporarily unavailable during runtime policy churn.
      // Fallback to primary upstream instead of failing closed on canary-only drift.
      upstreamName = routeConfig.upstream;
      upstream = config.upstreams[upstreamName];
      securityLog.warn({
        event: 'route_canary_upstream_unavailable_fallback',
        correlationId,
        path: req.path,
        method: req.method,
        canaryUpstream: routeResolution.upstreamName,
        fallbackUpstream: upstreamName,
      });
      routeCanaryUsed = false;
    }

    const decisionAtMs = Date.now();
    canaryMonitor.recordDecision(routeCanaryKey, {
      atMs: decisionAtMs,
      routePath: routeConfig.path,
      primaryUpstream: routeConfig.upstream,
      canaryUpstream: String(routeConfig.canary?.upstream ?? '').trim(),
      selectedUpstream: upstreamName,
      usedCanary: routeCanaryUsed,
      rolloutPercent: routeResolution.rolloutPercent,
      bucket: routeResolution.bucket,
      rollbackSuppressed: Boolean(routeResolution.rollbackSuppressed),
    }, decisionAtMs);

    if (!upstream) {
      securityLog.error({
        event: 'upstream_not_configured',
        correlationId,
        path: req.path,
        upstreamName,
        reason: 'Route references unconfigured upstream',
      });
      res.status(502).json({ error: 'Bad Gateway' });
      return;
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (req as any)[SELECTED_CANARY_ROUTE_KEY] = routeCanaryKey;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (req as any)[SELECTED_CANARY_USED] = routeCanaryUsed;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (req as any)[SELECTED_CANARY_PATH] = routeConfig.path;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (req as any)[SELECTED_CANARY_PRIMARY] = routeConfig.upstream;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (req as any)[SELECTED_CANARY_TARGET] = String(routeConfig.canary?.upstream ?? '').trim();

    if (routeConfig.canary?.enabled) {
      accessLog.debug({
        event: 'route_canary_decision',
        correlationId,
        path: req.path,
        method: req.method,
        primaryUpstream: routeConfig.upstream,
        selectedUpstream: upstreamName,
        canaryUpstream: routeConfig.canary.upstream,
        canarySelected: routeCanaryUsed,
        rolloutPercent: routeResolution.rolloutPercent,
        bucket: routeResolution.bucket,
        rollbackActive,
        rollbackSuppressed: Boolean(routeResolution.rollbackSuppressed),
      });
    }

    const affinity = resolveAffinity(req, upstream);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (req as any)[SELECTED_ENDPOINT_AFFINITY_KEY] = affinity.key;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (req as any)[UPSTREAM_RETRY_ATTEMPTS] = 0;
    if (affinity.setCookieHeader) {
      appendSetCookie(res, affinity.setCookieHeader);
    }

    retryBudgetManager.recordRequest(upstreamName, upstream);

    // ── Circuit breaker check ─────────────────────────────────────────
    if (!circuitBreaker.canRequest(upstreamName, upstream)) {
      securityLog.warn({
        event: 'upstream_circuit_open',
        correlationId,
        upstream: upstreamName,
        path: req.path,
        method: req.method,
        circuitState: circuitBreaker.getState(upstreamName),
      });
      res.status(503).json({ error: 'Service Unavailable' });
      return;
    }

    // ── Timeout enforcement ───────────────────────────────────────────
    const timeout = routeConfig.timeoutMs || upstream.timeoutMs;
    const timer = setTimeout(() => {
      if (!res.headersSent) {
        circuitBreaker.recordFailure(upstreamName, upstream);
        securityLog.warn({
          event: 'upstream_timeout',
          correlationId,
          upstream: upstreamName,
          path: req.path,
          timeout,
        });
        res.status(504).json({ error: 'Gateway Timeout' });
      }
    }, timeout);

    // Clear timeout when response finishes
    res.on('finish', () => clearTimeout(timer));
    res.on('close', () => clearTimeout(timer));

    // ── Proxy the request ─────────────────────────────────────────────
    const proxyMiddleware = proxyMiddlewares.get(upstreamName);
    if (!proxyMiddleware) {
      clearTimeout(timer);
      securityLog.error({
        event: 'upstream_proxy_not_found',
        correlationId,
        upstream: upstreamName,
        reason: 'Proxy middleware not initialized for upstream',
      });
      res.status(502).json({ error: 'Bad Gateway' });
      return;
    }

    // Track circuit breaker for half-open state
    if (circuitBreaker.getState(upstreamName) === CircuitState.HALF_OPEN) {
      accessLog.info({
        event: 'upstream_half_open_request',
        correlationId,
        upstream: upstreamName,
        path: req.path,
      });
    }

    proxyMiddleware(req, res, next);
  };
}
