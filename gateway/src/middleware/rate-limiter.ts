import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { GatewayConfig, RateLimitTier } from '../../config/default';
import { getRouteConfig } from '../../config/default';
import { createSecurityLogger } from './request-logger';
import { extractClientIp } from '../utils/client-ip';
import type { SecurityStateStore } from '../state/security-state-store';
import {
  InMemoryRateLimitStore,
  recordRateLimitHit,
  type RateLimitConfig,
  type RateLimitResult,
  type RateLimitStore,
} from '@zerotrust/shared';
import {
  type GreylistFailureCounter,
  InMemoryGreylistFailureCounter,
} from './greylist-failure-counter';
import type { GatewayIdentity } from './jwt-validation';

/**
 * Three-tier rate limiter with token bucket algorithm.
 *
 * Tiers: per-IP, per-identity, per-route.
 * Each tier has independent burst and steady-state rates.
 * Greylisting: IPs with suspicious behavior (many 401s, scanning) get throttled.
 * X-Forwarded-For abuse prevention: validate chain depth, use rightmost trusted.
 */

// ─── Rate Limit Middleware ───────────────────────────────────────────────────

function tierToStoreConfig(tier: RateLimitTier): RateLimitConfig {
  const windowSeconds = Math.max(0.001, tier.windowMs / 1000);
  const refillPerSecond = tier.maxRequests / windowSeconds;
  return {
    burstSize: Math.max(1, Math.floor(tier.burstMax)),
    // Floor to a tiny positive value so retry-after math never divides by 0.
    refillRatePerSecond: Math.max(0.01, refillPerSecond),
  };
}

function setRateLimitHeaders(res: Response, result: RateLimitResult): void {
  res.setHeader('X-RateLimit-Limit', String(result.limit));
  res.setHeader('X-RateLimit-Remaining', String(Math.max(0, Math.floor(result.remaining))));

  // "Reset" is ambiguous for token buckets. We expose "next token time" semantics.
  const resetSeconds = Math.ceil((Date.now() + Math.max(0, result.retryAfterMs)) / 1000);
  res.setHeader('X-RateLimit-Reset', String(resetSeconds));

  if (!result.allowed && result.retryAfterMs > 0) {
    res.setHeader('Retry-After', String(Math.ceil(result.retryAfterMs / 1000)));
  }
}

export function createRateLimiterMiddleware(
  config: GatewayConfig,
  options?: {
    store?: RateLimitStore;
    greylistFailureCounter?: GreylistFailureCounter;
  }
): RequestHandler {
  const securityLog = createSecurityLogger(config);

  const store = options?.store ?? new InMemoryRateLimitStore();

  const trustedProxies = new Set(config.rateLimit.trustedProxies);
  const maxXffDepth = config.rateLimit.xForwardedForMaxDepth;

  const greylistEnabled = config.rateLimit.greylist.enabled;
  const greylistMultiplier = Math.max(0, Math.min(1, config.rateLimit.greylist.tightenedRateMultiplier));
  const greylistFailureCounter: GreylistFailureCounter | undefined = greylistEnabled
    ? (options?.greylistFailureCounter ?? new InMemoryGreylistFailureCounter({
        failureWindowMs: config.rateLimit.greylist.failureWindowMs,
        failureThreshold: config.rateLimit.greylist.failureThreshold,
        greylistDurationMs: config.rateLimit.greylist.greylistDurationMs,
        rateMultiplier: greylistMultiplier,
        store,
        reason: 'auth_failures',
      }))
    : undefined;

  // Track failures for greylisting on response
  const _trackResponseForGreylist = (_req: Request, res: Response, ipKey: string): void => {
    const originalEnd = res.end;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    res.end = function (this: Response, ...args: any[]): Response {
      if (res.statusCode === 401 || res.statusCode === 403) {
        // Fire-and-forget; rate limiting must never break responses.
        void greylistFailureCounter?.recordFailure(ipKey).catch(() => {});
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return originalEnd.apply(this, args as any);
    };
  };

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const correlationId = (req.headers['x-correlation-id'] as string) || 'unknown';
    const clientIp = extractClientIp(req, maxXffDepth, trustedProxies);
    const routeConfig = getRouteConfig(config, req.path, req.method);

    // Track response status for greylisting
    if (greylistEnabled) {
      _trackResponseForGreylist(req, res, `ip:${clientIp}`);
    }

    // ── Tier 1: Per-IP rate limit ─────────────────────────────────────
    const ipTier = routeConfig?.rateLimit?.perIp ?? config.rateLimit.global.perIp;
    const ipKey = `ip:${clientIp}`;
    const ipResult = await store.consume(ipKey, tierToStoreConfig(ipTier));
    if (!ipResult.allowed) {
      const retryAfterSeconds = Math.max(1, Math.ceil(ipResult.retryAfterMs / 1000));

      recordRateLimitHit('per_ip', 'gateway');

      securityLog.warn({
        event: 'rate_limit_exceeded',
        tier: 'per_ip',
        correlationId,
        clientIp,
        path: req.path,
        method: req.method,
        greylisted: greylistEnabled ? Boolean(await store.isGreylisted(ipKey)) : false,
        retryAfterSeconds,
      });

      setRateLimitHeaders(res, ipResult);
      res.status(429).json({ error: 'Too Many Requests', retryAfter: retryAfterSeconds });
      return;
    }

    // ── Tier 2: Per-route rate limit ──────────────────────────────────
    if (routeConfig?.rateLimit?.perRoute) {
      const routeTier = routeConfig.rateLimit.perRoute;
      const routeKey = `route:${routeConfig.path}:${clientIp}`;
      const routeResult = await store.consume(routeKey, tierToStoreConfig(routeTier));
      if (!routeResult.allowed) {
        const retryAfterSeconds = Math.max(1, Math.ceil(routeResult.retryAfterMs / 1000));

        recordRateLimitHit('per_route', 'gateway');

        securityLog.warn({
          event: 'rate_limit_exceeded',
          tier: 'per_route',
          correlationId,
          route: routeConfig.path,
          clientIp,
          path: req.path,
          method: req.method,
          retryAfterSeconds,
        });

        setRateLimitHeaders(res, routeResult);
        res.status(429).json({ error: 'Too Many Requests', retryAfter: retryAfterSeconds });
        return;
      }
    }

    // Set rate limit headers (from IP tier)
    setRateLimitHeaders(res, ipResult);
    next();
  };
}

/**
 * Post-auth rate limiter: per-identity limits.
 *
 * Must run AFTER JWT validation so `req.identity` exists.
 */
export function createIdentityRateLimiterMiddleware(
  config: GatewayConfig,
  options?: { stateStore?: SecurityStateStore; store?: RateLimitStore }
): RequestHandler {
  const securityLog = createSecurityLogger(config);
  const store = options?.store ?? new InMemoryRateLimitStore();
  const tenantRateLimit = config.rateLimit.tenant;

  const resolveTenantId = (req: Request, identity: GatewayIdentity): string | undefined => {
    if (!tenantRateLimit.enabled) return undefined;
    if (tenantRateLimit.keySource === 'header') {
      const headerName = tenantRateLimit.headerName.toLowerCase();
      const value = req.headers[headerName];
      const tenant = Array.isArray(value) ? value[0] : value;
      if (typeof tenant === 'string' && tenant.trim().length > 0) {
        return tenant.trim().slice(0, 128);
      }
      return undefined;
    }
    return identity.tenantId;
  };

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const correlationId = (req.headers['x-correlation-id'] as string) || 'unknown';
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const identity = (req as any).identity as GatewayIdentity | undefined;
    if (!identity?.sub) return next();

    const routeConfig = getRouteConfig(config, req.path, req.method);
    const identityTier = routeConfig?.rateLimit?.perIdentity ?? config.rateLimit.global.perIdentity;
    const tenantTier = routeConfig?.rateLimit?.perTenant ?? tenantRateLimit.perTenant;
    const tenantId = resolveTenantId(req, identity);

    let multiplier = 1.0;
    try {
      const throttle = options?.stateStore ? await options.stateStore.getThrottle(identity.sub) : null;
      if (throttle) {
        multiplier = Math.max(0.01, Math.min(1.0, throttle.reducedRatePercent / 100));
      }
    } catch {
      // fail open on throttle checks
    }

    const base = tierToStoreConfig(identityTier);
    const effectiveConfig: RateLimitConfig = multiplier === 1.0
      ? base
      : {
          burstSize: Math.max(1, Math.floor(base.burstSize * multiplier)),
          refillRatePerSecond: Math.max(0.01, base.refillRatePerSecond * multiplier),
        };

    const identityKey = `identity:${identity.sub}`;
    const result = await store.consume(identityKey, effectiveConfig);
    if (!result.allowed) {
      const retryAfterSeconds = Math.max(1, Math.ceil(result.retryAfterMs / 1000));

      recordRateLimitHit('per_identity', 'gateway');

      securityLog.warn({
        event: 'rate_limit_exceeded',
        tier: 'per_identity',
        correlationId,
        identity: identity.sub,
        path: req.path,
        method: req.method,
        retryAfterSeconds,
      });

      setRateLimitHeaders(res, result);
      res.status(429).json({ error: 'Too Many Requests', retryAfter: retryAfterSeconds });
      return;
    }

    if (tenantRateLimit.enabled && tenantId) {
      const tenantResult = await store.consume(
        `tenant:${tenantId}`,
        tierToStoreConfig(tenantTier),
      );
      if (!tenantResult.allowed) {
        const retryAfterSeconds = Math.max(1, Math.ceil(tenantResult.retryAfterMs / 1000));

        recordRateLimitHit('per_tenant', 'gateway');

        securityLog.warn({
          event: 'rate_limit_exceeded',
          tier: 'per_tenant',
          correlationId,
          tenantId,
          identity: identity.sub,
          path: req.path,
          method: req.method,
          retryAfterSeconds,
        });

        setRateLimitHeaders(res, tenantResult);
        res.status(429).json({ error: 'Too Many Requests', retryAfter: retryAfterSeconds });
        return;
      }
    }

    // Overwrite headers with identity-tier values (more relevant for auth'd requests)
    setRateLimitHeaders(res, result);
    next();
  };
}
