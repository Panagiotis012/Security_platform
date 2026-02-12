import type { Request, Response, NextFunction } from 'express';
import express from 'express';
import cookieParser from 'cookie-parser';
import hpp from 'hpp';
import compression from 'compression';
import { v4 as uuidv4 } from 'uuid';
import type { GatewayConfig } from '../config/default';
import { createHelmetMiddleware, conditionalHsts, noCacheHeaders } from './middleware/helmet-config';
import { createBodyLimitsMiddleware } from './middleware/body-limits';
import { createNormalizationMiddleware } from './middleware/normalization';
import { createCorsMiddleware } from './middleware/cors-handler';
import { createRateLimiterMiddleware, createIdentityRateLimiterMiddleware } from './middleware/rate-limiter';
import { createBotManagementMiddleware } from './middleware/bot-management';
import { createWafMiddleware } from './middleware/waf';
import { createJwtValidationMiddleware } from './middleware/jwt-validation';
import { createPolicyCheckMiddleware } from './middleware/policy-check';
import { createRequestLoggerMiddleware } from './middleware/request-logger';
import { createAdaptiveIpDefenseMiddleware } from './middleware/adaptive-ip-defense';
import { createBotChallengeMiddleware } from './middleware/bot-challenge';
import { createAccessControlMiddleware } from './middleware/access-control';
import { createEdgeCacheMiddleware } from './middleware/edge-cache';
import { createUpstreamRouter } from './proxy/upstream-router';
import type { RoutePolicyManager } from './proxy/route-policy-manager';
import type { UpstreamRoutingPolicyManager } from './proxy/upstream-policy-manager';
import { createSecurityLogger } from './middleware/request-logger';
import { getRouteConfig } from '../config/default';
import { extractClientIp } from './utils/client-ip';
import { createInternalRoutes } from './internal/internal-routes';
import type { SecurityStateStore } from './state/security-state-store';
import type { IdentitySecurityStore } from './state/identity-security-store';
import type { IpReputationStore } from './state/ip-reputation-store';
import type { BotChallengeStore } from './state/bot-challenge-store';
import type { GreylistFailureCounter } from './middleware/greylist-failure-counter';
import type { EdgeCacheStore } from './state/edge-cache-store';
import type { EdgeInvalidationEventStore } from './state/edge-invalidation-event-store';
import type { ControlPlaneAuditStore } from './state/control-plane-audit-store';
import type { SecurityControlsAuditStore } from './state/security-controls-audit-store';
import {
  createRequestMetricsMiddleware,
  breakGlassMiddleware,
  BreakGlassManager,
  verifyInternalAuthAsync,
  type InternalAuthOptions,
  type InternalAuthReplayStore,
  type RateLimitStore,
} from '@zerotrust/shared';

/**
 * Express application factory.
 *
 * Middleware order is CRITICAL for security:
 *
 *   1. correlation-id      — Tag every request for tracing
 *   2. request-logger      — Log entry (captures timing)
 *   3. helmet              — Security headers on every response
 *   4. body-limits         — Reject oversized / malformed bodies early
 *   5. normalization       — Canonicalize BEFORE any auth decisions
 *   6. cors                — DENY by default, allowlist only
 *   7. access-control      — IP/CIDR + geo/ASN gates
 *   8. rate-limiter        — Throttle before expensive auth work
 *   9. waf                 — Block obvious attacks before auth
 *  10. jwt-validation      — Authenticate identity
 *  11. policy-check        — Authorize via PDP (fail-closed)
 *  12. proxy               — Route to upstream service
 *
 * No implicit allows. Every route goes through the full chain.
 * The ONLY exception is the health check endpoint.
 */

export interface AppDependencies {
  stateStore: SecurityStateStore;
  identitySecurityStore?: IdentitySecurityStore;
  ipReputationStore: IpReputationStore;
  botChallengeStore: BotChallengeStore;
  rateLimitStore?: RateLimitStore;
  greylistFailureCounter?: GreylistFailureCounter;
  internalAuthReplayStore?: InternalAuthReplayStore;
  abuseIntelReplayStore?: InternalAuthReplayStore;
  edgeCacheStore?: EdgeCacheStore;
  edgeInvalidationEventStore?: EdgeInvalidationEventStore;
  controlPlaneAuditStore?: ControlPlaneAuditStore;
  routePolicyManager?: RoutePolicyManager;
  upstreamPolicyManager?: UpstreamRoutingPolicyManager;
  securityControlsAuditStore?: SecurityControlsAuditStore;
}

export function createApp(config: GatewayConfig, deps: AppDependencies): express.Application {
  const app = express();
  const securityLog = createSecurityLogger(config);
  const trustedProxies = new Set(config.rateLimit.trustedProxies);
  const maxXffDepth = config.rateLimit.xForwardedForMaxDepth;
  const healthPaths = new Set<string>([config.healthCheck.path, '/healthz']);
  const isHealthPath = (path: string): boolean => {
    if (healthPaths.has(path)) return true;
    for (const healthPath of healthPaths) {
      if (path === `${healthPath}/`) return true;
    }
    return false;
  };

  // ── Trust proxy configuration ───────────────────────────────────────
  // Required for correct client IP detection behind load balancers.
  // MUST be set correctly — over-trusting allows IP spoofing.
  app.set('trust proxy', config.server.trustProxy);

  // ── Disable Express fingerprinting ──────────────────────────────────
  app.disable('x-powered-by');
  app.disable('etag'); // Prevent information leakage via ETags

  // ── 1. Correlation ID ──────────────────────────────────────────────
  // Assign a unique ID to every request for distributed tracing.
  // If a trusted upstream already set one, use it; otherwise generate.
  app.use((req: Request, res: Response, next: NextFunction) => {
    const existing = req.headers['x-correlation-id'];
    const isSafe =
      typeof existing === 'string' &&
      existing.length > 0 &&
      existing.length <= 128 &&
      /^[A-Za-z0-9._:-]+$/.test(existing);

    const id = isSafe ? existing : uuidv4();
    req.headers['x-correlation-id'] = id;

    // Make tracing easier for clients and downstream services.
    res.setHeader('X-Correlation-Id', id);

    next();
  });

  // ── 2. Request Logger ──────────────────────────────────────────────
  // Must be early to capture timing for the entire request lifecycle.
  app.use(createRequestLoggerMiddleware(config));

  // ── 2.0. Internal mTLS (Envoy -> Gateway) ──────────────────────────
  // If the gateway is placed behind a front proxy (Envoy, API Gateway, LB),
  // require mTLS on the public listener so only the proxy can reach it.
  // Internal control-plane calls (/internal/*) are still protected by internal-auth.
  const mtlsRequired =
    ['true', '1', 'yes'].includes((process.env['GATEWAY_MTLS_REQUIRED'] ?? '').toLowerCase());
  const expectedCn = (process.env['GATEWAY_MTLS_EXPECTED_CN'] ?? '').trim();
  const internalAllowedClientCns = new Set(
    (process.env['GATEWAY_INTERNAL_MTLS_ALLOWED_CLIENT_CNS'] ?? '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
  app.use((req, res, next) => {
    if (!mtlsRequired) return next();
    if (isHealthPath(req.path)) return next();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const sock: any = req.socket;
    const authorized = sock && sock.authorized === true;
    const cert = sock?.getPeerCertificate?.();

    if (!authorized || !cert || Object.keys(cert).length === 0) {
      securityLog.warn({
        event: 'mtls_required',
        path: req.path,
        method: req.method,
        ip: req.socket.remoteAddress,
        correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
      });
      res.status(403).json({ error: 'mTLS required' });
      return;
    }

    if (req.path.startsWith('/internal/') && internalAllowedClientCns.size > 0) {
      const cn = String(cert?.subject?.CN ?? '').trim().toLowerCase();
      if (!cn || !internalAllowedClientCns.has(cn)) {
        securityLog.warn({
          event: 'mtls_internal_client_cn_denied',
          cn,
          path: req.path,
          method: req.method,
          correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
        });
        res.status(403).json({ error: 'Forbidden' });
        return;
      }
    }

    // Optionally pin public traffic to a specific client certificate identity (CN).
    // This prevents other internal services (which may also have CA-signed certs)
    // from bypassing the edge proxy and directly calling the gateway's public API.
    if (expectedCn && !req.path.startsWith('/internal/')) {
      const cn = String(cert?.subject?.CN ?? '').trim();
      if (cn !== expectedCn) {
        securityLog.warn({
          event: 'mtls_client_cn_mismatch',
          expectedCn,
          cn,
          path: req.path,
          method: req.method,
          correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
        });
        res.status(403).json({ error: 'Forbidden' });
        return;
      }
    }

    next();
  });

  // ──────────────────────────────────────────────────────────────────
  // HEALTH CHECK ENDPOINT — The ONLY endpoint exempt from auth.
  // Must run before adaptive/rate/bot/WAF layers so probes do not get challenged.
  // ──────────────────────────────────────────────────────────────────
  if (config.healthCheck.enabled) {
    app.use((req: Request, res: Response, next: NextFunction) => {
      if (req.method !== 'GET' && req.method !== 'HEAD') return next();
      if (!isHealthPath(req.path)) return next();
      res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
      });
    });
  }

  // ── 2.1. Adaptive Enforcement: IP Blocklist ────────────────────────
  // Block known bad IPs as early as possible.
  app.use(async (req: Request, res: Response, next: NextFunction) => {
    const clientIp = extractClientIp(req, maxXffDepth, trustedProxies);
    try {
      const entry = await deps.stateStore.isIpBlocked(clientIp);
      if (entry) {
        securityLog.warn({
          event: 'ip_blocked',
          ip: clientIp,
          path: req.path,
          method: req.method,
          reason: entry.reason,
          expiresAt: entry.expiresAt,
          correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
        });
        res.status(403).json({ error: 'Forbidden' });
        return;
      }
    } catch {
      // Fail open if the blocklist store is unavailable; log-only to avoid self-DoS.
    }
    next();
  });

  // ── 2.5. Metrics Collection ────────────────────────────────────────
  // Collect request metrics for Prometheus monitoring.
  app.use(createRequestMetricsMiddleware({ serviceName: 'gateway' }));

  // ── 2.6. Adaptive IP Defense (score -> temporary block) ────────────
  app.use(createAdaptiveIpDefenseMiddleware(config, {
    stateStore: deps.stateStore,
    reputationStore: deps.ipReputationStore,
    challengeStore: deps.botChallengeStore,
  }));

  // ── 2.7. Bot Challenge Gate (soft challenge before block) ──────────
  app.use(createBotChallengeMiddleware(config, {
    challengeStore: deps.botChallengeStore,
  }));

  // ── 2.8. Edge Access Control (IP/CIDR + geo/ASN policy) ────────────
  app.use(createAccessControlMiddleware(config));

  // ── 3. Helmet Security Headers ─────────────────────────────────────
  app.use(createHelmetMiddleware());
  app.use(conditionalHsts());
  app.use(noCacheHeaders());

  // ── Cookie Parser ──────────────────────────────────────────────────
  // Needed for JWT cookie extraction. No signing secret needed (JWTs are self-signed).
  app.use(cookieParser());

  // ── HTTP Parameter Pollution Protection ────────────────────────────
  app.use(hpp());

  // ── Compression ────────────────────────────────────────────────────
  // Compress responses to reduce bandwidth. Applied after security headers.
  app.use(compression({
    threshold: 1024, // Only compress responses > 1KB
    level: 6,        // Balance between speed and compression ratio
    filter: (req: Request, res: Response) => {
      // Don't compress if the request asks not to
      if (req.headers['x-no-compression']) {
        return false;
      }
      return compression.filter(req, res);
    },
  }));

  // ── 4. Body Limits ─────────────────────────────────────────────────
  // Parse and validate body BEFORE normalization so we can inspect content.
  const bodyMiddlewares = createBodyLimitsMiddleware(config);
  for (const mw of bodyMiddlewares) {
    app.use(mw);
  }

  // ── 5. Normalization ───────────────────────────────────────────────
  // CRITICAL: Canonicalize paths, headers BEFORE any auth/routing.
  app.use(createNormalizationMiddleware(config));

  // ──────────────────────────────────────────────────────────────────
  // INTERNAL CONTROL PLANE — protected by internal auth
  // ──────────────────────────────────────────────────────────────────
  if (config.internalAuth.enabled) {
    const internalAuthOptions: InternalAuthOptions = {
      enabled: true,
      secret: config.internalAuth.secret ?? '',
      allowedSkewSeconds: config.internalAuth.allowedSkewSeconds,
      exemptPaths: [],
      requireNonce: config.internalAuth.requireNonce,
      requireCallerId: config.internalAuth.requireCallerId,
      requireKeyId: config.internalAuth.requireKeyId,
      allowedCallerIds: config.internalAuth.allowedCallerIds,
      allowedKeyIds: config.internalAuth.allowedKeyIds,
      expectedAudience: config.internalAuth.expectedAudience,
      keyring: config.internalAuth.keyring,
      replayProtectionEnabled: config.internalAuth.replayProtectionEnabled,
      replayCacheMaxEntries: config.internalAuth.replayCacheMaxEntries,
    };

    app.use(async (req: Request, res: Response, next: NextFunction) => {
      if (!req.path.startsWith('/internal/')) return next();
      const result = await verifyInternalAuthAsync(
        {
          method: req.method,
          path: req.originalUrl || req.url || req.path,
          headers: req.headers as unknown as Record<string, unknown>,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          rawBody: (req as any).rawBody as Buffer | undefined,
        },
        internalAuthOptions,
        deps.internalAuthReplayStore,
      );

      if (!result.ok) {
        securityLog.warn({
          event: 'internal_auth_denied',
          reason: result.reason,
          path: req.path,
          method: req.method,
          ip: req.ip,
          correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
        });
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }
      next();
    });

    app.use(createInternalRoutes(deps.stateStore, {
      abuseIntel: config.adaptiveDefense.abuseIntel,
      abuseIntelReplayStore: deps.abuseIntelReplayStore,
      mutationReplayStore: deps.internalAuthReplayStore,
      edgeCache: config.edgeCache,
      edgeCacheStore: deps.edgeCacheStore,
      edgeInvalidationEventStore: deps.edgeInvalidationEventStore,
      controlPlaneAuditStore: deps.controlPlaneAuditStore,
      routePolicyManager: deps.routePolicyManager,
      upstreamPolicyManager: deps.upstreamPolicyManager,
      securityControlsAuditStore: deps.securityControlsAuditStore,
      gatewayConfig: config,
    }));
  }

  // ── 6. CORS ────────────────────────────────────────────────────────
  // DENY by default. Exact origin allowlist. No wildcards with credentials.
  app.use(createCorsMiddleware(config));

  // ── 7. Rate Limiter ────────────────────────────────────────────────
  // Pre-auth: per-IP, per-route. Runs before auth to protect auth endpoints from brute force.
  app.use(createRateLimiterMiddleware(config, {
    store: deps.rateLimitStore,
    greylistFailureCounter: deps.greylistFailureCounter,
  }));

  // ── 7.5. Bot Management ────────────────────────────────────────────
  app.use(createBotManagementMiddleware(config, {
    challengeStore: deps.botChallengeStore,
  }));

  // ── 8. WAF ─────────────────────────────────────────────────────────
  // Pattern-based attack detection. Defense in depth.
  app.use(createWafMiddleware(config, {
    challengeStore: deps.botChallengeStore,
  }));

  // ──────────────────────────────────────────────────────────────────
  // ── 9. JWT Validation ──────────────────────────────────────────────
  // Authenticate every request (except health check above).
  const jwtValidation = createJwtValidationMiddleware(config);
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/internal/')) return next();
    const routeConfig = getRouteConfig(config, req.path, req.method);
    if (routeConfig && routeConfig.authRequired === false) {
      return next();
    }
    return void jwtValidation(req, res, next);
  });

  // ── 9.5. Post-auth Rate Limiter (per-identity) ─────────────────────
  app.use(createIdentityRateLimiterMiddleware(config, { stateStore: deps.stateStore, store: deps.rateLimitStore }));

  // ── 9.6. Adaptive Enforcement: Token Revocation / Token Version ────
  app.use(async (req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/internal/')) return next();
    const routeConfig = getRouteConfig(config, req.path, req.method);
    if (routeConfig && routeConfig.authRequired === false) return next();

    const identity = req.identity;
    if (!identity || !deps.identitySecurityStore) return next();

    const enforceTokenVersion =
      process.env['TOKEN_VERSION_ENFORCEMENT'] === 'true' ||
      (process.env['TOKEN_VERSION_ENFORCEMENT'] === undefined && process.env['NODE_ENV'] === 'production');

    const enforceJtiRevocation =
      process.env['JWT_REVOCATION_CHECK_ENABLED'] === 'true' ||
      (process.env['JWT_REVOCATION_CHECK_ENABLED'] === undefined && process.env['NODE_ENV'] === 'production');

    try {
      if (enforceTokenVersion) {
        if (typeof identity.tokenVersion !== 'number') {
          securityLog.warn({
            event: 'jwt_missing_token_version',
            correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
            sub: identity.sub,
          });
          res.status(401).json({ error: 'Unauthorized' });
          return;
        }

        const current = await deps.identitySecurityStore.getTokenVersion(identity.sub);
        if (current !== identity.tokenVersion) {
          securityLog.warn({
            event: 'jwt_token_version_mismatch',
            correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
            sub: identity.sub,
            tokenVersion: identity.tokenVersion,
            currentVersion: current,
          });
          res.status(401).json({ error: 'Unauthorized' });
          return;
        }
      }

      if (enforceJtiRevocation && identity.jti) {
        const revoked = await deps.identitySecurityStore.isJtiRevoked(identity.jti);
        if (revoked) {
          securityLog.warn({
            event: 'jwt_revoked',
            correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
            sub: identity.sub,
            jti: identity.jti,
          });
          res.status(401).json({ error: 'Unauthorized' });
          return;
        }
      }
    } catch (err) {
      const failOpen =
        process.env['TOKEN_ENFORCEMENT_FAIL_OPEN'] === 'true' ||
        (process.env['TOKEN_ENFORCEMENT_FAIL_OPEN'] === undefined && process.env['NODE_ENV'] !== 'production');

      securityLog.error({
        event: 'token_enforcement_error',
        correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
        error: err instanceof Error ? err.message : String(err),
      });

      if (!failOpen) {
        res.status(503).json({ error: 'Service Unavailable' });
        return;
      }
    }

    next();
  });

  // ── 9.7. Adaptive Enforcement: Step-Up Requirements ────────────────
  app.use(async (req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/internal/')) return next();
    const routeConfig = getRouteConfig(config, req.path, req.method);
    if (routeConfig && routeConfig.authRequired === false) return next();

    const identity = req.identity;
    if (!identity) return next();

    try {
      const requirement = await deps.stateStore.getStepUpRequirement(identity.sub);
      if (requirement && identity.stepUpLevel < requirement.requiredLevel) {
        securityLog.warn({
          event: 'step_up_required',
          correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
          sub: identity.sub,
          currentLevel: identity.stepUpLevel,
          requiredLevel: requirement.requiredLevel,
          reason: requirement.reason,
        });
        res.setHeader('x-zt-step-up-required', 'true');
        res.setHeader('x-zt-required-step-up-level', String(requirement.requiredLevel));
        res.status(403).json({ error: 'Step-up authentication required' });
        return;
      }
    } catch {
      // fail open; enforcement can be enabled for strict mode if desired
    }

    next();
  });

  // ── 10. Policy Check ───────────────────────────────────────────────
  // Authorize via PDP. FAIL-CLOSED: if PDP unreachable, DENY.
  const policyCheck = createPolicyCheckMiddleware(config);
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/internal/')) return next();
    const routeConfig = getRouteConfig(config, req.path, req.method);
    if (routeConfig && routeConfig.authRequired === false) {
      return next();
    }
    return void policyCheck(req, res, next);
  });

  // ── 10.5. Break-Glass Emergency Access ──────────────────────────────
  // Allows emergency bypass of PDP with mandatory audit trail.
  // Enabled only when BREAK_GLASS_ENABLED=true in environment.
  if (process.env['BREAK_GLASS_ENABLED'] === 'true') {
    const breakGlassManager = new BreakGlassManager({
      eligibility: {
        allowedRoles: ['security-admin', 'incident-responder'],
      },
      review: {
        reviewerUserIds: [],
      },
    });
    app.use(breakGlassMiddleware({
      manager: breakGlassManager,
    }));
  }

  // ── 10.6. Edge Response Cache (route opt-in) ───────────────────────
  // Serves cache hits before upstream to reduce origin load and tail latency.
  app.use(createEdgeCacheMiddleware(config, {
    store: deps.edgeCacheStore,
  }));

  // ── 11. Upstream Proxy ─────────────────────────────────────────────
  // Route to internal services with mTLS, circuit breaker, timeouts.
  app.use(createUpstreamRouter(config, {
    upstreamPolicyManager: deps.upstreamPolicyManager,
  }));

  // ── Global Error Handler ────────────────────────────────────────────
  // Catch any unhandled errors. Never leak stack traces or internal details.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: Error, req: Request, res: Response, _next: NextFunction) => {
    const correlationId = (req.headers['x-correlation-id'] as string) || 'unknown';

    securityLog.error({
      event: 'unhandled_error',
      correlationId,
      ip: req.ip,
      path: req.path,
      method: req.method,
      error: err.message,
      stack: process.env['NODE_ENV'] !== 'production' ? err.stack : undefined,
    });

    if (!res.headersSent) {
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

  // ── 404 Handler ─────────────────────────────────────────────────────
  // If nothing matched (shouldn't happen since proxy is a catch-all),
  // return 404. This is belt-and-suspenders.
  app.use((_req: Request, res: Response) => {
    if (!res.headersSent) {
      res.status(404).json({ error: 'Not Found' });
    }
  });

  return app;
}
