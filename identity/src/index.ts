/**
 * Identity & Authorization Plane -- Server Entry Point.
 *
 * Bootstraps all services, mounts middleware and routes, and starts the
 * Express HTTP server on port 8182.  Handles graceful shutdown on SIGTERM
 * and SIGINT.
 */

import express from 'express';
import cookieParser from 'cookie-parser';
import https from 'https';
import fs from 'fs';
import type { TLSSocket } from 'tls';
import { config } from '../config/default';
import { createLogger } from './logger';
import {
  readSecret,
  verifyInternalAuthAsync,
  RedisInternalAuthReplayStore,
  type InternalAuthOptions,
  type InternalAuthReplayStore,
} from '@zerotrust/shared';

// Services
import { JWKSManager } from './tokens/jwks';
import { TokenService } from './tokens/token-service';
import {
  InMemoryTokenVersionStore,
  RedisTokenVersionStore,
  type TokenVersionStore,
} from './tokens/token-version-store';
import {
  InMemoryJtiRevocationStore,
  RedisJtiRevocationStore,
  type JtiRevocationStore,
} from './tokens/jti-revocation-store';
import { InMemorySessionStore } from './sessions/session-store';
import { RedisSessionStore } from './sessions/redis-session-store';
import { SessionManager } from './sessions/session-manager';
import { OIDCProviderRegistry } from './oidc/provider';
import { StepUpAuthService } from './stepup/step-up-auth';
import { WorkloadIdentityService } from './workload/workload-identity';
import {
  HealthProbeManager,
  createRedisCheck,
  initializeTracing,
  createRequestMetricsMiddleware,
  globalMetrics,
  initializeDefaultMetrics,
  // These are imported but not used directly in this file
  // recordAuthAttempt,
  // setActiveSessionCount,
  // setRedisConnectionStatus,
} from '@zerotrust/shared';
import Redis from 'ioredis';

// API
import { createAuthRoutes } from './api/routes';
import {
  requestIdMiddleware,
  sessionExtraction,
  tokenExtraction,
  securityHeaders,
  corsMiddleware,
} from './api/middleware';
import { createInternalRoutes } from './api/internal-routes';
import { InMemoryAuthFlowStore, RedisAuthFlowStore } from './api/auth-flow-store';
import { InMemoryRefreshTokenStore, RedisRefreshTokenStore } from './tokens/refresh-token-store';
import { createWebAuthnRoutes } from './api/webauthn-routes';
import { InMemoryWebAuthnStore, RedisWebAuthnStore } from './webauthn/webauthn-store';

const logger = createLogger('server');

function isEnabled(raw: string | undefined, defaultValue = false): boolean {
  if (raw === undefined) return defaultValue;
  return ['true', '1', 'yes'].includes(raw.toLowerCase());
}

function parseCsv(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseKeyring(raw: string): Record<string, string> {
  const value = raw.trim();
  if (!value) return {};
  const result: Record<string, string> = {};
  for (const entry of value.split(',').map((e) => e.trim()).filter(Boolean)) {
    const eqIdx = entry.indexOf('=');
    const colonIdx = entry.indexOf(':');
    let idx = -1;
    if (eqIdx > 0) idx = eqIdx;
    if (colonIdx > 0 && (idx === -1 || colonIdx < idx)) idx = colonIdx;
    if (idx <= 0 || idx === entry.length - 1) {
      throw new Error(`Invalid INTERNAL_AUTH_KEYRING entry "${entry}"`);
    }
    const keyId = entry.slice(0, idx).trim();
    const secret = entry.slice(idx + 1).trim();
    if (!keyId || !secret) {
      throw new Error(`Invalid INTERNAL_AUTH_KEYRING entry "${entry}"`);
    }
    result[keyId] = secret;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

async function bootstrap(): Promise<void> {
  logger.info('Starting Identity & Authorization Plane', {
    port: config.server.port,
    host: config.server.host,
  });

  const isProduction = process.env['NODE_ENV'] === 'production';
  const internalAuthEnabled = isEnabled(process.env['INTERNAL_AUTH_ENABLED'], isProduction);
  const internalAuthRequireNonce = isEnabled(process.env['INTERNAL_AUTH_REQUIRE_NONCE'], true);
  const internalAuthRequireCaller = isEnabled(process.env['INTERNAL_AUTH_REQUIRE_CALLER'], true);
  const internalAuthRequireKeyId = isEnabled(process.env['INTERNAL_AUTH_REQUIRE_KEY_ID'], true);
  const internalAuthAllowedCallers = (() => {
    const fromEnv = parseCsv(process.env['INTERNAL_AUTH_ALLOWED_CALLERS']);
    return fromEnv.length > 0 ? fromEnv : ['gateway', 'telemetry'];
  })();
  const internalAuthAllowedKeyIds = (() => {
    const fromEnv = parseCsv(process.env['INTERNAL_AUTH_ALLOWED_KEY_IDS']);
    return fromEnv.length > 0 ? fromEnv : ['gateway-v1', 'telemetry-v1'];
  })();
  const internalAuthExpectedAudience = (process.env['INTERNAL_AUTH_EXPECTED_AUDIENCE'] ?? 'identity').trim();
  const internalAuthReplayProtectionEnabled = isEnabled(
    process.env['INTERNAL_AUTH_REPLAY_PROTECTION_ENABLED'],
    true,
  );
  const internalAuthReplayCacheMaxEntries = parseInt(
    process.env['INTERNAL_AUTH_REPLAY_CACHE_MAX_ENTRIES'] ?? '50000',
    10,
  );
  const devTokenIssuerEnabled = isEnabled(process.env['DEV_TOKEN_ISSUER_ENABLED'], false);
  const allowDevIssuerInProduction = isEnabled(process.env['ALLOW_DEV_TOKEN_ISSUER_IN_PRODUCTION'], false);

  // In production, enforce strict authn/authz guardrails.
  if (isProduction) {
    if (!internalAuthEnabled) {
      logger.error('INTERNAL_AUTH_ENABLED=false is not allowed in production; refusing to start');
      process.exit(1);
    }
    if (!internalAuthRequireNonce) {
      logger.error('INTERNAL_AUTH_REQUIRE_NONCE=false is not allowed in production; refusing to start');
      process.exit(1);
    }
    if (!internalAuthRequireCaller) {
      logger.error('INTERNAL_AUTH_REQUIRE_CALLER=false is not allowed in production; refusing to start');
      process.exit(1);
    }
    if (!internalAuthRequireKeyId) {
      logger.error('INTERNAL_AUTH_REQUIRE_KEY_ID=false is not allowed in production; refusing to start');
      process.exit(1);
    }
    if (internalAuthAllowedCallers.length === 0) {
      logger.error('INTERNAL_AUTH_ALLOWED_CALLERS must be non-empty in production; refusing to start');
      process.exit(1);
    }
    if (internalAuthAllowedKeyIds.length === 0) {
      logger.error('INTERNAL_AUTH_ALLOWED_KEY_IDS must be non-empty in production; refusing to start');
      process.exit(1);
    }
    if (!internalAuthExpectedAudience) {
      logger.error('INTERNAL_AUTH_EXPECTED_AUDIENCE must be set in production; refusing to start');
      process.exit(1);
    }
    if (!internalAuthReplayProtectionEnabled) {
      logger.error(
        'INTERNAL_AUTH_REPLAY_PROTECTION_ENABLED=false is not allowed in production; refusing to start',
      );
      process.exit(1);
    }

    if (devTokenIssuerEnabled && !allowDevIssuerInProduction) {
      logger.error(
        'DEV_TOKEN_ISSUER_ENABLED=true is blocked in production. Set ALLOW_DEV_TOKEN_ISSUER_IN_PRODUCTION=true only for short-lived controlled tests.',
      );
      process.exit(1);
    }
    if (devTokenIssuerEnabled && allowDevIssuerInProduction) {
      logger.warn('DEV_TOKEN_ISSUER_ENABLED is active in production due to explicit override');
    }

    const csrf = readSecret('CSRF_SECRET');
    const looksDefault = csrf.toLowerCase().includes('change-me') || csrf.toLowerCase().includes('csrf-dev-secret');
    if (!csrf || looksDefault || csrf.length < 32) {
      logger.error('Missing/weak/default CSRF_SECRET in production; refusing to start');
      process.exit(1);
    }

    const internalSecret = readSecret('INTERNAL_SHARED_SECRET');
    const internalLooksDefault = internalSecret.toLowerCase().includes('change-me') || internalSecret.toLowerCase().includes('not-secure');
    if (!internalSecret || internalLooksDefault || internalSecret.length < 32) {
      logger.error('Missing/weak/default INTERNAL_SHARED_SECRET in production; refusing to start');
      process.exit(1);
    }
  }

  // -----------------------------------------------------------------------
  // Redis connection (for session persistence)
  // -----------------------------------------------------------------------
  const redisUrl = process.env['REDIS_URL'];
  const redisHost = process.env['REDIS_HOST'] ?? 'redis';
  const redisPort = parseInt(process.env['REDIS_PORT'] ?? '6379', 10);
  const redisPassword = readSecret('REDIS_PASSWORD');
  const redisDb = parseInt(process.env['REDIS_DB'] ?? '1', 10);
  let redis: Redis | null = null;

  try {
    redis = redisUrl
      ? new Redis(redisUrl, {
        db: redisDb,
        maxRetriesPerRequest: 3,
        retryStrategy: (times: number) => Math.min(times * 200, 5000),
        lazyConnect: true,
        enableReadyCheck: true,
      })
      : new Redis({
        host: redisHost,
        port: redisPort,
        db: redisDb,
        password: redisPassword || undefined,
        maxRetriesPerRequest: 3,
        retryStrategy: (times: number) => Math.min(times * 200, 5000),
        lazyConnect: true,
        enableReadyCheck: true,
      });
    await redis.connect();
    logger.info('Redis connected for identity state', {
      host: redisUrl ? 'url' : redisHost,
      port: redisUrl ? undefined : redisPort,
      db: redisDb,
    });
  } catch (err) {
    const redisRequired = process.env['IDENTITY_REDIS_REQUIRED']
      ? ['true', '1', 'yes'].includes(process.env['IDENTITY_REDIS_REQUIRED'].toLowerCase())
      : isProduction;

    logger.error('Redis unavailable for identity state', {
      required: redisRequired,
      error: (err as Error).message,
    });

    if (redisRequired) {
      logger.error('Redis is required for identity in production; refusing to start');
      process.exit(1);
    } else {
      logger.warn('Falling back to in-memory stores (NOT suitable for production HA)');
      redis = null;
    }
  }

  // -----------------------------------------------------------------------
  // Initialize core services
  // -----------------------------------------------------------------------

  // 1. JWKS key manager
  const jwksManager = new JWKSManager(config.tokens.algorithm);
  await jwksManager.initialize();
  logger.info('JWKS manager initialized');

  // 2. Token service
  const tokenVersions: TokenVersionStore = redis
    ? new RedisTokenVersionStore(redis)
    : new InMemoryTokenVersionStore();
  const jtiRevocations: JtiRevocationStore = redis
    ? new RedisJtiRevocationStore(redis)
    : new InMemoryJtiRevocationStore();
  const refreshTokenStore = redis
    ? new RedisRefreshTokenStore(redis, { keyPrefix: process.env['REFRESH_TOKEN_PREFIX'] ?? 'zt:identity:rt:', logger })
    : new InMemoryRefreshTokenStore();

  // Optional override; by default TokenService derives it from INTERNAL_SHARED_SECRET.
  const refreshTokenHashSecret = readSecret('REFRESH_TOKEN_HASH_SECRET', { defaultValue: '' }) || undefined;

  const tokenService = new TokenService(jwksManager, {
    tokenVersions,
    jtiRevocations,
    refreshTokenStore,
    refreshTokenHashSecret,
  });

  // 3. Session store & manager
  const sessionStore = redis
    ? new RedisSessionStore(redis, { keyPrefix: 'session:' })
    : new InMemorySessionStore();
  logger.info('Session store initialized', { type: redis ? 'redis' : 'in-memory' });
  const sessionManager = new SessionManager(sessionStore);

  // 3.5 WebAuthn store (passkeys)
  const webauthnStore = redis
    ? new RedisWebAuthnStore(redis, { keyPrefix: process.env['WEBAUTHN_PREFIX'] ?? 'zt:identity:webauthn:' })
    : new InMemoryWebAuthnStore();

  // 4. OIDC provider registry
  const oidcRegistry = new OIDCProviderRegistry();
  for (const [name, providerConfig] of Object.entries(config.oidcProviders)) {
    if (providerConfig.enabled) {
      try {
        await oidcRegistry.register(name, providerConfig);
      } catch (err) {
        logger.warn('Failed to register OIDC provider (continuing)', {
          provider: name,
          error: (err as Error).message,
        });
      }
    }
  }

  // 5. Step-up authentication service
  const stepUpService = new StepUpAuthService();

  // 6. Workload identity service
  const workloadService = new WorkloadIdentityService(jwksManager);

  // -----------------------------------------------------------------------
  // Observability: Metrics & Tracing
  // -----------------------------------------------------------------------
  initializeDefaultMetrics();
  initializeTracing({
    serviceName: 'identity-plane',
    serviceVersion: '1.0.0',
    environment: process.env['NODE_ENV'] ?? 'development',
    exporterEndpoint: process.env['OTEL_EXPORTER_OTLP_ENDPOINT'] ?? 'http://localhost:4318',
  });

  // -----------------------------------------------------------------------
  // Express application
  // -----------------------------------------------------------------------

  const app = express();

  // -- Global middleware (order matters) --

  // -- Prometheus metrics collection --
  app.use(createRequestMetricsMiddleware({ serviceName: 'identity' }));

  // -----------------------------------------------------------------------
  // Internal mTLS (gateway <-> plane)
  // -----------------------------------------------------------------------
  // Enforced before body parsing to reduce resource usage for unauthenticated requests.
  // We enforce this at the application layer (not TLS handshake) so we can exempt
  // public-ish endpoints like JWKS while still requiring client certs for plane APIs.
  const tlsEnabled = isEnabled(process.env['IDENTITY_TLS_ENABLED'], false);
  const mtlsRequired = tlsEnabled && isEnabled(process.env['INTERNAL_MTLS_REQUIRED'], false);
  if (isProduction && (!tlsEnabled || !mtlsRequired)) {
    logger.error('Production requires IDENTITY_TLS_ENABLED=true and INTERNAL_MTLS_REQUIRED=true; refusing to start');
    process.exit(1);
  }
  const mtlsExemptPaths = new Set<string>(['/health', '/ready', '/healthz', '/readyz', '/startupz', '/metrics', '/.well-known/jwks.json']);
  const allowedClientCns = new Set(
    (process.env['INTERNAL_MTLS_ALLOWED_CLIENT_CNS'] ?? '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );

  const tlsSocketFromReq = (req: express.Request): TLSSocket | undefined => {
    const candidate = req.socket as unknown;
    if (!candidate || typeof candidate !== 'object') return undefined;
    const sock = candidate as TLSSocket;
    return typeof sock.getPeerCertificate === 'function' ? sock : undefined;
  };

  app.use((req, res, next) => {
    if (!mtlsRequired) return next();
    if (mtlsExemptPaths.has(req.path)) return next();

    const sock = tlsSocketFromReq(req);
    const authorized = sock?.authorized === true;
    const cert = sock?.getPeerCertificate();

    if (!authorized || !cert || Object.keys(cert).length === 0) {
      res.status(403).json({ error: { code: 'MTLS_REQUIRED', message: 'Client certificate required' } });
      return;
    }

    if (allowedClientCns.size > 0) {
      const cn = String(cert?.subject?.CN ?? '').trim().toLowerCase();
      if (!cn || !allowedClientCns.has(cn)) {
        res.status(403).json({ error: { code: 'FORBIDDEN', message: 'Forbidden' } });
        return;
      }
    }

    next();
  });

  // Parse JSON bodies (with a reasonable size limit).
  type RawBodyRequest = express.Request & { rawBody?: Buffer };
  app.use(express.json({
    limit: '16kb',
    verify: (req, _res, buf) => {
      // Capture raw body so internal auth can validate integrity.
      (req as RawBodyRequest).rawBody = buf;
    },
  }));

  // Parse cookies (needed for session extraction).
  app.use(cookieParser());

  // Assign a request ID to every request.
  app.use(requestIdMiddleware());

  // -----------------------------------------------------------------------
  // Internal service-to-service authentication (HMAC)
  // -----------------------------------------------------------------------
  // Protect identity APIs from unauthenticated lateral movement if a network boundary is misconfigured.
  // NOTE: JWKS is intentionally exempt because the gateway's JWT validator fetches it without internal headers.
  const internalAuthSecret = readSecret('INTERNAL_SHARED_SECRET', { required: internalAuthEnabled });
  let internalAuthKeyring: Record<string, string> = {};
  try {
    internalAuthKeyring = parseKeyring(readSecret('INTERNAL_AUTH_KEYRING', { defaultValue: '' }));
  } catch (err) {
    logger.error('Failed to parse INTERNAL_AUTH_KEYRING', { error: (err as Error).message });
    process.exit(1);
  }
  if (Object.keys(internalAuthKeyring).length === 0 && internalAuthSecret) {
    for (const keyId of internalAuthAllowedKeyIds) {
      internalAuthKeyring[keyId] = internalAuthSecret;
    }
  }
  if (isProduction && Object.keys(internalAuthKeyring).length === 0) {
    logger.error('Internal auth keyring is empty in production; refusing to start');
    process.exit(1);
  }
  const replayStoreMode = (process.env['INTERNAL_AUTH_REPLAY_STORE'] ?? (redis ? 'redis' : 'memory')).toLowerCase();
  let internalAuthReplayStore: InternalAuthReplayStore | undefined;
  if (replayStoreMode === 'redis') {
    if (redis) {
      internalAuthReplayStore = new RedisInternalAuthReplayStore(redis, {
        keyPrefix: process.env['INTERNAL_AUTH_REPLAY_REDIS_PREFIX'] ?? 'zt:internal-auth:replay:',
      });
    } else {
      logger.warn('Internal auth replay store is configured for Redis but Redis is unavailable; using in-memory fallback');
    }
  }
  const internalAuthOptions: InternalAuthOptions = {
    enabled: internalAuthEnabled,
    secret: internalAuthSecret,
    allowedSkewSeconds: parseInt(process.env['INTERNAL_AUTH_SKEW_SECONDS'] ?? '60', 10),
    exemptPaths: ['/health', '/ready', '/healthz', '/readyz', '/startupz', '/metrics', '/.well-known/jwks.json'],
    requireNonce: internalAuthRequireNonce,
    requireCallerId: internalAuthRequireCaller,
    requireKeyId: internalAuthRequireKeyId,
    allowedCallerIds: internalAuthAllowedCallers,
    allowedKeyIds: internalAuthAllowedKeyIds,
    expectedAudience: internalAuthExpectedAudience,
    keyring: internalAuthKeyring,
    replayProtectionEnabled: internalAuthReplayProtectionEnabled,
    replayCacheMaxEntries: Number.isFinite(internalAuthReplayCacheMaxEntries)
      ? Math.max(1, internalAuthReplayCacheMaxEntries)
      : 50_000,
  };

  app.use(async (req, res, next) => {
    const result = await verifyInternalAuthAsync({
      method: req.method,
      path: req.originalUrl || req.url || req.path,
      headers: req.headers as unknown as Record<string, unknown>,
      rawBody: (req as RawBodyRequest).rawBody,
    }, internalAuthOptions, internalAuthReplayStore);

    if (!result.ok) {
      logger.warn('Internal auth denied', {
        method: req.method,
        path: req.path,
        ip: req.ip,
        reason: result.reason,
      });
      res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Unauthorized' } });
      return;
    }

    next();
  });

  // Set security headers on all responses.
  app.use(securityHeaders());

  // CORS (configured via config).
  app.use(corsMiddleware());

  // Extract session from cookie (populates req.session).
  app.use(sessionExtraction(sessionManager));

  // Extract Bearer token from Authorization header (populates req.tokenClaims).
  app.use(tokenExtraction(tokenService));

  // -----------------------------------------------------------------------
  // Health Probes (Kubernetes-grade)
  // -----------------------------------------------------------------------
  const probeManager = new HealthProbeManager({
    serviceName: 'identity-plane',
    version: '1.0.0',
  });

  if (redis) {
    probeManager.addDependencyCheck('redis', createRedisCheck(redis));
  }

  // Mount health routes BEFORE auth middleware
  app.use(probeManager.createHealthRouter());

  // Expose Prometheus metrics endpoint
  app.get('/metrics', (_req, res) => {
    res.setHeader('Content-Type', 'text/plain; version=0.0.4');
    res.send(globalMetrics.serialize());
  });

  // -----------------------------------------------------------------------
  // Auth routes
  // -----------------------------------------------------------------------

  // Internal incident-response routes (mTLS + internal-auth protected by global middleware)
  app.use(createInternalRoutes({ tokenService, sessionManager }));

  // WebAuthn routes (passkeys + step-up)
  app.use(createWebAuthnRoutes({ store: webauthnStore, tokenService, sessionManager }));

  const authFlowStore = redis
    ? new RedisAuthFlowStore(redis, { keyPrefix: process.env['AUTH_FLOW_PREFIX'] ?? 'zt:identity:oidcflow:' })
    : new InMemoryAuthFlowStore(10 * 60 * 1000);

  const authRoutes = createAuthRoutes({
    oidcRegistry,
    authFlowStore,
    tokenService,
    jwksManager,
    sessionManager,
    stepUpService,
    workloadService,
  });

  app.use(authRoutes);

  // -----------------------------------------------------------------------
  // 404 catch-all
  // -----------------------------------------------------------------------

  app.use((_req, res) => {
    res.status(404).json({
      error: { code: 'NOT_FOUND', message: 'Endpoint not found' },
    });
  });

  // -----------------------------------------------------------------------
  // Global error handler
  // -----------------------------------------------------------------------

  app.use(
	    (
	      err: Error,
	      _req: express.Request,
	      res: express.Response,
	      _next: express.NextFunction,
	    ) => {
	      void _next; // preserve 4-arg signature for Express error middleware
	      logger.error('Unhandled error', {
	        error: err.message,
	        stack: err.stack,
	      });

      res.status(500).json({
        error: { code: 'INTERNAL', message: 'An internal error occurred' },
      });
    },
  );

  // -----------------------------------------------------------------------
  // Start server
  // -----------------------------------------------------------------------

  const server = (() => {
    if (!tlsEnabled) {
      return app.listen(config.server.port, config.server.host, () => {
        logger.info(`Identity Plane listening (HTTP) on ${config.server.host}:${config.server.port}`);
        probeManager.markReady();
      });
    }

    const certPath = process.env['IDENTITY_TLS_CERT_PATH'] ?? '/certs/identity.crt';
    const keyPath = process.env['IDENTITY_TLS_KEY_PATH'] ?? '/certs/identity.key';
    const caPath = process.env['IDENTITY_TLS_CA_PATH'] ?? process.env['INTERNAL_MTLS_CA_PATH'] ?? '/certs/ca.crt';

    const tlsOptions: https.ServerOptions = {
      cert: fs.readFileSync(certPath),
      key: fs.readFileSync(keyPath),
      // We request a client cert but don't reject at handshake time; middleware enforces.
      requestCert: true,
      rejectUnauthorized: false,
    };

    if (fs.existsSync(caPath)) {
      tlsOptions.ca = fs.readFileSync(caPath);
    }

    const httpsServer = https.createServer(tlsOptions, app);
    httpsServer.listen(config.server.port, config.server.host, () => {
      logger.info(`Identity Plane listening (HTTPS) on ${config.server.host}:${config.server.port}`);
      probeManager.markReady();
    });
    return httpsServer;
  })();

  // Set keep-alive and headers timeouts to avoid hanging connections.
  server.keepAliveTimeout = 65_000;
  server.headersTimeout = 66_000;

  // -----------------------------------------------------------------------
  // Graceful shutdown
  // -----------------------------------------------------------------------

  const shutdown = async (signal: string): Promise<void> => {
    logger.info(`Received ${signal}, starting graceful shutdown`);

    // Stop accepting new connections.
    server.close((err) => {
      if (err) {
        logger.error('Error closing HTTP server', { error: err.message });
      }
    });

    // Allow in-flight requests to complete (10-second grace period).
    const forceExitTimer = setTimeout(() => {
      logger.warn('Graceful shutdown timed out, forcing exit');
      process.exit(1);
    }, 10_000);
    forceExitTimer.unref();

    // Clean up resources.
    try {
      tokenService.destroy();
      if (sessionStore instanceof InMemorySessionStore) {
        sessionStore.destroy();
      }
      if (jtiRevocations instanceof InMemoryJtiRevocationStore) {
        jtiRevocations.destroy();
      }
      stepUpService.destroy();
      if (redis) await redis.quit();
      logger.info('All resources cleaned up');
    } catch (cleanupErr) {
      logger.error('Error during cleanup', {
        error: (cleanupErr as Error).message,
      });
    }

    // Exit cleanly.
    process.exit(0);
  };

  process.on('SIGTERM', () => { void shutdown('SIGTERM'); });
  process.on('SIGINT', () => { void shutdown('SIGINT'); });

  // Catch unhandled rejections and uncaught exceptions.
  process.on('unhandledRejection', (reason) => {
    logger.error('Unhandled promise rejection', {
      reason: reason instanceof Error ? reason.message : String(reason),
      stack: reason instanceof Error ? reason.stack : undefined,
    });
  });

  process.on('uncaughtException', (err) => {
    logger.error('Uncaught exception', {
      error: err.message,
      stack: err.stack,
    });
    // Uncaught exceptions leave the process in an undefined state.
    // Exit after logging so the orchestrator can restart us.
    process.exit(1);
  });
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

bootstrap().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('Fatal: failed to start Identity Plane', err);
  process.exit(1);
});
