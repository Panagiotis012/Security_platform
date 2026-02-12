import express from 'express';
import fs from 'fs';
import path from 'path';
import https from 'https';
import Redis from 'ioredis';
import type { TLSSocket } from 'tls';
import config from '../config/default';
import { createRoutes } from './api/routes';
import {
  correlationId,
  requestLogger,
  errorHandler,
  notFoundHandler,
} from './api/middleware';
import { createEnvoyAuthzRoutes } from './api/envoy-authz';
import { PolicyEvaluator } from './engine/evaluator';
import { InMemoryPolicyStore, type PolicyStore } from './store/policy-store';
import { InMemoryDecisionLogger } from './store/decision-log';
import { FilePolicyStore } from './store/file-policy-store';
import { FileDecisionLogger } from './store/file-decision-log';
import { createLogger } from './utils/logger';
import type { Policy } from './models/policy-schema';
import {
  readSecret,
  verifyInternalAuthAsync,
  RedisInternalAuthReplayStore,
  type InternalAuthOptions,
  type InternalAuthReplayStore,
} from '@zerotrust/shared';
import {
  HealthProbeManager,
  initializeTracing,
  initializeDefaultMetrics,
  globalMetrics,
  createRequestMetricsMiddleware,
} from '@zerotrust/shared';

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

// ─── Application bootstrap ─────────────────────────────────────────────────

async function bootstrap(): Promise<void> {
  const isProduction = process.env['NODE_ENV'] === 'production';
  const internalAuthEnabled = isEnabled(process.env['INTERNAL_AUTH_ENABLED'], isProduction);
  const internalAuthRequireNonce = isEnabled(process.env['INTERNAL_AUTH_REQUIRE_NONCE'], true);
  const internalAuthRequireCaller = isEnabled(process.env['INTERNAL_AUTH_REQUIRE_CALLER'], true);
  const internalAuthRequireKeyId = isEnabled(process.env['INTERNAL_AUTH_REQUIRE_KEY_ID'], true);
  const internalAuthAllowedCallers = (() => {
    const fromEnv = parseCsv(process.env['INTERNAL_AUTH_ALLOWED_CALLERS']);
    return fromEnv.length > 0 ? fromEnv : ['gateway'];
  })();
  const internalAuthAllowedKeyIds = (() => {
    const fromEnv = parseCsv(process.env['INTERNAL_AUTH_ALLOWED_KEY_IDS']);
    return fromEnv.length > 0 ? fromEnv : ['gateway-v1'];
  })();
  const internalAuthExpectedAudience = (process.env['INTERNAL_AUTH_EXPECTED_AUDIENCE'] ?? 'policy-engine').trim();
  const internalAuthReplayProtectionEnabled = isEnabled(
    process.env['INTERNAL_AUTH_REPLAY_PROTECTION_ENABLED'],
    true,
  );
  const internalAuthReplayCacheMaxEntries = parseInt(
    process.env['INTERNAL_AUTH_REPLAY_CACHE_MAX_ENTRIES'] ?? '50000',
    10,
  );

  // Fail-fast on insecure production secrets.
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

    const adminSecret = config.admin.jwtSecret ?? '';
    const adminLooksDefault = adminSecret.toLowerCase().includes('change-me') || adminSecret.toLowerCase().includes('not-secure');
    if (!adminSecret || adminLooksDefault || adminSecret.length < 32) {
      logger.error('Missing/weak/default PDP_ADMIN_JWT_SECRET in production; refusing to start');
      process.exit(1);
    }

    const internalSecret = readSecret('INTERNAL_SHARED_SECRET');
    const internalLooksDefault = internalSecret.toLowerCase().includes('change-me') || internalSecret.toLowerCase().includes('not-secure');
    if (!internalSecret || internalLooksDefault || internalSecret.length < 32) {
      logger.error('Missing/weak/default INTERNAL_SHARED_SECRET in production; refusing to start');
      process.exit(1);
    }
  }

  logger.info('Starting Policy Decision Point (PDP)', {
    port: config.server.port,
    host: config.server.host,
    defaultEffect: config.authorization.defaultEffect,
  });

  // Observability
  initializeDefaultMetrics();
  initializeTracing({
    serviceName: 'policy-engine',
    serviceVersion: '1.0.0',
    environment: process.env['NODE_ENV'] ?? 'development',
    exporterEndpoint: process.env['OTEL_EXPORTER_OTLP_ENDPOINT'] ?? 'http://localhost:4318',
  });

  const replayStoreMode = (process.env['INTERNAL_AUTH_REPLAY_STORE'] ?? (isProduction ? 'redis' : 'memory')).toLowerCase();
  const replayRedisRequired = isEnabled(
    process.env['INTERNAL_AUTH_REPLAY_REDIS_REQUIRED'],
    isProduction && replayStoreMode === 'redis',
  );
  let replayRedis: Redis | null = null;
  let internalAuthReplayStore: InternalAuthReplayStore | undefined;
  if (replayStoreMode === 'redis') {
    const replayRedisUrl = process.env['INTERNAL_AUTH_REPLAY_REDIS_URL'] ?? process.env['REDIS_URL'];
    const replayRedisHost = process.env['INTERNAL_AUTH_REPLAY_REDIS_HOST'] ?? process.env['REDIS_HOST'] ?? 'redis';
    const replayRedisPort = parseInt(process.env['INTERNAL_AUTH_REPLAY_REDIS_PORT'] ?? process.env['REDIS_PORT'] ?? '6379', 10);
    const replayRedisDb = parseInt(process.env['INTERNAL_AUTH_REPLAY_REDIS_DB'] ?? process.env['REDIS_DB'] ?? '1', 10);
    const replayRedisPassword = readSecret('INTERNAL_AUTH_REPLAY_REDIS_PASSWORD', {
      defaultValue: readSecret('REDIS_PASSWORD', { defaultValue: '' }),
    });

    try {
      replayRedis = replayRedisUrl
        ? new Redis(replayRedisUrl, {
            db: replayRedisDb,
            maxRetriesPerRequest: 3,
            retryStrategy: (times: number) => Math.min(times * 200, 5000),
            lazyConnect: true,
            enableReadyCheck: true,
          })
        : new Redis({
            host: replayRedisHost,
            port: replayRedisPort,
            db: replayRedisDb,
            password: replayRedisPassword || undefined,
            maxRetriesPerRequest: 3,
            retryStrategy: (times: number) => Math.min(times * 200, 5000),
            lazyConnect: true,
            enableReadyCheck: true,
          });
      await replayRedis.connect();
      internalAuthReplayStore = new RedisInternalAuthReplayStore(replayRedis, {
        keyPrefix: process.env['INTERNAL_AUTH_REPLAY_REDIS_PREFIX'] ?? 'zt:internal-auth:replay:',
      });
      logger.info('Internal auth replay store configured', {
        mode: 'redis',
        db: replayRedisDb,
      });
    } catch (err) {
      logger.error('Failed to initialize Redis replay store', {
        error: err instanceof Error ? err.message : String(err),
      });
      replayRedis = null;
      if (replayRedisRequired) {
        process.exit(1);
      }
      logger.warn('Falling back to in-memory replay store');
    }
  }

  // Initialize stores
  const storeKind = (process.env['PDP_STORE'] ?? 'memory').toLowerCase();
  const dataDir = process.env['PDP_DATA_DIR'] ?? '/data/pdp';
  const policySnapshotPath = process.env['PDP_POLICY_STORE_PATH'] ?? path.join(dataDir, 'policies.json');
  const decisionLogPath = process.env['PDP_DECISION_LOG_PATH'] ?? path.join(dataDir, 'decisions.jsonl');

  const policyStore: PolicyStore =
    storeKind === 'file'
      ? new FilePolicyStore({ filePath: policySnapshotPath })
      : new InMemoryPolicyStore();

  const decisionLogger =
    storeKind === 'file'
      ? new FileDecisionLogger({ filePath: decisionLogPath })
      : new InMemoryDecisionLogger();

  // Load default policies
  await loadDefaultPolicies(policyStore);

  // Initialize evaluator
  const evaluator = new PolicyEvaluator(policyStore);

  // Create Express application
  const app = express();

  // ─── Global middleware ──────────────────────────────────────────────────

  // ─── Internal mTLS (gateway/envoy <-> plane) ─────────────────────────────
  // Enforced before body parsing to reduce resource usage for unauthenticated requests.
  const tlsEnabled = isEnabled(process.env['PDP_TLS_ENABLED'], false);
  const mtlsRequired = tlsEnabled && isEnabled(process.env['INTERNAL_MTLS_REQUIRED'], false);
  if (isProduction && (!tlsEnabled || !mtlsRequired)) {
    logger.error('Production requires PDP_TLS_ENABLED=true and INTERNAL_MTLS_REQUIRED=true; refusing to start');
    process.exit(1);
  }
  const mtlsExemptPaths = new Set<string>(['/health', '/ready', '/metrics', '/healthz', '/readyz', '/startupz']);
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
      res.status(403).json({ error: 'mTLS required' });
      return;
    }

    if (allowedClientCns.size > 0) {
      const cn = String(cert?.subject?.CN ?? '').trim().toLowerCase();
      if (!cn || !allowedClientCns.has(cn)) {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }
    }

    next();
  });

  // Parse JSON bodies (limit to 1MB to prevent abuse)
  type RawBodyRequest = express.Request & { rawBody?: Buffer };
  app.use(express.json({
    limit: '1mb',
    verify: (req, _res, buf) => {
      // Capture raw body so internal auth can validate integrity.
      (req as RawBodyRequest).rawBody = buf;
    },
  }));

  // Attach correlation ID to every request
  app.use(correlationId);

  // Log every request
  app.use(requestLogger);

  // Add request metrics middleware
  app.use(createRequestMetricsMiddleware({ serviceName: 'policy-engine' }));

  // Disable leaky headers
  app.disable('x-powered-by');

  // ─── Health endpoint (no auth required) ─────────────────────────────────

  const probeManager = new HealthProbeManager({
    serviceName: 'policy-engine',
    version: '1.0.0',
  });
  app.use(probeManager.createHealthRouter());

  // ─── Internal service-to-service authentication (HMAC) ────────────────
  // Protect PDP APIs from unauthenticated lateral movement if a network boundary is misconfigured.
  const internalAuthSecret = readSecret('INTERNAL_SHARED_SECRET', { required: internalAuthEnabled });
  let internalAuthKeyring: Record<string, string> = {};
  try {
    internalAuthKeyring = parseKeyring(readSecret('INTERNAL_AUTH_KEYRING', { defaultValue: '' }));
  } catch (err) {
    logger.error('Failed to parse INTERNAL_AUTH_KEYRING', {
      error: err instanceof Error ? err.message : String(err),
    });
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
  const internalAuthOptions: InternalAuthOptions = {
    enabled: internalAuthEnabled,
    secret: internalAuthSecret,
    allowedSkewSeconds: parseInt(process.env['INTERNAL_AUTH_SKEW_SECONDS'] ?? '60', 10),
    // Envoy ext_authz endpoint is protected by mTLS and may not be able to compute our HMAC.
    exemptPaths: ['/health', '/ready', '/metrics', '/healthz', '/readyz', '/startupz', '/v1/envoy/authz'],
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
    if (req.path.startsWith('/v1/envoy/authz')) return next();

    const result = await verifyInternalAuthAsync({
      method: req.method,
      path: req.originalUrl || req.url || req.path,
      headers: req.headers as unknown as Record<string, unknown>,
      rawBody: (req as RawBodyRequest).rawBody,
    }, internalAuthOptions, internalAuthReplayStore);

    if (!result.ok) {
      logger.warn('Internal auth denied', {
        correlationId: (req as unknown as { correlationId?: string }).correlationId,
        method: req.method,
        path: req.path,
        ip: req.ip || req.socket.remoteAddress,
        reason: result.reason,
      });
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    next();
  });

  // ─── Metrics endpoint ───────────────────────────────────────────────────

  app.get('/metrics', (_req, res) => {
    res.setHeader('Content-Type', 'text/plain; version=0.0.4');
    res.send(globalMetrics.serialize());
  });

  // ─── API routes ─────────────────────────────────────────────────────────

  // Envoy ext_authz (mTLS-protected, internal-auth exempt)
  app.use(createEnvoyAuthzRoutes());

  const routes = createRoutes(evaluator, policyStore, decisionLogger);
  app.use(routes);

  // ─── Error handling ─────────────────────────────────────────────────────

  app.use(notFoundHandler);
  app.use(errorHandler);

  // ─── Start server ───────────────────────────────────────────────────────

  const server = (() => {
    if (!tlsEnabled) {
      return app.listen(config.server.port, config.server.host, () => {
        logger.info(`PDP listening (HTTP) on ${config.server.host}:${config.server.port}`);
        logger.info('FAIL-CLOSED mode active: default decision is DENY');
      });
    }

    const certPath = process.env['PDP_TLS_CERT_PATH'] ?? '/certs/policy-engine.crt';
    const keyPath = process.env['PDP_TLS_KEY_PATH'] ?? '/certs/policy-engine.key';
    const caPath = process.env['PDP_TLS_CA_PATH'] ?? process.env['INTERNAL_MTLS_CA_PATH'] ?? '/certs/ca.crt';

    const tlsOptions: https.ServerOptions = {
      cert: fs.readFileSync(certPath),
      key: fs.readFileSync(keyPath),
      requestCert: true,
      rejectUnauthorized: false,
    };
    if (fs.existsSync(caPath)) {
      tlsOptions.ca = fs.readFileSync(caPath);
    }

    const httpsServer = https.createServer(tlsOptions, app);
    httpsServer.listen(config.server.port, config.server.host, () => {
      logger.info(`PDP listening (HTTPS) on ${config.server.host}:${config.server.port}`);
      logger.info('FAIL-CLOSED mode active: default decision is DENY');
      probeManager.markReady();
    });
    return httpsServer;
  })();

  // Mark server ready if HTTP
  if (!tlsEnabled) {
    probeManager.markReady();
  }

  // ─── Graceful shutdown ──────────────────────────────────────────────────

  const shutdown = async (signal: string): Promise<void> => {
    logger.info(`Received ${signal}, starting graceful shutdown...`);

    // Mark as not ready to prevent new requests
    probeManager.markNotReady();

    // Stop accepting new connections
    server.close((err) => {
      if (err) {
        logger.error('Error during server close', { error: err.message });
      }
    });

    // Wait for existing connections to drain (with timeout)
    const shutdownTimeout = setTimeout(() => {
      logger.warn('Shutdown timeout exceeded, forcing exit');
      process.exit(1);
    }, config.server.shutdownTimeoutMs);

    try {
      // Perform cleanup
      if (replayRedis) {
        await replayRedis.quit();
      }
      logger.info('Cleanup complete');
      clearTimeout(shutdownTimeout);
      process.exit(0);
    } catch (err) {
      logger.error('Error during shutdown cleanup', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
      clearTimeout(shutdownTimeout);
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  // Handle uncaught errors
  process.on('uncaughtException', (err) => {
    logger.error('Uncaught exception', { error: err.message, stack: err.stack });
    // An uncaught exception can leave the process in an undefined state.
    // In production, crash and let the orchestrator restart (fail-closed remains true at the gateway).
    if (process.env['NODE_ENV'] === 'production') {
      process.exit(1);
    }
  });

  process.on('unhandledRejection', (reason) => {
    logger.error('Unhandled rejection', {
      reason: reason instanceof Error ? reason.message : String(reason),
    });
  });
}

// ─── Load default policies from JSON file ───────────────────────────────────

async function loadDefaultPolicies(store: PolicyStore): Promise<void> {
  const defaultPoliciesPath = path.join(__dirname, '..', 'policies', 'default-policies.json');

  try {
    if (!fs.existsSync(defaultPoliciesPath)) {
      logger.warn('No default policies file found', { path: defaultPoliciesPath });
      return;
    }

    const content = fs.readFileSync(defaultPoliciesPath, 'utf-8');
    const data = JSON.parse(content);
    const policies: Policy[] = data.policies ?? [];

    if (policies.length === 0) {
      logger.info('No default policies to load');
      return;
    }

    await store.loadDefaults(policies);
    logger.info(`Loaded ${policies.length} default policies`);
  } catch (err) {
    logger.error('Failed to load default policies', {
      error: err instanceof Error ? err.message : 'Unknown error',
      path: defaultPoliciesPath,
    });
    // Non-fatal: PDP continues without defaults (fail-closed still applies)
  }
}

// ─── Start the application ──────────────────────────────────────────────────

bootstrap().catch((err) => {
  logger.error('Fatal error during bootstrap', {
    error: err instanceof Error ? err.message : 'Unknown error',
    stack: err instanceof Error ? err.stack : undefined,
  });
  process.exit(1);
});
