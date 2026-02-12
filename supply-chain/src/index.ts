/**
 * Supply Chain & Deployment Integrity Plane
 * Server Entry Point
 *
 * Initializes all services, generates bootstrap signing keys,
 * mounts API routes, and starts the Express server with graceful shutdown.
 */

import type { Request, Response, NextFunction } from 'express';
import express from 'express';
import winston from 'winston';
import { v4 as uuidv4 } from 'uuid';
import defaultConfig from '../config/default';
import Redis from 'ioredis';
import {
  verifyInternalAuthAsync,
  readSecret,
  RedisInternalAuthReplayStore,
  type InternalAuthOptions,
  type InternalAuthReplayStore,
} from '@zerotrust/shared';
import crypto from 'crypto';
import {
  HealthProbeManager,
  initializeTracing,
  initializeDefaultMetrics,
  globalMetrics,
  createRequestMetricsMiddleware,
} from '@zerotrust/shared';
import https from 'https';
import fs from 'fs';
import type { TLSSocket } from 'tls';
import { SBOMGenerator } from './sbom/sbom-generator';
import { InMemorySBOMStore } from './sbom/sbom-store';
import { ProvenanceAttestor } from './provenance/attestation';
import { InMemoryProvenanceStore } from './provenance/provenance-store';
import { ArtifactSigner, InMemoryKeyProvider, type KeyMetadata, type SigningAlgorithm } from './signing/artifact-signer';
import { KeyRegistry } from './signing/key-registry';
import { SupplyChainKeystore, parseKeystoreMasterKey } from './signing/keystore';
import { AdmissionGate } from './admission/admission-gate';
import { RequireApproval } from './admission/deploy-policies';
import { HardeningValidator } from './runtime/hardening-validator';
import { VulnerabilityChecker } from './vulnerability/vuln-checker';
import type { RouteServices } from './api/routes';
import { createRoutes } from './api/routes';

// ── Logger ──

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL ?? 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: {
    service: 'supply-chain-plane',
    version: '1.0.0',
  },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ timestamp, level, message, service, ...meta }) => {
          const metaStr = Object.keys(meta).length > 0
            ? ` ${JSON.stringify(meta)}`
            : '';
          return `${timestamp} [${service}] ${level}: ${message}${metaStr}`;
        })
      ),
    }),
  ],
});

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

// ── Bootstrap Services ──

async function bootstrapServices(): Promise<RouteServices> {
  logger.info('Bootstrapping supply chain services...');

  // 1. Vulnerability Checker
  const vulnChecker = new VulnerabilityChecker();
  logger.info('Vulnerability checker initialized', vulnChecker.getDatabaseStats());

  // 2. SBOM Generator & Store
  const sbomGenerator = new SBOMGenerator('1.5', vulnChecker);
  const sbomStore = new InMemorySBOMStore();
  logger.info('SBOM generator and store initialized');

  // 3. Signing infrastructure
  const keyProvider = new InMemoryKeyProvider();
  const artifactSigner = new ArtifactSigner(keyProvider);
  const keyRegistry = new KeyRegistry();

  const normalizeSigningAlgorithm = (value: string): SigningAlgorithm => {
    if (value === 'RSA-4096-SHA256' || value === 'EC-P256-SHA256') return value;
    return 'EC-P256-SHA256';
  };

  const normalizeKeyPurpose = (value: string): KeyMetadata['purpose'] => {
    if (value === 'artifact-signing' || value === 'image-signing' || value === 'attestation-signing') return value;
    return 'artifact-signing';
  };

  // Optional encrypted keystore (recommended for production): persist signing keys across restarts.
  let keystore: SupplyChainKeystore | undefined = undefined;
  const keystoreEnabledRaw =
    process.env['SUPPLY_CHAIN_KEYSTORE_ENABLED'] ??
    (process.env['NODE_ENV'] === 'production' ? 'true' : 'false');
  const keystoreEnabled = ['true', '1', 'yes'].includes(keystoreEnabledRaw.toLowerCase());
  if (keystoreEnabled) {
    const filePath = process.env['SUPPLY_CHAIN_KEYSTORE_PATH'] ?? '/data/keys/keystore.json';
    const masterRaw = readSecret('SUPPLY_CHAIN_KEYSTORE_MASTER_KEY');
    try {
      const masterKey = parseKeystoreMasterKey(masterRaw);
      keystore = new SupplyChainKeystore(filePath, masterKey);
      await keystore.load();
      logger.info('Supply-chain keystore loaded', {
        path: filePath,
        keyCount: keystore.listRecords().length,
      });
    } catch (err) {
      // Production should never silently proceed without its key persistence.
      if (process.env['NODE_ENV'] === 'production') {
        throw err;
      }
      logger.warn('Keystore disabled (invalid/missing master key)', {
        error: (err as Error).message,
      });
      keystore = undefined;
    }
  }

  if (keystore && !keystore.isEmpty()) {
    // Restore keys + registry state.
    let restored = 0;
    for (const record of keystore.listRecords()) {
      const privateKeyPem = keystore.getPrivateKeyPem(record.keyId);
      if (!privateKeyPem) {
        logger.error('Keystore entry missing private key', { keyId: record.keyId });
        continue;
      }
      try {
        const privateKey = crypto.createPrivateKey(privateKeyPem);
        const publicKey = crypto.createPublicKey(record.publicKeyPem);
        const metadata: KeyMetadata = {
          keyId: record.keyId,
          algorithm: normalizeSigningAlgorithm(record.algorithm),
          created: record.createdAt,
          purpose: normalizeKeyPurpose(record.purpose),
          environment: record.environment,
        };
        keyProvider.storeKeyPair(record.keyId, privateKey, publicKey, metadata);
        keyRegistry.importKey(record);
        restored++;
      } catch (err) {
        logger.error('Failed to restore key from keystore', {
          keyId: record.keyId,
          error: (err as Error).message,
        });
      }
    }
    if (process.env['NODE_ENV'] === 'production' && restored === 0) {
      throw new Error('Keystore is present but no signing keys could be restored');
    }
    logger.info('Signing keys restored from keystore', { restored });
  } else {
    // Generate bootstrap signing keys for each environment.
    for (const env of ['dev', 'staging', 'production']) {
      const keyPair = await artifactSigner.generateSigningKeyPair(
        'EC-P256-SHA256',
        'artifact-signing',
        env
      );

      const registered = keyRegistry.registerKey(keyPair.keyId, keyPair.publicKeyPem, {
        algorithm: keyPair.metadata.algorithm,
        purpose: 'artifact-signing',
        environment: env,
        createdBy: 'system-bootstrap',
      });

      if (keystore) {
        try {
          await keystore.upsert(registered, keyPair.privateKeyPem);
        } catch (err) {
          logger.error('Failed to persist bootstrap signing key to keystore', {
            keyId: registered.keyId,
            error: (err as Error).message,
          });
          if (process.env['NODE_ENV'] === 'production') {
            throw err;
          }
        }
      }

      logger.info(`Bootstrap signing key created for ${env}`, {
        keyId: keyPair.keyId,
        environment: env,
      });
    }
  }

  logger.info('Signing infrastructure initialized', keyRegistry.getStats());

  // 4. Provenance attestation
  const provenanceAttestor = new ProvenanceAttestor();
  await provenanceAttestor.initializeSigningKey();
  const provenanceStore = new InMemoryProvenanceStore();
  logger.info('Provenance attestor and store initialized');

  // 5. Admission Gate
  const approvalPolicy = new RequireApproval();
  const admissionGate = new AdmissionGate({
    signer: artifactSigner,
    keyRegistry,
    provenanceStore,
    sbomStore,
    vulnChecker,
    approvalPolicy,
  });
  logger.info('Admission gate initialized');

  // 6. Hardening Validator
  const hardeningValidator = new HardeningValidator();
  logger.info('Hardening validator initialized');

  return {
    sbomGenerator,
    sbomStore,
    provenanceAttestor,
    provenanceStore,
    artifactSigner,
    keyRegistry,
    keystore,
    admissionGate,
    approvalPolicy,
    hardeningValidator,
    vulnChecker,
  };
}

// ── Server Setup ──

async function startServer(): Promise<void> {
  const app = express();
  const port = defaultConfig.server.port;
  const host = defaultConfig.server.host;
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
  const internalAuthExpectedAudience = (process.env['INTERNAL_AUTH_EXPECTED_AUDIENCE'] ?? 'supply-chain').trim();
  const internalAuthReplayProtectionEnabled = isEnabled(
    process.env['INTERNAL_AUTH_REPLAY_PROTECTION_ENABLED'],
    true,
  );
  const internalAuthReplayCacheMaxEntries = parseInt(
    process.env['INTERNAL_AUTH_REPLAY_CACHE_MAX_ENTRIES'] ?? '50000',
    10,
  );

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

    const internalSecret = readSecret('INTERNAL_SHARED_SECRET');
    const looksDefault = internalSecret.toLowerCase().includes('change-me') || internalSecret.toLowerCase().includes('not-secure');
    if (!internalSecret || looksDefault || internalSecret.length < 32) {
      logger.error('Missing/weak/default INTERNAL_SHARED_SECRET in production; refusing to start');
      process.exit(1);
    }
  }

  // Observability
  initializeDefaultMetrics();
  initializeTracing({
    serviceName: 'supply-chain-plane',
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
    const replayRedisDb = parseInt(process.env['INTERNAL_AUTH_REPLAY_REDIS_DB'] ?? process.env['REDIS_DB'] ?? '3', 10);
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
      logger.info('Internal auth replay store configured', { mode: 'redis', db: replayRedisDb });
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

  // ── Middleware ──

  // Disable leaky headers
  app.disable('x-powered-by');

  // Request ID middleware
  app.use((req: Request, _res: Response, next: NextFunction) => {
    (req as Request & { id: string }).id = uuidv4();
    next();
  });

  // Request logging
  app.use((req: Request, res: Response, next: NextFunction) => {
    const start = Date.now();
    res.on('finish', () => {
      const duration = Date.now() - start;
      logger.info('HTTP request', {
        method: req.method,
        path: req.path,
        statusCode: res.statusCode,
        durationMs: duration,
        requestId: (req as Request & { id: string }).id,
        userAgent: req.get('user-agent'),
      });
    });
    next();
  });

  // Add request metrics middleware
  app.use(createRequestMetricsMiddleware({ serviceName: 'supply-chain' }));

  // ── Health Endpoint ──

  app.get('/health', (_req: Request, res: Response) => {
    res.json({
      status: 'healthy',
      service: 'supply-chain-integrity-plane',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    });
  });

  app.get('/ready', (_req: Request, res: Response) => {
    res.json({
      status: 'ready',
      service: 'supply-chain-integrity-plane',
      timestamp: new Date().toISOString(),
    });
  });

  const probeManager = new HealthProbeManager({
    serviceName: 'supply-chain-plane',
    version: '1.0.0',
  });
  app.use(probeManager.createHealthRouter());

  // ─── Internal mTLS (gateway <-> plane) ────────────────────────────────
  const tlsEnabled = isEnabled(process.env['SUPPLY_CHAIN_TLS_ENABLED'], false);
  const mtlsRequired = tlsEnabled && isEnabled(process.env['INTERNAL_MTLS_REQUIRED'], false);
  if (isProduction && (!tlsEnabled || !mtlsRequired)) {
    logger.error('Production requires SUPPLY_CHAIN_TLS_ENABLED=true and INTERNAL_MTLS_REQUIRED=true; refusing to start');
    process.exit(1);
  }
  const mtlsExemptPaths = new Set<string>(['/health', '/ready', '/metrics', '/healthz', '/readyz', '/startupz']);
  const allowedClientCns = new Set(
    (process.env['INTERNAL_MTLS_ALLOWED_CLIENT_CNS'] ?? '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );

  const tlsSocketFromReq = (req: Request): TLSSocket | undefined => {
    const candidate = req.socket as unknown;
    if (!candidate || typeof candidate !== 'object') return undefined;
    const sock = candidate as TLSSocket;
    return typeof sock.getPeerCertificate === 'function' ? sock : undefined;
  };

  app.use((req: Request, res: Response, next: NextFunction) => {
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

  // Parse JSON bodies (after mTLS) so unauthenticated requests don't consume large resources.
  type RawBodyRequest = Request & { rawBody?: Buffer };
  app.use(express.json({
    limit: '10mb',
    verify: (req, _res, buf) => {
      // Capture raw body so internal auth can validate integrity.
      (req as RawBodyRequest).rawBody = buf;
    },
  }));

  // ─── Internal service-to-service authentication (HMAC) ────────────────
  // Protect plane APIs from unauthenticated lateral movement if a network boundary is misconfigured.
  const internalAuthOptions: InternalAuthOptions = {
    enabled: internalAuthEnabled,
    secret: internalAuthSecret,
    allowedSkewSeconds: parseInt(process.env['INTERNAL_AUTH_SKEW_SECONDS'] ?? '60', 10),
    exemptPaths: ['/health', '/ready', '/metrics', '/healthz', '/readyz', '/startupz'],
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

  app.use(async (req: Request, res: Response, next: NextFunction) => {
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
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    next();
  });

  // ── Bootstrap Services and Mount Routes ──

  let services: RouteServices;
  try {
    services = await bootstrapServices();
  } catch (err) {
    logger.error('Failed to bootstrap services', { error: (err as Error).message });
    process.exit(1);
  }

  // ── Metrics endpoint ───────────────────────────────────────────────────

  app.get('/metrics', (_req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/plain; version=0.0.4');
    res.send(globalMetrics.serialize());
  });

  const routes = createRoutes(services);
  app.use(routes);

  // ── 404 Handler ──

  app.use((_req: Request, res: Response) => {
    res.status(404).json({
      error: 'Not found',
      message: 'The requested endpoint does not exist',
    });
  });

  // ── Error Handler ──

  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    void _next; // preserve 4-arg signature for Express error middleware
    logger.error('Unhandled error', {
      error: err.message,
      stack: err.stack,
    });
    res.status(500).json({
      error: 'Internal server error',
      message: process.env.NODE_ENV === 'production'
        ? 'An unexpected error occurred'
        : err.message,
    });
  });

  // ── Start Listening ──

  const server = (() => {
    if (!tlsEnabled) {
      return app.listen(port, host, () => {
        logger.info(`Supply Chain & Deployment Integrity Plane started (HTTP)`, {
          port,
          host,
          nodeVersion: process.version,
          environment: process.env.NODE_ENV ?? 'development',
        });
        logger.info('Available endpoints:', {
          health: `GET /health`,
          ready: `GET /ready`,
          sbomGenerate: `POST /v1/sbom/generate`,
          sbomRetrieve: `GET /v1/sbom/:buildId`,
          sbomSearch: `POST /v1/sbom/search`,
          provenanceAttest: `POST /v1/provenance/attest`,
          provenanceRetrieve: `GET /v1/provenance/:artifactDigest`,
          sign: `POST /v1/sign`,
          verify: `POST /v1/verify`,
          admissionEvaluate: `POST /v1/admission/evaluate`,
          runtimeValidate: `POST /v1/runtime/validate`,
          vulnCheck: `POST /v1/vuln/check`,
          keysList: `GET /v1/keys`,
          keysRotate: `POST /v1/keys/rotate`,
        });
      });
    }

    const certPath = process.env['SUPPLY_CHAIN_TLS_CERT_PATH'] ?? '/certs/supply-chain.crt';
    const keyPath = process.env['SUPPLY_CHAIN_TLS_KEY_PATH'] ?? '/certs/supply-chain.key';
    const caPath = process.env['SUPPLY_CHAIN_TLS_CA_PATH'] ?? process.env['INTERNAL_MTLS_CA_PATH'] ?? '/certs/ca.crt';

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
    httpsServer.listen(port, host, () => {
      logger.info(`Supply Chain & Deployment Integrity Plane started (HTTPS)`, {
        port,
        host,
        nodeVersion: process.version,
        environment: process.env.NODE_ENV ?? 'development',
      });
      logger.info('Available endpoints:', {
        health: `GET /health`,
        ready: `GET /ready`,
        sbomGenerate: `POST /v1/sbom/generate`,
        sbomRetrieve: `GET /v1/sbom/:buildId`,
        sbomSearch: `POST /v1/sbom/search`,
        provenanceAttest: `POST /v1/provenance/attest`,
        provenanceRetrieve: `GET /v1/provenance/:artifactDigest`,
        sign: `POST /v1/sign`,
        verify: `POST /v1/verify`,
        admissionEvaluate: `POST /v1/admission/evaluate`,
        runtimeValidate: `POST /v1/runtime/validate`,
        vulnCheck: `POST /v1/vuln/check`,
        keysList: `GET /v1/keys`,
        keysRotate: `POST /v1/keys/rotate`,
      });
      probeManager.markReady();
    });
    return httpsServer;
  })();

  // Mark server ready if HTTP
  if (!tlsEnabled) {
    server.once('listening', () => {
      probeManager.markReady();
    });
  }

  // ── Request Timeout ──

  server.timeout = defaultConfig.server.requestTimeoutMs;

  // ── Graceful Shutdown ──

  let isShuttingDown = false;

  async function gracefulShutdown(signal: string): Promise<void> {
    if (isShuttingDown) return;
    isShuttingDown = true;

    logger.info(`Received ${signal}, starting graceful shutdown...`);

    // Mark as not ready to prevent new requests
    probeManager.markNotReady();

    if (replayRedis) {
      try {
        await replayRedis.quit();
        logger.info('Replay Redis client disconnected');
      } catch (err) {
        logger.warn('Failed to disconnect replay Redis client', {
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    // Stop accepting new connections
    server.close((err) => {
      if (err) {
        logger.error('Error during server close', { error: err.message });
        process.exit(1);
      }

      logger.info('HTTP server closed');
      logger.info('Graceful shutdown complete');
      process.exit(0);
    });

    // Force shutdown after 30 seconds
    setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 30000);
  }

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled promise rejection', {
      reason: String(reason),
      promise: String(promise),
    });
  });

  process.on('uncaughtException', (err) => {
    logger.error('Uncaught exception', {
      error: err.message,
      stack: err.stack,
    });
    gracefulShutdown('uncaughtException');
  });
}

// ── Entry Point ──

startServer().catch((err) => {
  logger.error('Failed to start server', { error: (err as Error).message });
  process.exit(1);
});
