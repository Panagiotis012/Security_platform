// ─── Telemetry & Detection Plane - Server Entry Point ───
// Unified audit logs, tamper-evident storage, anomaly/attack detection,
// alerting, and incident response hooks for the Zero Trust security platform.

import express from 'express';
import winston from 'winston';
import config from '../config/default';
import Redis from 'ioredis';
import {
  readSecret,
  verifyInternalAuthAsync,
  RedisInternalAuthReplayStore,
  type InternalAuthOptions,
  type InternalAuthReplayStore,
} from '@zerotrust/shared';
import https from 'https';
import fs from 'fs';
import type { TLSSocket } from 'tls';

// Audit components
import { AuditIngester } from './audit/audit-ingester';
import { InMemoryAuditStore, type AuditStore, type AuditEvent } from './audit/audit-store';
import { FileAuditStore } from './audit/file-audit-store';

// Detection components
import type { Alert } from './detection/detection-engine';
import { DetectionEngine } from './detection/detection-engine';
import { BruteForceDetection } from './detection/detections/brute-force';
import { CredentialStuffingDetection } from './detection/detections/credential-stuffing';
import { PasswordSprayingDetection } from './detection/detections/password-spraying';
import { TokenReplayDetection } from './detection/detections/token-replay';
import { ImpossibleTravelDetection } from './detection/detections/impossible-travel';
import { MassExportDetection } from './detection/detections/mass-export';
import { PrivilegeEscalationDetection } from './detection/detections/privilege-escalation';
import { AnomalousAccessPatternDetection } from './detection/detections/anomalous-access-pattern';
import { PolicyViolationSurgeDetection } from './detection/detections/policy-violation-surge';
import { SessionAnomalyDetection } from './detection/detections/session-anomaly';

// Observability imports
import {
  MerkleTree,
  AuditAnchorChain,
  hashAuditEvent,
  HealthProbeManager,
  PIIRedactor,
  initializeTracing,
  initializeDefaultMetrics,
  globalMetrics,
  createRequestMetricsMiddleware,
  recordDetectionAlert,
  recordAuditEventsIngested,
} from '@zerotrust/shared';

import { AdaptiveBaseline } from './detection/adaptive-baseline';
import { DetectionConfigManager } from './detection/detection-config';

// Alerting components
import { AlertManager } from './alerting/alert-manager';
import { ResponseHookExecutor } from './alerting/response-hooks';

// API routes
import { createAuditRoutes, createAlertRoutes, createDetectionRoutes } from './api/routes';

// ─── Logger ───

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'telemetry-plane', version: '1.0.0' },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ timestamp, level, message, service, ...meta }) => {
          const metaStr = Object.keys(meta).length > 0 ? ` ${JSON.stringify(meta)}` : '';
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

// ─── Initialize Components ───

async function bootstrap() {
  logger.info('Initializing Telemetry & Detection Plane...');

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
  const internalAuthExpectedAudience = (process.env['INTERNAL_AUTH_EXPECTED_AUDIENCE'] ?? 'telemetry').trim();
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
    const replayRedisDb = parseInt(process.env['INTERNAL_AUTH_REPLAY_REDIS_DB'] ?? process.env['REDIS_DB'] ?? '2', 10);
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

  // 1. Audit Store (append-only, tamper-evident)
  const auditStore: (AuditStore & { getEventsInWindow(windowMs: number): AuditEvent[] }) = (() => {
    const mode = (process.env['AUDIT_STORE'] ?? '').toLowerCase();
    if (mode === 'file') {
      const filePath = process.env['AUDIT_STORE_PATH'] ?? '/data/audit/audit.jsonl';
      const fsyncOnAppend = (process.env['AUDIT_FSYNC'] ?? 'true').toLowerCase() !== 'false';
      return new FileAuditStore({ filePath, fsyncOnAppend });
    }
    return new InMemoryAuditStore();
  })();
  logger.info('Audit store initialized', {
    kind: auditStore instanceof FileAuditStore ? 'file' : 'memory',
  });

  // Merkle tree for cryptographic audit anchoring
  const merkleTree = new MerkleTree();
  const anchorChain = new AuditAnchorChain(1000, 300000);
  logger.info('Merkle tree audit anchoring initialized');

  // 2. Audit Ingester (validate, redact PII, enrich, store)
  const ingester = new AuditIngester(auditStore);
  logger.info('Audit ingester initialized');

  // Hook: every ingested event gets added to the Merkle tree
  const originalIngest = ingester.ingest.bind(ingester);
  ingester.ingest = async (event: unknown) => {
    const result = await originalIngest(event);
    try {
      const eventHash = hashAuditEvent(result);
      merkleTree.addLeaf(eventHash);
      recordAuditEventsIngested(1);
    } catch (err) {
      logger.warn('Failed to add event to Merkle tree', { error: (err as Error).message });
    }
    return result;
  };

  // 3. Alert Manager
  const alertManager = new AlertManager();

  // Route critical/high alerts to an external webhook (optional).
  // If no webhook URL is configured, severity routing excludes the "webhook" channel.
  const webhookRedactor = new PIIRedactor();
  alertManager.onWebhook(async (alert) => {
    const routing =
      alert.severity === 'CRITICAL'
        ? config.alertRouting.critical
        : alert.severity === 'HIGH'
          ? config.alertRouting.high
          : null;
    if (!routing) return;

    const webhookUrl = routing.webhookUrl;
    if (!webhookUrl) return;

    const payload = webhookRedactor.redact({
      version: 1,
      source: 'security-platform.telemetry',
      alert,
    });

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), routing.maxResponseTimeMs);
    try {
      const res = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!res.ok) {
        const body = await res.text().catch(() => '');
        const snippet = body ? body.slice(0, 512) : '';
        throw new Error(
          `webhook responded ${res.status} ${res.statusText}${snippet ? `: ${snippet}` : ''}`,
        );
      }
    } finally {
      clearTimeout(timeout);
    }
  });

  // 4. Response Hook Executor
  const responseHookExecutor = new ResponseHookExecutor();

  // Wire up: hook executions generate audit events
  responseHookExecutor.onAuditEvent(async (hookExecution) => {
    await ingester.ingest({
      actor: { type: 'system' as const, id: 'telemetry-plane' },
      subject: { type: 'response-hook', id: hookExecution.hookType },
      action: `hook.${hookExecution.hookType.toLowerCase().replace(/_/g, '-')}.execute`,
      resource: {
        type: 'alert',
        id: hookExecution.context.alertId,
        attributes: {
          hookType: hookExecution.hookType,
          success: hookExecution.result.success,
        },
      },
      result: {
        decision: hookExecution.result.success ? 'ALLOW' as const : 'ERROR' as const,
        reason: hookExecution.result.error || 'Hook executed successfully',
      },
      context: {
        ip: hookExecution.context.ip,
      },
      metadata: {
        executionId: hookExecution.id,
        hookDetails: hookExecution.result.details,
      },
    });
  });

  // 5. Detection Engine
  const detectionEngine = new DetectionEngine(auditStore);

  // Register all detections
  detectionEngine.registerDetection(BruteForceDetection);
  detectionEngine.registerDetection(CredentialStuffingDetection);
  detectionEngine.registerDetection(PasswordSprayingDetection);
  detectionEngine.registerDetection(TokenReplayDetection);
  detectionEngine.registerDetection(ImpossibleTravelDetection);
  detectionEngine.registerDetection(MassExportDetection);
  detectionEngine.registerDetection(PrivilegeEscalationDetection);
  detectionEngine.registerDetection(AnomalousAccessPatternDetection);
  detectionEngine.registerDetection(PolicyViolationSurgeDetection);
  detectionEngine.registerDetection(SessionAnomalyDetection);

  logger.info('All detections registered', {
    count: detectionEngine.getDetections().length,
    detections: detectionEngine.getDetections().map((d) => d.id),
  });

  // Adaptive baseline engine for statistical anomaly detection
  const baselineEngine = new AdaptiveBaseline();
  logger.info('Adaptive baseline engine initialized');

  // Detection config hot-reload
  let configManager: DetectionConfigManager | undefined;
  const configPath = process.env['DETECTION_CONFIG_PATH'] ?? '';
  if (configPath) {
    configManager = new DetectionConfigManager(configPath);
    try {
      await configManager.initialize();
      logger.info('Detection config hot-reload enabled', { path: configPath });
    } catch (err) {
      logger.warn('Detection config hot-reload failed to start', { error: (err as Error).message });
    }
  }

  // Wire up: detection alerts flow to alert manager, then to response hooks
  detectionEngine.onAlerts(async (alerts: Alert[]) => {
    const managedAlerts = await alertManager.processDetectionAlerts(alerts);

    // Record metrics for all alerts
    for (const alert of alerts) {
      const severity = alert.severity.toLowerCase() as 'low' | 'medium' | 'high' | 'critical';
      recordDetectionAlert(alert.detectionId, severity, 'telemetry-plane');
    }

    // Execute response hooks for new (non-deduplicated) alerts
    for (const managed of managedAlerts) {
      if (managed.responseHooks.length > 0) {
        try {
          await responseHookExecutor.executeAlertHooks(
            managed.id,
            managed.detectionId,
            managed.responseHooks,
            managed.context
          );
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Unknown error';
          logger.error('Response hook execution failed', {
            alertId: managed.id,
            error: message,
          });
        }
      }
    }
  });

  // 6. Express Application
  const app = express();

  // Disable leaky headers
  app.disable('x-powered-by');

  // Initialize observability
  initializeDefaultMetrics();
  initializeTracing({
    serviceName: 'telemetry-plane',
    serviceVersion: '1.0.0',
    environment: process.env['NODE_ENV'] ?? 'development',
    exporterEndpoint: process.env['OTEL_EXPORTER_OTLP_ENDPOINT'] ?? 'http://localhost:4318',
  });

  // Middleware
  app.use(createRequestMetricsMiddleware({ serviceName: 'telemetry' }));

  // Request logging middleware
  app.use((req, _res, next) => {
    logger.debug('Incoming request', {
      method: req.method,
      path: req.path,
      ip: req.ip,
    });
    next();
  });

  // ─── Internal mTLS (gateway <-> plane) ────────────────────────────────
  // Enforced before body parsing to reduce resource usage for unauthenticated requests.
  const tlsEnabled = isEnabled(process.env['TELEMETRY_TLS_ENABLED'], false);
  const mtlsRequired = tlsEnabled && isEnabled(process.env['INTERNAL_MTLS_REQUIRED'], false);
  if (isProduction && (!tlsEnabled || !mtlsRequired)) {
    logger.error('Production requires TELEMETRY_TLS_ENABLED=true and INTERNAL_MTLS_REQUIRED=true; refusing to start');
    process.exit(1);
  }
  const mtlsExemptPaths = new Set<string>(['/health', '/metrics', '/healthz', '/readyz', '/startupz']);
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

  // Body parsing (after mTLS) so unauthenticated requests don't consume large resources.
  type RawBodyRequest = express.Request & { rawBody?: Buffer };
  app.use(express.json({
    limit: '10mb',
    verify: (req, _res, buf) => {
      // Capture raw body so internal auth can validate integrity.
      (req as RawBodyRequest).rawBody = buf;
    },
  }));
  app.use(express.urlencoded({
    extended: true,
    verify: (req, _res, buf) => {
      (req as RawBodyRequest).rawBody = buf;
    },
  }));

  // ─── Health Probes ───
  const probeManager = new HealthProbeManager({
    serviceName: 'telemetry-plane',
    version: '1.0.0',
  });

  app.use(probeManager.createHealthRouter());

  // Keep legacy /health endpoint for backwards compatibility
  app.get('/health', (_req, res) => {
    const engineMetrics = detectionEngine.getEngineMetrics();
    const ingestionMetrics = ingester.getMetrics();

    res.status(200).json({
      status: 'healthy',
      service: 'telemetry-plane',
      version: '1.0.0',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      components: {
        auditStore: {
          status: 'up',
          eventCount: auditStore.getCount(),
        },
        detectionEngine: {
          status: engineMetrics.running ? 'running' : 'stopped',
          registeredDetections: engineMetrics.registeredDetections,
          enabledDetections: engineMetrics.enabledDetections,
          totalEvaluations: engineMetrics.totalEvaluations,
          totalAlerts: engineMetrics.totalAlertsGenerated,
        },
        ingestion: {
          totalIngested: ingestionMetrics.ingested,
          validationErrors: ingestionMetrics.validationErrors,
        },
      },
    });
  });

  // ─── Metrics Endpoint ───
  app.get('/metrics', (_req, res) => {
    res.setHeader('Content-Type', 'text/plain; version=0.0.4');
    res.send(globalMetrics.serialize());
  });

  // ─── Internal service-to-service authentication (HMAC) ────────────────
  // Protect plane APIs from unauthenticated lateral movement if a network boundary is misconfigured.
  const internalAuthOptions: InternalAuthOptions = {
    enabled: internalAuthEnabled,
    secret: internalAuthSecret,
    allowedSkewSeconds: parseInt(process.env['INTERNAL_AUTH_SKEW_SECONDS'] ?? '60', 10),
    exemptPaths: ['/health', '/metrics', '/healthz', '/readyz', '/startupz'],
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
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    next();
  });

  // ─── Mount Routes ───
  const auditRoutes = createAuditRoutes(ingester, auditStore);
  const alertRoutes = createAlertRoutes(alertManager);
  const detectionRoutes = createDetectionRoutes(detectionEngine, alertManager, responseHookExecutor, ingester);

  app.use(auditRoutes);
  app.use(alertRoutes);
  app.use(detectionRoutes);

  // ─── Merkle Tree Anchor Endpoints ───
  app.get('/v1/audit/anchor', (_req, res) => {
    const anchor = anchorChain.forceCreateAnchor();
    res.json({
      anchor: anchor ? {
        id: anchor.id,
        timestamp: anchor.timestamp,
        rootHash: anchor.rootHash,
        leafCount: anchor.leafCount,
      } : null,
      treeSize: merkleTree.leafCount,
    });
  });

  app.get('/v1/audit/anchor/chain', (_req, res) => {
    res.json({
      anchors: anchorChain.getAnchors().map(a => ({
        id: a.id,
        timestamp: a.timestamp,
        rootHash: a.rootHash,
        leafCount: a.leafCount,
      })),
      chainLength: anchorChain.getAnchors().length,
    });
  });

  // ─── 404 Handler ───
  app.use((_req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  // ─── Error Handler ───
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    void _next; // preserve 4-arg signature for Express error middleware
    logger.error('Unhandled error', {
      error: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: 'Internal server error' });
  });

  return {
    app,
    detectionEngine,
    responseHookExecutor,
    auditStore,
    ingester,
    alertManager,
    merkleTree,
    anchorChain,
    baselineEngine,
    probeManager,
    configManager,
    replayRedis,
  };
}

// ─── Start Server ───

let app: express.Application;

(async () => {
const result = await bootstrap();
app = result.app;
const { detectionEngine, responseHookExecutor, probeManager, configManager, replayRedis } = result;

const server = (() => {
  const tlsEnabled = ['true', '1', 'yes'].includes((process.env['TELEMETRY_TLS_ENABLED'] ?? '').toLowerCase());
  if (!tlsEnabled) {
    return app.listen(config.server.port, config.server.host, () => {
      logger.info(`Telemetry & Detection Plane listening (HTTP) on ${config.server.host}:${config.server.port}`);
      logger.info('Endpoints available:', {
        health: `GET /health`,
        metrics: `GET /metrics`,
        healthz: `GET /healthz`,
        readyz: `GET /readyz`,
        startupz: `GET /startupz`,
        ingestAudit: `POST /v1/audit/events`,
        queryAudit: `GET /v1/audit/events`,
        verifyChain: `GET /v1/audit/verify`,
        exportAudit: `GET /v1/audit/export`,
        auditAnchor: `GET /v1/audit/anchor`,
        auditAnchorChain: `GET /v1/audit/anchor/chain`,
        listAlerts: `GET /v1/alerts`,
        acknowledgeAlert: `POST /v1/alerts/:id/acknowledge`,
        resolveAlert: `POST /v1/alerts/:id/resolve`,
        listDetections: `GET /v1/detections`,
      });

      // Start the detection engine periodic evaluation
      detectionEngine.start();
      logger.info('Detection engine cron started', {
        intervalSeconds: config.detectionEngine.evaluationIntervalSeconds,
      });

      // Mark probes as ready
      probeManager.markReady();
    });
  }

  const certPath = process.env['TELEMETRY_TLS_CERT_PATH'] ?? '/certs/telemetry.crt';
  const keyPath = process.env['TELEMETRY_TLS_KEY_PATH'] ?? '/certs/telemetry.key';
  const caPath = process.env['TELEMETRY_TLS_CA_PATH'] ?? process.env['INTERNAL_MTLS_CA_PATH'] ?? '/certs/ca.crt';

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
    logger.info(`Telemetry & Detection Plane listening (HTTPS) on ${config.server.host}:${config.server.port}`);
    logger.info('Endpoints available:', {
      health: `GET /health`,
      metrics: `GET /metrics`,
      healthz: `GET /healthz`,
      readyz: `GET /readyz`,
      startupz: `GET /startupz`,
      ingestAudit: `POST /v1/audit/events`,
      queryAudit: `GET /v1/audit/events`,
      verifyChain: `GET /v1/audit/verify`,
      exportAudit: `GET /v1/audit/export`,
      auditAnchor: `GET /v1/audit/anchor`,
      auditAnchorChain: `GET /v1/audit/anchor/chain`,
      listAlerts: `GET /v1/alerts`,
      acknowledgeAlert: `POST /v1/alerts/:id/acknowledge`,
      resolveAlert: `POST /v1/alerts/:id/resolve`,
      listDetections: `GET /v1/detections`,
    });

    detectionEngine.start();
    logger.info('Detection engine cron started', {
      intervalSeconds: config.detectionEngine.evaluationIntervalSeconds,
    });

    // Mark probes as ready
    probeManager.markReady();
  });
  return httpsServer;
})();

// ─── Graceful Shutdown ───

async function gracefulShutdown(signal: string) {
  logger.info(`Received ${signal}, starting graceful shutdown...`);

  // Stop accepting new connections
  server.close((err) => {
    if (err) {
      logger.error('Error closing server', { error: err.message });
    } else {
      logger.info('HTTP server closed');
    }
  });

  // Stop detection engine
  detectionEngine.stop();
  logger.info('Detection engine stopped');

  // Stop response hook executor (cleanup timers)
  responseHookExecutor.stop();
  logger.info('Response hook executor stopped');

  // Stop detection config watching
  if (configManager) {
    configManager.shutdown();
    logger.info('Detection config manager stopped');
  }

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

  // Allow in-flight requests to complete (5s grace period)
  setTimeout(() => {
    logger.info('Graceful shutdown complete');
    process.exit(0);
  }, 5000);
}

process.on('SIGTERM', () => { void gracefulShutdown('SIGTERM'); });
process.on('SIGINT', () => { void gracefulShutdown('SIGINT'); });

process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception', { error: err.message, stack: err.stack });
  void gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled rejection', { reason: String(reason) });
});
})().catch((err) => {
  logger.error('Failed to start server', { error: (err as Error).message, stack: (err as Error).stack });
  process.exit(1);
});

export { app };
