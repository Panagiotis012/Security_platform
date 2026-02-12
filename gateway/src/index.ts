import * as http from 'http';
import * as https from 'https';
import * as fs from 'fs';
import express from 'express';
import Redis from 'ioredis';
import { loadConfig } from '../config/default';
import { createApp } from './app';
import { createAccessLogger, createSecurityLogger } from './middleware/request-logger';
import { InMemorySecurityStateStore } from './state/inmemory-security-state-store';
import { RedisSecurityStateStore } from './state/redis-security-state-store';
import { RedisIdentitySecurityStore } from './state/identity-security-store';
import { InMemoryIpReputationStore } from './state/inmemory-ip-reputation-store';
import { RedisIpReputationStore } from './state/redis-ip-reputation-store';
import type { IpReputationStore } from './state/ip-reputation-store';
import { InMemoryBotChallengeStore } from './state/inmemory-bot-challenge-store';
import { RedisBotChallengeStore } from './state/redis-bot-challenge-store';
import type { BotChallengeStore } from './state/bot-challenge-store';
import { InMemoryEdgeCacheStore } from './state/inmemory-edge-cache-store';
import { RedisEdgeCacheStore } from './state/redis-edge-cache-store';
import type { EdgeCacheStore } from './state/edge-cache-store';
import { InMemoryEdgeInvalidationEventStore } from './state/inmemory-edge-invalidation-event-store';
import { RedisEdgeInvalidationEventStore } from './state/redis-edge-invalidation-event-store';
import type { EdgeInvalidationEventStore } from './state/edge-invalidation-event-store';
import { InMemoryControlPlaneAuditStore } from './state/inmemory-control-plane-audit-store';
import { RedisControlPlaneAuditStore } from './state/redis-control-plane-audit-store';
import type { ControlPlaneAuditStore } from './state/control-plane-audit-store';
import { InMemorySecurityControlsAuditStore } from './state/inmemory-security-controls-audit-store';
import { RedisSecurityControlsAuditStore } from './state/redis-security-controls-audit-store';
import type { SecurityControlsAuditStore } from './state/security-controls-audit-store';
import { RoutePolicyManager } from './proxy/route-policy-manager';
import { UpstreamRoutingPolicyManager } from './proxy/upstream-policy-manager';
import { runConvergenceOnce } from './internal/convergence-worker';
import { RedisGreylistFailureCounter } from './middleware/greylist-failure-counter';
import {
  initializeTracing,
  initializeDefaultMetrics,
  HealthProbeManager,
  createHttpCheck,
  globalMetrics,
  readSecret,
  InMemoryRateLimitStore,
  RedisRateLimitStore,
  RedisInternalAuthReplayStore,
  type InternalAuthReplayStore,
  type RateLimitStore,
} from '@zerotrust/shared';

/**
 * Zero Trust Gateway — Main Entry Point
 *
 * Responsibilities:
 * - Load and validate configuration (fail fast on invalid config)
 * - Create the Express app with all security middleware
 * - Start the HTTP/HTTPS server with secure TLS settings
 * - Handle graceful shutdown on SIGTERM/SIGINT
 * - Connection timeouts: read 5s, write 30s, idle 60s
 */

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

function parseCsvEnv(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseKeyringEnv(value: string | undefined): Record<string, string> {
  if (!value) return {};
  const output: Record<string, string> = {};
  for (const item of value.split(',').map((v) => v.trim()).filter(Boolean)) {
    const sep = item.includes(':') ? ':' : item.includes('=') ? '=' : '';
    if (!sep) continue;
    const idx = item.indexOf(sep);
    if (idx <= 0) continue;
    const key = item.slice(0, idx).trim();
    const secret = item.slice(idx + 1).trim();
    if (!key || !secret) continue;
    output[key] = secret;
  }
  return output;
}

function parseHeadersJsonEnv(value: string | undefined): Record<string, string> {
  if (!value || !value.trim()) return {};
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    const headers: Record<string, string> = {};
    for (const [key, raw] of Object.entries(parsed)) {
      const headerKey = key.trim();
      const headerValue = String(raw ?? '').trim();
      if (!headerKey || !headerValue) continue;
      headers[headerKey] = headerValue;
    }
    return headers;
  } catch {
    return {};
  }
}

async function main(): Promise<void> {
  // ── Load and validate configuration ─────────────────────────────────
  // loadConfig() will call process.exit(1) on validation failure.
  const config = loadConfig();

  const accessLog = createAccessLogger(config);
  const securityLog = createSecurityLogger(config);

  accessLog.info({
    event: 'gateway_starting',
    port: config.server.port,
    host: config.server.host,
    tls: config.tls.enabled,
    healthCheckPath: config.healthCheck.path,
    routeCount: config.routes.length,
    upstreamCount: Object.keys(config.upstreams).length,
  });

  // ── Initialize observability ───────────────────────────────────────
  initializeDefaultMetrics();
  initializeTracing({
    serviceName: 'gateway',
    serviceVersion: '1.0.0',
    environment: process.env['NODE_ENV'] ?? 'development',
    exporterEndpoint: process.env['OTEL_EXPORTER_OTLP_ENDPOINT'] ?? 'http://localhost:4318',
  });

  // ── Redis (security state + token enforcement) ─────────────────────
  const isProduction = process.env['NODE_ENV'] === 'production';
  const redisRequired = process.env['GATEWAY_REDIS_REQUIRED']
    ? process.env['GATEWAY_REDIS_REQUIRED'] === 'true'
    : isProduction;

  const redisHost = process.env['REDIS_HOST'] ?? 'redis';
  const redisPort = parseInt(process.env['REDIS_PORT'] ?? '6379', 10);
  const redisDb = parseInt(process.env['REDIS_DB'] ?? '1', 10);
  const redisPassword = readSecret('REDIS_PASSWORD');

  let redis: Redis | null = null;
  try {
    redis = new Redis({
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
    accessLog.info({ event: 'redis_connected', host: redisHost, port: redisPort, db: redisDb });
  } catch (err) {
    accessLog.error({
      event: 'redis_connect_failed',
      host: redisHost,
      port: redisPort,
      db: redisDb,
      error: err instanceof Error ? err.message : String(err),
    });
    if (redisRequired) {
      accessLog.error({ event: 'startup_aborted', reason: 'redis_required_but_unavailable' });
      process.exit(1);
    }
    redis = null;
  }

  const stateStore = redis
    ? new RedisSecurityStateStore(redis, { keyPrefix: process.env['GATEWAY_STATE_PREFIX'] ?? 'zt:gateway:' })
    : new InMemorySecurityStateStore();

  const identitySecurityStore = redis
    ? new RedisIdentitySecurityStore(redis, { keyPrefix: process.env['IDENTITY_STATE_PREFIX'] ?? 'zt:identity:' })
    : undefined;

  // ── Distributed Rate Limiting (Redis-backed in prod) ────────────────
  const rateLimitPrefix = process.env['GATEWAY_RATE_LIMIT_PREFIX'] ?? 'zt:gateway:rl:';
  const rateLimitStore: RateLimitStore = redis
    ? new RedisRateLimitStore(redis, { keyPrefix: rateLimitPrefix, logger: accessLog })
    : new InMemoryRateLimitStore();

  const tightenedMultiplier = Math.max(0, Math.min(1, config.rateLimit.greylist.tightenedRateMultiplier));
  const greylistFailureCounter = redis
    ? new RedisGreylistFailureCounter(redis, {
        keyPrefix: rateLimitPrefix,
        failureWindowMs: config.rateLimit.greylist.failureWindowMs,
        failureThreshold: config.rateLimit.greylist.failureThreshold,
        greylistDurationMs: config.rateLimit.greylist.greylistDurationMs,
        rateMultiplier: tightenedMultiplier,
        store: rateLimitStore,
        reason: 'auth_failures',
      })
    : undefined;

  // ── Adaptive IP Reputation Store (Redis-backed in prod) ────────────
  const adaptiveStoreMode = (process.env['ADAPTIVE_DEFENSE_STORE'] ?? (redis ? 'redis' : 'memory')).toLowerCase();
  const adaptiveRedisRequired =
    process.env['ADAPTIVE_DEFENSE_REDIS_REQUIRED']
      ? process.env['ADAPTIVE_DEFENSE_REDIS_REQUIRED'] === 'true'
      : isProduction;

  let ipReputationStore: IpReputationStore;
  if (adaptiveStoreMode === 'redis') {
    if (redis) {
      ipReputationStore = new RedisIpReputationStore(redis, {
        keyPrefix: process.env['ADAPTIVE_DEFENSE_REDIS_PREFIX'] ?? 'zt:gateway:ip-reputation:',
        logger: accessLog,
      });
    } else {
      accessLog.error({
        event: 'adaptive_ip_reputation_store_unavailable',
        configured: 'redis',
        required: adaptiveRedisRequired,
      });
      if (adaptiveRedisRequired) {
        accessLog.error({ event: 'startup_aborted', reason: 'adaptive_redis_required_but_unavailable' });
        process.exit(1);
      }
      ipReputationStore = new InMemoryIpReputationStore();
    }
  } else {
    ipReputationStore = new InMemoryIpReputationStore();
  }

  // ── Bot Challenge State Store (Redis-backed in prod) ───────────────
  const botChallengeStoreMode = (process.env['ADAPTIVE_DEFENSE_CHALLENGE_STORE'] ?? (redis ? 'redis' : 'memory')).toLowerCase();
  const botChallengeRedisRequired =
    process.env['ADAPTIVE_DEFENSE_CHALLENGE_REDIS_REQUIRED']
      ? process.env['ADAPTIVE_DEFENSE_CHALLENGE_REDIS_REQUIRED'] === 'true'
      : isProduction;

  let botChallengeStore: BotChallengeStore;
  if (botChallengeStoreMode === 'redis') {
    if (redis) {
      botChallengeStore = new RedisBotChallengeStore(redis, {
        keyPrefix: process.env['ADAPTIVE_DEFENSE_CHALLENGE_REDIS_PREFIX'] ?? 'zt:gateway:bot-challenge:',
      });
    } else {
      accessLog.error({
        event: 'bot_challenge_store_unavailable',
        configured: 'redis',
        required: botChallengeRedisRequired,
      });
      if (botChallengeRedisRequired) {
        accessLog.error({ event: 'startup_aborted', reason: 'bot_challenge_redis_required_but_unavailable' });
        process.exit(1);
      }
      botChallengeStore = new InMemoryBotChallengeStore();
    }
  } else {
    botChallengeStore = new InMemoryBotChallengeStore();
  }

  // ── Edge Response Cache Store (Redis-backed for multi-instance) ────
  const edgeCacheStoreMode = (process.env['EDGE_CACHE_STORE'] ?? (redis ? 'redis' : 'memory')).toLowerCase();
  const edgeCacheRedisRequired =
    process.env['EDGE_CACHE_REDIS_REQUIRED']
      ? process.env['EDGE_CACHE_REDIS_REQUIRED'] === 'true'
      : false;
  let edgeCacheStore: EdgeCacheStore | undefined;
  if (config.edgeCache.enabled) {
    if (edgeCacheStoreMode === 'redis') {
      if (redis) {
        edgeCacheStore = new RedisEdgeCacheStore(redis, {
          keyPrefix: process.env['EDGE_CACHE_REDIS_PREFIX'] ?? 'zt:gateway:edge-cache:',
        });
      } else {
        accessLog.error({
          event: 'edge_cache_store_unavailable',
          configured: 'redis',
          required: edgeCacheRedisRequired,
        });
        if (edgeCacheRedisRequired) {
          accessLog.error({ event: 'startup_aborted', reason: 'edge_cache_redis_required_but_unavailable' });
          process.exit(1);
        }
        edgeCacheStore = new InMemoryEdgeCacheStore(config.edgeCache.memoryMaxEntries);
      }
    } else {
      edgeCacheStore = new InMemoryEdgeCacheStore(config.edgeCache.memoryMaxEntries);
    }
  }

  // ── Edge Invalidation Event Log (Redis-backed for replication) ────
  const edgeInvalidationStoreMode = (
    process.env['EDGE_INVALIDATION_LOG_STORE'] ?? (redis ? 'redis' : 'memory')
  ).toLowerCase();
  const edgeInvalidationRedisRequired =
    process.env['EDGE_INVALIDATION_LOG_REDIS_REQUIRED']
      ? process.env['EDGE_INVALIDATION_LOG_REDIS_REQUIRED'] === 'true'
      : false;
  let edgeInvalidationEventStore: EdgeInvalidationEventStore | undefined;
  if (config.edgeCache.enabled) {
    if (edgeInvalidationStoreMode === 'redis') {
      if (redis) {
        edgeInvalidationEventStore = new RedisEdgeInvalidationEventStore(redis, {
          keyPrefix: process.env['EDGE_INVALIDATION_LOG_REDIS_PREFIX'] ?? 'zt:gateway:edge-invalidation:',
        });
      } else {
        accessLog.error({
          event: 'edge_invalidation_store_unavailable',
          configured: 'redis',
          required: edgeInvalidationRedisRequired,
        });
        if (edgeInvalidationRedisRequired) {
          accessLog.error({ event: 'startup_aborted', reason: 'edge_invalidation_redis_required_but_unavailable' });
          process.exit(1);
        }
        edgeInvalidationEventStore = new InMemoryEdgeInvalidationEventStore();
      }
    } else {
      edgeInvalidationEventStore = new InMemoryEdgeInvalidationEventStore();
    }
  }

  // ── Control-Plane Mutation Audit Log (Redis-backed for SOC replication) ────
  const controlPlaneAuditStoreMode = (
    process.env['CONTROL_PLANE_AUDIT_STORE'] ?? (redis ? 'redis' : 'memory')
  ).toLowerCase();
  const controlPlaneAuditRedisRequired =
    process.env['CONTROL_PLANE_AUDIT_REDIS_REQUIRED']
      ? process.env['CONTROL_PLANE_AUDIT_REDIS_REQUIRED'] === 'true'
      : isProduction;
  let controlPlaneAuditStore: ControlPlaneAuditStore;
  if (controlPlaneAuditStoreMode === 'redis') {
    if (redis) {
      controlPlaneAuditStore = new RedisControlPlaneAuditStore(redis, {
        keyPrefix: process.env['CONTROL_PLANE_AUDIT_REDIS_PREFIX'] ?? 'zt:gateway:control-plane-audit:',
      });
    } else {
      accessLog.error({
        event: 'control_plane_audit_store_unavailable',
        configured: 'redis',
        required: controlPlaneAuditRedisRequired,
      });
      if (controlPlaneAuditRedisRequired) {
        accessLog.error({ event: 'startup_aborted', reason: 'control_plane_audit_redis_required_but_unavailable' });
        process.exit(1);
      }
      controlPlaneAuditStore = new InMemoryControlPlaneAuditStore();
    }
  } else {
    controlPlaneAuditStore = new InMemoryControlPlaneAuditStore();
  }

  // ── Distributed Internal-Auth Replay Store ─────────────────────────
  const replayStoreMode = (process.env['INTERNAL_AUTH_REPLAY_STORE'] ?? (redis ? 'redis' : 'memory')).toLowerCase();
  let internalAuthReplayStore: InternalAuthReplayStore | undefined;
  if (replayStoreMode === 'redis') {
    if (redis) {
      internalAuthReplayStore = new RedisInternalAuthReplayStore(redis, {
        keyPrefix: process.env['INTERNAL_AUTH_REPLAY_REDIS_PREFIX'] ?? 'zt:internal-auth:replay:',
      });
    } else {
      accessLog.warn({
        event: 'internal_auth_replay_store_fallback',
        configured: 'redis',
        active: 'in-memory',
        reason: 'redis_unavailable',
      });
    }
  }

  // ── Abuse-Intel Signed-Bundle Replay Store ─────────────────────────
  const abuseIntelReplayStoreMode = (
    process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_REPLAY_STORE'] ?? (redis ? 'redis' : 'memory')
  ).toLowerCase();
  let abuseIntelReplayStore: InternalAuthReplayStore | undefined;
  if (abuseIntelReplayStoreMode === 'redis') {
    if (redis) {
      abuseIntelReplayStore = new RedisInternalAuthReplayStore(redis, {
        keyPrefix: process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_REPLAY_REDIS_PREFIX'] ?? 'zt:gateway:abuse-intel:replay:',
      });
    } else {
      accessLog.warn({
        event: 'abuse_intel_replay_store_fallback',
        configured: 'redis',
        active: 'in-memory',
        reason: 'redis_unavailable',
      });
    }
  }

  // ── Security Controls Audit History Store ──────────────────────────
  const securityControlsHistoryStoreMode = (
    process.env['SECURITY_CONTROLS_HISTORY_STORE'] ?? (redis ? 'redis' : 'memory')
  ).toLowerCase();
  const securityControlsHistoryRedisRequired =
    process.env['SECURITY_CONTROLS_HISTORY_REDIS_REQUIRED']
      ? process.env['SECURITY_CONTROLS_HISTORY_REDIS_REQUIRED'] === 'true'
      : isProduction;

  let securityControlsAuditStore: SecurityControlsAuditStore;
  if (securityControlsHistoryStoreMode === 'redis') {
    if (redis) {
      securityControlsAuditStore = new RedisSecurityControlsAuditStore(redis, {
        keyPrefix: process.env['SECURITY_CONTROLS_HISTORY_REDIS_PREFIX'] ?? 'zt:gateway:security-controls-audit:',
      });
    } else {
      accessLog.error({
        event: 'security_controls_history_store_unavailable',
        configured: 'redis',
        required: securityControlsHistoryRedisRequired,
      });
      if (securityControlsHistoryRedisRequired) {
        accessLog.error({ event: 'startup_aborted', reason: 'security_controls_history_redis_required_but_unavailable' });
        process.exit(1);
      }
      securityControlsAuditStore = new InMemorySecurityControlsAuditStore();
    }
  } else {
    securityControlsAuditStore = new InMemorySecurityControlsAuditStore();
  }

  const routePolicyManager = new RoutePolicyManager(config);
  const upstreamPolicyManager = new UpstreamRoutingPolicyManager(config);

  // ── Optional Regional Convergence Worker ───────────────────────────
  const convergenceEnabled = parseBooleanEnv(
    process.env['CONTROL_PLANE_CONVERGENCE_ENABLED'],
    false,
  );
  const convergencePeers = parseCsvEnv(process.env['CONTROL_PLANE_CONVERGENCE_PEERS']);
  const convergenceAutoHeal = parseBooleanEnv(
    process.env['CONTROL_PLANE_CONVERGENCE_AUTO_HEAL'],
    true,
  );
  const convergenceIntervalMs = parseIntegerEnv(
    process.env['CONTROL_PLANE_CONVERGENCE_INTERVAL_MS'],
    60_000,
    5_000,
    60 * 60 * 1000,
  );
  const convergenceExportLimit = parseIntegerEnv(
    process.env['CONTROL_PLANE_CONVERGENCE_EXPORT_LIMIT'],
    1000,
    1,
    5000,
  );
  const convergenceHeaders = parseHeadersJsonEnv(
    process.env['CONTROL_PLANE_CONVERGENCE_HEADERS_JSON'],
  );

  // ── Create Express application ──────────────────────────────────────
  const app = createApp(config, {
    stateStore,
    identitySecurityStore,
    ipReputationStore,
    botChallengeStore,
    rateLimitStore,
    greylistFailureCounter,
    internalAuthReplayStore,
    abuseIntelReplayStore,
    edgeCacheStore,
    edgeInvalidationEventStore,
    controlPlaneAuditStore,
    routePolicyManager,
    upstreamPolicyManager,
    securityControlsAuditStore,
  });

  // ── Internal-only metrics server ────────────────────────────────────
  // The gateway's public listener should not expose /metrics.
  const metricsEnabled =
    process.env['GATEWAY_METRICS_ENABLED'] === 'true' ||
    (process.env['GATEWAY_METRICS_ENABLED'] === undefined);

  let metricsServer: http.Server | null = null;
  if (metricsEnabled) {
    const metricsPort = parseInt(process.env['GATEWAY_METRICS_PORT'] ?? '9095', 10);
    const metricsHost = process.env['GATEWAY_METRICS_HOST'] ?? (isProduction ? '0.0.0.0' : '127.0.0.1');

    const metricsApp = express();
    metricsApp.disable('x-powered-by');
    metricsApp.get('/metrics', (_req, res) => {
      res.setHeader('Content-Type', 'text/plain; version=0.0.4');
      res.send(globalMetrics.serialize());
    });
    metricsApp.get('/healthz', (_req, res) => {
      res.status(200).json({ status: 'ok' });
    });

    metricsServer = http.createServer(metricsApp);
    metricsServer.listen(metricsPort, metricsHost, () => {
      accessLog.info({ event: 'gateway_metrics_started', host: metricsHost, port: metricsPort });
    });
  }

  // ── Initialize health probe manager ─────────────────────────────────
  const probeManager = new HealthProbeManager({
    serviceName: 'gateway',
    version: '1.0.0',
  });

  // Register upstream health checks
  for (const [name, upstream] of Object.entries(config.upstreams)) {
    probeManager.addDependencyCheck(name, createHttpCheck(
      `${upstream.url}/health`,
      3000
    ));
  }

  // ── Create server (HTTPS if TLS configured, HTTP otherwise) ─────────
  let server: http.Server | https.Server;
  let httpRedirectServer: http.Server | null = null;

  if (config.tls.enabled && config.tls.certPath && config.tls.keyPath) {
    const mtlsRequired = ['true', '1', 'yes'].includes((process.env['GATEWAY_MTLS_REQUIRED'] ?? '').toLowerCase());

    const tlsOptions: https.ServerOptions = {
      cert: fs.readFileSync(config.tls.certPath),
      key: fs.readFileSync(config.tls.keyPath),
      minVersion: config.tls.minVersion,
      honorCipherOrder: config.tls.honorCipherOrder,
      sessionTimeout: config.tls.sessionTimeout,
      // When running behind an edge proxy (Envoy), the gateway can be locked down
      // to accept only mTLS connections from inside the cluster.
      ...(mtlsRequired ? { requestCert: true, rejectUnauthorized: false } : {}),
    };

    const caPath =
      config.tls.caPath ??
      process.env['TLS_CA_PATH'] ??
      process.env['INTERNAL_MTLS_CA_PATH'] ??
      '/certs/ca.crt';
    if (fs.existsSync(caPath)) {
      tlsOptions.ca = fs.readFileSync(caPath);
    }

    if (config.tls.ciphers) {
      tlsOptions.ciphers = config.tls.ciphers;
    }

    server = https.createServer(tlsOptions, app);

    accessLog.info({
      event: 'tls_configured',
      minVersion: config.tls.minVersion,
      honorCipherOrder: config.tls.honorCipherOrder,
    });
  } else {
    // HTTP mode — should only be used in development or behind a TLS-terminating LB
    if (process.env['NODE_ENV'] === 'production') {
      securityLog.error({
        event: 'tls_disabled_in_production',
        reason: 'TLS is disabled in production mode. This is a security risk.',
        severity: 'CRITICAL',
      });
    }
    server = http.createServer(app);
  }

  // Optional HTTP listener (health checks + redirect to HTTPS).
  // This is useful when you want TLS on the primary port but still need an
  // internal plain-HTTP probe endpoint (or a dev redirect from :8080).
  if (config.tls.enabled && typeof config.server.httpPort === 'number') {
    httpRedirectServer = http.createServer((req, res) => {
      const url = req.url || '/';
      const pathOnly = url.split('?')[0] ?? url;

      // Keep the health check reachable over HTTP.
      const healthPaths = new Set<string>([config.healthCheck.path, '/healthz']);
      if (config.healthCheck.enabled && healthPaths.has(pathOnly)) {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ status: 'healthy', timestamp: new Date().toISOString() }));
        return;
      }

      const hostHeader = String(req.headers.host || config.server.host || 'localhost');
      const hostname = hostHeader.includes(':') ? hostHeader.split(':')[0] : hostHeader;
      const httpsPort = config.server.port;
      const portPart = httpsPort === 443 ? '' : `:${httpsPort}`;
      const location = `https://${hostname}${portPart}${url}`;

      // Keep method semantics on redirect.
      res.statusCode = req.method === 'GET' || req.method === 'HEAD' ? 308 : 307;
      res.setHeader('Location', location);
      res.end();
    });

    httpRedirectServer.requestTimeout = config.server.readTimeoutMs;
    httpRedirectServer.headersTimeout = config.server.readTimeoutMs + 1000;
    httpRedirectServer.timeout = config.server.writeTimeoutMs;
    httpRedirectServer.keepAliveTimeout = config.server.keepAliveTimeoutMs;
    httpRedirectServer.maxHeadersCount = 100;

    httpRedirectServer.listen(config.server.httpPort, config.server.host, () => {
      accessLog.info({
        event: 'gateway_http_redirect_started',
        port: config.server.httpPort,
        host: config.server.host,
        redirectsToPort: config.server.port,
      });
    });
  }

  // ── Connection timeouts ─────────────────────────────────────────────
  // These protect against slowloris and resource exhaustion attacks.
  server.requestTimeout = config.server.readTimeoutMs;       // Time to receive full request
  server.headersTimeout = config.server.readTimeoutMs + 1000; // Slightly more than requestTimeout
  server.timeout = config.server.writeTimeoutMs;              // Time to send response
  server.keepAliveTimeout = config.server.keepAliveTimeoutMs; // Idle connection timeout
  server.maxHeadersCount = 100;                                // Limit header count

  // Set max header size if supported (Node.js 14+)
  if ('maxHeaderSize' in server) {
    // maxHeaderSize is typically set at the http.Server level or via --max-http-header-size flag
    // We enforce header sizes in our normalization middleware as well.
  }

  // ── Start listening ─────────────────────────────────────────────────
  let convergenceTimer: ReturnType<typeof setInterval> | null = null;
  let convergenceInFlight = false;

  const runConvergenceTick = async (): Promise<void> => {
    if (!convergenceEnabled || convergencePeers.length === 0 || convergenceInFlight) {
      return;
    }
    convergenceInFlight = true;
    try {
      const securityControlsAuditSecret = (
        readSecret('SECURITY_CONTROLS_AUDIT_SECRET') ||
        config.internalAuth.secret ||
        config.adaptiveDefense.abuseIntel.signingSecret ||
        config.adaptiveDefense.challenge.secret ||
        readSecret('INTERNAL_SHARED_SECRET') ||
        ''
      ).trim();

      const securityAllowedSources = parseCsvEnv(
        process.env['SECURITY_CONTROLS_HISTORY_BUNDLE_ALLOWED_SOURCES'],
      );
      const securityAllowedKeyIds = parseCsvEnv(
        process.env['SECURITY_CONTROLS_HISTORY_BUNDLE_ALLOWED_KEY_IDS'],
      );
      const securitySigningKeyId = String(
        process.env['SECURITY_CONTROLS_HISTORY_BUNDLE_SIGNING_KEY_ID'] ?? 'gateway-controls-v1',
      ).trim() || 'gateway-controls-v1';
      const securityBundleSigningSecret = String(
        process.env['SECURITY_CONTROLS_HISTORY_BUNDLE_SIGNING_SECRET'] ?? securityControlsAuditSecret,
      ).trim();
      const securityKeyring = parseKeyringEnv(process.env['SECURITY_CONTROLS_HISTORY_BUNDLE_KEYRING']);
      if (Object.keys(securityKeyring).length === 0 && securityBundleSigningSecret) {
        const fallbackKeyIds = securityAllowedKeyIds.length > 0
          ? securityAllowedKeyIds
          : [securitySigningKeyId];
        for (const keyId of fallbackKeyIds) {
          securityKeyring[keyId] = securityBundleSigningSecret;
        }
      }

      const edgeAllowedSources = parseCsvEnv(
        process.env['EDGE_CACHE_VERSION_BUNDLE_ALLOWED_SOURCES'],
      );
      const edgeAllowedKeyIds = parseCsvEnv(
        process.env['EDGE_CACHE_VERSION_BUNDLE_ALLOWED_KEY_IDS'],
      );
      const edgeSigningKeyId = String(
        process.env['EDGE_CACHE_VERSION_BUNDLE_SIGNING_KEY_ID'] ?? 'gateway-edge-cache-v1',
      ).trim() || 'gateway-edge-cache-v1';
      const edgeBundleSigningSecret = String(
        process.env['EDGE_CACHE_VERSION_BUNDLE_SIGNING_SECRET'] ??
        readSecret('INTERNAL_SHARED_SECRET') ??
        config.internalAuth.secret,
      ).trim();
      const edgeKeyring = parseKeyringEnv(process.env['EDGE_CACHE_VERSION_BUNDLE_KEYRING']);
      if (Object.keys(edgeKeyring).length === 0 && edgeBundleSigningSecret) {
        const fallbackKeyIds = edgeAllowedKeyIds.length > 0 ? edgeAllowedKeyIds : [edgeSigningKeyId];
        for (const keyId of fallbackKeyIds) {
          edgeKeyring[keyId] = edgeBundleSigningSecret;
        }
      }

      const edgeInvalidationAllowedSources = parseCsvEnv(
        process.env['EDGE_INVALIDATION_BUNDLE_ALLOWED_SOURCES'],
      );
      const edgeInvalidationAllowedKeyIds = parseCsvEnv(
        process.env['EDGE_INVALIDATION_BUNDLE_ALLOWED_KEY_IDS'],
      );
      const edgeInvalidationSigningKeyId = String(
        process.env['EDGE_INVALIDATION_BUNDLE_SIGNING_KEY_ID'] ?? 'gateway-edge-invalidation-v1',
      ).trim() || 'gateway-edge-invalidation-v1';
      const edgeInvalidationBundleSigningSecret = String(
        process.env['EDGE_INVALIDATION_BUNDLE_SIGNING_SECRET'] ??
        readSecret('INTERNAL_SHARED_SECRET') ??
        config.internalAuth.secret,
      ).trim();
      const edgeInvalidationKeyring = parseKeyringEnv(process.env['EDGE_INVALIDATION_BUNDLE_KEYRING']);
      if (Object.keys(edgeInvalidationKeyring).length === 0 && edgeInvalidationBundleSigningSecret) {
        const fallbackKeyIds = edgeInvalidationAllowedKeyIds.length > 0
          ? edgeInvalidationAllowedKeyIds
          : [edgeInvalidationSigningKeyId];
        for (const keyId of fallbackKeyIds) {
          edgeInvalidationKeyring[keyId] = edgeInvalidationBundleSigningSecret;
        }
      }

      const controlPlaneAuditAllowedSources = parseCsvEnv(
        process.env['CONTROL_PLANE_AUDIT_BUNDLE_ALLOWED_SOURCES'],
      );
      const controlPlaneAuditAllowedKeyIds = parseCsvEnv(
        process.env['CONTROL_PLANE_AUDIT_BUNDLE_ALLOWED_KEY_IDS'],
      );
      const controlPlaneAuditSigningKeyId = String(
        process.env['CONTROL_PLANE_AUDIT_BUNDLE_SIGNING_KEY_ID'] ?? 'gateway-control-plane-audit-v1',
      ).trim() || 'gateway-control-plane-audit-v1';
      const controlPlaneAuditSigningSecret = String(
        process.env['CONTROL_PLANE_AUDIT_BUNDLE_SIGNING_SECRET'] ??
        readSecret('INTERNAL_SHARED_SECRET') ??
        config.internalAuth.secret,
      ).trim();
      const controlPlaneAuditKeyring = parseKeyringEnv(process.env['CONTROL_PLANE_AUDIT_BUNDLE_KEYRING']);
      if (Object.keys(controlPlaneAuditKeyring).length === 0 && controlPlaneAuditSigningSecret) {
        const fallbackKeyIds = controlPlaneAuditAllowedKeyIds.length > 0
          ? controlPlaneAuditAllowedKeyIds
          : [controlPlaneAuditSigningKeyId];
        for (const keyId of fallbackKeyIds) {
          controlPlaneAuditKeyring[keyId] = controlPlaneAuditSigningSecret;
        }
      }

      const upstreamRoutingAllowedSources = parseCsvEnv(
        process.env['UPSTREAM_ROUTING_POLICY_BUNDLE_ALLOWED_SOURCES'],
      );
      const upstreamRoutingAllowedKeyIds = parseCsvEnv(
        process.env['UPSTREAM_ROUTING_POLICY_BUNDLE_ALLOWED_KEY_IDS'],
      );
      const upstreamRoutingSigningKeyId = String(
        process.env['UPSTREAM_ROUTING_POLICY_BUNDLE_SIGNING_KEY_ID'] ?? 'gateway-upstream-routing-v1',
      ).trim() || 'gateway-upstream-routing-v1';
      const upstreamRoutingSigningSecret = String(
        process.env['UPSTREAM_ROUTING_POLICY_BUNDLE_SIGNING_SECRET'] ??
        readSecret('INTERNAL_SHARED_SECRET') ??
        config.internalAuth.secret,
      ).trim();
      const upstreamRoutingKeyring = parseKeyringEnv(process.env['UPSTREAM_ROUTING_POLICY_BUNDLE_KEYRING']);
      if (Object.keys(upstreamRoutingKeyring).length === 0 && upstreamRoutingSigningSecret) {
        const fallbackKeyIds = upstreamRoutingAllowedKeyIds.length > 0
          ? upstreamRoutingAllowedKeyIds
          : [upstreamRoutingSigningKeyId];
        for (const keyId of fallbackKeyIds) {
          upstreamRoutingKeyring[keyId] = upstreamRoutingSigningSecret;
        }
      }

      const routePolicyAllowedSources = parseCsvEnv(
        process.env['ROUTE_POLICY_BUNDLE_ALLOWED_SOURCES'],
      );
      const routePolicyAllowedKeyIds = parseCsvEnv(
        process.env['ROUTE_POLICY_BUNDLE_ALLOWED_KEY_IDS'],
      );
      const routePolicySigningKeyId = String(
        process.env['ROUTE_POLICY_BUNDLE_SIGNING_KEY_ID'] ?? 'gateway-route-policy-v1',
      ).trim() || 'gateway-route-policy-v1';
      const routePolicySigningSecret = String(
        process.env['ROUTE_POLICY_BUNDLE_SIGNING_SECRET'] ??
        readSecret('INTERNAL_SHARED_SECRET') ??
        config.internalAuth.secret,
      ).trim();
      const routePolicyKeyring = parseKeyringEnv(process.env['ROUTE_POLICY_BUNDLE_KEYRING']);
      if (Object.keys(routePolicyKeyring).length === 0 && routePolicySigningSecret) {
        const fallbackKeyIds = routePolicyAllowedKeyIds.length > 0
          ? routePolicyAllowedKeyIds
          : [routePolicySigningKeyId];
        for (const keyId of fallbackKeyIds) {
          routePolicyKeyring[keyId] = routePolicySigningSecret;
        }
      }

      const convergencePolicyQuorumEnabled = parseBooleanEnv(
        process.env['CONTROL_PLANE_CONVERGENCE_POLICY_QUORUM_ENABLED'],
        false,
      );
      const convergencePolicyQuorumMinPeers = parseIntegerEnv(
        process.env['CONTROL_PLANE_CONVERGENCE_POLICY_QUORUM_MIN_PEERS'],
        2,
        1,
        Math.max(1, convergencePeers.length || 1),
      );
      const convergenceAuditEnabled = parseBooleanEnv(
        process.env['CONTROL_PLANE_CONVERGENCE_AUDIT_ENABLED'],
        true,
      );
      const convergenceAuditSigningKeyId = String(
        process.env['CONTROL_PLANE_CONVERGENCE_AUDIT_SIGNING_KEY_ID'] ?? 'gateway-convergence-v1',
      ).trim() || 'gateway-convergence-v1';
      const convergenceAuditSigningSecret = String(
        process.env['CONTROL_PLANE_CONVERGENCE_AUDIT_SIGNING_SECRET'] ??
        readSecret('INTERNAL_SHARED_SECRET') ??
        config.internalAuth.secret,
      ).trim();
      const convergenceAuditActor = String(
        process.env['CONTROL_PLANE_CONVERGENCE_AUDIT_ACTOR'] ?? 'convergence-worker',
      ).trim() || 'convergence-worker';
      const convergenceAuditPath = String(
        process.env['CONTROL_PLANE_CONVERGENCE_AUDIT_PATH'] ?? '/internal/control-plane/convergence/peer',
      ).trim() || '/internal/control-plane/convergence/peer';
      const convergenceAuditScope = String(
        process.env['CONTROL_PLANE_CONVERGENCE_AUDIT_PERMISSION_SCOPE'] ?? 'convergence.write',
      ).trim() || 'convergence.write';

      const result = await runConvergenceOnce({
        peers: convergencePeers,
        autoHeal: convergenceAutoHeal,
        exportLimit: convergenceExportLimit,
        requestHeaders: convergenceHeaders,
        policyQuorum: {
          enabled: convergencePolicyQuorumEnabled,
          minPeers: convergencePolicyQuorumMinPeers,
        },
        securityControls: {
          auditStore: securityControlsAuditStore,
          signingSecret: securityControlsAuditSecret,
          maxEntries: parseIntegerEnv(
            process.env['SECURITY_CONTROLS_HISTORY_MAX_ENTRIES'],
            10_000,
            100,
            100_000,
          ),
          requireSignedImports: parseBooleanEnv(
            process.env['SECURITY_CONTROLS_HISTORY_BUNDLE_REQUIRE_SIGNED_IMPORTS'],
            true,
          ),
          verification: {
            keyring: securityKeyring,
            allowedSources: securityAllowedSources,
            allowedKeyIds: securityAllowedKeyIds,
            maxSkewSeconds: parseIntegerEnv(
              process.env['SECURITY_CONTROLS_HISTORY_BUNDLE_MAX_SKEW_SECONDS'],
              300,
              1,
              24 * 60 * 60,
            ),
            replayProtectionEnabled: parseBooleanEnv(
              process.env['SECURITY_CONTROLS_HISTORY_BUNDLE_REPLAY_PROTECTION_ENABLED'],
              false,
            ),
            replayCacheMaxEntries: parseIntegerEnv(
              process.env['SECURITY_CONTROLS_HISTORY_BUNDLE_REPLAY_CACHE_MAX_ENTRIES'],
              50_000,
              1,
              500_000,
            ),
          },
        },
        edgeCache: edgeCacheStore ? {
          store: edgeCacheStore,
          requireSignedImports: parseBooleanEnv(
            process.env['EDGE_CACHE_VERSION_BUNDLE_REQUIRE_SIGNED_IMPORTS'],
            true,
          ),
          verification: {
            keyring: edgeKeyring,
            allowedSources: edgeAllowedSources,
            allowedKeyIds: edgeAllowedKeyIds,
            maxSkewSeconds: parseIntegerEnv(
              process.env['EDGE_CACHE_VERSION_BUNDLE_MAX_SKEW_SECONDS'],
              300,
              1,
              24 * 60 * 60,
            ),
            replayProtectionEnabled: parseBooleanEnv(
              process.env['EDGE_CACHE_VERSION_BUNDLE_REPLAY_PROTECTION_ENABLED'],
              false,
            ),
            replayCacheMaxEntries: parseIntegerEnv(
              process.env['EDGE_CACHE_VERSION_BUNDLE_REPLAY_CACHE_MAX_ENTRIES'],
              50_000,
              1,
              500_000,
            ),
          },
          invalidation: edgeInvalidationEventStore ? {
            eventStore: edgeInvalidationEventStore,
            maxEntries: parseIntegerEnv(
              process.env['EDGE_INVALIDATION_LOG_MAX_ENTRIES'],
              100_000,
              100,
              500_000,
            ),
            localSourceId: String(
              process.env['EDGE_INVALIDATION_BUNDLE_SOURCE_ID'] ?? 'gateway-edge',
            ).trim() || 'gateway-edge',
            requireSignedImports: parseBooleanEnv(
              process.env['EDGE_INVALIDATION_BUNDLE_REQUIRE_SIGNED_IMPORTS'],
              true,
            ),
            verification: {
              keyring: edgeInvalidationKeyring,
              allowedSources: edgeInvalidationAllowedSources,
              allowedKeyIds: edgeInvalidationAllowedKeyIds,
              maxSkewSeconds: parseIntegerEnv(
                process.env['EDGE_INVALIDATION_BUNDLE_MAX_SKEW_SECONDS'],
                300,
                1,
                24 * 60 * 60,
              ),
              replayProtectionEnabled: parseBooleanEnv(
                process.env['EDGE_INVALIDATION_BUNDLE_REPLAY_PROTECTION_ENABLED'],
                false,
              ),
              replayCacheMaxEntries: parseIntegerEnv(
                process.env['EDGE_INVALIDATION_BUNDLE_REPLAY_CACHE_MAX_ENTRIES'],
                50_000,
                1,
                500_000,
              ),
            },
          } : undefined,
        } : undefined,
        controlPlaneAudit: controlPlaneAuditStore ? {
          store: controlPlaneAuditStore,
          maxEntries: parseIntegerEnv(
            process.env['CONTROL_PLANE_AUDIT_MAX_ENTRIES'],
            200_000,
            1000,
            1_000_000,
          ),
          localSourceId: String(
            process.env['CONTROL_PLANE_AUDIT_BUNDLE_SOURCE_ID'] ?? 'gateway-edge',
          ).trim() || 'gateway-edge',
          requireSignedImports: parseBooleanEnv(
            process.env['CONTROL_PLANE_AUDIT_BUNDLE_REQUIRE_SIGNED_IMPORTS'],
            true,
          ),
          verification: {
            keyring: controlPlaneAuditKeyring,
            allowedSources: controlPlaneAuditAllowedSources,
            allowedKeyIds: controlPlaneAuditAllowedKeyIds,
            maxSkewSeconds: parseIntegerEnv(
              process.env['CONTROL_PLANE_AUDIT_BUNDLE_MAX_SKEW_SECONDS'],
              300,
              1,
              24 * 60 * 60,
            ),
            replayProtectionEnabled: parseBooleanEnv(
              process.env['CONTROL_PLANE_AUDIT_BUNDLE_REPLAY_PROTECTION_ENABLED'],
              false,
            ),
            replayCacheMaxEntries: parseIntegerEnv(
              process.env['CONTROL_PLANE_AUDIT_BUNDLE_REPLAY_CACHE_MAX_ENTRIES'],
              50_000,
              1,
              500_000,
            ),
          },
        } : undefined,
        upstreamRouting: {
          manager: upstreamPolicyManager,
          requireSignedImports: parseBooleanEnv(
            process.env['UPSTREAM_ROUTING_POLICY_BUNDLE_REQUIRE_SIGNED_IMPORTS'],
            true,
          ),
          verification: {
            keyring: upstreamRoutingKeyring,
            allowedSources: upstreamRoutingAllowedSources,
            allowedKeyIds: upstreamRoutingAllowedKeyIds,
            maxSkewSeconds: parseIntegerEnv(
              process.env['UPSTREAM_ROUTING_POLICY_BUNDLE_MAX_SKEW_SECONDS'],
              300,
              1,
              24 * 60 * 60,
            ),
            replayProtectionEnabled: parseBooleanEnv(
              process.env['UPSTREAM_ROUTING_POLICY_BUNDLE_REPLAY_PROTECTION_ENABLED'],
              false,
            ),
            replayCacheMaxEntries: parseIntegerEnv(
              process.env['UPSTREAM_ROUTING_POLICY_BUNDLE_REPLAY_CACHE_MAX_ENTRIES'],
              50_000,
              1,
              500_000,
            ),
          },
        },
        routePolicy: {
          manager: routePolicyManager,
          requireSignedImports: parseBooleanEnv(
            process.env['ROUTE_POLICY_BUNDLE_REQUIRE_SIGNED_IMPORTS'],
            true,
          ),
          verification: {
            keyring: routePolicyKeyring,
            allowedSources: routePolicyAllowedSources,
            allowedKeyIds: routePolicyAllowedKeyIds,
            maxSkewSeconds: parseIntegerEnv(
              process.env['ROUTE_POLICY_BUNDLE_MAX_SKEW_SECONDS'],
              300,
              1,
              24 * 60 * 60,
            ),
            replayProtectionEnabled: parseBooleanEnv(
              process.env['ROUTE_POLICY_BUNDLE_REPLAY_PROTECTION_ENABLED'],
              false,
            ),
            replayCacheMaxEntries: parseIntegerEnv(
              process.env['ROUTE_POLICY_BUNDLE_REPLAY_CACHE_MAX_ENTRIES'],
              50_000,
              1,
              500_000,
            ),
          },
        },
        auditTrail: convergenceAuditEnabled && controlPlaneAuditStore && convergenceAuditSigningSecret
          ? {
            store: controlPlaneAuditStore,
            maxEntries: parseIntegerEnv(
              process.env['CONTROL_PLANE_AUDIT_MAX_ENTRIES'],
              200_000,
              1000,
              1_000_000,
            ),
            localSourceId: String(
              process.env['CONTROL_PLANE_AUDIT_BUNDLE_SOURCE_ID'] ?? 'gateway-edge',
            ).trim() || 'gateway-edge',
            actor: convergenceAuditActor,
            signingKeyId: convergenceAuditSigningKeyId,
            signingSecret: convergenceAuditSigningSecret,
            path: convergenceAuditPath,
            permissionScope: convergenceAuditScope,
          }
          : undefined,
      });

      accessLog.info({
        event: 'control_plane_convergence_tick',
        peers: result.peers,
        driftsDetected: result.driftsDetected,
        healedPeers: result.healedPeers,
        errors: result.errors,
      });
    } catch (error) {
      accessLog.error({
        event: 'control_plane_convergence_failed',
        error: error instanceof Error ? error.message : String(error),
      });
    } finally {
      convergenceInFlight = false;
    }
  };

  server.listen(config.server.port, config.server.host, () => {
    accessLog.info({
      event: 'gateway_started',
      port: config.server.port,
      host: config.server.host,
      protocol: config.tls.enabled ? 'https' : 'http',
      pid: process.pid,
      nodeVersion: process.version,
    });

    if (convergenceEnabled && convergencePeers.length > 0) {
      accessLog.info({
        event: 'control_plane_convergence_started',
        peers: convergencePeers,
        intervalMs: convergenceIntervalMs,
        autoHeal: convergenceAutoHeal,
      });
      void runConvergenceTick();
      convergenceTimer = setInterval(() => {
        void runConvergenceTick();
      }, convergenceIntervalMs);
      if (convergenceTimer && typeof convergenceTimer === 'object' && 'unref' in convergenceTimer) {
        convergenceTimer.unref();
      }
    } else if (convergenceEnabled) {
      accessLog.warn({
        event: 'control_plane_convergence_disabled',
        reason: 'no_peers_configured',
      });
    }

    // Mark as ready for traffic after server starts listening
    probeManager.markReady();
  });

  // ── Graceful Shutdown ───────────────────────────────────────────────
  // On SIGTERM/SIGINT:
  // 1. Stop accepting new connections
  // 2. Wait for existing requests to complete (with timeout)
  // 3. Clean up resources
  // 4. Exit
  const SHUTDOWN_TIMEOUT_MS = 30_000; // 30 seconds to drain connections
  let shuttingDown = false;

  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) {
      accessLog.warn({ event: 'shutdown_duplicate', signal, reason: 'Shutdown already in progress' });
      return;
    }
    shuttingDown = true;

    accessLog.info({
      event: 'gateway_shutting_down',
      signal,
      timeout: SHUTDOWN_TIMEOUT_MS,
    });

    // Stop health check from reporting healthy
    // (Load balancers will stop routing traffic)
    app.get(config.healthCheck.path, (_req, res) => {
      res.status(503).json({ status: 'shutting_down' });
    });

    // Stop accepting new connections
    if (convergenceTimer !== null) {
      clearInterval(convergenceTimer);
      convergenceTimer = null;
    }
    server.close((err) => {
      if (err) {
        accessLog.error({
          event: 'gateway_close_error',
          error: err.message,
        });
      }

      accessLog.info({
        event: 'gateway_stopped',
        signal,
      });

      process.exit(0);
    });

    // Stop accepting redirect/health traffic too.
    if (httpRedirectServer) {
      httpRedirectServer.close();
    }
    if (metricsServer) {
      metricsServer.close();
    }

    // Force shutdown after timeout
    const forceShutdownTimer = setTimeout(() => {
      accessLog.error({
        event: 'gateway_force_shutdown',
        reason: `Graceful shutdown timed out after ${SHUTDOWN_TIMEOUT_MS}ms`,
        signal,
      });
      process.exit(1);
    }, SHUTDOWN_TIMEOUT_MS);

    // Don't let the timer prevent the process from exiting if all connections close
    forceShutdownTimer.unref();

    // Close idle connections immediately
    server.closeIdleConnections();
  };

  process.on('SIGTERM', () => { void shutdown('SIGTERM'); });
  process.on('SIGINT', () => { void shutdown('SIGINT'); });

  // ── Unhandled rejection / exception handlers ────────────────────────
  // These should never fire in normal operation, but we log and exit
  // rather than continuing in an unknown state.

  process.on('unhandledRejection', (reason: unknown) => {
    securityLog.error({
      event: 'unhandled_rejection',
      reason: reason instanceof Error ? reason.message : String(reason),
      stack: reason instanceof Error ? reason.stack : undefined,
      severity: 'CRITICAL',
    });

    // In production, exit to let the orchestrator restart us.
    // A process in an unknown state is a security risk.
    if (process.env['NODE_ENV'] === 'production') {
      process.exit(1);
    }
  });

  process.on('uncaughtException', (err: Error) => {
    securityLog.error({
      event: 'uncaught_exception',
      error: err.message,
      stack: err.stack,
      severity: 'CRITICAL',
    });

    // Always exit on uncaught exception — the process state is unreliable.
    process.exit(1);
  });
}

// ── Start ─────────────────────────────────────────────────────────────────────
main().catch((err: Error) => {
  console.error('Gateway failed to start:', err.message);
  console.error(err.stack);
  process.exit(1);
});
