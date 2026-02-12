import { createHash } from 'crypto';
import * as http from 'http';
import * as https from 'https';
import * as fs from 'fs';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { computeInternalAuthHeaders, globalMetrics } from '@zerotrust/shared';
import type { GatewayConfig, RouteConfig } from '../../config/default';
import { getRouteConfig } from '../../config/default';
import type { CachedHttpResponse, EdgeCacheEntry, EdgeCacheStore } from '../state/edge-cache-store';
import { createSecurityLogger } from './request-logger';

interface EffectiveEdgeCachePolicy {
  enabled: boolean;
  ttlSeconds: number;
  staleWhileRevalidateSeconds: number;
  staleIfErrorSeconds: number;
  varyHeaders: string[];
  includeQueryString: boolean;
  ignoreQueryParams: Set<string>;
  cacheAuthenticated: boolean;
  maxBodyBytes: number;
  statusCodes: Set<number>;
  respectOriginCacheControl: boolean;
  cacheTagHeader: string;
  maxTagsPerEntry: number;
  maxTagLength: number;
  requestCoalescingEnabled: boolean;
  requestCoalescingWaitMs: number;
}

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'trailers',
  'transfer-encoding',
  'upgrade',
]);

const NON_CACHEABLE_HEADERS = new Set([
  'set-cookie',
  'x-correlation-id',
  'x-zt-edge-cache',
]);

function recordEdgeCacheMetric(
  metric:
    | 'edge_cache_hits_total'
    | 'edge_cache_stale_hits_total'
    | 'edge_cache_stale_if_error_total'
    | 'edge_cache_misses_total'
    | 'edge_cache_bypass_total'
    | 'edge_cache_store_errors_total'
    | 'edge_cache_revalidations_total'
    | 'edge_cache_revalidation_errors_total'
    | 'edge_cache_collapsed_requests_total',
  labels: Record<string, string>,
): void {
  try {
    globalMetrics.recordCounter(metric, 1, {
      service: 'gateway',
      ...labels,
    });
  } catch {
    // Metrics must never affect request handling.
  }
}

function normalizeHeaderName(value: string): string {
  return value.trim().toLowerCase();
}

function getHeaderValue(value: string | string[] | number | undefined | null): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number') return String(value);
  if (Array.isArray(value)) return value.join(', ');
  return '';
}

function normalizeCacheTags(
  rawValue: string | string[] | number | undefined | null,
  maxTags: number,
  maxTagLength: number,
): string[] {
  const raw = getHeaderValue(rawValue);
  if (!raw) return [];

  const unique = new Set<string>();
  const segments = raw
    .split(',')
    .map((segment) => segment.trim().toLowerCase())
    .filter(Boolean);

  for (const tag of segments) {
    if (tag.length > maxTagLength) continue;
    if (!/^[a-z0-9:_./-]+$/.test(tag)) continue;
    unique.add(tag);
    if (unique.size >= maxTags) break;
  }

  return [...unique];
}

function normalizeStatusCodes(codes: number[]): Set<number> {
  const set = new Set<number>();
  for (const code of codes) {
    if (Number.isInteger(code) && code >= 100 && code <= 599) {
      set.add(code);
    }
  }
  return set.size > 0 ? set : new Set<number>([200]);
}

function resolvePolicy(config: GatewayConfig, routeConfig: RouteConfig): EffectiveEdgeCachePolicy {
  if (!config.edgeCache.enabled) {
    return {
      enabled: false,
      ttlSeconds: config.edgeCache.defaultTtlSeconds,
      staleWhileRevalidateSeconds: config.edgeCache.staleWhileRevalidateSeconds,
      staleIfErrorSeconds: config.edgeCache.staleIfErrorSeconds,
      varyHeaders: config.edgeCache.varyHeaders,
      includeQueryString: config.edgeCache.includeQueryString,
      ignoreQueryParams: new Set(config.edgeCache.ignoreQueryParams.map((v) => normalizeHeaderName(v))),
      cacheAuthenticated: config.edgeCache.cacheAuthenticated,
      maxBodyBytes: config.edgeCache.maxBodyBytes,
      statusCodes: normalizeStatusCodes(config.edgeCache.statusCodes),
      respectOriginCacheControl: config.edgeCache.respectOriginCacheControl,
      cacheTagHeader: normalizeHeaderName(config.edgeCache.cacheTagHeader),
      maxTagsPerEntry: config.edgeCache.maxTagsPerEntry,
      maxTagLength: config.edgeCache.maxTagLength,
      requestCoalescingEnabled: config.edgeCache.requestCoalescingEnabled,
      requestCoalescingWaitMs: config.edgeCache.requestCoalescingWaitMs,
    };
  }

  const routeCache = routeConfig.edgeCache;
  if (!routeCache?.enabled) {
    return {
      enabled: false,
      ttlSeconds: config.edgeCache.defaultTtlSeconds,
      staleWhileRevalidateSeconds: config.edgeCache.staleWhileRevalidateSeconds,
      staleIfErrorSeconds: config.edgeCache.staleIfErrorSeconds,
      varyHeaders: config.edgeCache.varyHeaders,
      includeQueryString: config.edgeCache.includeQueryString,
      ignoreQueryParams: new Set(config.edgeCache.ignoreQueryParams.map((v) => normalizeHeaderName(v))),
      cacheAuthenticated: config.edgeCache.cacheAuthenticated,
      maxBodyBytes: config.edgeCache.maxBodyBytes,
      statusCodes: normalizeStatusCodes(config.edgeCache.statusCodes),
      respectOriginCacheControl: config.edgeCache.respectOriginCacheControl,
      cacheTagHeader: normalizeHeaderName(config.edgeCache.cacheTagHeader),
      maxTagsPerEntry: config.edgeCache.maxTagsPerEntry,
      maxTagLength: config.edgeCache.maxTagLength,
      requestCoalescingEnabled: config.edgeCache.requestCoalescingEnabled,
      requestCoalescingWaitMs: config.edgeCache.requestCoalescingWaitMs,
    };
  }

  const varyHeaders = (routeCache.varyHeaders && routeCache.varyHeaders.length > 0)
    ? routeCache.varyHeaders
    : config.edgeCache.varyHeaders;

  const ignoreQueryParams = (routeCache.ignoreQueryParams && routeCache.ignoreQueryParams.length > 0)
    ? routeCache.ignoreQueryParams
    : config.edgeCache.ignoreQueryParams;

  return {
    enabled: true,
    ttlSeconds: routeCache.ttlSeconds ?? config.edgeCache.defaultTtlSeconds,
    staleWhileRevalidateSeconds: routeCache.staleWhileRevalidateSeconds ?? config.edgeCache.staleWhileRevalidateSeconds,
    staleIfErrorSeconds: routeCache.staleIfErrorSeconds ?? config.edgeCache.staleIfErrorSeconds,
    varyHeaders,
    includeQueryString: routeCache.includeQueryString ?? config.edgeCache.includeQueryString,
    ignoreQueryParams: new Set(ignoreQueryParams.map((v) => normalizeHeaderName(v))),
    cacheAuthenticated: routeCache.cacheAuthenticated ?? config.edgeCache.cacheAuthenticated,
    maxBodyBytes: routeCache.maxBodyBytes ?? config.edgeCache.maxBodyBytes,
    statusCodes: normalizeStatusCodes(routeCache.statusCodes ?? config.edgeCache.statusCodes),
    respectOriginCacheControl: routeCache.respectOriginCacheControl ?? config.edgeCache.respectOriginCacheControl,
    cacheTagHeader: normalizeHeaderName(config.edgeCache.cacheTagHeader),
    maxTagsPerEntry: config.edgeCache.maxTagsPerEntry,
    maxTagLength: config.edgeCache.maxTagLength,
    requestCoalescingEnabled: config.edgeCache.requestCoalescingEnabled,
    requestCoalescingWaitMs: config.edgeCache.requestCoalescingWaitMs,
  };
}

function getHeaderValueForKey(value: string | string[] | undefined): string {
  if (Array.isArray(value)) return value.join(',');
  if (typeof value === 'string') return value;
  return '';
}

function normalizeQueryString(
  req: Request,
  includeQuery: boolean,
  ignoredParams: Set<string>,
): string {
  if (!includeQuery) return '';

  const rawQuery = req.originalUrl?.split('?')[1];
  if (!rawQuery) return '';

  const params = new URLSearchParams(rawQuery);
  const pairs: Array<[string, string]> = [];
  for (const [key, value] of params.entries()) {
    if (ignoredParams.has(normalizeHeaderName(key))) continue;
    pairs.push([key, value]);
  }

  pairs.sort((a, b) => {
    const byKey = a[0].localeCompare(b[0]);
    if (byKey !== 0) return byKey;
    return a[1].localeCompare(b[1]);
  });

  return pairs.map(([key, value]) => `${key}=${value}`).join('&');
}

function buildVaryHeaderKey(req: Request, varyHeaders: string[]): Record<string, string> {
  const vary: Record<string, string> = {};
  for (const header of varyHeaders) {
    const normalized = normalizeHeaderName(header);
    const value = req.headers[normalized];
    vary[normalized] = getHeaderValueForKey(value as string | string[] | undefined);
  }
  return vary;
}

function requestHasNoCacheDirective(req: Request): boolean {
  const cacheControl = String(req.headers['cache-control'] ?? '').toLowerCase();
  const pragma = String(req.headers['pragma'] ?? '').toLowerCase();
  return (
    cacheControl.includes('no-store') ||
    cacheControl.includes('no-cache') ||
    cacheControl.includes('max-age=0') ||
    pragma.includes('no-cache')
  );
}

function toHeaderRecord(res: Response): Record<string, string> {
  const headers: Record<string, string> = {};
  const rawHeaders = res.getHeaders();

  for (const [name, value] of Object.entries(rawHeaders)) {
    const normalized = normalizeHeaderName(name);
    if (HOP_BY_HOP_HEADERS.has(normalized) || NON_CACHEABLE_HEADERS.has(normalized)) {
      continue;
    }

    if (typeof value === 'string') {
      headers[normalized] = value;
      continue;
    }
    if (typeof value === 'number') {
      headers[normalized] = String(value);
      continue;
    }
    if (Array.isArray(value)) {
      headers[normalized] = value.map((v) => String(v)).join(', ');
      continue;
    }
    if (value !== undefined && value !== null) {
      headers[normalized] = String(value);
    }
  }

  delete headers['content-length'];
  return headers;
}

function toBuffer(
  chunk: unknown,
  encoding?: BufferEncoding | (() => void),
): Buffer | null {
  if (chunk === undefined || chunk === null) return null;
  if (Buffer.isBuffer(chunk)) return chunk;
  if (chunk instanceof Uint8Array) return Buffer.from(chunk);
  if (typeof chunk === 'string') {
    const enc: BufferEncoding = typeof encoding === 'string' ? encoding : 'utf8';
    return Buffer.from(chunk, enc);
  }
  return Buffer.from(String(chunk));
}

function responseHasSetCookie(res: Response): boolean {
  const value = res.getHeader('set-cookie');
  if (!value) return false;
  if (Array.isArray(value)) return value.length > 0;
  return String(value).trim().length > 0;
}

function responseCacheControlDisallowsStorage(res: Response): boolean {
  const cacheControl = String(res.getHeader('cache-control') ?? '').toLowerCase();
  if (!cacheControl) return false;
  return cacheControl.includes('no-store') || cacheControl.includes('private');
}

function responseCacheControlDisallowsStorageHeader(cacheControlRaw: string | undefined): boolean {
  const cacheControl = String(cacheControlRaw ?? '').toLowerCase();
  if (!cacheControl) return false;
  return cacheControl.includes('no-store') || cacheControl.includes('private');
}

function isCacheEntryStale(entry: EdgeCacheEntry, nowMs: number): boolean {
  return entry.expiresAtMs <= nowMs;
}

function isWithinStaleWhileRevalidateWindow(entry: EdgeCacheEntry, nowMs: number): boolean {
  return (entry.staleUntilMs ?? 0) > nowMs;
}

function isWithinStaleIfErrorWindow(entry: EdgeCacheEntry, nowMs: number): boolean {
  return (entry.staleIfErrorUntilMs ?? 0) > nowMs;
}

function toIncomingHeaderRecord(headers: http.IncomingHttpHeaders): Record<string, string> {
  const record: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    const normalized = normalizeHeaderName(name);
    if (HOP_BY_HOP_HEADERS.has(normalized) || NON_CACHEABLE_HEADERS.has(normalized)) {
      continue;
    }
    if (typeof value === 'string') {
      record[normalized] = value;
      continue;
    }
    if (Array.isArray(value)) {
      record[normalized] = value.join(', ');
      continue;
    }
    if (value !== undefined && value !== null) {
      record[normalized] = String(value);
    }
  }
  delete record['content-length'];
  return record;
}

function readIncomingHeaderValue(
  headers: http.IncomingHttpHeaders,
  headerName: string,
): string | undefined {
  const normalized = normalizeHeaderName(headerName);
  const value = headers[normalized];
  const raw = getHeaderValue(value as string | string[] | number | undefined | null);
  return raw || undefined;
}

function extractIncomingCacheTags(
  headers: http.IncomingHttpHeaders,
  policy: Pick<EffectiveEdgeCachePolicy, 'cacheTagHeader' | 'maxTagsPerEntry' | 'maxTagLength'>,
): string[] {
  const raw = readIncomingHeaderValue(headers, policy.cacheTagHeader);
  return normalizeCacheTags(raw, policy.maxTagsPerEntry, policy.maxTagLength);
}

function extractResponseCacheTags(
  res: Response,
  policy: Pick<EffectiveEdgeCachePolicy, 'cacheTagHeader' | 'maxTagsPerEntry' | 'maxTagLength'>,
): string[] {
  const value = res.getHeader(policy.cacheTagHeader);
  return normalizeCacheTags(
    value as string | string[] | number | undefined | null,
    policy.maxTagsPerEntry,
    policy.maxTagLength,
  );
}

const edgeRefreshAgentCache = new Map<string, https.Agent>();

function getEdgeRefreshAgent(upstream: GatewayConfig['upstreams'][string]): https.Agent | undefined {
  if (!upstream.mtls?.enabled) return undefined;

  const cacheKey = `${upstream.name}:${upstream.mtls.certPath}:${upstream.mtls.keyPath}:${upstream.mtls.caPath}:${upstream.mtls.rejectUnauthorized}`;
  let agent = edgeRefreshAgentCache.get(cacheKey);
  if (agent) return agent;

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
  edgeRefreshAgentCache.set(cacheKey, agent);
  return agent;
}

const revalidationInFlight = new Map<string, number>();
const cachePopulationInFlight = new Map<string, { promise: Promise<void>; resolve: () => void; expiresAtMs: number }>();

function createWaitPromise(waitMs: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, Math.max(1, waitMs));
    if (typeof timer === 'object' && 'unref' in timer) {
      timer.unref();
    }
  });
}

async function refreshStaleEntryInBackground(
  req: Request,
  routeConfig: RouteConfig,
  policy: EffectiveEdgeCachePolicy,
  config: GatewayConfig,
  store: EdgeCacheStore,
  cacheKey: string,
): Promise<void> {
  const now = Date.now();
  const existing = revalidationInFlight.get(cacheKey);
  if (existing && existing > now) return;
  revalidationInFlight.set(cacheKey, now + 15_000);

  try {
    const refreshed = await refreshEntryFromOrigin(
      req,
      routeConfig,
      policy,
      config,
      store,
      cacheKey,
    );
    if (refreshed) {
      recordEdgeCacheMetric('edge_cache_revalidations_total', { route: routeConfig.path });
    } else {
      recordEdgeCacheMetric('edge_cache_revalidation_errors_total', { route: routeConfig.path });
    }
  } catch {
    recordEdgeCacheMetric('edge_cache_revalidation_errors_total', { route: routeConfig.path });
  } finally {
    revalidationInFlight.delete(cacheKey);
  }
}

async function refreshEntryFromOrigin(
  req: Request,
  routeConfig: RouteConfig,
  policy: EffectiveEdgeCachePolicy,
  config: GatewayConfig,
  store: EdgeCacheStore,
  cacheKey: string,
): Promise<boolean> {
  const upstream = config.upstreams[routeConfig.upstream];
  if (!upstream) return false;

  const target = new URL(req.originalUrl || req.url || req.path, upstream.url);
  const isHttps = target.protocol === 'https:';

  const headers: Record<string, string> = {};
  for (const headerName of policy.varyHeaders) {
    const normalized = normalizeHeaderName(headerName);
    const value = req.headers[normalized];
    if (typeof value === 'string' && value.length > 0) {
      headers[normalized] = value;
    } else if (Array.isArray(value) && value.length > 0) {
      headers[normalized] = value.join(', ');
    }
  }
  headers['x-request-id'] = (req.headers['x-correlation-id'] as string) || 'edge-cache-revalidate';
  headers['x-internal-request'] = 'true';

  if (config.internalAuth.enabled) {
    const internalHeaders = computeInternalAuthHeaders(
      { method: 'GET', path: `${target.pathname}${target.search}` },
      config.internalAuth.callerSecret || config.internalAuth.secret || '',
      undefined,
      undefined,
      config.internalAuth.callerId,
      upstream.name,
      config.internalAuth.callerKeyId,
    );
    Object.assign(headers, internalHeaders);
  }

  const requestOptions: https.RequestOptions = {
    protocol: target.protocol,
    hostname: target.hostname,
    port: target.port || (isHttps ? 443 : 80),
    method: 'GET',
    path: `${target.pathname}${target.search}`,
    headers,
    timeout: upstream.timeoutMs,
    rejectUnauthorized: upstream.mtls?.rejectUnauthorized !== false,
    agent: isHttps ? getEdgeRefreshAgent(upstream) : undefined,
  };

  try {
    return await new Promise<boolean>((resolve, reject) => {
      const client = (isHttps ? https : http).request(requestOptions, (upRes) => {
        if (!policy.statusCodes.has(upRes.statusCode || 0)) {
          upRes.resume();
          return resolve(false);
        }

        if (policy.respectOriginCacheControl && responseCacheControlDisallowsStorageHeader(upRes.headers['cache-control'])) {
          upRes.resume();
          return resolve(false);
        }

        if (upRes.headers['set-cookie']) {
          upRes.resume();
          return resolve(false);
        }

        const chunks: Buffer[] = [];
        let size = 0;
        upRes.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size <= policy.maxBodyBytes) {
            chunks.push(chunk);
          }
        });
        upRes.on('end', () => {
          if (size > policy.maxBodyBytes) {
            return resolve(false);
          }
          const createdAtMs = Date.now();
          const response: CachedHttpResponse = {
            statusCode: upRes.statusCode || 200,
            headers: toIncomingHeaderRecord(upRes.headers),
            bodyBase64: Buffer.concat(chunks).toString('base64'),
            createdAtMs,
            expiresAtMs: createdAtMs + policy.ttlSeconds * 1000,
            staleUntilMs:
              policy.staleWhileRevalidateSeconds > 0
                ? createdAtMs + (policy.ttlSeconds + policy.staleWhileRevalidateSeconds) * 1000
                : undefined,
            staleIfErrorUntilMs:
              policy.staleIfErrorSeconds > 0
                ? createdAtMs + (policy.ttlSeconds + policy.staleIfErrorSeconds) * 1000
                : undefined,
            tags: extractIncomingCacheTags(upRes.headers, policy),
          };

          void store.set(cacheKey, routeConfig.path, policy.ttlSeconds, response)
            .then(() => resolve(true))
            .catch(reject);
        });
      });

      client.on('error', reject);
      client.on('timeout', () => {
        client.destroy(new Error('edge_cache_revalidate_timeout'));
      });
      client.end();
    });
  } catch {
    return false;
  }
}

export function buildEdgeCacheKey(
  req: Request,
  routePath: string,
  policy: Pick<EffectiveEdgeCachePolicy, 'includeQueryString' | 'ignoreQueryParams' | 'varyHeaders' | 'cacheAuthenticated'>,
  routeVersion: string = '0',
): string {
  const varyKey = buildVaryHeaderKey(req, policy.varyHeaders);
  const queryKey = normalizeQueryString(req, policy.includeQueryString, policy.ignoreQueryParams);

  const identityKey = policy.cacheAuthenticated
    ? (req.identity?.sub ?? 'anonymous')
    : 'anonymous';

  const normalizedVersion = routeVersion && routeVersion.trim().length > 0
    ? routeVersion.trim()
    : '0';

  const fingerprint = JSON.stringify({
    method: req.method.toUpperCase(),
    path: req.path,
    query: queryKey,
    vary: varyKey,
    identity: identityKey,
    version: normalizedVersion,
  });

  const digest = createHash('sha256').update(fingerprint).digest('hex');
  const routeTag = Buffer.from(routePath, 'utf8').toString('base64url');
  const versionTag = Buffer.from(normalizedVersion, 'utf8').toString('base64url');
  return `v2|${routeTag}|${versionTag}|${digest}`;
}

function writeCachedResponse(
  req: Request,
  res: Response,
  entry: EdgeCacheEntry,
  mode: 'HIT' | 'STALE' | 'STALE_IF_ERROR',
): void {
  for (const [name, value] of Object.entries(entry.headers)) {
    res.setHeader(name, value);
  }

  const ageSeconds = Math.max(0, Math.floor((Date.now() - entry.createdAtMs) / 1000));
  res.setHeader('age', String(ageSeconds));
  res.setHeader('x-zt-edge-cache', mode === 'STALE_IF_ERROR' ? 'STALE-IF-ERROR' : mode);

  const body = Buffer.from(entry.bodyBase64, 'base64');
  res.status(entry.statusCode);
  res.setHeader('content-length', String(body.length));

  if (req.method.toUpperCase() === 'HEAD') {
    res.end();
    return;
  }
  res.end(body);
}

export function createEdgeCacheMiddleware(
  config: GatewayConfig,
  deps: { store?: EdgeCacheStore },
): RequestHandler {
  const store = deps.store;
  if (!config.edgeCache.enabled || !store) {
    return (_req: Request, _res: Response, next: NextFunction): void => next();
  }

  const securityLog = createSecurityLogger(config);

  return (req: Request, res: Response, next: NextFunction): void => {
    void (async () => {
      let releasedPopulationLock = false;
      let populationLock:
        | { promise: Promise<void>; resolve: () => void; expiresAtMs: number }
        | null = null;
      let ownsPopulationLock = false;
      let cacheKeyForPopulationLock: string | null = null;
      const releasePopulationLock = (): void => {
        if (releasedPopulationLock) return;
        releasedPopulationLock = true;
        if (!ownsPopulationLock) return;
        if (!populationLock || !cacheKeyForPopulationLock) return;
        if (cachePopulationInFlight.get(cacheKeyForPopulationLock) === populationLock) {
          cachePopulationInFlight.delete(cacheKeyForPopulationLock);
        }
        populationLock.resolve();
      };

      try {
        if (req.path.startsWith('/internal/')) {
          return next();
        }

        if (req.method.toUpperCase() !== 'GET') {
          return next();
        }

        const routeConfig = getRouteConfig(config, req.path, req.method);
        if (!routeConfig) {
          return next();
        }

        const policy = resolvePolicy(config, routeConfig);
        if (!policy.enabled) {
          recordEdgeCacheMetric('edge_cache_bypass_total', { reason: 'route_disabled', route: routeConfig.path });
          return next();
        }

        if (requestHasNoCacheDirective(req)) {
          recordEdgeCacheMetric('edge_cache_bypass_total', { reason: 'request_no_cache', route: routeConfig.path });
          return next();
        }

        if (!policy.cacheAuthenticated && routeConfig.authRequired !== false) {
          recordEdgeCacheMetric('edge_cache_bypass_total', { reason: 'auth_route', route: routeConfig.path });
          return next();
        }

        if (!policy.cacheAuthenticated && req.identity) {
          recordEdgeCacheMetric('edge_cache_bypass_total', { reason: 'authenticated', route: routeConfig.path });
          return next();
        }

        let routeVersion = '0';
        try {
          routeVersion = await store.getRouteVersion(routeConfig.path);
        } catch (err) {
          securityLog.error({
            event: 'edge_cache_route_version_read_error',
            route: routeConfig.path,
            path: req.path,
            method: req.method,
            error: err instanceof Error ? err.message : String(err),
            correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
          });
        }

        const cacheKey = buildEdgeCacheKey(req, routeConfig.path, policy, routeVersion);
        cacheKeyForPopulationLock = cacheKey;
        let cacheMissRecorded = false;

        const cached = await store.get(cacheKey);
        if (cached) {
          const nowMs = Date.now();
          const stale = isCacheEntryStale(cached, nowMs);
          if (!stale) {
            recordEdgeCacheMetric('edge_cache_hits_total', { route: routeConfig.path });
            writeCachedResponse(req, res, cached, 'HIT');
            return;
          }

          if (
            policy.staleWhileRevalidateSeconds > 0 &&
            routeConfig.authRequired === false &&
            isWithinStaleWhileRevalidateWindow(cached, nowMs)
          ) {
            recordEdgeCacheMetric('edge_cache_stale_hits_total', { route: routeConfig.path });
            writeCachedResponse(req, res, cached, 'STALE');
            void refreshStaleEntryInBackground(req, routeConfig, policy, config, store, cacheKey);
            return;
          }

          if (policy.staleIfErrorSeconds > 0 && isWithinStaleIfErrorWindow(cached, nowMs)) {
            const refreshed = await refreshEntryFromOrigin(
              req,
              routeConfig,
              policy,
              config,
              store,
              cacheKey,
            );
            if (refreshed) {
              const updated = await store.get(cacheKey);
              if (updated && !isCacheEntryStale(updated, Date.now())) {
                recordEdgeCacheMetric('edge_cache_revalidations_total', { route: routeConfig.path });
                recordEdgeCacheMetric('edge_cache_hits_total', { route: routeConfig.path });
                writeCachedResponse(req, res, updated, 'HIT');
                return;
              }
            }

            recordEdgeCacheMetric('edge_cache_stale_if_error_total', { route: routeConfig.path });
            writeCachedResponse(req, res, cached, 'STALE_IF_ERROR');
            return;
          }

          // Entry is stale and outside fallback windows.
          await store.delete(cacheKey);
        }

        if (policy.requestCoalescingEnabled) {
          const inFlight = cachePopulationInFlight.get(cacheKey);
          if (inFlight && inFlight.expiresAtMs > Date.now()) {
            await Promise.race([
              inFlight.promise,
              createWaitPromise(policy.requestCoalescingWaitMs),
            ]);

            const collapsed = await store.get(cacheKey);
            if (collapsed) {
              const nowMs = Date.now();
              const stale = isCacheEntryStale(collapsed, nowMs);
              if (!stale) {
                recordEdgeCacheMetric('edge_cache_collapsed_requests_total', { route: routeConfig.path, mode: 'hit' });
                recordEdgeCacheMetric('edge_cache_hits_total', { route: routeConfig.path });
                writeCachedResponse(req, res, collapsed, 'HIT');
                return;
              }
              if (
                policy.staleWhileRevalidateSeconds > 0 &&
                routeConfig.authRequired === false &&
                isWithinStaleWhileRevalidateWindow(collapsed, nowMs)
              ) {
                recordEdgeCacheMetric('edge_cache_collapsed_requests_total', { route: routeConfig.path, mode: 'stale' });
                recordEdgeCacheMetric('edge_cache_stale_hits_total', { route: routeConfig.path });
                writeCachedResponse(req, res, collapsed, 'STALE');
                return;
              }
              if (policy.staleIfErrorSeconds > 0 && isWithinStaleIfErrorWindow(collapsed, nowMs)) {
                recordEdgeCacheMetric('edge_cache_collapsed_requests_total', { route: routeConfig.path, mode: 'stale_if_error' });
                recordEdgeCacheMetric('edge_cache_stale_if_error_total', { route: routeConfig.path });
                writeCachedResponse(req, res, collapsed, 'STALE_IF_ERROR');
                return;
              }
            }
          }
        }

        if (!cacheMissRecorded) {
          recordEdgeCacheMetric('edge_cache_misses_total', { route: routeConfig.path });
          res.setHeader('x-zt-edge-cache', 'MISS');
        }

        if (policy.requestCoalescingEnabled) {
          const existingInFlight = cachePopulationInFlight.get(cacheKey);
          if (!existingInFlight || existingInFlight.expiresAtMs <= Date.now()) {
            let resolveLock: (() => void) | null = null;
            const promise = new Promise<void>((resolve) => {
              resolveLock = resolve;
            });
            populationLock = {
              promise,
              resolve: resolveLock || (() => undefined),
              expiresAtMs: Date.now() + Math.max(
                policy.requestCoalescingWaitMs * 4,
                routeConfig.timeoutMs || 30_000,
              ),
            };
            cachePopulationInFlight.set(cacheKey, populationLock);
            ownsPopulationLock = true;
          }
        }

        const chunks: Buffer[] = [];
        let bytes = 0;
        let captureTruncated = false;
        let pendingEndChunk: Buffer | null = null;

        const captureChunk = (buf: Buffer | null): void => {
          if (!buf) return;
          bytes += buf.length;
          if (bytes <= policy.maxBodyBytes) {
            chunks.push(buf);
          } else {
            captureTruncated = true;
          }
        };

        const originalWrite = res.write.bind(res);
        const originalEnd = res.end.bind(res);

        res.write = ((chunk: unknown, encoding?: BufferEncoding | (() => void), cb?: () => void): boolean => {
          const buf = toBuffer(chunk, encoding);
          if (buf && pendingEndChunk && buf.length === pendingEndChunk.length && buf.equals(pendingEndChunk)) {
            // Some Response implementations internally route end(chunk) through write(chunk).
            // Skip one duplicate capture in that case.
            pendingEndChunk = null;
          } else {
            captureChunk(buf);
          }

          if (typeof encoding === 'function') {
            return originalWrite(chunk as never, encoding as never);
          }
          return originalWrite(chunk as never, encoding as never, cb as never);
        }) as typeof res.write;

        res.end = ((chunk?: unknown, encoding?: BufferEncoding | (() => void), cb?: () => void): Response => {
          const buf = toBuffer(chunk, encoding);
          captureChunk(buf);
          pendingEndChunk = buf;

          if (typeof encoding === 'function') {
            return originalEnd(chunk as never, encoding as never);
          }
          return originalEnd(chunk as never, encoding as never, cb as never);
        }) as typeof res.end;

        res.once('finish', () => {
          void (async () => {
            try {
              if (!policy.statusCodes.has(res.statusCode)) {
                return;
              }

              if (captureTruncated || bytes > policy.maxBodyBytes) {
                recordEdgeCacheMetric('edge_cache_bypass_total', {
                  reason: 'body_too_large',
                  route: routeConfig.path,
                });
                return;
              }

              if (responseHasSetCookie(res)) {
                recordEdgeCacheMetric('edge_cache_bypass_total', { reason: 'set_cookie', route: routeConfig.path });
                return;
              }

              if (policy.respectOriginCacheControl && responseCacheControlDisallowsStorage(res)) {
                recordEdgeCacheMetric('edge_cache_bypass_total', {
                  reason: 'origin_cache_control',
                  route: routeConfig.path,
                });
                return;
              }

              const createdAtMs = Date.now();
              const response: CachedHttpResponse = {
                statusCode: res.statusCode,
                headers: toHeaderRecord(res),
                bodyBase64: Buffer.concat(chunks).toString('base64'),
                createdAtMs,
                expiresAtMs: createdAtMs + policy.ttlSeconds * 1000,
                staleUntilMs:
                  policy.staleWhileRevalidateSeconds > 0
                    ? createdAtMs + (policy.ttlSeconds + policy.staleWhileRevalidateSeconds) * 1000
                    : undefined,
                staleIfErrorUntilMs:
                  policy.staleIfErrorSeconds > 0
                    ? createdAtMs + (policy.ttlSeconds + policy.staleIfErrorSeconds) * 1000
                    : undefined,
                tags: extractResponseCacheTags(res, policy),
              };

              await store.set(cacheKey, routeConfig.path, policy.ttlSeconds, response);
            } catch (err) {
              recordEdgeCacheMetric('edge_cache_store_errors_total', { route: routeConfig.path });
              securityLog.error({
                event: 'edge_cache_store_error',
                route: routeConfig.path,
                path: req.path,
                method: req.method,
                error: err instanceof Error ? err.message : String(err),
                correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
              });
            } finally {
              releasePopulationLock();
            }
          })();
        });

        res.once('close', () => {
          releasePopulationLock();
        });

        next();
      } catch (err) {
        releasePopulationLock();
        recordEdgeCacheMetric('edge_cache_store_errors_total', { route: 'unknown' });
        securityLog.error({
          event: 'edge_cache_error',
          path: req.path,
          method: req.method,
          error: err instanceof Error ? err.message : String(err),
          correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
        });
        next();
      }
    })();
  };
}
