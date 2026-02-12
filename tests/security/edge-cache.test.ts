import { EventEmitter } from 'events';
import type { Request, Response } from 'express';
import { GatewayConfigSchema } from '../../gateway/config/default';
import {
  applyEdgeCachePurge,
  bumpEdgeCacheRouteVersion,
  getEdgeCacheRouteVersion,
} from '../../gateway/src/internal/internal-routes';
import { buildEdgeCacheKey, createEdgeCacheMiddleware } from '../../gateway/src/middleware/edge-cache';
import { InMemoryEdgeCacheStore } from '../../gateway/src/state/inmemory-edge-cache-store';
import type { CachedHttpResponse } from '../../gateway/src/state/edge-cache-store';
import type { GatewayIdentity } from '../../gateway/src/middleware/jwt-validation';
import { createNext } from '../test-utils/mock-express';

class MockEdgeResponse extends EventEmitter {
  public statusCode = 200;
  public headers: Record<string, string> = {};
  public body = Buffer.alloc(0);

  public setHeader(name: string, value: unknown): void {
    const normalized = name.toLowerCase();
    if (Array.isArray(value)) {
      this.headers[normalized] = value.map((v) => String(v)).join(', ');
      return;
    }
    this.headers[normalized] = String(value);
  }

  public getHeader(name: string): string | undefined {
    return this.headers[name.toLowerCase()];
  }

  public getHeaders(): Record<string, string> {
    return { ...this.headers };
  }

  public status(code: number): this {
    this.statusCode = code;
    return this;
  }

  public write(chunk: unknown, encoding?: BufferEncoding): boolean {
    const buf = Buffer.isBuffer(chunk)
      ? chunk
      : Buffer.from(String(chunk), encoding ?? 'utf8');
    this.body = Buffer.concat([this.body, buf]);
    return true;
  }

  public end(chunk?: unknown, encoding?: BufferEncoding): this {
    if (chunk !== undefined) {
      this.write(chunk, encoding);
    }
    this.emit('finish');
    return this;
  }
}

function buildConfig(routeAuthRequired: boolean) {
  return GatewayConfigSchema.parse({
    jwt: {
      jwksUri: 'https://example.invalid/jwks.json',
      issuer: 'issuer',
      audience: 'aud',
    },
    pdp: {
      url: 'https://example.invalid',
    },
    edgeCache: {
      enabled: true,
      defaultTtlSeconds: 30,
      staleIfErrorSeconds: 120,
      varyHeaders: ['accept', 'accept-encoding'],
      includeQueryString: true,
      ignoreQueryParams: ['_'],
      cacheAuthenticated: false,
      maxBodyBytes: 1024,
      statusCodes: [200],
      respectOriginCacheControl: false,
      cacheTagHeader: 'cache-tag',
      maxTagsPerEntry: 64,
      maxTagLength: 64,
      requestCoalescingEnabled: true,
      requestCoalescingWaitMs: 1000,
      memoryMaxEntries: 5000,
    },
    routes: [
      {
        path: '/public',
        upstream: 'identity',
        methods: ['GET'],
        authRequired: routeAuthRequired,
        edgeCache: {
          enabled: true,
          ttlSeconds: 60,
        },
      },
    ],
    upstreams: {
      identity: {
        name: 'identity',
        url: 'https://identity.example.invalid',
        timeoutMs: 25,
      },
    },
  });
}

function buildRequest(overrides: Partial<Request> = {}): Request {
  const req: Partial<Request> = {
    method: 'GET',
    path: '/public',
    url: '/public?foo=bar',
    originalUrl: '/public?foo=bar',
    headers: {
      accept: 'application/json',
      'accept-encoding': 'gzip',
    },
    query: { foo: 'bar' },
    socket: { remoteAddress: '203.0.113.10' } as unknown as Request['socket'],
    ...overrides,
  };
  return req as Request;
}

function cachedResponse(body: string): CachedHttpResponse {
  const now = Date.now();
  return {
    statusCode: 200,
    headers: {
      'content-type': 'application/json',
    },
    bodyBase64: Buffer.from(body, 'utf8').toString('base64'),
    createdAtMs: now,
    expiresAtMs: now + 60_000,
  };
}

describe('Edge Cache Middleware', () => {
  test('stores a miss response and serves a subsequent hit', async () => {
    const store = new InMemoryEdgeCacheStore(1000);
    const mw = createEdgeCacheMiddleware(buildConfig(false), { store });

    const req1 = buildRequest();
    const res1 = new MockEdgeResponse();
    const next1 = createNext();

    await mw(req1, res1 as unknown as Response, next1);
    await new Promise((resolve) => setImmediate(resolve));
    expect(next1).toHaveBeenCalledTimes(1);
    expect(res1.getHeader('x-zt-edge-cache')).toBe('MISS');

    res1.status(200);
    res1.setHeader('content-type', 'application/json');
    res1.end('{"ok":true}');
    await new Promise((resolve) => setImmediate(resolve));

    const req2 = buildRequest();
    const res2 = new MockEdgeResponse();
    const next2 = createNext();

    await mw(req2, res2 as unknown as Response, next2);
    await new Promise((resolve) => setImmediate(resolve));

    expect(next2).not.toHaveBeenCalled();
    expect(res2.statusCode).toBe(200);
    expect(res2.getHeader('x-zt-edge-cache')).toBe('HIT');
    expect(res2.body.toString('utf8')).toBe('{"ok":true}');

    store.destroy();
  });

  test('bypasses caching for authenticated routes unless explicitly allowed', async () => {
    const store = new InMemoryEdgeCacheStore(1000);
    const mw = createEdgeCacheMiddleware(buildConfig(true), { store });

    const identity: GatewayIdentity = {
      sub: 'user-1',
      iss: 'issuer',
      aud: 'aud',
      exp: Math.floor(Date.now() / 1000) + 300,
      iat: Math.floor(Date.now() / 1000),
      roles: [],
      scopes: [],
      permissions: [],
      stepUpLevel: 0,
      raw: {},
    };

    const req1 = buildRequest({ identity });
    const res1 = new MockEdgeResponse();
    const next1 = createNext();

    await mw(req1, res1 as unknown as Response, next1);
    await new Promise((resolve) => setImmediate(resolve));

    expect(next1).toHaveBeenCalledTimes(1);
    expect(res1.getHeader('x-zt-edge-cache')).toBeUndefined();

    const req2 = buildRequest({ identity });
    const res2 = new MockEdgeResponse();
    const next2 = createNext();

    await mw(req2, res2 as unknown as Response, next2);
    await new Promise((resolve) => setImmediate(resolve));

    expect(next2).toHaveBeenCalledTimes(1);

    store.destroy();
  });

  test('serves stale response within stale-while-revalidate window', async () => {
    const cfg = buildConfig(false);
    const store = new InMemoryEdgeCacheStore(1000);
    const mw = createEdgeCacheMiddleware(cfg, { store });
    const req = buildRequest();

    const cacheKey = buildEdgeCacheKey(req, '/public', {
      includeQueryString: true,
      ignoreQueryParams: new Set(['_']),
      varyHeaders: ['accept', 'accept-encoding'],
      cacheAuthenticated: false,
    });

    const now = Date.now();
    await store.set(cacheKey, '/public', 60, {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      bodyBase64: Buffer.from('{"stale":true}', 'utf8').toString('base64'),
      createdAtMs: now - 120_000,
      expiresAtMs: now - 30_000,
      staleUntilMs: now + 30_000,
    });

    const res = new MockEdgeResponse();
    const next = createNext();
    await mw(req, res as unknown as Response, next);
    await new Promise((resolve) => setImmediate(resolve));

    expect(next).not.toHaveBeenCalled();
    expect(res.getHeader('x-zt-edge-cache')).toBe('STALE');
    expect(res.body.toString('utf8')).toBe('{"stale":true}');

    store.destroy();
  });

  test('collapses concurrent misses so only first request hits upstream', async () => {
    const store = new InMemoryEdgeCacheStore(1000);
    const mw = createEdgeCacheMiddleware(buildConfig(false), { store });

    const req1 = buildRequest();
    const res1 = new MockEdgeResponse();
    const next1 = createNext();

    await mw(req1, res1 as unknown as Response, next1);
    await new Promise((resolve) => setImmediate(resolve));
    expect(next1).toHaveBeenCalledTimes(1);
    expect(res1.getHeader('x-zt-edge-cache')).toBe('MISS');

    const req2 = buildRequest();
    const res2 = new MockEdgeResponse();
    const next2 = createNext();
    void mw(req2, res2 as unknown as Response, next2);

    await new Promise((resolve) => setTimeout(resolve, 25));
    expect(next2).not.toHaveBeenCalled();

    res1.status(200);
    res1.setHeader('content-type', 'application/json');
    res1.end('{"coalesced":true}');
    await new Promise((resolve) => setTimeout(resolve, 25));

    expect(next2).not.toHaveBeenCalled();
    expect(res2.getHeader('x-zt-edge-cache')).toBe('HIT');
    expect(res2.body.toString('utf8')).toBe('{"coalesced":true}');

    store.destroy();
  });

  test('serves stale-if-error when refresh fails within stale-if-error window', async () => {
    const cfg = buildConfig(false);
    const store = new InMemoryEdgeCacheStore(1000);
    const mw = createEdgeCacheMiddleware(cfg, { store });
    const req = buildRequest();

    const cacheKey = buildEdgeCacheKey(req, '/public', {
      includeQueryString: true,
      ignoreQueryParams: new Set(['_']),
      varyHeaders: ['accept', 'accept-encoding'],
      cacheAuthenticated: false,
    });

    const now = Date.now();
    await store.set(cacheKey, '/public', 60, {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      bodyBase64: Buffer.from('{"staleIfError":true}', 'utf8').toString('base64'),
      createdAtMs: now - 180_000,
      expiresAtMs: now - 120_000,
      staleUntilMs: now - 60_000,
      staleIfErrorUntilMs: now + 30_000,
    });

    const res = new MockEdgeResponse();
    const next = createNext();
    await mw(req, res as unknown as Response, next);
    await new Promise((resolve) => setTimeout(resolve, 40));

    expect(next).not.toHaveBeenCalled();
    expect(res.getHeader('x-zt-edge-cache')).toBe('STALE-IF-ERROR');
    expect(res.body.toString('utf8')).toBe('{"staleIfError":true}');

    store.destroy();
  });
});

describe('Edge Cache Purge Helpers', () => {
  test('purges by route path and by full clear', async () => {
    const store = new InMemoryEdgeCacheStore(1000);

    await store.set('k1', '/public', 60, cachedResponse('{"a":1}'));
    await store.set('k2', '/public', 60, cachedResponse('{"b":1}'));
    await store.set('k3', '/other', 60, cachedResponse('{"c":1}'));

    const routePurge = await applyEdgeCachePurge(store, {
      routePath: '/public',
      maxDelete: 100,
      all: false,
    });

    expect(routePurge.mode).toBe('route');
    expect(routePurge.purged).toBe(2);
    expect(await store.get('k1')).toBeNull();
    expect(await store.get('k2')).toBeNull();
    expect(await store.get('k3')).not.toBeNull();

    const allPurge = await applyEdgeCachePurge(store, {
      all: true,
      maxDelete: 100,
    });
    expect(allPurge.mode).toBe('all');
    expect(allPurge.purged).toBe(1);
    expect(await store.get('k3')).toBeNull();

    store.destroy();
  });

  test('purges entries by cache tags', async () => {
    const store = new InMemoryEdgeCacheStore(1000);

    await store.set('k1', '/public', 60, { ...cachedResponse('{"a":1}'), tags: ['catalog', 'home'] });
    await store.set('k2', '/public', 60, { ...cachedResponse('{"b":1}'), tags: ['catalog'] });
    await store.set('k3', '/other', 60, { ...cachedResponse('{"c":1}'), tags: ['profile'] });

    const tagPurge = await applyEdgeCachePurge(store, {
      tags: ['catalog'],
      maxDelete: 100,
      all: false,
    });

    expect(tagPurge.mode).toBe('tags');
    expect(tagPurge.purged).toBe(2);
    expect(await store.get('k1')).toBeNull();
    expect(await store.get('k2')).toBeNull();
    expect(await store.get('k3')).not.toBeNull();

    store.destroy();
  });

  test('bumps route version for soft purge and changes cache key namespace', async () => {
    const store = new InMemoryEdgeCacheStore(1000);
    const req = buildRequest();
    const policy = {
      includeQueryString: true,
      ignoreQueryParams: new Set(['_']),
      varyHeaders: ['accept', 'accept-encoding'],
      cacheAuthenticated: false,
    };

    const beforeVersion = await getEdgeCacheRouteVersion(store, { routePath: '/public' });
    expect(beforeVersion.version).toBe('0');

    const keyBefore = buildEdgeCacheKey(req, '/public', policy, beforeVersion.version);

    const bumped = await bumpEdgeCacheRouteVersion(store, { routePath: '/public' });
    expect(bumped.previousVersion).toBe('0');
    expect(bumped.currentVersion).toBe('1');

    const afterVersion = await getEdgeCacheRouteVersion(store, { routePath: '/public' });
    const keyAfter = buildEdgeCacheKey(req, '/public', policy, afterVersion.version);
    expect(keyAfter).not.toBe(keyBefore);

    store.destroy();
  });
});
