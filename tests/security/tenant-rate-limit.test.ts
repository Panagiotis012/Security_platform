import type { Request } from 'express';
import type { Response } from 'express';
import { GatewayConfigSchema } from '../../gateway/config/default';
import { createIdentityRateLimiterMiddleware } from '../../gateway/src/middleware/rate-limiter';
import { createMockRes, createNext } from '../test-utils/mock-express';

function makeConfig(keySource: 'identity' | 'header' = 'identity') {
  return GatewayConfigSchema.parse({
    jwt: {
      jwksUri: 'https://example.invalid/jwks.json',
      issuer: 'issuer',
      audience: 'aud',
    },
    pdp: { url: 'https://example.invalid' },
    rateLimit: {
      tenant: {
        enabled: true,
        keySource,
        headerName: 'x-tenant-id',
        perTenant: {
          windowMs: 60_000,
          maxRequests: 1,
          burstMax: 1,
          burstWindowMs: 1_000,
        },
      },
      global: {
        perIp: { windowMs: 60_000, maxRequests: 100, burstMax: 10, burstWindowMs: 1_000 },
        perIdentity: { windowMs: 60_000, maxRequests: 100, burstMax: 10, burstWindowMs: 1_000 },
      },
      greylist: { enabled: false },
    },
    routes: [{ path: '/api', upstream: 'u', methods: ['GET'], rateLimit: { perTenant: { windowMs: 60_000, maxRequests: 1, burstMax: 1, burstWindowMs: 1_000 } } }],
    upstreams: { u: { name: 'u', url: 'http://example.invalid' } },
  });
}

function makeReq(partial: Partial<Request>): Request {
  const req: Partial<Request> = {
    method: 'GET',
    path: '/api/data',
    url: '/api/data',
    headers: {},
    query: {},
    ip: '203.0.113.10',
    ...partial,
  };
  return req as Request;
}

describe('Tenant rate limiting', () => {
  test('enforces shared tenant bucket across different identities', async () => {
    const mw = createIdentityRateLimiterMiddleware(makeConfig('identity'));

    const req1 = makeReq({
      identity: { sub: 'user-1', tenantId: 'tenant-a' } as Request['identity'],
    });
    const res1 = createMockRes() as unknown as Response;
    const next1 = createNext();
    await Promise.resolve(mw(req1, res1, next1));
    expect(next1).toHaveBeenCalledTimes(1);

    const req2 = makeReq({
      identity: { sub: 'user-2', tenantId: 'tenant-a' } as Request['identity'],
    });
    const res2 = createMockRes() as unknown as Response;
    const next2 = createNext();
    await Promise.resolve(mw(req2, res2, next2));
    expect(next2).not.toHaveBeenCalled();
    expect(res2.statusCode).toBe(429);
  });

  test('isolates buckets by tenant id', async () => {
    const mw = createIdentityRateLimiterMiddleware(makeConfig('identity'));

    const req1 = makeReq({
      identity: { sub: 'user-1', tenantId: 'tenant-a' } as Request['identity'],
    });
    const res1 = createMockRes() as unknown as Response;
    const next1 = createNext();
    await Promise.resolve(mw(req1, res1, next1));
    expect(next1).toHaveBeenCalledTimes(1);

    const req2 = makeReq({
      identity: { sub: 'user-2', tenantId: 'tenant-b' } as Request['identity'],
    });
    const res2 = createMockRes() as unknown as Response;
    const next2 = createNext();
    await Promise.resolve(mw(req2, res2, next2));
    expect(next2).toHaveBeenCalledTimes(1);
  });

  test('supports tenant key extraction from header', async () => {
    const mw = createIdentityRateLimiterMiddleware(makeConfig('header'));

    const req1 = makeReq({
      headers: { 'x-tenant-id': 'tenant-a' },
      identity: { sub: 'user-1' } as Request['identity'],
    });
    const res1 = createMockRes() as unknown as Response;
    const next1 = createNext();
    await Promise.resolve(mw(req1, res1, next1));
    expect(next1).toHaveBeenCalledTimes(1);

    const req2 = makeReq({
      headers: { 'x-tenant-id': 'tenant-b' },
      identity: { sub: 'user-2' } as Request['identity'],
    });
    const res2 = createMockRes() as unknown as Response;
    const next2 = createNext();
    await Promise.resolve(mw(req2, res2, next2));
    expect(next2).toHaveBeenCalledTimes(1);
  });
});
