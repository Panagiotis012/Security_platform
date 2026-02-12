import type { Request } from 'express';
import type { Response } from 'express';
import { GatewayConfigSchema } from '../../gateway/config/default';
import { createRateLimiterMiddleware } from '../../gateway/src/middleware/rate-limiter';
import { createMockRes, createNext } from '../test-utils/mock-express';

function makeConfig(trustedProxies: string[]) {
  return GatewayConfigSchema.parse({
    jwt: {
      jwksUri: 'https://example.invalid/jwks.json',
      issuer: 'issuer',
      audience: 'aud',
    },
    pdp: { url: 'https://example.invalid' },
    rateLimit: {
      trustedProxies,
      xForwardedForMaxDepth: 5,
      greylist: { enabled: false },
      global: {
        perIp: { windowMs: 60_000, maxRequests: 1, burstMax: 1, burstWindowMs: 1000 },
        perIdentity: { windowMs: 60_000, maxRequests: 1, burstMax: 1, burstWindowMs: 1000 },
      },
    },
    routes: [{ path: '/api', upstream: 'u', methods: ['GET'] }],
    upstreams: { u: { name: 'u', url: 'http://example.invalid' } },
  });
}

function makeReq(partial: Partial<Request>) {
  const req: Partial<Request> = {
    method: 'GET',
    path: '/api/users',
    url: '/api/users',
    headers: {},
    ip: '0.0.0.0',
    query: {},
    cookies: {},
    socket: { remoteAddress: '203.0.113.10' } as unknown as Request['socket'],
    ...partial,
  };
  return req as Request;
}

describe('Rate Limiter - X-Forwarded-For Spoofing', () => {
  test('ignores X-Forwarded-For when direct peer is not trusted', async () => {
    const mw = createRateLimiterMiddleware(makeConfig([]));

    // First request: allowed.
    const req1 = makeReq({
      headers: { 'x-forwarded-for': '1.1.1.1' },
    });
    const res1 = createMockRes() as unknown as Response;
    const next1 = createNext();
    await Promise.resolve(mw(req1, res1, next1));
    expect(next1).toHaveBeenCalledTimes(1);
    expect(res1.statusCode).toBe(200);

    // Second request: attacker attempts to bypass by changing XFF.
    const req2 = makeReq({
      headers: { 'x-forwarded-for': '2.2.2.2' },
    });
    const res2 = createMockRes() as unknown as Response;
    const next2 = createNext();
    await Promise.resolve(mw(req2, res2, next2));

    expect(next2).not.toHaveBeenCalled();
    expect(res2.statusCode).toBe(429);
  });

  test('uses X-Forwarded-For when direct peer is a trusted proxy', async () => {
    const mw = createRateLimiterMiddleware(makeConfig(['203.0.113.10']));

    const req1 = makeReq({
      headers: { 'x-forwarded-for': '1.1.1.1, 203.0.113.10' },
    });
    const res1 = createMockRes() as unknown as Response;
    const next1 = createNext();
    await Promise.resolve(mw(req1, res1, next1));
    expect(next1).toHaveBeenCalledTimes(1);

    // Different client IP behind the same proxy should get its own bucket.
    const req2 = makeReq({
      headers: { 'x-forwarded-for': '2.2.2.2, 203.0.113.10' },
    });
    const res2 = createMockRes() as unknown as Response;
    const next2 = createNext();
    await Promise.resolve(mw(req2, res2, next2));
    expect(next2).toHaveBeenCalledTimes(1);
  });
});
