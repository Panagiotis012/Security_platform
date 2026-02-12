import type { Request, Response } from 'express';
import { GatewayConfigSchema } from '../../gateway/config/default';
import { createAccessControlMiddleware } from '../../gateway/src/middleware/access-control';
import { createMockRes, createNext } from '../test-utils/mock-express';

function makeConfig() {
  return GatewayConfigSchema.parse({
    jwt: {
      jwksUri: 'https://example.invalid/jwks.json',
      issuer: 'issuer',
      audience: 'aud',
    },
    pdp: { url: 'https://example.invalid' },
    accessControl: {
      enabled: true,
      bypassInternal: true,
      countryHeader: 'x-geo-country',
      asnHeader: 'x-geo-asn',
      policy: {
        enabled: true,
        ipDenylist: ['203.0.113.0/24'],
        countryAllowlist: ['US'],
      },
      profiles: {
        admin: {
          countryAllowlist: ['US', 'CA'],
        },
      },
    },
    routes: [
      { path: '/api', upstream: 'u', methods: ['GET'] },
      { path: '/admin', upstream: 'u', methods: ['GET'], accessControlProfile: 'admin' },
    ],
    upstreams: {
      u: { name: 'u', url: 'http://example.invalid' },
    },
  });
}

function makeReq(partial: Partial<Request>): Request {
  const req: Partial<Request> = {
    method: 'GET',
    path: '/api/data',
    url: '/api/data',
    originalUrl: '/api/data',
    headers: {},
    query: {},
    socket: { remoteAddress: '198.51.100.10' } as unknown as Request['socket'],
    ...partial,
  };
  return req as Request;
}

describe('Access control middleware', () => {
  test('blocks requests from denied CIDR ranges', () => {
    const mw = createAccessControlMiddleware(makeConfig());
    const req = makeReq({
      socket: { remoteAddress: '203.0.113.25' } as unknown as Request['socket'],
      headers: { 'x-geo-country': 'US' },
    });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
    expect((res as unknown as { body?: { reason?: string } }).body?.reason).toBe('ip_denylist');
  });

  test('requires country allowlist membership when configured', () => {
    const mw = createAccessControlMiddleware(makeConfig());
    const req = makeReq({
      headers: { 'x-geo-country': 'DE' },
    });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
    expect((res as unknown as { body?: { reason?: string } }).body?.reason).toBe('country_not_allowlisted');
  });

  test('supports route profile overrides', () => {
    const mw = createAccessControlMiddleware(makeConfig());
    const req = makeReq({
      path: '/admin/users',
      url: '/admin/users',
      originalUrl: '/admin/users',
      headers: { 'x-geo-country': 'CA' },
    });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.statusCode).toBe(200);
  });

  test('bypasses internal routes when configured', () => {
    const mw = createAccessControlMiddleware(makeConfig());
    const req = makeReq({
      path: '/internal/upstreams/diagnostics',
      url: '/internal/upstreams/diagnostics',
      originalUrl: '/internal/upstreams/diagnostics',
      headers: { 'x-geo-country': 'DE' },
      socket: { remoteAddress: '203.0.113.25' } as unknown as Request['socket'],
    });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.statusCode).toBe(200);
  });
});
