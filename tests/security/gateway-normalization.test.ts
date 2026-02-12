import type { Request } from 'express';
import type { Response } from 'express';
import { GatewayConfigSchema } from '../../gateway/config/default';
import { createNormalizationMiddleware } from '../../gateway/src/middleware/normalization';
import { createMockRes, createNext } from '../test-utils/mock-express';

function baseConfig() {
  return GatewayConfigSchema.parse({
    jwt: {
      jwksUri: 'https://example.invalid/jwks.json',
      issuer: 'issuer',
      audience: 'aud',
    },
    pdp: { url: 'https://example.invalid' },
  });
}

function makeReq(partial: Partial<Request> & { rawHeaders?: string[] }) {
  const req: Partial<Request> = {
    method: 'GET',
    url: '/api/users',
    path: '/api/users',
    ip: '1.2.3.4',
    headers: {},
    rawHeaders: [],
    ...partial,
  };
  return req as Request;
}

describe('Gateway Normalization Middleware', () => {
  test('canonicalizes path (slashes, case, trailing slash)', () => {
    const mw = createNormalizationMiddleware(baseConfig());
    const req = makeReq({
      method: 'GET',
      url: '/API//USERS/',
      rawHeaders: ['Host', 'example.test'],
    });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(req.url).toBe('/api/users');
  });

  test('rejects disallowed HTTP methods', () => {
    const cfg = baseConfig();
    cfg.allowedHttpMethods = ['GET', 'POST', 'OPTIONS'];

    const mw = createNormalizationMiddleware(cfg);
    const req = makeReq({
      method: 'TRACE',
      url: '/api/users',
      rawHeaders: ['Host', 'example.test'],
    });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(405);
  });

  test('rejects Content-Length + Transfer-Encoding ambiguity', () => {
    const mw = createNormalizationMiddleware(baseConfig());
    const req = makeReq({
      method: 'POST',
      url: '/api/users',
      headers: { 'content-length': '3', 'transfer-encoding': 'chunked' },
      rawHeaders: [
        'Host', 'example.test',
        'Content-Length', '3',
        'Transfer-Encoding', 'chunked',
      ],
    });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });

  test('rejects double-encoded path sequences', () => {
    const mw = createNormalizationMiddleware(baseConfig());
    const req = makeReq({
      method: 'GET',
      url: '/..%252fetc%252fpasswd',
      rawHeaders: ['Host', 'example.test'],
    });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });
});
