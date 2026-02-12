import type { Request, Response } from 'express';
import { GatewayConfigSchema } from '../../gateway/config/default';
import { UpstreamRoutingPolicyManager } from '../../gateway/src/proxy/upstream-policy-manager';
import { createUpstreamRouter } from '../../gateway/src/proxy/upstream-router';
import { createMockRes, createNext } from '../test-utils/mock-express';

function makeConfig() {
  return GatewayConfigSchema.parse({
    jwt: {
      jwksUri: 'https://example.invalid/jwks.json',
      issuer: 'issuer',
      audience: 'aud',
    },
    pdp: { url: 'https://example.invalid' },
    routes: [
      { path: '/api', upstream: 'u1', methods: ['GET'] },
    ],
    upstreams: {
      u1: {
        name: 'u1',
        url: 'http://example.invalid',
        pool: {
          enabled: true,
          endpoints: [
            { url: 'http://example.invalid', weight: 2 },
            { url: 'http://example2.invalid', weight: 1 },
          ],
        },
      },
      u2: {
        name: 'u2',
        url: 'http://example3.invalid',
      },
    },
  });
}

function makeReq(query: Record<string, string> = {}): Request {
  const req: Partial<Request> = {
    method: 'GET',
    path: '/internal/upstreams/diagnostics',
    url: '/internal/upstreams/diagnostics',
    originalUrl: '/internal/upstreams/diagnostics',
    headers: {},
    ip: '203.0.113.10',
    query: query as unknown as Request['query'],
  };
  return req as Request;
}

describe('Upstream router diagnostics endpoint', () => {
  test('returns diagnostics snapshot for all upstreams', () => {
    const mw = createUpstreamRouter(makeConfig());
    const req = makeReq();
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(200);
    const body = (res as unknown as { body?: { upstreamCount?: number; upstreams?: Array<{ name: string }> } }).body;
    expect(body?.upstreamCount).toBe(2);
    expect(body?.upstreams?.map((u) => u.name).sort()).toEqual(['u1', 'u2']);
  });

  test('returns 404 for unknown upstream filter', () => {
    const mw = createUpstreamRouter(makeConfig());
    const req = makeReq({ upstream: 'does-not-exist' });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(404);
    expect((res as unknown as { body?: { error?: string } }).body?.error).toBe('upstream_not_found');
  });

  test('reflects runtime upstream policy updates in diagnostics', () => {
    const config = makeConfig();
    const manager = new UpstreamRoutingPolicyManager(config);
    const mw = createUpstreamRouter(config, { upstreamPolicyManager: manager });

    const patch = manager.applyPatch({
      u1: {
        url: 'http://updated-example.invalid',
      },
    });
    expect(patch.ok).toBe(true);

    const req = makeReq({ upstream: 'u1' });
    const res = createMockRes() as unknown as Response;
    const next = createNext();
    mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(200);
    const body = (res as unknown as {
      body?: {
        policyRevision?: string;
        upstreams?: Array<{ configuredUrl?: string }>;
      };
    }).body;
    expect(body?.policyRevision).toBe(manager.getRevision());
    expect(body?.upstreams?.[0]?.configuredUrl).toBe('http://updated-example.invalid');
  });
});
