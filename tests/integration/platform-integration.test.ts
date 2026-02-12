import http from 'http';
import type { Request, Response } from 'express';
import { JWKSManager } from '../../identity/src/tokens/jwks';
import { TokenService } from '../../identity/src/tokens/token-service';
import { InMemoryTokenVersionStore } from '../../identity/src/tokens/token-version-store';
import { InMemoryJtiRevocationStore } from '../../identity/src/tokens/jti-revocation-store';
import { GatewayConfigSchema } from '../../gateway/config/default';
import { createJwtValidationMiddleware } from '../../gateway/src/middleware/jwt-validation';
import type { GatewayIdentity } from '../../gateway/src/middleware/jwt-validation';
import { createPolicyCheckMiddleware } from '../../gateway/src/middleware/policy-check';
import { createMockRes, createNext } from '../test-utils/mock-express';

async function listen(server: http.Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('expected address');
  return addr.port;
}

describe('Integration - Identity token -> Gateway JWT -> Gateway PDP call', () => {
  test('valid token is accepted and PDP allow passes', async () => {
    // 1) Identity issues token + serves JWKS.
    const jwksManager = new JWKSManager('ES256');
    await jwksManager.initialize();
    const tokenVersions = new InMemoryTokenVersionStore();
    const jtiRevocations = new InMemoryJtiRevocationStore();
    const tokenService = new TokenService(jwksManager, { tokenVersions, jtiRevocations });

    const jwks = await jwksManager.toJWKS();

    // 2) Mock JWKS + PDP endpoints.
    const server = http.createServer((req, res) => {
      if (req.url === '/jwks.json') {
        res.statusCode = 200;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify(jwks));
        return;
      }

      if (req.url === '/v1/evaluate' && req.method === 'POST') {
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => {
          // Minimal shape check.
          const parsed = JSON.parse(body) as { actor?: { id?: string } };
          res.statusCode = 200;
          res.setHeader('content-type', 'application/json');
          res.end(
            JSON.stringify({
              decision: 'ALLOW',
              policyId: 'policy:test-allow',
              reason: `ok:${parsed.actor?.id ?? 'unknown'}`,
            })
          );
        });
        return;
      }

      res.statusCode = 404;
      res.end();
    });

    const port = await listen(server);
    const jwksUri = `http://127.0.0.1:${port}/jwks.json`;
    const pdpUrl = `http://127.0.0.1:${port}`;

    const issued = await tokenService.issueAccessToken('user-1', ['user'], ['scope:read'], 0, 'sid-1');

    // 3) Gateway middlewares execute against the token and PDP.
    const gwConfig = GatewayConfigSchema.parse({
      jwt: {
        jwksUri,
        issuer: 'https://identity.zerotrust.local',
        audience: 'https://api.zerotrust.local',
        algorithms: ['ES256'],
        maxTokenAgeSeconds: 900,
      },
      pdp: { url: pdpUrl },
      routes: [{ path: '/api', upstream: 'u', methods: ['GET'] }],
      upstreams: { u: { name: 'u', url: 'http://example.invalid' } },
    });

    const jwtMw = createJwtValidationMiddleware(gwConfig);
    const policyMw = createPolicyCheckMiddleware(gwConfig);

    type TestRequest = Request & { identity?: GatewayIdentity; policyDecisionId?: string };

    const req = {
      method: 'GET',
      path: '/api/resource',
      url: '/api/resource',
      headers: {
        authorization: `Bearer ${issued.token}`,
        'x-correlation-id': '00000000-0000-0000-0000-000000000000',
      },
      cookies: {},
      query: {},
      ip: '1.2.3.4',
    } as unknown as TestRequest;

    const res = createMockRes() as unknown as Response;

    const next1 = createNext();
    await jwtMw(req, res, next1);
    expect(next1).toHaveBeenCalledTimes(1);
    expect(req.identity?.sub).toBe('user-1');

    const next2 = createNext();
    await policyMw(req, res, next2);
    expect(next2).toHaveBeenCalledTimes(1);
    expect(typeof req.policyDecisionId).toBe('string');

    server.close();
    jtiRevocations.destroy();
  });

  test('PDP unreachable is fail-closed (503) when failClosed=true', async () => {
    const gwConfig = GatewayConfigSchema.parse({
      jwt: {
        jwksUri: 'https://example.invalid/jwks.json',
        issuer: 'issuer',
        audience: 'aud',
      },
      pdp: { url: 'http://127.0.0.1:9', failClosed: true }, // unreachable
    });

    const policyMw = createPolicyCheckMiddleware(gwConfig);

    type TestRequest = Request & { identity?: GatewayIdentity };

    const req = {
      method: 'GET',
      path: '/api/resource',
      url: '/api/resource',
      headers: { 'x-correlation-id': '00000000-0000-0000-0000-000000000000' },
      cookies: {},
      query: {},
      ip: '1.2.3.4',
      identity: { sub: 'user-1', roles: [], permissions: [], scopes: [], stepUpLevel: 0, exp: 0, iat: 0, iss: 'i', aud: 'a', raw: {} },
    } as unknown as TestRequest;
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    await policyMw(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(503);
  });
});
