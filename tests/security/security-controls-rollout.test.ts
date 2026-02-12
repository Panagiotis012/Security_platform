import type { Request, Response } from 'express';
import { GatewayConfigSchema } from '../../gateway/config/default';
import {
  applySecurityControlsPatch,
  buildSecurityControlsSnapshot,
} from '../../gateway/src/internal/internal-routes';
import { createAccessControlMiddleware } from '../../gateway/src/middleware/access-control';
import { createWafMiddleware } from '../../gateway/src/middleware/waf';
import { createMockRes, createNext } from '../test-utils/mock-express';

function makeConfig() {
  return GatewayConfigSchema.parse({
    jwt: {
      jwksUri: 'https://example.invalid/jwks.json',
      issuer: 'issuer',
      audience: 'aud',
    },
    pdp: { url: 'https://example.invalid' },
    waf: {
      enabled: true,
      riskScoreThreshold: 20,
      ruleSets: {
        custom: { enabled: true, action: 'block' },
      },
      customRules: [
        {
          id: 'CUST-ROLLOUT',
          ruleSet: 'custom',
          description: 'Runtime rollout test',
          pattern: 'attack-marker-runtime',
          flags: 'i',
          score: 25,
          targets: ['query'],
          rolloutPercent: 0,
          action: 'block',
        },
      ],
    },
    botManagement: {
      enabled: true,
      challengeThreshold: 30,
      blockThreshold: 60,
      clearance: {
        enabled: true,
        secret: 'bot-clearance-secret-1234567890',
        previousSecrets: ['old-secret'],
      },
    },
    accessControl: {
      enabled: false,
      policy: {
        ipDenylist: [],
      },
    },
    routes: [
      { path: '/api', upstream: 'u', methods: ['GET'], wafRuleSets: ['custom'] },
    ],
    upstreams: {
      u: { name: 'u', url: 'http://example.invalid' },
    },
  });
}

function makeReq(partial: Partial<Request> = {}): Request {
  const req: Partial<Request> = {
    method: 'GET',
    path: '/api/users',
    url: '/api/users',
    originalUrl: '/api/users',
    headers: {},
    query: {},
    body: undefined,
    cookies: {},
    ip: '198.51.100.2',
    socket: { remoteAddress: '198.51.100.2' } as unknown as Request['socket'],
    ...partial,
  };
  return req as Request;
}

describe('Security Controls Rollout', () => {
  test('builds a sanitized security controls snapshot', () => {
    const config = makeConfig();
    const snapshot = buildSecurityControlsSnapshot(config);

    expect(snapshot.botManagement.clearance.secretConfigured).toBe(true);
    expect(snapshot.botManagement.clearance.previousSecretsConfigured).toBe(1);
    expect((snapshot.botManagement.clearance as unknown as { secret?: string }).secret).toBeUndefined();
  });

  test('rejects invalid security control patches', () => {
    const config = makeConfig();
    const result = applySecurityControlsPatch(config, {
      botManagement: {
        challengeThreshold: 90,
        blockThreshold: 20,
      },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.issues.some((issue) => issue.path.includes('botManagement'))).toBe(true);
    }
  });

  test('applies runtime WAF rollout changes without middleware restart', () => {
    const config = makeConfig();
    const mw = createWafMiddleware(config);

    const req1 = makeReq({ query: { q: 'attack-marker-runtime' } });
    const res1 = createMockRes() as unknown as Response;
    const next1 = createNext();
    mw(req1, res1, next1);
    expect(next1).toHaveBeenCalledTimes(1);

    const patch = applySecurityControlsPatch(config, {
      waf: {
        customRules: [
          {
            id: 'CUST-ROLLOUT',
            ruleSet: 'custom',
            description: 'Runtime rollout test',
            pattern: 'attack-marker-runtime',
            flags: 'i',
            score: 25,
            targets: ['query'],
            rolloutPercent: 100,
            action: 'block',
          },
        ],
      },
    });
    expect(patch.ok).toBe(true);

    const req2 = makeReq({ query: { q: 'attack-marker-runtime' } });
    const res2 = createMockRes() as unknown as Response;
    const next2 = createNext();
    mw(req2, res2, next2);

    expect(next2).not.toHaveBeenCalled();
    expect(res2.statusCode).toBe(403);
  });

  test('applies runtime access-control changes without middleware restart', () => {
    const config = makeConfig();
    const mw = createAccessControlMiddleware(config);

    const req1 = makeReq({
      headers: { 'x-geo-country': 'US' },
    });
    const res1 = createMockRes() as unknown as Response;
    const next1 = createNext();
    mw(req1, res1, next1);
    expect(next1).toHaveBeenCalledTimes(1);

    const patch = applySecurityControlsPatch(config, {
      accessControl: {
        enabled: true,
        policy: {
          ipDenylist: ['198.51.100.0/24'],
        },
      },
    });
    expect(patch.ok).toBe(true);

    const req2 = makeReq({
      headers: { 'x-geo-country': 'US' },
      socket: { remoteAddress: '198.51.100.9' } as unknown as Request['socket'],
    });
    const res2 = createMockRes() as unknown as Response;
    const next2 = createNext();
    mw(req2, res2, next2);

    expect(next2).not.toHaveBeenCalled();
    expect(res2.statusCode).toBe(403);
    expect((res2 as unknown as { body?: { reason?: string } }).body?.reason).toBe('ip_denylist');
  });
});
