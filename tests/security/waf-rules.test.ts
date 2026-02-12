import type { Request } from 'express';
import type { Response } from 'express';
import { GatewayConfigSchema } from '../../gateway/config/default';
import { createWafMiddleware } from '../../gateway/src/middleware/waf';
import { InMemoryBotChallengeStore } from '../../gateway/src/state/inmemory-bot-challenge-store';
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
      riskScoreThreshold: 25,
      ruleSets: {
        xss: { enabled: true, action: 'block' },
        sqli: { enabled: true, action: 'block' },
        cmdi: { enabled: true, action: 'block' },
        ssrf: { enabled: true, action: 'block' },
        traversal: { enabled: true, action: 'block' }
      }
    },
    routes: [
      { path: '/api', upstream: 'u', methods: ['GET', 'POST'], wafRuleSets: ['xss'] }
    ],
    upstreams: {
      u: { name: 'u', url: 'http://example.invalid' }
    }
  });
}

function makeReq(partial: Partial<Request>) {
  const req: Partial<Request> = {
    method: 'GET',
    path: '/api/users',
    url: '/api/users',
    originalUrl: '/api/users',
    headers: {},
    query: {},
    body: undefined,
    cookies: {},
    ip: '1.2.3.4',
    socket: { remoteAddress: '203.0.113.10' } as unknown as Request['socket'],
    ...partial,
  };
  return req as Request;
}

describe('WAF Middleware', () => {
  test('blocks obvious XSS payloads in query/body', () => {
    const mw = createWafMiddleware(makeConfig());
    const req = makeReq({ query: { q: '<script>alert(1)</script>' } });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  test('annotates request with risk score and match IDs when not blocked', () => {
    const cfg = makeConfig();
    cfg.waf.riskScoreThreshold = 100; // avoid blocking

    const mw = createWafMiddleware(cfg);
    const req = makeReq({ query: { q: '<script>alert(1)</script>' } });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    const enriched = req as Request & { wafRiskScore?: number; wafMatches?: string[] };
    expect(enriched.wafRiskScore).toBeGreaterThan(0);
    expect(Array.isArray(enriched.wafMatches)).toBe(true);
  });

  test('supports challenge action and creates bot challenge state', async () => {
    const cfg = makeConfig();
    cfg.waf.ruleSets.xss = { enabled: true, action: 'challenge' };
    cfg.waf.challengeDurationMs = 120_000;
    const store = new InMemoryBotChallengeStore();
    const mw = createWafMiddleware(cfg, { challengeStore: store });

    const req = makeReq({ query: { q: '<script>alert(1)</script>' } });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);
    await new Promise((resolve) => setImmediate(resolve));

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
    expect((res as unknown as { body?: { error?: string } }).body?.error).toBe('bot_challenge_required');
    expect((res as unknown as { headers?: Record<string, string> }).headers?.['x-zt-bot-challenge']).toBe('required');

    const challenge = await store.getChallenge('203.0.113.10');
    expect(challenge).not.toBeNull();
    store.destroy();
  });

  test('supports custom regex rules from config', () => {
    const cfg = GatewayConfigSchema.parse({
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
            id: 'CUST-001',
            ruleSet: 'custom',
            description: 'Test custom marker',
            pattern: 'attack-marker-123',
            flags: 'i',
            score: 25,
            targets: ['query'],
            action: 'block',
          },
        ],
      },
      routes: [
        { path: '/api', upstream: 'u', methods: ['GET'], wafRuleSets: ['custom'] },
      ],
      upstreams: {
        u: { name: 'u', url: 'http://example.invalid' },
      },
    });

    const mw = createWafMiddleware(cfg);
    const req = makeReq({ query: { q: 'attack-marker-123' } });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  test('does not apply custom rule when rollout is 0%', () => {
    const cfg = GatewayConfigSchema.parse({
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
            id: 'CUST-ROLLOUT-0',
            ruleSet: 'custom',
            description: 'Rollout disabled',
            pattern: 'attack-marker-456',
            flags: 'i',
            score: 25,
            targets: ['query'],
            rolloutPercent: 0,
            action: 'block',
          },
        ],
      },
      routes: [
        { path: '/api', upstream: 'u', methods: ['GET'], wafRuleSets: ['custom'] },
      ],
      upstreams: {
        u: { name: 'u', url: 'http://example.invalid' },
      },
    });

    const mw = createWafMiddleware(cfg);
    const req = makeReq({ query: { q: 'attack-marker-456' } });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
  });

  test('does not apply custom rule when version is not allowed', () => {
    const cfg = GatewayConfigSchema.parse({
      jwt: {
        jwksUri: 'https://example.invalid/jwks.json',
        issuer: 'issuer',
        audience: 'aud',
      },
      pdp: { url: 'https://example.invalid' },
      waf: {
        enabled: true,
        riskScoreThreshold: 20,
        managedRulesVersion: 'v1',
        allowedRuleVersions: ['v1'],
        ruleSets: {
          custom: { enabled: true, action: 'block' },
        },
        customRules: [
          {
            id: 'CUST-V2',
            ruleSet: 'custom',
            version: 'v2',
            description: 'Version not allowed',
            pattern: 'attack-marker-789',
            flags: 'i',
            score: 25,
            targets: ['query'],
            action: 'block',
          },
        ],
      },
      routes: [
        { path: '/api', upstream: 'u', methods: ['GET'], wafRuleSets: ['custom'] },
      ],
      upstreams: {
        u: { name: 'u', url: 'http://example.invalid' },
      },
    });

    const mw = createWafMiddleware(cfg);
    const req = makeReq({ query: { q: 'attack-marker-789' } });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
  });

  test('enforces WAF rate rule with block action', () => {
    const cfg = makeConfig();
    cfg.waf.rateRules = [
      {
        id: 'RATE-001',
        version: 'v1',
        enabled: true,
        rolloutPercent: 100,
        threshold: 2,
        windowMs: 60_000,
        blockDurationMs: 30_000,
        action: 'block',
        keyBy: 'ip',
        pathPattern: '^/api',
        methods: ['GET'],
        description: 'Basic per-IP rate rule',
      },
    ];

    const mw = createWafMiddleware(cfg);

    const req1 = makeReq({});
    const res1 = createMockRes() as unknown as Response;
    const next1 = createNext();
    mw(req1, res1, next1);
    expect(next1).toHaveBeenCalledTimes(1);

    const req2 = makeReq({});
    const res2 = createMockRes() as unknown as Response;
    const next2 = createNext();
    mw(req2, res2, next2);
    expect(next2).toHaveBeenCalledTimes(1);

    const req3 = makeReq({});
    const res3 = createMockRes() as unknown as Response;
    const next3 = createNext();
    mw(req3, res3, next3);
    expect(next3).not.toHaveBeenCalled();
    expect(res3.statusCode).toBe(429);
    expect((res3 as unknown as { body?: { error?: string } }).body?.error).toBe('rate_limited_by_waf');
    expect((res3 as unknown as { headers?: Record<string, string> }).headers?.['retry-after']).toBeDefined();
  });

  test('supports WAF rate rule challenge action', async () => {
    const cfg = makeConfig();
    cfg.waf.rateRules = [
      {
        id: 'RATE-CHALLENGE',
        version: 'v1',
        enabled: true,
        rolloutPercent: 100,
        threshold: 1,
        windowMs: 60_000,
        blockDurationMs: 30_000,
        action: 'challenge',
        keyBy: 'ip',
        pathPattern: '^/api',
        methods: ['GET'],
        description: 'Rate challenge rule',
      },
    ];
    cfg.waf.challengeDurationMs = 120_000;

    const store = new InMemoryBotChallengeStore();
    const mw = createWafMiddleware(cfg, { challengeStore: store });

    const req1 = makeReq({});
    const res1 = createMockRes() as unknown as Response;
    const next1 = createNext();
    mw(req1, res1, next1);
    expect(next1).toHaveBeenCalledTimes(1);

    const req2 = makeReq({});
    const res2 = createMockRes() as unknown as Response;
    const next2 = createNext();
    mw(req2, res2, next2);
    await new Promise((resolve) => setImmediate(resolve));

    expect(next2).not.toHaveBeenCalled();
    expect(res2.statusCode).toBe(403);
    expect((res2 as unknown as { body?: { error?: string } }).body?.error).toBe('bot_challenge_required');
    const challenge = await store.getChallenge('203.0.113.10');
    expect(challenge).not.toBeNull();
    store.destroy();
  });

  test('does not apply WAF rate rule when version is not allowed', () => {
    const cfg = makeConfig();
    cfg.waf.managedRulesVersion = 'v1';
    cfg.waf.allowedRuleVersions = ['v1'];
    cfg.waf.rateRules = [
      {
        id: 'RATE-V2',
        version: 'v2',
        enabled: true,
        rolloutPercent: 100,
        threshold: 1,
        windowMs: 60_000,
        blockDurationMs: 60_000,
        action: 'block',
        keyBy: 'ip',
        pathPattern: '^/api',
        methods: ['GET'],
        description: 'Version-gated rate rule',
      },
    ];

    const mw = createWafMiddleware(cfg);
    const req = makeReq({});
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
  });
});
