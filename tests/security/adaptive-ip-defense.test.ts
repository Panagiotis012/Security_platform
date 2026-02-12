import type { Request, Response } from 'express';
import { GatewayConfigSchema } from '../../gateway/config/default';
import { createAdaptiveIpDefenseMiddleware } from '../../gateway/src/middleware/adaptive-ip-defense';
import { InMemorySecurityStateStore } from '../../gateway/src/state/inmemory-security-state-store';
import { InMemoryIpReputationStore } from '../../gateway/src/state/inmemory-ip-reputation-store';
import { InMemoryBotChallengeStore } from '../../gateway/src/state/inmemory-bot-challenge-store';
import { createMockRes, createNext } from '../test-utils/mock-express';

function makeConfig(ipAllowlist: string[] = []) {
  return GatewayConfigSchema.parse({
    jwt: {
      jwksUri: 'https://example.invalid/jwks.json',
      issuer: 'issuer',
      audience: 'aud',
    },
    pdp: { url: 'https://example.invalid' },
    adaptiveDefense: {
      enabled: true,
      scoreWindowMs: 60_000,
      blockThreshold: 20,
      challengeThreshold: 10,
      blockDurationMs: 600_000,
      ipAllowlist,
      signals: {
        wafBlock: 50,
        rateLimitExceeded: 30,
        authFailure: 10,
        forbidden: 5,
        botFingerprint: 5,
      },
    },
    routes: [{ path: '/api', upstream: 'u', methods: ['GET', 'POST'] }],
    upstreams: { u: { name: 'u', url: 'http://example.invalid' } },
  });
}

function makeReq(partial: Partial<Request> = {}): Request {
  const req: Partial<Request> = {
    method: 'GET',
    path: '/api/resource',
    url: '/api/resource',
    headers: {},
    ip: '0.0.0.0',
    query: {},
    cookies: {},
    socket: { remoteAddress: '203.0.113.10' } as unknown as Request['socket'],
    ...partial,
  };
  return req as Request;
}

async function flushAsync(): Promise<void> {
  await new Promise((resolve) => setImmediate(resolve));
}

describe('Adaptive IP Defense Middleware', () => {
  test('blocks IP after repeated auth failures cross threshold', async () => {
    const stateStore = new InMemorySecurityStateStore();
    const reputationStore = new InMemoryIpReputationStore();
    const challengeStore = new InMemoryBotChallengeStore();
    const mw = createAdaptiveIpDefenseMiddleware(makeConfig(), {
      stateStore,
      reputationStore,
      challengeStore,
    });

    const req1 = makeReq();
    const res1 = createMockRes() as unknown as Response;
    const next1 = createNext();
    mw(req1, res1, next1);
    expect(next1).toHaveBeenCalledTimes(1);
    res1.statusCode = 401;
    res1.end();
    await flushAsync();

    const notYetBlocked = await stateStore.isIpBlocked('203.0.113.10');
    expect(notYetBlocked).toBeNull();

    const req2 = makeReq();
    const res2 = createMockRes() as unknown as Response;
    const next2 = createNext();
    mw(req2, res2, next2);
    expect(next2).toHaveBeenCalledTimes(1);
    res2.statusCode = 401;
    res2.end();
    await flushAsync();

    const blocked = await stateStore.isIpBlocked('203.0.113.10');
    expect(blocked).not.toBeNull();
    expect(blocked?.reason).toContain('adaptive_ip_reputation');

    challengeStore.destroy();
    reputationStore.destroy();
    stateStore.destroy();
  });

  test('treats WAF-forbidden responses as high-signal abuse', async () => {
    const stateStore = new InMemorySecurityStateStore();
    const reputationStore = new InMemoryIpReputationStore();
    const challengeStore = new InMemoryBotChallengeStore();
    const mw = createAdaptiveIpDefenseMiddleware(makeConfig(), {
      stateStore,
      reputationStore,
      challengeStore,
    });

    const req = makeReq({ wafMatches: ['XSS-001'] } as unknown as Partial<Request>);
    const res = createMockRes() as unknown as Response;
    const next = createNext();
    mw(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    res.statusCode = 403;
    res.end();
    await flushAsync();

    const blocked = await stateStore.isIpBlocked('203.0.113.10');
    expect(blocked).not.toBeNull();

    challengeStore.destroy();
    reputationStore.destroy();
    stateStore.destroy();
  });

  test('does not score or block allowlisted IPs', async () => {
    const stateStore = new InMemorySecurityStateStore();
    const reputationStore = new InMemoryIpReputationStore();
    const challengeStore = new InMemoryBotChallengeStore();
    const mw = createAdaptiveIpDefenseMiddleware(makeConfig(['203.0.113.10']), {
      stateStore,
      reputationStore,
      challengeStore,
    });

    for (let i = 0; i < 5; i += 1) {
      const req = makeReq();
      const res = createMockRes() as unknown as Response;
      const next = createNext();
      mw(req, res, next);
      expect(next).toHaveBeenCalledTimes(1);
      res.statusCode = 429;
      res.end();
      await flushAsync();
    }

    const blocked = await stateStore.isIpBlocked('203.0.113.10');
    expect(blocked).toBeNull();

    challengeStore.destroy();
    reputationStore.destroy();
    stateStore.destroy();
  });

  test('uses route adaptive profile overrides', async () => {
    const cfg = GatewayConfigSchema.parse({
      jwt: {
        jwksUri: 'https://example.invalid/jwks.json',
        issuer: 'issuer',
        audience: 'aud',
      },
      pdp: { url: 'https://example.invalid' },
      adaptiveDefense: {
        enabled: true,
        scoreWindowMs: 60_000,
        blockThreshold: 100,
        challengeThreshold: 50,
        blockDurationMs: 600_000,
        signals: {
          wafBlock: 50,
          rateLimitExceeded: 30,
          authFailure: 10,
          forbidden: 5,
          botFingerprint: 5,
        },
        profiles: {
          auth: {
            blockThreshold: 20,
            challengeThreshold: 10,
          },
        },
      },
      routes: [{ path: '/auth', upstream: 'u', methods: ['POST'], adaptiveProfile: 'auth' }],
      upstreams: { u: { name: 'u', url: 'http://example.invalid' } },
    });

    const stateStore = new InMemorySecurityStateStore();
    const reputationStore = new InMemoryIpReputationStore();
    const challengeStore = new InMemoryBotChallengeStore();
    const mw = createAdaptiveIpDefenseMiddleware(cfg, {
      stateStore,
      reputationStore,
      challengeStore,
    });

    const req1 = makeReq({ method: 'POST', path: '/auth/login', url: '/auth/login' });
    const res1 = createMockRes() as unknown as Response;
    const next1 = createNext();
    mw(req1, res1, next1);
    res1.statusCode = 401;
    res1.end();
    await flushAsync();

    const req2 = makeReq({ method: 'POST', path: '/auth/login', url: '/auth/login' });
    const res2 = createMockRes() as unknown as Response;
    const next2 = createNext();
    mw(req2, res2, next2);
    res2.statusCode = 401;
    res2.end();
    await flushAsync();

    const blocked = await stateStore.isIpBlocked('203.0.113.10');
    expect(blocked).not.toBeNull();

    challengeStore.destroy();
    reputationStore.destroy();
    stateStore.destroy();
  });

  test('scores suspicious bot fingerprint signals even on non-error responses', async () => {
    const cfg = GatewayConfigSchema.parse({
      jwt: {
        jwksUri: 'https://example.invalid/jwks.json',
        issuer: 'issuer',
        audience: 'aud',
      },
      pdp: { url: 'https://example.invalid' },
      adaptiveDefense: {
        enabled: true,
        scoreWindowMs: 60_000,
        blockThreshold: 6,
        challengeThreshold: 4,
        blockDurationMs: 600_000,
        signals: {
          wafBlock: 50,
          rateLimitExceeded: 30,
          authFailure: 10,
          forbidden: 5,
          botFingerprint: 6,
        },
      },
      routes: [{ path: '/api', upstream: 'u', methods: ['GET'] }],
      upstreams: { u: { name: 'u', url: 'http://example.invalid' } },
    });

    const stateStore = new InMemorySecurityStateStore();
    const reputationStore = new InMemoryIpReputationStore();
    const challengeStore = new InMemoryBotChallengeStore();
    const mw = createAdaptiveIpDefenseMiddleware(cfg, {
      stateStore,
      reputationStore,
      challengeStore,
    });

    const req = makeReq({
      headers: {
        'user-agent': 'curl/8.0.1',
      },
    });
    const res = createMockRes() as unknown as Response;
    const next = createNext();
    mw(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    res.statusCode = 200;
    res.end();
    await flushAsync();

    const blocked = await stateStore.isIpBlocked('203.0.113.10');
    expect(blocked).not.toBeNull();
    expect(blocked?.reason).toContain('bot_fingerprint');

    challengeStore.destroy();
    reputationStore.destroy();
    stateStore.destroy();
  });
});
