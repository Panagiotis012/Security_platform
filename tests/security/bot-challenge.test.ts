import type { Request, Response } from 'express';
import { GatewayConfigSchema } from '../../gateway/config/default';
import { createBotChallengeMiddleware } from '../../gateway/src/middleware/bot-challenge';
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
    adaptiveDefense: {
      enabled: true,
      blockThreshold: 100,
      challengeThreshold: 50,
      challenge: {
        enabled: true,
        headerName: 'x-zt-bot-challenge-token',
        tokenTtlMs: 60_000,
        durationMs: 300_000,
        maxInvalidAttempts: 2,
        invalidAttemptWindowMs: 60_000,
        invalidAttemptBackoffMs: 1_000,
        secret: '0123456789abcdef0123456789abcdef',
      },
    },
    botManagement: {
      clearance: {
        enabled: true,
        cookieName: '__zt_bot_clearance',
        ttlSeconds: 1800,
        secure: true,
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        secret: 'clearance-secret-0123456789abcdef',
      },
    },
  });
}

function makeReq(partial: Partial<Request> = {}): Request {
  const req: Partial<Request> = {
    method: 'GET',
    path: '/api/resource',
    url: '/api/resource',
    headers: { 'user-agent': 'Mozilla/Test' },
    ip: '0.0.0.0',
    query: {},
    cookies: {},
    socket: { remoteAddress: '203.0.113.10' } as unknown as Request['socket'],
    ...partial,
  };
  return req as Request;
}

describe('Bot Challenge Middleware', () => {
  test('requires challenge and returns signed token', async () => {
    const store = new InMemoryBotChallengeStore();
    await store.setChallenge('203.0.113.10', 60, 'adaptive_test');

    const mw = createBotChallengeMiddleware(makeConfig(), { challengeStore: store });

    const req = makeReq();
    const res = createMockRes();
    const next = createNext();
    await mw(req, res as unknown as Response, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
    expect((res.body as { error?: string }).error).toBe('bot_challenge_required');
    const token = (res.body as { challenge?: { token?: string } }).challenge?.token;
    expect(typeof token).toBe('string');

    store.destroy();
  });

  test('allows request when valid token is presented', async () => {
    const store = new InMemoryBotChallengeStore();
    await store.setChallenge('203.0.113.10', 60, 'adaptive_test');
    const cfg = makeConfig();
    const mw = createBotChallengeMiddleware(cfg, { challengeStore: store });

    const req1 = makeReq();
    const res1 = createMockRes();
    const next1 = createNext();
    await mw(req1, res1 as unknown as Response, next1);
    const token = (res1.body as { challenge?: { token?: string } }).challenge?.token as string;

    const req2 = makeReq({
      headers: {
        'user-agent': 'Mozilla/Test',
        [cfg.adaptiveDefense.challenge.headerName]: token,
      },
    });
    const res2 = createMockRes();
    const next2 = createNext();
    await mw(req2, res2 as unknown as Response, next2);

    expect(next2).toHaveBeenCalledTimes(1);
    expect(typeof (res2 as unknown as { getHeader: (name: string) => string | undefined }).getHeader('set-cookie')).toBe('string');
    const remaining = await store.getChallenge('203.0.113.10');
    expect(remaining).toBeNull();

    store.destroy();
  });

  test('enforces temporary backoff after repeated invalid challenge tokens', async () => {
    const store = new InMemoryBotChallengeStore();
    await store.setChallenge('203.0.113.10', 60, 'adaptive_test');
    const cfg = makeConfig();
    const mw = createBotChallengeMiddleware(cfg, { challengeStore: store });

    const badReq1 = makeReq({
      headers: {
        'user-agent': 'Mozilla/Test',
        [cfg.adaptiveDefense.challenge.headerName]: 'bad.token',
      },
    });
    const badRes1 = createMockRes();
    const badNext1 = createNext();
    await mw(badReq1, badRes1 as unknown as Response, badNext1);

    expect(badRes1.statusCode).toBe(403);

    const badReq2 = makeReq({
      headers: {
        'user-agent': 'Mozilla/Test',
        [cfg.adaptiveDefense.challenge.headerName]: 'bad.token',
      },
    });
    const badRes2 = createMockRes();
    const badNext2 = createNext();
    await mw(badReq2, badRes2 as unknown as Response, badNext2);

    expect(badNext2).not.toHaveBeenCalled();
    expect(badRes2.statusCode).toBe(429);
    expect((badRes2.body as { error?: string }).error).toBe('bot_challenge_backoff');

    store.destroy();
  });
});
