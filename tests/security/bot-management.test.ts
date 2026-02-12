import type { Request } from 'express';
import type { Response } from 'express';
import { GatewayConfigSchema } from '../../gateway/config/default';
import { createBotManagementMiddleware } from '../../gateway/src/middleware/bot-management';
import { issueChallengeToken } from '../../gateway/src/middleware/bot-challenge-token';
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
    botManagement: {
      enabled: true,
      challengeThreshold: 25,
      blockThreshold: 60,
      challengeDurationMs: 120_000,
      verifiedBotUserAgentPatterns: ['googlebot'],
      signals: {
        missingUserAgent: 20,
        automationUserAgent: 30,
        missingAccept: 8,
        missingAcceptLanguage: 6,
        suspiciousPath: 15,
        excessiveForwardedChain: 12,
        headlessHints: 20,
      },
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
      profiles: {
        strictAuth: {
          challengeThreshold: 15,
          blockThreshold: 30,
        },
      },
    },
    routes: [
      { path: '/api', upstream: 'u', methods: ['GET'] },
      { path: '/auth', upstream: 'u', methods: ['GET'], botManagementProfile: 'strictAuth' },
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
    cookies: {},
    ip: '1.2.3.4',
    socket: { remoteAddress: '203.0.113.10' } as unknown as Request['socket'],
    ...partial,
  };
  return req as Request;
}

describe('Bot management middleware', () => {
  test('allows verified good bots', () => {
    const mw = createBotManagementMiddleware(makeConfig());
    const req = makeReq({
      headers: {
        'user-agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
      },
    });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.statusCode).toBe(200);
  });

  test('challenges suspicious automation requests and writes challenge state', async () => {
    const store = new InMemoryBotChallengeStore();
    const mw = createBotManagementMiddleware(makeConfig(), { challengeStore: store });
    const req = makeReq({
      headers: {
        'user-agent': 'curl/8.0',
      },
    });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);
    await new Promise((resolve) => setImmediate(resolve));

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
    expect((res as unknown as { body?: { error?: string } }).body?.error).toBe('bot_challenge_required');
    const challenge = await store.getChallenge('203.0.113.10');
    expect(challenge).not.toBeNull();
    store.destroy();
  });

  test('uses strict route profile and blocks high-risk bot traffic', () => {
    const mw = createBotManagementMiddleware(makeConfig());
    const req = makeReq({
      path: '/auth/login',
      url: '/auth/login',
      originalUrl: '/auth/login',
      headers: {
        'user-agent': 'headless-chrome',
        'x-playwright': '1',
      },
    });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
    expect((res as unknown as { body?: { error?: string } }).body?.error).toBe('bot_blocked');
  });

  test('allows suspicious traffic with a valid bot clearance cookie', () => {
    const config = makeConfig();
    const mw = createBotManagementMiddleware(config);
    const userAgent = 'curl/8.0';
    const token = issueChallengeToken({
      ip: '203.0.113.10',
      userAgent,
      ttlSeconds: 300,
      secret: config.botManagement.clearance.secret as string,
    }).token;

    const req = makeReq({
      headers: {
        'user-agent': userAgent,
        cookie: `__zt_bot_clearance=${encodeURIComponent(token)}`,
      },
    });
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.statusCode).toBe(200);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((req as any).botClearance).toBe(true);
  });
});
