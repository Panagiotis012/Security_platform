import { InMemorySessionStore } from '../../identity/src/sessions/session-store';
import { SessionManager } from '../../identity/src/sessions/session-manager';
import { config as identityConfig } from '../../identity/config/default';
import type { Response } from 'express';

function mockRes() {
  const cookies: Array<{ name: string; value: string; options: Record<string, unknown> }> = [];
  const cleared: Array<{ name: string; options: Record<string, unknown> }> = [];

  const res = {
    cookies,
    cleared,
    cookie(name: string, value: string, options: Record<string, unknown>) {
      cookies.push({ name, value, options });
      return this;
    },
    clearCookie(name: string, options: Record<string, unknown>) {
      cleared.push({ name, options });
      return this;
    },
  };

  return res;
}

describe('Identity - Session Security (Real)', () => {
  test('rotates session id on escalation and invalidates old session', async () => {
    const store = new InMemorySessionStore();
    const manager = new SessionManager(store);

    const res1 = mockRes();
    const s1 = await manager.createSession(
      { userId: 'user-1', ipAddress: '1.2.3.4', deviceFingerprint: 'ua', privilegeLevel: 0 },
      res1 as unknown as Response,
    );

    const res2 = mockRes();
    const s2 = await manager.rotateSession(s1.id, res2 as unknown as Response, 1);

    expect(s2).not.toBeNull();
    expect(s2!.id).not.toBe(s1.id);

    const old = await store.get(s1.id);
    expect(old).toBeNull();
  });

  test('sets session cookies with secure defaults', async () => {
    const store = new InMemorySessionStore();
    const manager = new SessionManager(store);

    const res = mockRes();
    await manager.createSession(
      { userId: 'user-1', ipAddress: '1.2.3.4', deviceFingerprint: 'ua', privilegeLevel: 0 },
      res as unknown as Response,
    );

    expect(res.cookies.length).toBe(1);
    const cookie = res.cookies[0];

    expect(cookie.name).toBe(identityConfig.sessions.cookieName);
    expect(cookie.options.httpOnly).toBe(true);
    expect(cookie.options.secure).toBe(identityConfig.sessions.cookieSecure);
    expect(cookie.options.sameSite).toBe(identityConfig.sessions.cookieSameSite);
    expect(cookie.options.path).toBe(identityConfig.sessions.cookiePath);
    // Domain should be absent by default (host-only cookie)
    expect(cookie.options.domain).toBeUndefined();
  });
});
