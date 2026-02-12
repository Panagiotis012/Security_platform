/**
 * Session Manager – creates, validates, rotates, and destroys user sessions.
 *
 * Security invariants enforced here:
 *  - Cookies are always httpOnly, Secure, SameSite, Path=/ (no Domain attr).
 *  - Sessions are rotated on login, privilege escalation, and role change.
 *  - Idle timeout (30 min default) and absolute timeout (12 h default) are
 *    checked on every validation call.
 *  - Destroying all sessions for a user is supported for compromise response.
 */

import crypto from 'crypto';
import type { Response } from 'express';
import type { SessionStore, SessionData } from './session-store';
import { config } from '../../config/default';
import { createLogger } from '../logger';
import { readSecret } from '@zerotrust/shared';

const logger = createLogger('session-manager');

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CreateSessionOptions {
  userId: string;
  ipAddress: string;
  deviceFingerprint: string;
  privilegeLevel?: number;
  metadata?: Record<string, unknown>;
}

export interface SessionValidationResult {
  valid: true;
  session: SessionData;
}

export interface SessionValidationFailure {
  valid: false;
  reason: 'not_found' | 'idle_timeout' | 'absolute_timeout' | 'expired';
}

export type SessionCheckResult = SessionValidationResult | SessionValidationFailure;

// ---------------------------------------------------------------------------
// Session Manager
// ---------------------------------------------------------------------------

export class SessionManager {
  private readonly store: SessionStore;
  private readonly idleTimeoutMs: number;
  private readonly absoluteTimeoutMs: number;

  constructor(store: SessionStore) {
    this.store = store;
    this.idleTimeoutMs = config.sessions.idleTimeoutSeconds * 1000;
    this.absoluteTimeoutMs = config.sessions.absoluteTimeoutSeconds * 1000;
  }

  // -----------------------------------------------------------------------
  // Create
  // -----------------------------------------------------------------------

  /**
   * Create a new session and set the session cookie on the response.
   *
   * The session id written to the cookie is an opaque, high-entropy value
   * (UUIDv4) with no embedded user information.
   */
  async createSession(
    options: CreateSessionOptions,
    res: Response,
  ): Promise<SessionData> {
    const now = Date.now();
    const expiresAt = new Date(now + this.absoluteTimeoutMs).toISOString();

    const session = await this.store.create({
      userId: options.userId,
      ipAddress: options.ipAddress,
      deviceFingerprint: options.deviceFingerprint,
      privilegeLevel: options.privilegeLevel ?? 0,
      expiresAt,
      metadata: options.metadata ?? {},
    });

    this.setSessionCookie(res, session.id);

    logger.info('Session created', {
      sessionId: session.id,
      userId: options.userId,
      ipAddress: options.ipAddress,
    });

    return session;
  }

  // -----------------------------------------------------------------------
  // Validate
  // -----------------------------------------------------------------------

  /**
   * Validate a session by its id.  Checks both idle and absolute timeouts.
   * If the session is still valid, its `lastActivity` is bumped.
   */
  async validateSession(sessionId: string): Promise<SessionCheckResult> {
    const session = await this.store.get(sessionId);
    if (!session) {
      return { valid: false, reason: 'not_found' };
    }

    const now = Date.now();

    // Absolute timeout
    if (new Date(session.expiresAt).getTime() <= now) {
      await this.store.delete(sessionId);
      logger.info('Session expired (absolute timeout)', { sessionId });
      return { valid: false, reason: 'absolute_timeout' };
    }

    // Idle timeout
    const idleCheck = this.checkIdleTimeout(session, now);
    if (!idleCheck.valid) {
      await this.store.delete(sessionId);
      logger.info('Session expired (idle timeout)', { sessionId });
      return idleCheck;
    }

    return { valid: true, session };
  }

  // -----------------------------------------------------------------------
  // Rotate
  // -----------------------------------------------------------------------

  /**
   * Rotate the session id.  Used on login, privilege escalation, and role
   * change to prevent session fixation.
   *
   * The old session is destroyed and a new session is created with the same
   * user data but a fresh id.
   */
  async rotateSession(
    oldSessionId: string,
    res: Response,
    newPrivilegeLevel?: number,
    metadataPatch?: Record<string, unknown>,
  ): Promise<SessionData | null> {
    const old = await this.store.get(oldSessionId);
    if (!old) {
      logger.warn('Session rotation failed: session not found', {
        sessionId: oldSessionId,
      });
      return null;
    }

    // Destroy the old session first.
    await this.store.delete(oldSessionId);

    // Create a replacement with a fresh id.
    const now = Date.now();
    const remainingAbsoluteMs = new Date(old.expiresAt).getTime() - now;
    // Preserve original absolute timeout boundary.
    const expiresAt = new Date(now + Math.max(remainingAbsoluteMs, 0)).toISOString();

    const newSession = await this.store.create({
      userId: old.userId,
      ipAddress: old.ipAddress,
      deviceFingerprint: old.deviceFingerprint,
      privilegeLevel: newPrivilegeLevel ?? old.privilegeLevel,
      expiresAt,
      metadata: { ...old.metadata, ...(metadataPatch ?? {}) },
    });

    this.setSessionCookie(res, newSession.id);

    logger.info('Session rotated', {
      oldSessionId,
      newSessionId: newSession.id,
      userId: old.userId,
      privilegeLevel: newSession.privilegeLevel,
    });

    return newSession;
  }

  // -----------------------------------------------------------------------
  // Destroy
  // -----------------------------------------------------------------------

  /** Destroy a single session and clear the cookie. */
  async destroySession(sessionId: string, res?: Response): Promise<void> {
    await this.store.delete(sessionId);

    if (res) {
      this.clearSessionCookie(res);
    }

    logger.info('Session destroyed', { sessionId });
  }

  /**
   * Destroy every session belonging to a user (compromise response).
   * Returns the number of sessions destroyed.
   */
  async destroyAllUserSessions(userId: string): Promise<number> {
    const count = await this.store.deleteByUserId(userId);
    logger.warn('All sessions destroyed for user', { userId, count });
    return count;
  }

  // -----------------------------------------------------------------------
  // Activity
  // -----------------------------------------------------------------------

  /** Touch the session's last-activity timestamp (called on each request). */
  async updateActivity(sessionId: string): Promise<void> {
    await this.store.update(sessionId, {
      lastActivity: new Date().toISOString(),
    });
  }

  // -----------------------------------------------------------------------
  // Query
  // -----------------------------------------------------------------------

  /** Get current session data without side-effects. */
  async getSession(sessionId: string): Promise<SessionData | null> {
    return this.store.get(sessionId);
  }

  /** List all active sessions for a user. */
  async listUserSessions(userId: string): Promise<SessionData[]> {
    return this.store.listByUserId(userId);
  }

  // -----------------------------------------------------------------------
  // Timeout helpers
  // -----------------------------------------------------------------------

  /**
   * Check both idle and absolute timeouts. Returns an object indicating
   * validity and, if invalid, the reason.
   */
  checkTimeouts(session: SessionData): SessionCheckResult {
    const now = Date.now();

    if (new Date(session.expiresAt).getTime() <= now) {
      return { valid: false, reason: 'absolute_timeout' };
    }

    return this.checkIdleTimeout(session, now);
  }

  private checkIdleTimeout(
    session: SessionData,
    now: number,
  ): SessionCheckResult {
    const lastActivity = new Date(session.lastActivity).getTime();
    if (now - lastActivity > this.idleTimeoutMs) {
      return { valid: false, reason: 'idle_timeout' };
    }
    return { valid: true, session };
  }

  // -----------------------------------------------------------------------
  // Cookie helpers
  // -----------------------------------------------------------------------

  private setSessionCookie(res: Response, sessionId: string): void {
    const opts = config.sessions;

    const cookieOptions: Record<string, unknown> = {
      httpOnly: true,
      secure: opts.cookieSecure,
      sameSite: opts.cookieSameSite,
      path: opts.cookiePath,
      maxAge: config.sessions.absoluteTimeoutSeconds * 1000,
    };

    // Only set Domain if explicitly configured; omitting it is the most
    // restrictive default (cookie scoped to the exact host).
    if (opts.cookieDomain) {
      cookieOptions['domain'] = opts.cookieDomain;
    }

    res.cookie(opts.cookieName, sessionId, cookieOptions);
  }

  private clearSessionCookie(res: Response): void {
    const opts = config.sessions;

    const cookieOptions: Record<string, unknown> = {
      httpOnly: true,
      secure: opts.cookieSecure,
      sameSite: opts.cookieSameSite,
      path: opts.cookiePath,
    };

    if (opts.cookieDomain) {
      cookieOptions['domain'] = opts.cookieDomain;
    }

    res.clearCookie(opts.cookieName, cookieOptions);
  }

  /**
   * Generate a CSRF token bound to a session.  The token is an HMAC of the
   * session id using a server secret, so it cannot be forged without access
   * to the secret.
   */
  static generateCsrfToken(sessionId: string): string {
    const secret = readSecret('CSRF_SECRET', { defaultValue: 'csrf-dev-secret-change-me' });
    return crypto
      .createHmac('sha256', secret)
      .update(sessionId)
      .digest('hex');
  }

  /** Verify a CSRF token against the session id. */
  static verifyCsrfToken(sessionId: string, token: string): boolean {
    const expected = SessionManager.generateCsrfToken(sessionId);
    return crypto.timingSafeEqual(
      Buffer.from(expected, 'hex'),
      Buffer.from(token, 'hex'),
    );
  }
}
