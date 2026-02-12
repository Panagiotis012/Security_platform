/**
 * Session storage abstraction for the Identity Plane.
 *
 * Provides an interface-based design so the backing store can be swapped from
 * the bundled in-memory implementation to Redis (or any other store) in
 * production without changing consumer code.
 */

import { v4 as uuidv4 } from 'uuid';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SessionData {
  /** Opaque session identifier (unguessable, high-entropy). */
  id: string;
  /** The authenticated user this session belongs to. */
  userId: string;
  /** ISO-8601 timestamp of session creation. */
  createdAt: string;
  /** ISO-8601 timestamp of last activity (used for idle timeout). */
  lastActivity: string;
  /** ISO-8601 timestamp at which this session unconditionally expires. */
  expiresAt: string;
  /** IP address of the client that created the session. */
  ipAddress: string;
  /** Device fingerprint supplied by the client at login time. */
  deviceFingerprint: string;
  /**
   * Current privilege / step-up level:
   *   0 = basic (password or OIDC only)
   *   1 = MFA verified
   *   2 = recent MFA (within step-up TTL)
   */
  privilegeLevel: number;
  /** Arbitrary metadata bag (never contains secrets). */
  metadata: Record<string, unknown>;
}

export type SessionCreateInput = Omit<SessionData, 'id' | 'createdAt' | 'lastActivity'>;

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

export interface SessionStore {
  /** Persist a new session and return its data (id is generated internally). */
  create(input: SessionCreateInput): Promise<SessionData>;

  /** Retrieve a session by its id. Returns null when not found. */
  get(id: string): Promise<SessionData | null>;

  /** Update mutable fields of an existing session. Returns the updated session or null. */
  update(id: string, patch: Partial<Pick<SessionData, 'lastActivity' | 'privilegeLevel' | 'metadata' | 'expiresAt'>>): Promise<SessionData | null>;

  /** Delete a single session. Returns true if it existed. */
  delete(id: string): Promise<boolean>;

  /** Delete every session belonging to a user (compromise response). */
  deleteByUserId(userId: string): Promise<number>;

  /** List all active sessions for a user (useful for "active sessions" UI). */
  listByUserId(userId: string): Promise<SessionData[]>;
}

// ---------------------------------------------------------------------------
// In-memory implementation (development / testing)
// ---------------------------------------------------------------------------

/**
 * Non-durable, single-process session store.  Suitable for development and
 * tests.  In production, replace with a Redis-backed implementation that
 * shares state across instances.
 */
export class InMemorySessionStore implements SessionStore {
  /** Primary index: session id -> session data. */
  private readonly sessions = new Map<string, SessionData>();

  /** Secondary index: userId -> Set of session ids (for fast user lookups). */
  private readonly userIndex = new Map<string, Set<string>>();

  /** Interval handle for the periodic eviction sweep. */
  private evictionTimer: ReturnType<typeof setInterval> | null = null;

  constructor(evictionIntervalMs = 60_000) {
    // Periodically purge expired sessions so memory does not grow unbounded.
    this.evictionTimer = setInterval(() => this.evictExpired(), evictionIntervalMs);
    // Allow the Node process to exit even if the timer is still running.
    if (this.evictionTimer.unref) {
      this.evictionTimer.unref();
    }
  }

  async create(input: SessionCreateInput): Promise<SessionData> {
    const now = new Date().toISOString();
    const session: SessionData = {
      id: uuidv4(),
      userId: input.userId,
      createdAt: now,
      lastActivity: now,
      expiresAt: input.expiresAt,
      ipAddress: input.ipAddress,
      deviceFingerprint: input.deviceFingerprint,
      privilegeLevel: input.privilegeLevel,
      metadata: { ...input.metadata },
    };

    this.sessions.set(session.id, session);
    this.addToUserIndex(session.userId, session.id);

    return { ...session };
  }

  async get(id: string): Promise<SessionData | null> {
    const session = this.sessions.get(id);
    if (!session) return null;

    // Transparently evict if expired.
    if (new Date(session.expiresAt).getTime() <= Date.now()) {
      await this.delete(id);
      return null;
    }

    return { ...session };
  }

  async update(
    id: string,
    patch: Partial<Pick<SessionData, 'lastActivity' | 'privilegeLevel' | 'metadata' | 'expiresAt'>>,
  ): Promise<SessionData | null> {
    const session = this.sessions.get(id);
    if (!session) return null;

    if (patch.lastActivity !== undefined) session.lastActivity = patch.lastActivity;
    if (patch.privilegeLevel !== undefined) session.privilegeLevel = patch.privilegeLevel;
    if (patch.expiresAt !== undefined) session.expiresAt = patch.expiresAt;
    if (patch.metadata !== undefined) {
      session.metadata = { ...session.metadata, ...patch.metadata };
    }

    this.sessions.set(id, session);
    return { ...session };
  }

  async delete(id: string): Promise<boolean> {
    const session = this.sessions.get(id);
    if (!session) return false;

    this.sessions.delete(id);
    this.removeFromUserIndex(session.userId, id);
    return true;
  }

  async deleteByUserId(userId: string): Promise<number> {
    const ids = this.userIndex.get(userId);
    if (!ids || ids.size === 0) return 0;

    const count = ids.size;
    for (const id of ids) {
      this.sessions.delete(id);
    }
    this.userIndex.delete(userId);
    return count;
  }

  async listByUserId(userId: string): Promise<SessionData[]> {
    const ids = this.userIndex.get(userId);
    if (!ids) return [];

    const now = Date.now();
    const results: SessionData[] = [];

    for (const id of ids) {
      const session = this.sessions.get(id);
      if (session && new Date(session.expiresAt).getTime() > now) {
        results.push({ ...session });
      }
    }

    return results;
  }

  /** Stop the background eviction timer (call during graceful shutdown). */
  public destroy(): void {
    if (this.evictionTimer) {
      clearInterval(this.evictionTimer);
      this.evictionTimer = null;
    }
  }

  // -----------------------------------------------------------------------
  // Internal helpers
  // -----------------------------------------------------------------------

  private addToUserIndex(userId: string, sessionId: string): void {
    let set = this.userIndex.get(userId);
    if (!set) {
      set = new Set();
      this.userIndex.set(userId, set);
    }
    set.add(sessionId);
  }

  private removeFromUserIndex(userId: string, sessionId: string): void {
    const set = this.userIndex.get(userId);
    if (!set) return;
    set.delete(sessionId);
    if (set.size === 0) {
      this.userIndex.delete(userId);
    }
  }

  private evictExpired(): void {
    const now = Date.now();
    for (const [id, session] of this.sessions) {
      if (new Date(session.expiresAt).getTime() <= now) {
        this.sessions.delete(id);
        this.removeFromUserIndex(session.userId, id);
      }
    }
  }
}
