/**
 * Redis-backed session store for the Identity Plane.
 *
 * Production implementation of SessionStore interface, providing:
 *  - Distributed session storage with TTL-based auto-expiration.
 *  - Atomic multi-operation transactions (MULTI/EXEC).
 *  - User-to-session index for efficient lookups.
 *  - Fail-closed behavior when Redis is unavailable.
 *  - Health check and graceful shutdown support.
 *  - Key prefix support for multi-tenant deployments.
 */

import type Redis from 'ioredis';
import { v4 as uuidv4 } from 'uuid';
import type {
  SessionStore,
  SessionData,
  SessionCreateInput,
} from './session-store';

type LoggerLike = {
  debug?: (message: string, meta?: Record<string, unknown>) => void;
  info?: (message: string, meta?: Record<string, unknown>) => void;
  warn?: (message: string, meta?: Record<string, unknown>) => void;
  error?: (message: string, meta?: Record<string, unknown>) => void;
};

// ---------------------------------------------------------------------------
// RedisSessionStore
// ---------------------------------------------------------------------------

/**
 * Production Redis-backed session store.
 *
 * Stores session data as Redis hashes with TTL, maintains a user index
 * as Redis sets, and provides atomic operations via MULTI/EXEC.
 */
export class RedisSessionStore implements SessionStore {
  private readonly redis: Redis;
  private readonly keyPrefix: string;
  private readonly logger?: LoggerLike;

  /**
   * Create a new Redis session store.
   *
   * @param redisClient - Configured ioredis client
   * @param options - Configuration options
   * @param options.keyPrefix - Prefix for all Redis keys (default: "session:")
   * @param options.logger - Optional logger for debugging
   */
  constructor(
    redisClient: Redis,
    options?: {
      keyPrefix?: string;
      logger?: LoggerLike;
    }
  ) {
    this.redis = redisClient;
    this.keyPrefix = options?.keyPrefix ?? 'session:';
    this.logger = options?.logger;
  }

  // -----------------------------------------------------------------------
  // SessionStore implementation
  // -----------------------------------------------------------------------

  /**
   * Create a new session.
   *
   * @param input - Session creation parameters
   * @returns The created session with generated ID and timestamps
   * @throws If Redis is unavailable (fail-closed)
   */
  public async create(input: SessionCreateInput): Promise<SessionData> {
    try {
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

      // Calculate TTL from expiresAt
      const ttlSeconds = this.calculateTTL(session.expiresAt);

      // Use transaction to atomically create session and update user index
      const pipeline = this.redis.pipeline();

      // Store session data as a Redis hash
      const sessionKey = this.makeSessionKey(session.id);
      pipeline.hset(
        sessionKey,
        'id',
        session.id,
        'userId',
        session.userId,
        'createdAt',
        session.createdAt,
        'lastActivity',
        session.lastActivity,
        'expiresAt',
        session.expiresAt,
        'ipAddress',
        session.ipAddress,
        'deviceFingerprint',
        session.deviceFingerprint,
        'privilegeLevel',
        session.privilegeLevel.toString(),
        'metadata',
        JSON.stringify(session.metadata)
      );

      // Set TTL on the session key
      pipeline.expire(sessionKey, ttlSeconds);

      // Add session ID to user index
      const userIndexKey = this.makeUserIndexKey(session.userId);
      pipeline.sadd(userIndexKey, session.id);

      // Execute transaction
      await pipeline.exec();

      this.logger?.debug?.('Session created', {
        sessionId: session.id,
        userId: session.userId,
      });

      return session;
    } catch (err) {
      this.logger?.error?.('Failed to create session', { error: err });
      throw new Error('Session creation failed: Redis unavailable');
    }
  }

  /**
   * Retrieve a session by ID.
   *
   * @param id - Session ID
   * @returns Session data if found and not expired, null otherwise
   * @throws If Redis is unavailable (fail-closed)
   */
  public async get(id: string): Promise<SessionData | null> {
    try {
      const sessionKey = this.makeSessionKey(id);
      const data = await this.redis.hgetall(sessionKey);

      if (!data || Object.keys(data).length === 0) {
        return null;
      }

      // Check if expired
      const expiresAt = new Date(data.expiresAt ?? '').getTime();
      if (expiresAt <= Date.now()) {
        // Session is expired; clean it up transparently
        await this.delete(id);
        return null;
      }

      return this.hashToSessionData(data);
    } catch (err) {
      this.logger?.error?.('Failed to get session', { id, error: err });
      throw new Error('Session retrieval failed: Redis unavailable');
    }
  }

  /**
   * Update mutable fields of a session.
   *
   * @param id - Session ID
   * @param patch - Partial update with mutable fields only
   * @returns Updated session or null if not found
   * @throws If Redis is unavailable (fail-closed)
   */
  public async update(
    id: string,
    patch: Partial<
      Pick<SessionData, 'lastActivity' | 'privilegeLevel' | 'metadata' | 'expiresAt'>
    >
  ): Promise<SessionData | null> {
    try {
      const sessionKey = this.makeSessionKey(id);

      // Fetch current session
      const data = await this.redis.hgetall(sessionKey);
      if (!data || Object.keys(data).length === 0) {
        return null;
      }

      // Check if expired
      const expiresAt = new Date(data.expiresAt ?? '').getTime();
      if (expiresAt <= Date.now()) {
        await this.delete(id);
        return null;
      }

      // Build update
      const updates: Record<string, string> = {};

      if (patch.lastActivity !== undefined) {
        updates.lastActivity = patch.lastActivity;
      }

      if (patch.privilegeLevel !== undefined) {
        updates.privilegeLevel = patch.privilegeLevel.toString();
      }

      if (patch.expiresAt !== undefined) {
        updates.expiresAt = patch.expiresAt;
      }

      if (patch.metadata !== undefined) {
        // Merge metadata
        const existing = JSON.parse(data.metadata || '{}') as Record<string, unknown>;
        const merged = { ...existing, ...patch.metadata };
        updates.metadata = JSON.stringify(merged);
      }

      // Update session in Redis
      const pipeline = this.redis.pipeline();
      pipeline.hset(sessionKey, updates);

      // If expiresAt changed, update TTL
      if (patch.expiresAt !== undefined) {
        const ttlSeconds = this.calculateTTL(patch.expiresAt);
        pipeline.expire(sessionKey, ttlSeconds);
      }

      await pipeline.exec();

      // Fetch and return updated session
      const updatedData = await this.redis.hgetall(sessionKey);
      return this.hashToSessionData(updatedData);
    } catch (err) {
      this.logger?.error?.('Failed to update session', { id, error: err });
      throw new Error('Session update failed: Redis unavailable');
    }
  }

  /**
   * Delete a session by ID.
   *
   * @param id - Session ID
   * @returns true if session existed, false otherwise
   * @throws If Redis is unavailable (fail-closed)
   */
  public async delete(id: string): Promise<boolean> {
    try {
      const sessionKey = this.makeSessionKey(id);

      // Get session to retrieve userId for index cleanup
      const data = await this.redis.hgetall(sessionKey);
      if (!data || Object.keys(data).length === 0) {
        return false;
      }

      const userId = data.userId;

      // Use transaction to atomically delete session and clean index
      const pipeline = this.redis.pipeline();
      pipeline.del(sessionKey);
      if (userId) {
        const userIndexKey = this.makeUserIndexKey(userId);
        pipeline.srem(userIndexKey, id);
      }

      await pipeline.exec();

      this.logger?.debug?.('Session deleted', { id, userId });

      return true;
    } catch (err) {
      this.logger?.error?.('Failed to delete session', { id, error: err });
      throw new Error('Session deletion failed: Redis unavailable');
    }
  }

  /**
   * Delete all sessions for a user (useful for compromise response).
   *
   * @param userId - User ID
   * @returns Number of sessions deleted
   * @throws If Redis is unavailable (fail-closed)
   */
  public async deleteByUserId(userId: string): Promise<number> {
    try {
      const userIndexKey = this.makeUserIndexKey(userId);

      // Get all session IDs for this user
      const sessionIds = await this.redis.smembers(userIndexKey);

      if (sessionIds.length === 0) {
        return 0;
      }

      // Delete all sessions in a transaction
      const pipeline = this.redis.pipeline();

      for (const sessionId of sessionIds) {
        const sessionKey = this.makeSessionKey(sessionId);
        pipeline.del(sessionKey);
      }

      // Clean up the user index
      pipeline.del(userIndexKey);

      await pipeline.exec();

      this.logger?.debug?.('All sessions deleted for user', {
        userId,
        count: sessionIds.length,
      });

      return sessionIds.length;
    } catch (err) {
      this.logger?.error?.('Failed to delete sessions for user', {
        userId,
        error: err,
      });
      throw new Error('Bulk session deletion failed: Redis unavailable');
    }
  }

  /**
   * List all active (non-expired) sessions for a user.
   *
   * @param userId - User ID
   * @returns Array of session data
   * @throws If Redis is unavailable (fail-closed)
   */
  public async listByUserId(userId: string): Promise<SessionData[]> {
    try {
      const userIndexKey = this.makeUserIndexKey(userId);

      // Get all session IDs for this user
      const sessionIds = await this.redis.smembers(userIndexKey);

      if (sessionIds.length === 0) {
        return [];
      }

      const now = Date.now();
      const results: SessionData[] = [];
      const expiredIds: string[] = [];

      // Fetch all sessions
      for (const sessionId of sessionIds) {
        const sessionKey = this.makeSessionKey(sessionId);
        const data = await this.redis.hgetall(sessionKey);

        if (!data || Object.keys(data).length === 0) {
          // Session was deleted or doesn't exist
          expiredIds.push(sessionId);
          continue;
        }

        // Check expiration
        const expiresAt = new Date(data.expiresAt ?? '').getTime();
        if (expiresAt <= now) {
          expiredIds.push(sessionId);
          continue;
        }

        results.push(this.hashToSessionData(data));
      }

      // Clean up expired/missing sessions from index
      if (expiredIds.length > 0) {
        await this.redis.srem(userIndexKey, ...expiredIds);
      }

      return results;
    } catch (err) {
      this.logger?.error?.('Failed to list sessions for user', {
        userId,
        error: err,
      });
      throw new Error('Session listing failed: Redis unavailable');
    }
  }

  // -----------------------------------------------------------------------
  // Lifecycle & Health
  // -----------------------------------------------------------------------

  /**
   * Disconnect from Redis and release resources.
   */
  public async destroy(): Promise<void> {
    try {
      await this.redis.quit();
      this.logger?.debug?.('Session store disconnected');
    } catch (err) {
      this.logger?.warn?.('Error during Redis disconnect', { error: err });
    }
  }

  /**
   * Check if Redis is healthy.
   */
  public async isHealthy(): Promise<boolean> {
    try {
      const pong = await this.redis.ping();
      return pong === 'PONG';
    } catch (err) {
      this.logger?.warn?.('Health check failed', { error: err });
      return false;
    }
  }

  // -----------------------------------------------------------------------
  // Internals
  // -----------------------------------------------------------------------

  /**
   * Convert a Redis hash to SessionData.
   */
  private hashToSessionData(hash: Record<string, string>): SessionData {
    return {
      id: hash.id ?? '',
      userId: hash.userId ?? '',
      createdAt: hash.createdAt ?? '',
      lastActivity: hash.lastActivity ?? '',
      expiresAt: hash.expiresAt ?? '',
      ipAddress: hash.ipAddress ?? '',
      deviceFingerprint: hash.deviceFingerprint ?? '',
      privilegeLevel: parseInt(hash.privilegeLevel ?? '0', 10),
      metadata: JSON.parse(hash.metadata ?? '{}'),
    };
  }

  /**
   * Calculate TTL in seconds from an expiresAt ISO timestamp.
   */
  private calculateTTL(expiresAtIso: string): number {
    const expiresAt = new Date(expiresAtIso).getTime();
    const ttlMs = Math.max(0, expiresAt - Date.now());
    // Add 1 second minimum, otherwise round up
    return Math.max(1, Math.ceil(ttlMs / 1000));
  }

  /**
   * Build the Redis key for session data.
   */
  private makeSessionKey(sessionId: string): string {
    return `${this.keyPrefix}data:${sessionId}`;
  }

  /**
   * Build the Redis key for the user-to-sessions index.
   */
  private makeUserIndexKey(userId: string): string {
    return `${this.keyPrefix}user:${userId}`;
  }
}
