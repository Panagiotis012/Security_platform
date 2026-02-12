/**
 * Rate limit store with token-bucket algorithm.
 *
 * Provides:
 *  - An abstract `RateLimitStore` interface so Redis / Memcached / etc.
 *    can be plugged in without changing calling code.
 *  - A production-quality `InMemoryRateLimitStore` for single-process
 *    deployments and testing.
 *  - Per-IP, per-identity, and per-route limiting via composite keys.
 *  - Burst / steady rate support (token bucket).
 *  - Greylisting support for suspicious sources.
 *
 * Token bucket overview:
 *   - Each bucket holds up to `burstSize` tokens.
 *   - Tokens are added at a steady rate of `refillRate` tokens / second.
 *   - Each request consumes 1 token. If the bucket is empty the request
 *     is rejected.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RateLimitConfig {
  /** Maximum number of tokens (burst capacity). */
  burstSize: number;
  /** Tokens added per second (steady-state rate). */
  refillRatePerSecond: number;
}

export interface RateLimitResult {
  /** Whether the request is allowed. */
  allowed: boolean;
  /** Tokens remaining after this request (-1 if denied). */
  remaining: number;
  /** Milliseconds until the bucket next has a token (0 if allowed). */
  retryAfterMs: number;
  /** The total burst capacity for this key. */
  limit: number;
}

export interface GreylistEntry {
  /** The greylisted key. */
  key: string;
  /** Reason for greylisting. */
  reason: string;
  /** When the greylist entry was created. */
  createdAt: number;
  /** When the greylist entry expires (epoch ms). */
  expiresAt: number;
  /**
   * Rate multiplier while greylisted (e.g. 0.5 = half the normal rate).
   * A value of 0 blocks entirely.
   */
  rateMultiplier: number;
}

// ---------------------------------------------------------------------------
// Abstract interface
// ---------------------------------------------------------------------------

/**
 * Abstract rate-limit store.
 *
 * Implement this interface for Redis, DynamoDB, etc.
 */
export interface RateLimitStore {
  /**
   * Consume one token for the given key.
   * Returns whether the request is allowed and the current state.
   */
  consume(key: string, config: RateLimitConfig): Promise<RateLimitResult>;

  /**
   * Peek at the current state without consuming a token.
   */
  peek(key: string, config: RateLimitConfig): Promise<RateLimitResult>;

  /**
   * Reset (delete) the bucket for a key.
   */
  reset(key: string): Promise<void>;

  /**
   * Add a key to the greylist.
   */
  greylist(entry: GreylistEntry): Promise<void>;

  /**
   * Check if a key is greylisted.
   */
  isGreylisted(key: string): Promise<GreylistEntry | null>;

  /**
   * Remove a key from the greylist.
   */
  ungreylist(key: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Token bucket state
// ---------------------------------------------------------------------------

interface TokenBucket {
  /** Current number of available tokens. */
  tokens: number;
  /** Timestamp (epoch ms) of the last refill. */
  lastRefill: number;
}

// ---------------------------------------------------------------------------
// InMemoryRateLimitStore
// ---------------------------------------------------------------------------

export class InMemoryRateLimitStore implements RateLimitStore {
  private readonly buckets: Map<string, TokenBucket> = new Map();
  private readonly greylistMap: Map<string, GreylistEntry> = new Map();

  /**
   * Interval handle for periodic cleanup of expired entries.
   * Call `dispose()` to clear.
   */
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  /**
   * @param cleanupIntervalMs  How often to sweep expired buckets and
   *   greylist entries. Set to 0 to disable automatic cleanup.
   */
  constructor(cleanupIntervalMs: number = 60_000) {
    if (cleanupIntervalMs > 0) {
      this.cleanupTimer = setInterval(() => {
        this.cleanup();
      }, cleanupIntervalMs);

      // Allow the process to exit even if the timer is pending.
      if (this.cleanupTimer && typeof this.cleanupTimer === 'object' && 'unref' in this.cleanupTimer) {
        this.cleanupTimer.unref();
      }
    }
  }

  // -----------------------------------------------------------------------
  // RateLimitStore implementation
  // -----------------------------------------------------------------------

  public async consume(
    key: string,
    config: RateLimitConfig,
  ): Promise<RateLimitResult> {
    const effectiveConfig = await this.applyGreylist(key, config);
    const bucket = this.getOrCreateBucket(key, effectiveConfig);
    this.refill(bucket, effectiveConfig);

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return {
        allowed: true,
        remaining: Math.floor(bucket.tokens),
        retryAfterMs: 0,
        limit: effectiveConfig.burstSize,
      };
    }

    // Denied – calculate retry-after.
    const tokensNeeded = 1 - bucket.tokens;
    const retryAfterMs = Math.ceil(
      (tokensNeeded / effectiveConfig.refillRatePerSecond) * 1000,
    );

    return {
      allowed: false,
      remaining: -1,
      retryAfterMs,
      limit: effectiveConfig.burstSize,
    };
  }

  public async peek(
    key: string,
    config: RateLimitConfig,
  ): Promise<RateLimitResult> {
    const effectiveConfig = await this.applyGreylist(key, config);
    const bucket = this.getOrCreateBucket(key, effectiveConfig);
    // Refill without consuming.
    this.refill(bucket, effectiveConfig);

    const allowed = bucket.tokens >= 1;
    const retryAfterMs = allowed
      ? 0
      : Math.ceil(((1 - bucket.tokens) / effectiveConfig.refillRatePerSecond) * 1000);

    return {
      allowed,
      remaining: Math.floor(bucket.tokens),
      retryAfterMs,
      limit: effectiveConfig.burstSize,
    };
  }

  public async reset(key: string): Promise<void> {
    this.buckets.delete(key);
  }

  public async greylist(entry: GreylistEntry): Promise<void> {
    this.greylistMap.set(entry.key, { ...entry });
  }

  public async isGreylisted(key: string): Promise<GreylistEntry | null> {
    const entry = this.greylistMap.get(key);
    if (!entry) return null;

    // Expired?
    if (Date.now() > entry.expiresAt) {
      this.greylistMap.delete(key);
      return null;
    }

    return { ...entry };
  }

  public async ungreylist(key: string): Promise<void> {
    this.greylistMap.delete(key);
  }

  // -----------------------------------------------------------------------
  // Lifecycle
  // -----------------------------------------------------------------------

  /**
   * Stop the background cleanup timer and release resources.
   */
  public dispose(): void {
    if (this.cleanupTimer !== null) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.buckets.clear();
    this.greylistMap.clear();
  }

  /**
   * Return the number of active buckets (for monitoring).
   */
  public get size(): number {
    return this.buckets.size;
  }

  // -----------------------------------------------------------------------
  // Internals
  // -----------------------------------------------------------------------

  private getOrCreateBucket(
    key: string,
    config: RateLimitConfig,
  ): TokenBucket {
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = {
        tokens: config.burstSize,
        lastRefill: Date.now(),
      };
      this.buckets.set(key, bucket);
    }
    return bucket;
  }

  /**
   * Add tokens based on elapsed time since last refill.
   */
  private refill(bucket: TokenBucket, config: RateLimitConfig): void {
    const now = Date.now();
    const elapsed = (now - bucket.lastRefill) / 1000; // seconds
    if (elapsed <= 0) return;

    const tokensToAdd = elapsed * config.refillRatePerSecond;
    bucket.tokens = Math.min(config.burstSize, bucket.tokens + tokensToAdd);
    bucket.lastRefill = now;
  }

  /**
   * If the key is greylisted, adjust the rate config accordingly.
   */
  private async applyGreylist(
    key: string,
    config: RateLimitConfig,
  ): Promise<RateLimitConfig> {
    const entry = await this.isGreylisted(key);
    if (!entry) return config;

    return {
      burstSize: Math.max(1, Math.floor(config.burstSize * entry.rateMultiplier)),
      refillRatePerSecond: Math.max(
        0.01, // floor to prevent division by zero
        config.refillRatePerSecond * entry.rateMultiplier,
      ),
    };
  }

  /**
   * Periodic cleanup: remove expired greylist entries and stale buckets
   * that have been full for longer than a reasonable TTL.
   */
  private cleanup(): void {
    const now = Date.now();
    const staleTTL = 5 * 60 * 1000; // 5 minutes of inactivity

    // Expired greylist entries.
    for (const [key, entry] of this.greylistMap.entries()) {
      if (now > entry.expiresAt) {
        this.greylistMap.delete(key);
      }
    }

    // Stale buckets (no activity for staleTTL).
    for (const [key, bucket] of this.buckets.entries()) {
      if (now - bucket.lastRefill > staleTTL) {
        this.buckets.delete(key);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Key builders
// ---------------------------------------------------------------------------

/**
 * Build a rate-limit key scoped to an IP address.
 */
export function rateLimitKeyByIP(ip: string): string {
  return `rl:ip:${ip}`;
}

/**
 * Build a rate-limit key scoped to an identity (user ID, service account, etc.).
 */
export function rateLimitKeyByIdentity(identityId: string): string {
  return `rl:id:${identityId}`;
}

/**
 * Build a rate-limit key scoped to a route.
 */
export function rateLimitKeyByRoute(method: string, path: string): string {
  return `rl:route:${method.toUpperCase()}:${path}`;
}

/**
 * Build a composite rate-limit key (e.g. per-identity + per-route).
 */
export function rateLimitKeyComposite(...parts: string[]): string {
  return `rl:composite:${parts.join(':')}`;
}
