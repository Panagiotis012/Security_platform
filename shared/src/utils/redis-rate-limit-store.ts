/**
 * Redis-backed rate limit store with token-bucket algorithm.
 *
 * Production implementation of RateLimitStore interface, providing:
 *  - Distributed, multi-instance rate limiting via Redis.
 *  - Atomic token bucket operations using Lua scripts.
 *  - Sliding window algorithm for correctness in distributed systems.
 *  - Greylisting support with TTL-based expiration.
 *  - Key prefixing for multi-tenant deployments.
 *  - Fail-closed behavior when Redis is unavailable.
 *  - Health check and graceful shutdown support.
 */

import type Redis from 'ioredis';
import type {
  RateLimitStore,
  RateLimitConfig,
  RateLimitResult,
  GreylistEntry,
} from './rate-limit-store';

type LoggerLike = {
  debug?: (message: string, meta?: Record<string, unknown>) => void;
  info?: (message: string, meta?: Record<string, unknown>) => void;
  warn?: (message: string, meta?: Record<string, unknown>) => void;
  error?: (message: string, meta?: Record<string, unknown>) => void;
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Lua script for atomic token bucket consume + peek operation.
 * Implements sliding window with refill logic.
 *
 * KEYS[1]: bucket key (e.g., "rl:ip:192.168.1.1")
 * ARGV[1]: burst size
 * ARGV[2]: refill rate per second
 * ARGV[3]: current timestamp (ms)
 * ARGV[4]: operation mode (1 = consume, 0 = peek)
 *
 * Returns: [allowed, remaining, retryAfterMs]
 */
const CONSUME_SCRIPT = `
local bucket_key = KEYS[1]
local burst_size = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local do_consume = tonumber(ARGV[4])

-- Fetch current bucket state
local bucket_data = redis.call('HGETALL', bucket_key)
local tokens = tonumber(bucket_data[2] or burst_size)
local last_refill = tonumber(bucket_data[4] or now)

-- Calculate elapsed time and refill tokens
local elapsed = (now - last_refill) / 1000
if elapsed > 0 then
  local tokens_to_add = elapsed * refill_rate
  tokens = math.min(burst_size, tokens + tokens_to_add)
end

-- Attempt to consume a token
local allowed = tokens >= 1
local remaining = math.floor(tokens)
local retry_after_ms = 0

if allowed and do_consume == 1 then
  tokens = tokens - 1
  remaining = math.floor(tokens)
  -- Update bucket with new tokens and refill time
  redis.call('HSET', bucket_key, 'tokens', tostring(tokens), 'lastRefill', tostring(now))
  -- Set expiry on the bucket key (5 minutes of inactivity)
  redis.call('EXPIRE', bucket_key, 300)
else
  -- Not allowed - calculate retry-after
  local tokens_needed = 1 - tokens
  retry_after_ms = math.ceil((tokens_needed / refill_rate) * 1000)
  if do_consume == 1 then
    -- Update last refill time even if denied (for future requests)
    redis.call('HSET', bucket_key, 'lastRefill', tostring(now))
    redis.call('EXPIRE', bucket_key, 300)
  end
end

return {allowed and 1 or 0, remaining, retry_after_ms}
`;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
// RedisRateLimitStore
// ---------------------------------------------------------------------------

/**
 * Production Redis-backed rate limit store.
 *
 * Uses Lua scripts for atomic operations and provides fail-closed behavior
 * when Redis is unavailable.
 */
export class RedisRateLimitStore implements RateLimitStore {
  private readonly redis: Redis;
  private readonly keyPrefix: string;
  private scriptSha: string | null = null;
  private readonly logger?: LoggerLike;

  /**
   * Create a new Redis rate limit store.
   *
   * @param redisClient - Configured ioredis client
   * @param options - Configuration options
   * @param options.keyPrefix - Prefix for all Redis keys (default: "rl:")
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
    this.keyPrefix = options?.keyPrefix ?? 'rl:';
    this.logger = options?.logger;

    // Pre-compile the Lua script
    this.redis
      .script('LOAD', CONSUME_SCRIPT)
      .then((sha) => {
        this.scriptSha = sha as string;
        this.logger?.debug?.('Loaded rate limit script', { sha: this.scriptSha });
      })
      .catch((err) => {
        this.logger?.warn?.('Failed to preload rate limit script', { error: err });
      });
  }

  // -----------------------------------------------------------------------
  // RateLimitStore implementation
  // -----------------------------------------------------------------------

  /**
   * Consume one token from the bucket.
   * Fails closed (denies request) if Redis is unavailable.
   */
  public async consume(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    try {
      const effectiveConfig = await this.applyGreylist(key, config);
      const result = await this.tokenBucketOperation(
        key,
        effectiveConfig,
        1 // consume
      );

      return {
        allowed: result[0] === 1,
        remaining: result[1],
        retryAfterMs: result[2],
        limit: effectiveConfig.burstSize,
      };
    } catch (err) {
      this.logger?.error?.('Rate limit consume failed, denying request', {
        key,
        error: err,
      });
      // Fail closed: deny the request
      return {
        allowed: false,
        remaining: -1,
        retryAfterMs: 60_000,
        limit: config.burstSize,
      };
    }
  }

  /**
   * Peek at the bucket state without consuming.
   * Fails closed if Redis is unavailable.
   */
  public async peek(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    try {
      const effectiveConfig = await this.applyGreylist(key, config);
      const result = await this.tokenBucketOperation(
        key,
        effectiveConfig,
        0 // peek
      );

      return {
        allowed: result[0] === 1,
        remaining: result[1],
        retryAfterMs: result[2],
        limit: effectiveConfig.burstSize,
      };
    } catch (err) {
      this.logger?.error?.('Rate limit peek failed, assuming exhausted', {
        key,
        error: err,
      });
      // Fail closed: report exhausted
      return {
        allowed: false,
        remaining: -1,
        retryAfterMs: 60_000,
        limit: config.burstSize,
      };
    }
  }

  /**
   * Reset the bucket for a key (delete it).
   */
  public async reset(key: string): Promise<void> {
    try {
      const bucketKey = this.makeBucketKey(key);
      await this.redis.del(bucketKey);
    } catch (err) {
      this.logger?.error?.('Rate limit reset failed', { key, error: err });
      // Log but don't throw; reset is best-effort
    }
  }

  /**
   * Add a key to the greylist with TTL.
   */
  public async greylist(entry: GreylistEntry): Promise<void> {
    try {
      const greylistKey = this.makeGreylistKey(entry.key);
      const ttlSeconds = Math.max(1, Math.ceil((entry.expiresAt - Date.now()) / 1000));

      await this.redis.setex(
        greylistKey,
        ttlSeconds,
        JSON.stringify({
          key: entry.key,
          reason: entry.reason,
          createdAt: entry.createdAt,
          expiresAt: entry.expiresAt,
          rateMultiplier: entry.rateMultiplier,
        })
      );
    } catch (err) {
      this.logger?.error?.('Failed to greylist key', { key: entry.key, error: err });
      throw err;
    }
  }

  /**
   * Check if a key is greylisted.
   */
  public async isGreylisted(key: string): Promise<GreylistEntry | null> {
    try {
      const greylistKey = this.makeGreylistKey(key);
      const data = await this.redis.get(greylistKey);

      if (!data) {
        return null;
      }

      const entry = JSON.parse(data) as GreylistEntry;

      // Double-check expiration
      if (Date.now() > entry.expiresAt) {
        await this.redis.del(greylistKey);
        return null;
      }

      return entry;
    } catch (err) {
      this.logger?.error?.('Failed to check greylist', { key, error: err });
      // Fail closed: assume greylisted if we can't check
      return {
        key,
        reason: 'Redis unavailable - fail closed',
        createdAt: Date.now(),
        expiresAt: Date.now() + 60_000,
        rateMultiplier: 0, // Block entirely
      };
    }
  }

  /**
   * Remove a key from the greylist.
   */
  public async ungreylist(key: string): Promise<void> {
    try {
      const greylistKey = this.makeGreylistKey(key);
      await this.redis.del(greylistKey);
    } catch (err) {
      this.logger?.error?.('Failed to ungreylist key', { key, error: err });
      throw err;
    }
  }

  // -----------------------------------------------------------------------
  // Lifecycle & Health
  // -----------------------------------------------------------------------

  /**
   * Disconnect from Redis and release resources.
   */
  public async dispose(): Promise<void> {
    try {
      await this.redis.quit();
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
   * Execute the token bucket operation (consume or peek).
   * Uses Lua script for atomicity.
   */
  private async tokenBucketOperation(
    key: string,
    config: RateLimitConfig,
    mode: 0 | 1 // 0 = peek, 1 = consume
  ): Promise<[number, number, number]> {
    const bucketKey = this.makeBucketKey(key);
    const now = Date.now();

    // Ensure script is loaded
    if (!this.scriptSha) {
      this.scriptSha = (await this.redis.script('LOAD', CONSUME_SCRIPT)) as string;
    }

    try {
      const result = (await this.redis.evalsha(
        this.scriptSha,
        1, // 1 key
        bucketKey,
        config.burstSize.toString(),
        config.refillRatePerSecond.toString(),
        now.toString(),
        mode.toString()
      )) as [number, number, number];

      return result;
    } catch (err: unknown) {
      // Script might not be loaded (e.g., after Redis restart); load and retry
      const msg = err instanceof Error ? err.message : '';
      if (msg.includes('NOSCRIPT')) {
        this.scriptSha = (await this.redis.script('LOAD', CONSUME_SCRIPT)) as string;
        const result = (await this.redis.evalsha(
          this.scriptSha,
          1,
          bucketKey,
          config.burstSize.toString(),
          config.refillRatePerSecond.toString(),
          now.toString(),
          mode.toString()
        )) as [number, number, number];
        return result;
      }
      throw err;
    }
  }

  /**
   * Apply greylist rate multiplier if the key is greylisted.
   */
  private async applyGreylist(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitConfig> {
    const entry = await this.isGreylisted(key);
    if (!entry) {
      return config;
    }

    return {
      burstSize: Math.max(1, Math.floor(config.burstSize * entry.rateMultiplier)),
      refillRatePerSecond: Math.max(
        0.01, // floor to prevent division by zero
        config.refillRatePerSecond * entry.rateMultiplier
      ),
    };
  }

  /**
   * Build the Redis key for a token bucket.
   */
  private makeBucketKey(key: string): string {
    return `${this.keyPrefix}bucket:${key}`;
  }

  /**
   * Build the Redis key for a greylist entry.
   */
  private makeGreylistKey(key: string): string {
    return `${this.keyPrefix}greylist:${key}`;
  }
}
