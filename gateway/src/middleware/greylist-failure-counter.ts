import type Redis from 'ioredis';
import type { RateLimitStore } from '@zerotrust/shared';

export interface GreylistFailureCounter {
  recordFailure(key: string): Promise<void>;
}

export class InMemoryGreylistFailureCounter implements GreylistFailureCounter {
  private readonly failures = new Map<string, number[]>();
  private readonly cleanupInterval: ReturnType<typeof setInterval>;

  constructor(
    private readonly options: {
      failureWindowMs: number;
      failureThreshold: number;
      greylistDurationMs: number;
      rateMultiplier: number;
      store: RateLimitStore;
      reason: string;
    }
  ) {
    this.cleanupInterval = setInterval(() => this.cleanup(), 60_000);
    this.cleanupInterval.unref();
  }

  async recordFailure(key: string): Promise<void> {
    const now = Date.now();
    const arr = this.failures.get(key) ?? [];
    arr.push(now);

    const cutoff = now - this.options.failureWindowMs;
    const pruned = arr.filter((t) => t >= cutoff);
    this.failures.set(key, pruned);

    if (pruned.length >= this.options.failureThreshold) {
      // Reset failures so we don't repeatedly trigger.
      this.failures.set(key, []);

      await this.options.store.greylist({
        key,
        reason: this.options.reason,
        createdAt: now,
        expiresAt: now + this.options.greylistDurationMs,
        rateMultiplier: this.options.rateMultiplier,
      });
    }
  }

  private cleanup(): void {
    const now = Date.now();
    const cutoff = now - this.options.failureWindowMs;
    for (const [key, arr] of this.failures.entries()) {
      const pruned = arr.filter((t) => t >= cutoff);
      if (pruned.length === 0) this.failures.delete(key);
      else this.failures.set(key, pruned);
    }
  }

  destroy(): void {
    clearInterval(this.cleanupInterval);
    this.failures.clear();
  }
}

export class RedisGreylistFailureCounter implements GreylistFailureCounter {
  private readonly keyPrefix: string;

  constructor(
    private readonly redis: Redis,
    private readonly options: {
      keyPrefix?: string;
      failureWindowMs: number;
      failureThreshold: number;
      greylistDurationMs: number;
      rateMultiplier: number;
      store: RateLimitStore;
      reason: string;
    }
  ) {
    this.keyPrefix = options.keyPrefix ?? 'zt:gateway:rl:';
  }

  async recordFailure(key: string): Promise<void> {
    const now = Date.now();
    const windowSeconds = Math.max(1, Math.ceil(this.options.failureWindowMs / 1000));
    const counterKey = `${this.keyPrefix}greyfail:${key}`;

    const n = await this.redis.incr(counterKey);
    if (n === 1) {
      await this.redis.expire(counterKey, windowSeconds);
    }

    if (n >= this.options.failureThreshold) {
      // Clear counter and greylist.
      await this.redis.del(counterKey);
      await this.options.store.greylist({
        key,
        reason: this.options.reason,
        createdAt: now,
        expiresAt: now + this.options.greylistDurationMs,
        rateMultiplier: this.options.rateMultiplier,
      });
    }
  }
}

