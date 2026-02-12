import type Redis from 'ioredis';
import {
  type IpBlockEntry,
  type SecurityStateStore,
  type StepUpEntry,
  type ThrottleEntry,
} from './security-state-store';

type CacheEntry<T> = { value: T; expiresAtMs: number };

function nowIso(): string {
  return new Date().toISOString();
}

function clampTtlSeconds(ttlSeconds: number): number {
  if (!Number.isFinite(ttlSeconds)) return 60;
  return Math.max(1, Math.min(Math.floor(ttlSeconds), 60 * 60 * 24 * 30)); // max 30d
}

export class RedisSecurityStateStore implements SecurityStateStore {
  private readonly prefix: string;

  private readonly cacheBlockedIp = new Map<string, CacheEntry<IpBlockEntry>>();
  private readonly cacheStepUp = new Map<string, CacheEntry<StepUpEntry>>();
  private readonly cacheThrottle = new Map<string, CacheEntry<ThrottleEntry>>();

  constructor(
    private readonly redis: Redis,
    options?: {
      keyPrefix?: string;
      cacheTtlMs?: number;
    }
  ) {
    this.prefix = options?.keyPrefix ?? 'zt:gateway:';
    this.cacheTtlMs = options?.cacheTtlMs ?? 2_000;
  }

  private readonly cacheTtlMs: number;

  async blockIps(
    ips: string[],
    ttlSeconds: number,
    meta: { reason: string; alertId?: string }
  ): Promise<IpBlockEntry[]> {
    const ttl = clampTtlSeconds(ttlSeconds);
    const now = nowIso();
    const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();

    const entries: IpBlockEntry[] = ips.map((ip) => ({
      ip,
      blockedAt: now,
      expiresAt,
      reason: meta.reason,
      alertId: meta.alertId,
    }));

    // Best-effort persistence; enforcement should not 500 if Redis is down.
    try {
      const pipeline = this.redis.pipeline();
      for (const entry of entries) {
        pipeline.setex(this.keyBlockedIp(entry.ip), ttl, JSON.stringify(entry));
        // Update local cache immediately.
        this.cacheBlockedIp.set(entry.ip, {
          value: entry,
          expiresAtMs: Date.now() + this.cacheTtlMs,
        });
      }
      await pipeline.exec();
    } catch {
      // ignore; caller still gets entries
    }

    return entries;
  }

  async isIpBlocked(ip: string): Promise<IpBlockEntry | null> {
    const cached = this.cacheBlockedIp.get(ip);
    if (cached && cached.expiresAtMs > Date.now()) return cached.value;

    try {
      const raw = await this.redis.get(this.keyBlockedIp(ip));
      if (!raw) return null;
      const entry = JSON.parse(raw) as IpBlockEntry;
      // Cache briefly to avoid hammering Redis.
      this.cacheBlockedIp.set(ip, { value: entry, expiresAtMs: Date.now() + this.cacheTtlMs });
      return entry;
    } catch {
      return null;
    }
  }

  async unblockIp(ip: string): Promise<void> {
    this.cacheBlockedIp.delete(ip);
    try {
      await this.redis.del(this.keyBlockedIp(ip));
    } catch {
      // ignore
    }
  }

  async listBlockedIps(limit: number = 1000): Promise<IpBlockEntry[]> {
    const max = Math.max(1, Math.floor(limit));
    const results: IpBlockEntry[] = [];

    try {
      let cursor = '0';
      do {
        const [nextCursor, keys] = await this.redis.scan(
          cursor,
          'MATCH',
          `${this.prefix}blockip:*`,
          'COUNT',
          '200'
        ) as [string, string[]];
        cursor = nextCursor;

        if (keys.length > 0) {
          const pipeline = this.redis.pipeline();
          for (const key of keys) pipeline.get(key);
          const values = await pipeline.exec();

          for (const item of values ?? []) {
            const raw = item?.[1];
            if (typeof raw !== 'string' || raw.length === 0) continue;
            try {
              const entry = JSON.parse(raw) as IpBlockEntry;
              if (Date.now() > Date.parse(entry.expiresAt)) continue;
              this.cacheBlockedIp.set(entry.ip, {
                value: entry,
                expiresAtMs: Date.now() + this.cacheTtlMs,
              });
              results.push(entry);
              if (results.length >= max) break;
            } catch {
              // ignore malformed entries
            }
          }
        }
      } while (cursor !== '0' && results.length < max);
    } catch {
      return [];
    }

    results.sort((a, b) => Date.parse(b.expiresAt) - Date.parse(a.expiresAt));
    return results.slice(0, max);
  }

  async requireStepUp(
    userId: string,
    requiredLevel: number,
    ttlSeconds: number,
    meta: { reason: string; alertId?: string }
  ): Promise<StepUpEntry> {
    const ttl = clampTtlSeconds(ttlSeconds);
    const entry: StepUpEntry = {
      userId,
      requiredLevel,
      flaggedAt: nowIso(),
      expiresAt: new Date(Date.now() + ttl * 1000).toISOString(),
      reason: meta.reason,
      alertId: meta.alertId,
    };

    try {
      await this.redis.setex(this.keyStepUp(userId), ttl, JSON.stringify(entry));
      this.cacheStepUp.set(userId, { value: entry, expiresAtMs: Date.now() + this.cacheTtlMs });
    } catch {
      // ignore
    }

    return entry;
  }

  async getStepUpRequirement(userId: string): Promise<StepUpEntry | null> {
    const cached = this.cacheStepUp.get(userId);
    if (cached && cached.expiresAtMs > Date.now()) return cached.value;

    try {
      const raw = await this.redis.get(this.keyStepUp(userId));
      if (!raw) return null;
      const entry = JSON.parse(raw) as StepUpEntry;
      this.cacheStepUp.set(userId, { value: entry, expiresAtMs: Date.now() + this.cacheTtlMs });
      return entry;
    } catch {
      return null;
    }
  }

  async clearStepUpRequirement(userId: string): Promise<void> {
    this.cacheStepUp.delete(userId);
    try {
      await this.redis.del(this.keyStepUp(userId));
    } catch {
      // ignore
    }
  }

  async throttleUser(
    userId: string,
    reducedRatePercent: number,
    ttlSeconds: number,
    meta: { reason: string; alertId?: string }
  ): Promise<ThrottleEntry> {
    const ttl = clampTtlSeconds(ttlSeconds);
    const entry: ThrottleEntry = {
      userId,
      reducedRatePercent,
      throttledAt: nowIso(),
      expiresAt: new Date(Date.now() + ttl * 1000).toISOString(),
      reason: meta.reason,
      alertId: meta.alertId,
    };

    try {
      await this.redis.setex(this.keyThrottle(userId), ttl, JSON.stringify(entry));
      this.cacheThrottle.set(userId, { value: entry, expiresAtMs: Date.now() + this.cacheTtlMs });
    } catch {
      // ignore
    }

    return entry;
  }

  async getThrottle(userId: string): Promise<ThrottleEntry | null> {
    const cached = this.cacheThrottle.get(userId);
    if (cached && cached.expiresAtMs > Date.now()) return cached.value;

    try {
      const raw = await this.redis.get(this.keyThrottle(userId));
      if (!raw) return null;
      const entry = JSON.parse(raw) as ThrottleEntry;
      this.cacheThrottle.set(userId, { value: entry, expiresAtMs: Date.now() + this.cacheTtlMs });
      return entry;
    } catch {
      return null;
    }
  }

  async clearThrottle(userId: string): Promise<void> {
    this.cacheThrottle.delete(userId);
    try {
      await this.redis.del(this.keyThrottle(userId));
    } catch {
      // ignore
    }
  }

  private keyBlockedIp(ip: string): string {
    return `${this.prefix}blockip:${ip}`;
  }

  private keyStepUp(userId: string): string {
    return `${this.prefix}stepup:${userId}`;
  }

  private keyThrottle(userId: string): string {
    return `${this.prefix}throttle:${userId}`;
  }
}
