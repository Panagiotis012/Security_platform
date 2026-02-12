import type Redis from 'ioredis';
import type {
  CachedHttpResponse,
  EdgeCacheEntry,
  EdgeCacheRouteVersion,
  EdgeCacheRouteVersionSetResult,
  EdgeCacheRouteVersionState,
  EdgeCacheStore,
} from './edge-cache-store';

function normalizeMaxDelete(maxDelete: number | undefined): number {
  if (!Number.isFinite(maxDelete ?? 0)) return 10_000;
  return Math.max(1, Math.min(Math.floor(maxDelete as number), 100_000));
}

function routeIndexToken(routePath: string): string {
  return Buffer.from(routePath, 'utf8').toString('base64url');
}

function tagIndexToken(tag: string): string {
  return Buffer.from(tag, 'utf8').toString('base64url');
}

function normalizeCacheTags(tags: string[] | undefined): string[] {
  if (!Array.isArray(tags) || tags.length === 0) return [];
  const unique = new Set<string>();
  for (const rawTag of tags) {
    const tag = String(rawTag).trim().toLowerCase();
    if (!tag) continue;
    unique.add(tag);
  }
  return [...unique];
}

function normalizeVersionListLimit(limit: number | undefined): number {
  if (!Number.isFinite(limit ?? 0)) return 1000;
  return Math.max(1, Math.min(Math.floor(limit as number), 5000));
}

export class RedisEdgeCacheStore implements EdgeCacheStore {
  private readonly prefix: string;

  constructor(
    private readonly redis: Redis,
    options?: { keyPrefix?: string },
  ) {
    this.prefix = options?.keyPrefix ?? 'zt:gateway:edge-cache:';
  }

  async get(key: string): Promise<EdgeCacheEntry | null> {
    try {
      const raw = await this.redis.get(this.entryKey(key));
      if (!raw) return null;

      const parsed = JSON.parse(raw) as EdgeCacheEntry;
      if (!parsed || typeof parsed !== 'object') {
        await this.redis.del(this.entryKey(key));
        return null;
      }
      const cutoff = Math.max(
        parsed.expiresAtMs ?? 0,
        parsed.staleUntilMs ?? 0,
        parsed.staleIfErrorUntilMs ?? 0,
      );
      if (cutoff <= Date.now()) {
        await this.delete(key);
        return null;
      }

      return {
        ...parsed,
        headers: { ...(parsed.headers ?? {}) },
        tags: Array.isArray(parsed.tags) ? [...parsed.tags] : undefined,
      };
    } catch {
      return null;
    }
  }

  async set(
    key: string,
    routePath: string,
    ttlSeconds: number,
    response: CachedHttpResponse,
  ): Promise<void> {
    const now = Date.now();
    const tags = normalizeCacheTags(response.tags);
    const retentionMs = Math.max(
      Math.max(
        response.staleIfErrorUntilMs ?? 0,
        response.staleUntilMs ?? 0,
        response.expiresAtMs,
      ) - now,
      ttlSeconds * 1000,
      1000,
    );
    const retentionSeconds = Math.max(1, Math.ceil(retentionMs / 1000));
    const entry: EdgeCacheEntry = {
      key,
      routePath,
      statusCode: response.statusCode,
      headers: { ...response.headers },
      bodyBase64: response.bodyBase64,
      createdAtMs: response.createdAtMs || now,
      expiresAtMs: response.expiresAtMs || now + Math.max(1, Math.floor(ttlSeconds)) * 1000,
      staleUntilMs: response.staleUntilMs,
      staleIfErrorUntilMs: response.staleIfErrorUntilMs,
      tags,
    };

    const routeIndexKey = this.routeKey(routePath);
    let previousRoutePath = '';
    let previousTags: string[] = [];

    try {
      const existingRaw = await this.redis.get(this.entryKey(key));
      if (existingRaw) {
        const parsed = JSON.parse(existingRaw) as Partial<EdgeCacheEntry>;
        if (typeof parsed.routePath === 'string' && parsed.routePath.length > 0) {
          previousRoutePath = parsed.routePath;
        }
        previousTags = normalizeCacheTags(parsed.tags);
      }
    } catch {
      // Best effort; continue with write path.
    }

    const pipeline = this.redis.pipeline();
    pipeline.setex(this.entryKey(key), retentionSeconds, JSON.stringify(entry));
    pipeline.sadd(routeIndexKey, key);
    pipeline.expire(routeIndexKey, Math.max(120, retentionSeconds + 60));

    if (previousRoutePath && previousRoutePath !== routePath) {
      pipeline.srem(this.routeKey(previousRoutePath), key);
    }

    if (tags.length > 0) {
      for (const tag of tags) {
        const tagKey = this.tagKey(tag);
        pipeline.sadd(tagKey, key);
        pipeline.expire(tagKey, Math.max(120, retentionSeconds + 60));
      }
    }

    if (previousTags.length > 0) {
      for (const tag of previousTags) {
        if (tags.includes(tag)) continue;
        pipeline.srem(this.tagKey(tag), key);
      }
    }

    await pipeline.exec();
  }

  async delete(key: string): Promise<boolean> {
    try {
      const raw = await this.redis.get(this.entryKey(key));
      if (!raw) return false;
      const parsed = JSON.parse(raw) as Partial<EdgeCacheEntry>;
      const routePath = typeof parsed.routePath === 'string' ? parsed.routePath : '';
      const tags = normalizeCacheTags(parsed.tags);

      const pipeline = this.redis.pipeline();
      pipeline.del(this.entryKey(key));
      if (routePath) {
        pipeline.srem(this.routeKey(routePath), key);
      }
      if (tags.length > 0) {
        for (const tag of tags) {
          pipeline.srem(this.tagKey(tag), key);
        }
      }
      await pipeline.exec();
      return true;
    } catch {
      return false;
    }
  }

  async purgeRoute(routePath: string, maxDelete?: number): Promise<number> {
    const routeIndexKey = this.routeKey(routePath);
    const limit = normalizeMaxDelete(maxDelete);

    try {
      const keys = await this.redis.smembers(routeIndexKey);
      if (!keys || keys.length === 0) return 0;

      let purged = 0;
      const targets = keys.slice(0, limit);
      for (const key of targets) {
        const deleted = await this.delete(key);
        if (deleted) purged += 1;
      }
      return purged;
    } catch {
      return 0;
    }
  }

  async purgeTags(tags: string[], maxDelete?: number): Promise<number> {
    const normalizedTags = normalizeCacheTags(tags);
    if (normalizedTags.length === 0) return 0;

    const limit = normalizeMaxDelete(maxDelete);
    const candidateKeys = new Set<string>();

    for (const tag of normalizedTags) {
      try {
        const keys = await this.redis.smembers(this.tagKey(tag));
        for (const key of keys) {
          candidateKeys.add(key);
          if (candidateKeys.size >= limit) break;
        }
      } catch {
        continue;
      }
      if (candidateKeys.size >= limit) break;
    }

    let purged = 0;
    for (const key of candidateKeys) {
      const deleted = await this.delete(key);
      if (deleted) purged += 1;
      if (purged >= limit) break;
    }
    return purged;
  }

  async clear(maxDelete?: number): Promise<number> {
    const limit = normalizeMaxDelete(maxDelete);
    let cursor = '0';
    let deleted = 0;

    do {
      const [nextCursor, keys] = await this.redis.scan(
        cursor,
        'MATCH',
        `${this.prefix}entry:*`,
        'COUNT',
        '200',
      ) as [string, string[]];
      cursor = nextCursor;

      if (keys.length > 0) {
        const slice = keys.slice(0, Math.max(0, limit - deleted));
        if (slice.length > 0) {
          await this.redis.del(...slice);
          deleted += slice.length;
        }
      }
    } while (cursor !== '0' && deleted < limit);

    if (deleted >= limit) {
      return deleted;
    }

    // Best-effort route index cleanup.
    cursor = '0';
    do {
      const [nextCursor, keys] = await this.redis.scan(
        cursor,
        'MATCH',
        `${this.prefix}route:*`,
        'COUNT',
        '200',
      ) as [string, string[]];
      cursor = nextCursor;
      if (keys.length > 0) {
        await this.redis.del(...keys);
      }
    } while (cursor !== '0');

    cursor = '0';
    do {
      const [nextCursor, keys] = await this.redis.scan(
        cursor,
        'MATCH',
        `${this.prefix}tag:*`,
        'COUNT',
        '200',
      ) as [string, string[]];
      cursor = nextCursor;
      if (keys.length > 0) {
        await this.redis.del(...keys);
      }
    } while (cursor !== '0');

    return deleted;
  }

  async getRouteVersion(routePath: string): Promise<string> {
    try {
      const value = await this.redis.get(this.routeVersionKey(routePath));
      return value || '0';
    } catch {
      return '0';
    }
  }

  async bumpRouteVersion(routePath: string): Promise<EdgeCacheRouteVersion> {
    const key = this.routeVersionKey(routePath);
    const previousRaw = await this.redis.get(key);
    const previousVersion = previousRaw || '0';
    const currentVersion = String(await this.redis.incr(key));
    return {
      routePath,
      previousVersion,
      currentVersion,
      bumpedAt: new Date().toISOString(),
    };
  }

  async setRouteVersion(routePath: string, version: string): Promise<EdgeCacheRouteVersionSetResult> {
    const key = this.routeVersionKey(routePath);
    const previousRaw = await this.redis.get(key);
    const previousVersion = previousRaw || '0';
    const currentVersion = String(version);
    const updated = previousVersion !== currentVersion;
    if (updated) {
      await this.redis.set(key, currentVersion);
    }
    return {
      routePath,
      previousVersion,
      currentVersion,
      updated,
      bumpedAt: new Date().toISOString(),
    };
  }

  async listRouteVersions(limit?: number): Promise<EdgeCacheRouteVersionState[]> {
    const normalizedLimit = normalizeVersionListLimit(limit);
    const keys: string[] = [];
    let cursor = '0';

    do {
      const [nextCursor, batch] = await this.redis.scan(
        cursor,
        'MATCH',
        `${this.prefix}route-version:*`,
        'COUNT',
        '200',
      ) as [string, string[]];
      cursor = nextCursor;
      for (const key of batch) {
        keys.push(key);
        if (keys.length >= normalizedLimit) break;
      }
    } while (cursor !== '0' && keys.length < normalizedLimit);

    if (keys.length === 0) return [];

    const pipeline = this.redis.pipeline();
    for (const key of keys) {
      pipeline.get(key);
    }
    const results = await pipeline.exec();
    if (!results) return [];

    const versions: EdgeCacheRouteVersionState[] = [];
    const tokenPrefix = `${this.prefix}route-version:`;
    for (let i = 0; i < keys.length && i < results.length; i += 1) {
      const key = keys[i];
      const value = results[i]?.[1];
      if (typeof key !== 'string' || !key.startsWith(tokenPrefix)) continue;
      if (typeof value !== 'string' || value.length === 0) continue;
      const token = key.slice(tokenPrefix.length);
      const routePath = decodeIndexToken(token);
      if (!routePath) continue;
      versions.push({ routePath, version: value });
    }

    versions.sort((a, b) => a.routePath.localeCompare(b.routePath));
    return versions.slice(0, normalizedLimit);
  }

  private entryKey(key: string): string {
    return `${this.prefix}entry:${key}`;
  }

  private routeKey(routePath: string): string {
    return `${this.prefix}route:${routeIndexToken(routePath)}`;
  }

  private tagKey(tag: string): string {
    return `${this.prefix}tag:${tagIndexToken(tag)}`;
  }

  private routeVersionKey(routePath: string): string {
    return `${this.prefix}route-version:${routeIndexToken(routePath)}`;
  }
}

function decodeIndexToken(token: string): string | null {
  try {
    const decoded = Buffer.from(token, 'base64url').toString('utf8').trim();
    return decoded || null;
  } catch {
    return null;
  }
}
