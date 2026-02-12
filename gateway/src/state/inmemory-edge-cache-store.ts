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

export class InMemoryEdgeCacheStore implements EdgeCacheStore {
  private readonly entries = new Map<string, EdgeCacheEntry>();
  private readonly routeIndex = new Map<string, Set<string>>();
  private readonly tagIndex = new Map<string, Set<string>>();
  private readonly routeVersions = new Map<string, string>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly maxEntries: number = 50_000,
    cleanupIntervalMs: number = 30_000,
  ) {
    if (cleanupIntervalMs > 0) {
      this.cleanupTimer = setInterval(() => this.cleanup(), cleanupIntervalMs);
      if (this.cleanupTimer && typeof this.cleanupTimer === 'object' && 'unref' in this.cleanupTimer) {
        this.cleanupTimer.unref();
      }
    }
  }

  async get(key: string): Promise<EdgeCacheEntry | null> {
    const entry = this.entries.get(key);
    if (!entry) return null;

    const cutoff = Math.max(
      entry.expiresAtMs,
      entry.staleUntilMs ?? 0,
      entry.staleIfErrorUntilMs ?? 0,
    );
    if (cutoff <= Date.now()) {
      this.removeEntry(key, entry.routePath, entry.tags);
      return null;
    }

    return {
      ...entry,
      headers: { ...entry.headers },
      tags: entry.tags ? [...entry.tags] : undefined,
    };
  }

  async set(
    key: string,
    routePath: string,
    ttlSeconds: number,
    response: CachedHttpResponse,
  ): Promise<void> {
    const ttlMs = Math.max(1, Math.floor(ttlSeconds)) * 1000;
    const now = Date.now();

    const existing = this.entries.get(key);
    if (existing) {
      this.removeEntry(key, existing.routePath, existing.tags);
    }

    while (this.entries.size >= this.maxEntries) {
      this.evictOne();
    }

    const entry: EdgeCacheEntry = {
      key,
      routePath,
      statusCode: response.statusCode,
      headers: { ...response.headers },
      bodyBase64: response.bodyBase64,
      createdAtMs: response.createdAtMs || now,
      expiresAtMs: response.expiresAtMs || now + ttlMs,
      staleUntilMs: response.staleUntilMs,
      staleIfErrorUntilMs: response.staleIfErrorUntilMs,
      tags: normalizeCacheTags(response.tags),
    };

    this.entries.set(key, entry);
    let routeSet = this.routeIndex.get(routePath);
    if (!routeSet) {
      routeSet = new Set<string>();
      this.routeIndex.set(routePath, routeSet);
    }
    routeSet.add(key);

    if (entry.tags && entry.tags.length > 0) {
      for (const tag of entry.tags) {
        let tagSet = this.tagIndex.get(tag);
        if (!tagSet) {
          tagSet = new Set<string>();
          this.tagIndex.set(tag, tagSet);
        }
        tagSet.add(key);
      }
    }
  }

  async delete(key: string): Promise<boolean> {
    const existing = this.entries.get(key);
    if (!existing) return false;
    this.removeEntry(key, existing.routePath, existing.tags);
    return true;
  }

  async purgeRoute(routePath: string, maxDelete?: number): Promise<number> {
    const routeSet = this.routeIndex.get(routePath);
    if (!routeSet || routeSet.size === 0) return 0;

    const limit = normalizeMaxDelete(maxDelete);
    let purged = 0;

    for (const key of routeSet) {
      const entry = this.entries.get(key);
      if (!entry) continue;

      this.removeEntry(key, routePath, entry.tags);
      purged += 1;
      if (purged >= limit) break;
    }

    return purged;
  }

  async purgeTags(tags: string[], maxDelete?: number): Promise<number> {
    const normalizedTags = normalizeCacheTags(tags);
    if (normalizedTags.length === 0) return 0;

    const limit = normalizeMaxDelete(maxDelete);
    let purged = 0;
    const seenKeys = new Set<string>();

    for (const tag of normalizedTags) {
      const tagSet = this.tagIndex.get(tag);
      if (!tagSet || tagSet.size === 0) continue;

      for (const key of tagSet) {
        if (seenKeys.has(key)) continue;
        seenKeys.add(key);

        const entry = this.entries.get(key);
        if (!entry) continue;
        this.removeEntry(key, entry.routePath, entry.tags);
        purged += 1;
        if (purged >= limit) return purged;
      }
    }

    return purged;
  }

  async clear(maxDelete?: number): Promise<number> {
    const limit = normalizeMaxDelete(maxDelete);
    let purged = 0;

    for (const [key, entry] of this.entries) {
      this.removeEntry(key, entry.routePath, entry.tags);
      purged += 1;
      if (purged >= limit) break;
    }

    return purged;
  }

  async getRouteVersion(routePath: string): Promise<string> {
    return this.routeVersions.get(routePath) ?? '0';
  }

  async bumpRouteVersion(routePath: string): Promise<EdgeCacheRouteVersion> {
    const previousVersion = this.routeVersions.get(routePath) ?? '0';
    const parsed = Number.parseInt(previousVersion, 10);
    const currentVersion = Number.isFinite(parsed) && parsed >= 0
      ? String(parsed + 1)
      : String(Date.now());
    this.routeVersions.set(routePath, currentVersion);
    return {
      routePath,
      previousVersion,
      currentVersion,
      bumpedAt: new Date().toISOString(),
    };
  }

  async setRouteVersion(routePath: string, version: string): Promise<EdgeCacheRouteVersionSetResult> {
    const previousVersion = this.routeVersions.get(routePath) ?? '0';
    const currentVersion = String(version);
    const updated = previousVersion !== currentVersion;
    if (updated) {
      this.routeVersions.set(routePath, currentVersion);
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
    const items = [...this.routeVersions.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .slice(0, normalizedLimit)
      .map(([routePath, version]) => ({
        routePath,
        version,
      }));
    return items;
  }

  public destroy(): void {
    if (this.cleanupTimer !== null) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.entries.clear();
    this.routeIndex.clear();
    this.tagIndex.clear();
    this.routeVersions.clear();
  }

  private removeEntry(key: string, routePath: string, tags?: string[]): void {
    this.entries.delete(key);

    const routeSet = this.routeIndex.get(routePath);
    if (routeSet) {
      routeSet.delete(key);
      if (routeSet.size === 0) {
        this.routeIndex.delete(routePath);
      }
    }

    if (tags && tags.length > 0) {
      for (const tag of tags) {
        const tagSet = this.tagIndex.get(tag);
        if (!tagSet) continue;
        tagSet.delete(key);
        if (tagSet.size === 0) {
          this.tagIndex.delete(tag);
        }
      }
    }
  }

  private evictOne(): void {
    let oldestKey: string | null = null;
    let oldestCreatedAt = Number.POSITIVE_INFINITY;
    let oldestRoutePath = '';

    for (const [key, entry] of this.entries) {
      if (entry.createdAtMs < oldestCreatedAt) {
        oldestCreatedAt = entry.createdAtMs;
        oldestKey = key;
        oldestRoutePath = entry.routePath;
      }
    }

    if (!oldestKey) return;
    const entry = this.entries.get(oldestKey);
    this.removeEntry(oldestKey, oldestRoutePath, entry?.tags);
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.entries) {
      const cutoff = Math.max(
        entry.expiresAtMs,
        entry.staleUntilMs ?? 0,
        entry.staleIfErrorUntilMs ?? 0,
      );
      if (cutoff <= now) {
        this.removeEntry(key, entry.routePath, entry.tags);
      }
    }
  }
}
