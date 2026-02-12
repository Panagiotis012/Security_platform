export interface CachedHttpResponse {
  statusCode: number;
  headers: Record<string, string>;
  bodyBase64: string;
  createdAtMs: number;
  expiresAtMs: number;
  staleUntilMs?: number;
  staleIfErrorUntilMs?: number;
  tags?: string[];
}

export interface EdgeCacheEntry extends CachedHttpResponse {
  key: string;
  routePath: string;
}

export interface EdgeCacheRouteVersion {
  routePath: string;
  previousVersion: string;
  currentVersion: string;
  bumpedAt: string;
}

export interface EdgeCacheRouteVersionState {
  routePath: string;
  version: string;
}

export interface EdgeCacheRouteVersionSetResult extends EdgeCacheRouteVersion {
  updated: boolean;
}

export interface EdgeCacheStore {
  get(key: string): Promise<EdgeCacheEntry | null>;
  set(key: string, routePath: string, ttlSeconds: number, response: CachedHttpResponse): Promise<void>;
  delete(key: string): Promise<boolean>;
  purgeRoute(routePath: string, maxDelete?: number): Promise<number>;
  purgeTags(tags: string[], maxDelete?: number): Promise<number>;
  clear(maxDelete?: number): Promise<number>;
  getRouteVersion(routePath: string): Promise<string>;
  bumpRouteVersion(routePath: string): Promise<EdgeCacheRouteVersion>;
  setRouteVersion(routePath: string, version: string): Promise<EdgeCacheRouteVersionSetResult>;
  listRouteVersions(limit?: number): Promise<EdgeCacheRouteVersionState[]>;
}
