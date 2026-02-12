import type Redis from 'ioredis';

type CacheEntry<T> = { value: T; expiresAtMs: number };

export interface IdentitySecurityStore {
  getTokenVersion(userId: string): Promise<number>;
  isJtiRevoked(jti: string): Promise<boolean>;
}

export class RedisIdentitySecurityStore implements IdentitySecurityStore {
  private readonly cacheTokenVersion = new Map<string, CacheEntry<number>>();
  private readonly cacheJtiRevoked = new Map<string, CacheEntry<boolean>>();

  constructor(
    private readonly redis: Redis,
    options?: {
      keyPrefix?: string;
      cacheTtlMs?: number;
    }
  ) {
    this.prefix = options?.keyPrefix ?? 'zt:identity:';
    this.cacheTtlMs = options?.cacheTtlMs ?? 2_000;
  }

  private readonly prefix: string;
  private readonly cacheTtlMs: number;

  async getTokenVersion(userId: string): Promise<number> {
    const cached = this.cacheTokenVersion.get(userId);
    if (cached && cached.expiresAtMs > Date.now()) return cached.value;

    try {
      const raw = await this.redis.get(this.keyTokenVersion(userId));
      const v = raw ? parseInt(raw, 10) : 0;
      const value = Number.isFinite(v) ? v : 0;
      this.cacheTokenVersion.set(userId, { value, expiresAtMs: Date.now() + this.cacheTtlMs });
      return value;
    } catch {
      // Fail closed for token-version enforcement should be handled by caller.
      throw new Error('identity_store_unavailable');
    }
  }

  async isJtiRevoked(jti: string): Promise<boolean> {
    const cached = this.cacheJtiRevoked.get(jti);
    if (cached && cached.expiresAtMs > Date.now()) return cached.value;

    try {
      const raw = await this.redis.get(this.keyRevokedJti(jti));
      const value = Boolean(raw);
      this.cacheJtiRevoked.set(jti, { value, expiresAtMs: Date.now() + this.cacheTtlMs });
      return value;
    } catch {
      throw new Error('identity_store_unavailable');
    }
  }

  private keyTokenVersion(userId: string): string {
    return `${this.prefix}token_version:${userId}`;
  }

  private keyRevokedJti(jti: string): string {
    return `${this.prefix}revoked_jti:${jti}`;
  }
}

