import type Redis from 'ioredis';

export interface JtiRevocationStore {
  revoke(jti: string, ttlSeconds: number): Promise<void>;
  isRevoked(jti: string): Promise<boolean>;
}

export class InMemoryJtiRevocationStore implements JtiRevocationStore {
  private readonly revoked = new Map<string, number>(); // jti -> expiresAtMs
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(cleanupIntervalMs: number = 60_000) {
    this.cleanupTimer = setInterval(() => this.cleanup(), cleanupIntervalMs);
    if (this.cleanupTimer.unref) this.cleanupTimer.unref();
  }

  async revoke(jti: string, ttlSeconds: number): Promise<void> {
    const ttlMs = Math.max(1_000, Math.floor(ttlSeconds * 1000));
    this.revoked.set(jti, Date.now() + ttlMs);
  }

  async isRevoked(jti: string): Promise<boolean> {
    const exp = this.revoked.get(jti);
    if (!exp) return false;
    if (Date.now() > exp) {
      this.revoked.delete(jti);
      return false;
    }
    return true;
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.revoked.clear();
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [jti, exp] of this.revoked) {
      if (now > exp) this.revoked.delete(jti);
    }
  }
}

export class RedisJtiRevocationStore implements JtiRevocationStore {
  constructor(
    private readonly redis: Redis,
    private readonly keyPrefix: string = 'zt:identity:',
  ) {}

  async revoke(jti: string, ttlSeconds: number): Promise<void> {
    const ttl = Math.max(1, Math.min(Math.floor(ttlSeconds), 60 * 60 * 24)); // max 24h
    await this.redis.setex(this.key(jti), ttl, '1');
  }

  async isRevoked(jti: string): Promise<boolean> {
    const v = await this.redis.get(this.key(jti));
    return Boolean(v);
  }

  private key(jti: string): string {
    return `${this.keyPrefix}revoked_jti:${jti}`;
  }
}

