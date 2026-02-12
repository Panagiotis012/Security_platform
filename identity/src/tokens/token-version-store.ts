import type Redis from 'ioredis';

export interface TokenVersionStore {
  getVersion(userId: string): Promise<number>;
  incrementVersion(userId: string): Promise<number>;
}

export class InMemoryTokenVersionStore implements TokenVersionStore {
  private readonly versions = new Map<string, number>();

  async getVersion(userId: string): Promise<number> {
    return this.versions.get(userId) ?? 0;
  }

  async incrementVersion(userId: string): Promise<number> {
    const next = (this.versions.get(userId) ?? 0) + 1;
    this.versions.set(userId, next);
    return next;
  }
}

export class RedisTokenVersionStore implements TokenVersionStore {
  constructor(
    private readonly redis: Redis,
    private readonly keyPrefix: string = 'zt:identity:',
  ) {}

  async getVersion(userId: string): Promise<number> {
    const raw = await this.redis.get(this.key(userId));
    if (!raw) return 0;
    const n = parseInt(raw, 10);
    return Number.isFinite(n) ? n : 0;
  }

  async incrementVersion(userId: string): Promise<number> {
    const v = await this.redis.incr(this.key(userId));
    return v;
  }

  private key(userId: string): string {
    return `${this.keyPrefix}token_version:${userId}`;
  }
}

