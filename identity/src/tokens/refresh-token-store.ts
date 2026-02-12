import type Redis from 'ioredis';

type LoggerLike = {
  debug?: (message: string, meta?: Record<string, unknown>) => void;
  info?: (message: string, meta?: Record<string, unknown>) => void;
  warn?: (message: string, meta?: Record<string, unknown>) => void;
  error?: (message: string, meta?: Record<string, unknown>) => void;
};

export interface RefreshTokenData {
  tokenId: string;
  userId: string;
  sessionId: string;
  familyId: string;
  createdAt: string;
  expiresAt: string;
  consumed: boolean;
}

export type MarkConsumedResult = 'ok' | 'not_found' | 'already_consumed';

export interface RefreshTokenStore {
  put(tokenHash: string, data: RefreshTokenData, ttlSeconds: number): Promise<void>;
  get(tokenHash: string): Promise<RefreshTokenData | null>;
  markConsumed(tokenHash: string): Promise<MarkConsumedResult>;
  revokeToken(tokenHash: string): Promise<void>;
  revokeFamily(familyId: string): Promise<number>;
  revokeUser(userId: string): Promise<number>;
  revokeSession(sessionId: string): Promise<number>;
}

// ---------------------------------------------------------------------------
// In-memory store (dev/tests)
// ---------------------------------------------------------------------------

type FamilyMeta = { userId: string; sessionId: string };

export class InMemoryRefreshTokenStore implements RefreshTokenStore {
  private readonly tokens = new Map<string, RefreshTokenData>(); // tokenHash -> data
  private readonly familyTokens = new Map<string, Set<string>>(); // familyId -> tokenHash set
  private readonly familyMeta = new Map<string, FamilyMeta>();
  private readonly userFamilies = new Map<string, Set<string>>(); // userId -> familyId set
  private readonly sessionFamilies = new Map<string, Set<string>>(); // sessionId -> familyId set
  private readonly cleanupTimer: ReturnType<typeof setInterval>;

  constructor(cleanupIntervalMs: number = 60_000) {
    this.cleanupTimer = setInterval(() => this.cleanup(), cleanupIntervalMs);
    this.cleanupTimer.unref();
  }

  async put(tokenHash: string, data: RefreshTokenData, _ttlSeconds: number): Promise<void> {
    void _ttlSeconds; // TTL enforced via expiresAt + periodic cleanup
    this.tokens.set(tokenHash, { ...data });

    this.familyMeta.set(data.familyId, { userId: data.userId, sessionId: data.sessionId });

    let ft = this.familyTokens.get(data.familyId);
    if (!ft) {
      ft = new Set();
      this.familyTokens.set(data.familyId, ft);
    }
    ft.add(tokenHash);

    let uf = this.userFamilies.get(data.userId);
    if (!uf) {
      uf = new Set();
      this.userFamilies.set(data.userId, uf);
    }
    uf.add(data.familyId);

    let sf = this.sessionFamilies.get(data.sessionId);
    if (!sf) {
      sf = new Set();
      this.sessionFamilies.set(data.sessionId, sf);
    }
    sf.add(data.familyId);
  }

  async get(tokenHash: string): Promise<RefreshTokenData | null> {
    const data = this.tokens.get(tokenHash);
    if (!data) return null;

    if (new Date(data.expiresAt).getTime() <= Date.now()) {
      await this.revokeToken(tokenHash);
      return null;
    }

    return { ...data };
  }

  async markConsumed(tokenHash: string): Promise<MarkConsumedResult> {
    const data = await this.get(tokenHash);
    if (!data) return 'not_found';
    if (data.consumed) return 'already_consumed';
    data.consumed = true;
    this.tokens.set(tokenHash, data);
    return 'ok';
  }

  async revokeToken(tokenHash: string): Promise<void> {
    const data = this.tokens.get(tokenHash);
    if (!data) return;

    this.tokens.delete(tokenHash);

    const ft = this.familyTokens.get(data.familyId);
    if (ft) {
      ft.delete(tokenHash);
      if (ft.size === 0) {
        this.familyTokens.delete(data.familyId);
      }
    }
  }

  async revokeFamily(familyId: string): Promise<number> {
    const hashes = this.familyTokens.get(familyId);
    if (!hashes || hashes.size === 0) return 0;

    const count = hashes.size;
    for (const h of hashes) {
      this.tokens.delete(h);
    }
    this.familyTokens.delete(familyId);

    const meta = this.familyMeta.get(familyId);
    if (meta) {
      this.userFamilies.get(meta.userId)?.delete(familyId);
      this.sessionFamilies.get(meta.sessionId)?.delete(familyId);
      this.familyMeta.delete(familyId);
    }

    return count;
  }

  async revokeUser(userId: string): Promise<number> {
    const families = this.userFamilies.get(userId);
    if (!families || families.size === 0) return 0;

    let total = 0;
    for (const familyId of Array.from(families)) {
      total += await this.revokeFamily(familyId);
    }

    this.userFamilies.delete(userId);
    return total;
  }

  async revokeSession(sessionId: string): Promise<number> {
    const families = this.sessionFamilies.get(sessionId);
    if (!families || families.size === 0) return 0;

    let total = 0;
    for (const familyId of Array.from(families)) {
      total += await this.revokeFamily(familyId);
    }

    this.sessionFamilies.delete(sessionId);
    return total;
  }

  destroy(): void {
    clearInterval(this.cleanupTimer);
    this.tokens.clear();
    this.familyTokens.clear();
    this.familyMeta.clear();
    this.userFamilies.clear();
    this.sessionFamilies.clear();
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [hash, data] of this.tokens.entries()) {
      if (new Date(data.expiresAt).getTime() <= now) {
        void this.revokeToken(hash);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Redis store (production)
// ---------------------------------------------------------------------------

const MARK_CONSUMED_SCRIPT = `
local token_key = KEYS[1]
if redis.call('EXISTS', token_key) == 0 then
  return 0
end
local consumed = redis.call('HGET', token_key, 'consumed')
if consumed == '1' then
  return 2
end
redis.call('HSET', token_key, 'consumed', '1')
return 1
`;

export class RedisRefreshTokenStore implements RefreshTokenStore {
  private readonly keyPrefix: string;
  private scriptSha: string | null = null;
  private readonly logger?: LoggerLike;

  constructor(
    private readonly redis: Redis,
    options?: { keyPrefix?: string; logger?: LoggerLike }
  ) {
    this.keyPrefix = options?.keyPrefix ?? 'zt:identity:rt:';
    this.logger = options?.logger;

    this.redis.script('LOAD', MARK_CONSUMED_SCRIPT).then((sha) => {
      this.scriptSha = sha as string;
    }).catch(() => {
      // lazy-load on first call
    });
  }

  async put(tokenHash: string, data: RefreshTokenData, ttlSeconds: number): Promise<void> {
    const ttl = clampTtl(ttlSeconds);
    const tokenKey = this.kToken(tokenHash);
    const familyKey = this.kFamily(data.familyId);
    const familyMetaKey = this.kFamilyMeta(data.familyId);
    const userKey = this.kUser(data.userId);
    const sessionKey = this.kSession(data.sessionId);

    const pipeline = this.redis.pipeline();

    pipeline.hset(
      tokenKey,
      'tokenId',
      data.tokenId,
      'userId',
      data.userId,
      'sessionId',
      data.sessionId,
      'familyId',
      data.familyId,
      'createdAt',
      data.createdAt,
      'expiresAt',
      data.expiresAt,
      'consumed',
      data.consumed ? '1' : '0'
    );
    pipeline.expire(tokenKey, ttl);

    pipeline.sadd(familyKey, tokenHash);
    pipeline.expire(familyKey, ttl);

    // Family meta used for efficient revocation cleanup.
    pipeline.hset(familyMetaKey, 'userId', data.userId, 'sessionId', data.sessionId);
    pipeline.expire(familyMetaKey, ttl);

    // Indexes: user -> families, session -> families
    pipeline.sadd(userKey, data.familyId);
    pipeline.expire(userKey, ttl);
    pipeline.sadd(sessionKey, data.familyId);
    pipeline.expire(sessionKey, ttl);

    await pipeline.exec();
  }

  async get(tokenHash: string): Promise<RefreshTokenData | null> {
    const tokenKey = this.kToken(tokenHash);
    const data = await this.redis.hgetall(tokenKey);
    if (!data || Object.keys(data).length === 0) return null;

    const parsed = this.parseTokenHash(data);
    if (!parsed) return null;

    if (new Date(parsed.expiresAt).getTime() <= Date.now()) {
      await this.revokeToken(tokenHash);
      return null;
    }

    return parsed;
  }

  async markConsumed(tokenHash: string): Promise<MarkConsumedResult> {
    const tokenKey = this.kToken(tokenHash);
    if (!this.scriptSha) {
      this.scriptSha = (await this.redis.script('LOAD', MARK_CONSUMED_SCRIPT)) as string;
    }

    try {
      const code = (await this.redis.evalsha(this.scriptSha, 1, tokenKey)) as number;
      if (code === 1) return 'ok';
      if (code === 2) return 'already_consumed';
      return 'not_found';
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : '';
      if (msg.includes('NOSCRIPT')) {
        this.scriptSha = (await this.redis.script('LOAD', MARK_CONSUMED_SCRIPT)) as string;
        const code = (await this.redis.evalsha(this.scriptSha, 1, tokenKey)) as number;
        if (code === 1) return 'ok';
        if (code === 2) return 'already_consumed';
        return 'not_found';
      }
      this.logger?.error?.('markConsumed failed', { error: err });
      throw err;
    }
  }

  async revokeToken(tokenHash: string): Promise<void> {
    const tokenKey = this.kToken(tokenHash);
    const familyId = await this.redis.hget(tokenKey, 'familyId');
    if (!familyId) {
      await this.redis.del(tokenKey);
      return;
    }

    const familyKey = this.kFamily(familyId);
    const pipeline = this.redis.pipeline();
    pipeline.del(tokenKey);
    pipeline.srem(familyKey, tokenHash);
    await pipeline.exec();
  }

  async revokeFamily(familyId: string): Promise<number> {
    const familyKey = this.kFamily(familyId);
    const familyMetaKey = this.kFamilyMeta(familyId);

    const [tokenHashes, meta] = await Promise.all([
      this.redis.smembers(familyKey),
      this.redis.hgetall(familyMetaKey),
    ]);

    if (tokenHashes.length === 0) {
      return 0;
    }

    const userId = meta?.userId;
    const sessionId = meta?.sessionId;
    const pipeline = this.redis.pipeline();

    for (const h of tokenHashes) {
      pipeline.del(this.kToken(h));
    }

    pipeline.del(familyKey);
    pipeline.del(familyMetaKey);

    if (userId) {
      pipeline.srem(this.kUser(userId), familyId);
    }
    if (sessionId) {
      pipeline.srem(this.kSession(sessionId), familyId);
    }

    await pipeline.exec();
    return tokenHashes.length;
  }

  async revokeUser(userId: string): Promise<number> {
    const userKey = this.kUser(userId);
    const familyIds = await this.redis.smembers(userKey);
    if (familyIds.length === 0) return 0;

    let total = 0;
    for (const familyId of familyIds) {
      total += await this.revokeFamily(familyId);
    }

    await this.redis.del(userKey);
    return total;
  }

  async revokeSession(sessionId: string): Promise<number> {
    const sessionKey = this.kSession(sessionId);
    const familyIds = await this.redis.smembers(sessionKey);
    if (familyIds.length === 0) return 0;

    let total = 0;
    for (const familyId of familyIds) {
      total += await this.revokeFamily(familyId);
    }

    await this.redis.del(sessionKey);
    return total;
  }

  private parseTokenHash(hash: Record<string, string>): RefreshTokenData | null {
    const tokenId = hash.tokenId ?? '';
    const userId = hash.userId ?? '';
    const sessionId = hash.sessionId ?? '';
    const familyId = hash.familyId ?? '';
    const createdAt = hash.createdAt ?? '';
    const expiresAt = hash.expiresAt ?? '';
    const consumed = hash.consumed === '1';

    if (!tokenId || !userId || !sessionId || !familyId || !createdAt || !expiresAt) {
      return null;
    }

    return { tokenId, userId, sessionId, familyId, createdAt, expiresAt, consumed };
  }

  private kToken(tokenHash: string): string {
    return `${this.keyPrefix}token:${tokenHash}`;
  }

  private kFamily(familyId: string): string {
    return `${this.keyPrefix}family:${familyId}`;
  }

  private kFamilyMeta(familyId: string): string {
    return `${this.keyPrefix}family_meta:${familyId}`;
  }

  private kUser(userId: string): string {
    return `${this.keyPrefix}user:${userId}`;
  }

  private kSession(sessionId: string): string {
    return `${this.keyPrefix}session:${sessionId}`;
  }
}

function clampTtl(ttlSeconds: number): number {
  if (!Number.isFinite(ttlSeconds)) return 60;
  return Math.max(1, Math.min(Math.floor(ttlSeconds), 60 * 60 * 24));
}
