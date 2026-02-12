import type Redis from 'ioredis';

export interface WebAuthnCredentialRecord {
  credentialID: string; // base64url
  credentialPublicKeyB64: string; // base64url-encoded bytes
  counter: number;
  transports?: string[];
  deviceType?: string;
  backedUp?: boolean;
  createdAt: string;
  lastUsedAt?: string;
}

export type WebAuthnChallengeType = 'registration' | 'authentication';

export interface WebAuthnStore {
  listCredentials(userId: string): Promise<WebAuthnCredentialRecord[]>;
  putCredential(userId: string, cred: WebAuthnCredentialRecord): Promise<void>;
  updateCredentialUsage(userId: string, credentialID: string, counter: number): Promise<void>;

  putChallenge(userId: string, type: WebAuthnChallengeType, challengeId: string, challenge: string, ttlSeconds: number): Promise<void>;
  consumeChallenge(userId: string, type: WebAuthnChallengeType, challengeId: string): Promise<string | null>;
}

// ---------------------------------------------------------------------------
// In-memory (dev/test)
// ---------------------------------------------------------------------------

export class InMemoryWebAuthnStore implements WebAuthnStore {
  private readonly creds = new Map<string, Map<string, WebAuthnCredentialRecord>>(); // userId -> credentialID -> record
  private readonly challenges = new Map<string, { challenge: string; expiresAtMs: number }>(); // key -> challenge

  async listCredentials(userId: string): Promise<WebAuthnCredentialRecord[]> {
    return Array.from(this.creds.get(userId)?.values() ?? []).map((c) => ({ ...c }));
  }

  async putCredential(userId: string, cred: WebAuthnCredentialRecord): Promise<void> {
    let map = this.creds.get(userId);
    if (!map) {
      map = new Map();
      this.creds.set(userId, map);
    }
    map.set(cred.credentialID, { ...cred });
  }

  async updateCredentialUsage(userId: string, credentialID: string, counter: number): Promise<void> {
    const map = this.creds.get(userId);
    if (!map) return;
    const existing = map.get(credentialID);
    if (!existing) return;
    existing.counter = counter;
    existing.lastUsedAt = new Date().toISOString();
    map.set(credentialID, existing);
  }

  async putChallenge(userId: string, type: WebAuthnChallengeType, challengeId: string, challenge: string, ttlSeconds: number): Promise<void> {
    const ttlMs = Math.max(1000, Math.floor(ttlSeconds * 1000));
    this.challenges.set(this.ck(userId, type, challengeId), { challenge, expiresAtMs: Date.now() + ttlMs });
  }

  async consumeChallenge(userId: string, type: WebAuthnChallengeType, challengeId: string): Promise<string | null> {
    const key = this.ck(userId, type, challengeId);
    const entry = this.challenges.get(key);
    if (!entry) return null;
    this.challenges.delete(key);
    if (Date.now() > entry.expiresAtMs) return null;
    return entry.challenge;
  }

  private ck(userId: string, type: WebAuthnChallengeType, challengeId: string): string {
    return `${type}:${userId}:${challengeId}`;
  }
}

// ---------------------------------------------------------------------------
// Redis (production)
// ---------------------------------------------------------------------------

const CONSUME_CHALLENGE_SCRIPT = `
local key = KEYS[1]
local v = redis.call('GET', key)
if v then
  redis.call('DEL', key)
end
return v
`;

export class RedisWebAuthnStore implements WebAuthnStore {
  private scriptSha: string | null = null;
  private readonly prefix: string;

  constructor(
    private readonly redis: Redis,
    options?: { keyPrefix?: string }
  ) {
    this.prefix = options?.keyPrefix ?? 'zt:identity:webauthn:';
    this.redis.script('LOAD', CONSUME_CHALLENGE_SCRIPT).then((sha) => {
      this.scriptSha = sha as string;
    }).catch(() => {
      // lazy-load later
    });
  }

  async listCredentials(userId: string): Promise<WebAuthnCredentialRecord[]> {
    const raw = await this.redis.hgetall(this.kCreds(userId));
    const results: WebAuthnCredentialRecord[] = [];
    for (const [credentialID, json] of Object.entries(raw ?? {})) {
      try {
        const parsed = JSON.parse(json) as WebAuthnCredentialRecord;
        if (parsed && parsed.credentialID === credentialID) {
          results.push(parsed);
        }
      } catch {
        // ignore bad entry
      }
    }
    return results;
  }

  async putCredential(userId: string, cred: WebAuthnCredentialRecord): Promise<void> {
    await this.redis.hset(this.kCreds(userId), cred.credentialID, JSON.stringify(cred));
  }

  async updateCredentialUsage(userId: string, credentialID: string, counter: number): Promise<void> {
    const key = this.kCreds(userId);
    const raw = await this.redis.hget(key, credentialID);
    if (!raw) return;
    try {
      const parsed = JSON.parse(raw) as WebAuthnCredentialRecord;
      parsed.counter = counter;
      parsed.lastUsedAt = new Date().toISOString();
      await this.redis.hset(key, credentialID, JSON.stringify(parsed));
    } catch {
      // ignore
    }
  }

  async putChallenge(userId: string, type: WebAuthnChallengeType, challengeId: string, challenge: string, ttlSeconds: number): Promise<void> {
    const ttl = clampTtl(ttlSeconds, 60 * 10);
    await this.redis.setex(this.kChallenge(userId, type, challengeId), ttl, challenge);
  }

  async consumeChallenge(userId: string, type: WebAuthnChallengeType, challengeId: string): Promise<string | null> {
    const key = this.kChallenge(userId, type, challengeId);
    if (!this.scriptSha) {
      this.scriptSha = (await this.redis.script('LOAD', CONSUME_CHALLENGE_SCRIPT)) as string;
    }

    try {
      const raw = await this.redis.evalsha(this.scriptSha, 1, key) as string | null;
      return raw ?? null;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : '';
      if (msg.includes('NOSCRIPT')) {
        this.scriptSha = (await this.redis.script('LOAD', CONSUME_CHALLENGE_SCRIPT)) as string;
        const raw = await this.redis.evalsha(this.scriptSha, 1, key) as string | null;
        return raw ?? null;
      }
      throw err;
    }
  }

  private kCreds(userId: string): string {
    return `${this.prefix}creds:${userId}`;
  }

  private kChallenge(userId: string, type: WebAuthnChallengeType, challengeId: string): string {
    return `${this.prefix}challenge:${type}:${userId}:${challengeId}`;
  }
}

function clampTtl(ttlSeconds: number, maxSeconds: number): number {
  if (!Number.isFinite(ttlSeconds)) return 60;
  return Math.max(1, Math.min(Math.floor(ttlSeconds), maxSeconds));
}
