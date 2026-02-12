import type Redis from 'ioredis';
import type {
  BotChallengeEntry,
  BotChallengeInvalidAttemptPolicy,
  BotChallengeInvalidAttemptResult,
  BotChallengeStore,
} from './bot-challenge-store';

const REGISTER_INVALID_ATTEMPT_SCRIPT = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local max_attempts = tonumber(ARGV[2])
local window_ms = tonumber(ARGV[3])
local backoff_ms = tonumber(ARGV[4])

local window_start = tonumber(redis.call('HGET', key, 'windowStartMs') or '0')
local count = tonumber(redis.call('HGET', key, 'count') or '0')
local blocked_until = tonumber(redis.call('HGET', key, 'blockedUntilMs') or '0')

if blocked_until > now then
  local retry_after_ms = blocked_until - now
  local ttl_ms = retry_after_ms
  if window_ms > ttl_ms then
    ttl_ms = window_ms
  end
  if ttl_ms < 1000 then
    ttl_ms = 1000
  end
  redis.call('PEXPIRE', key, ttl_ms)
  return {1, retry_after_ms, count}
end

if window_start == 0 or (now - window_start) > window_ms then
  window_start = now
  count = 0
end

count = count + 1
local attempts = count
local blocked = 0
local retry_after_ms = 0

if count >= max_attempts then
  blocked = 1
  retry_after_ms = backoff_ms
  blocked_until = now + backoff_ms
  count = 0
  window_start = now
else
  blocked_until = 0
end

redis.call(
  'HSET',
  key,
  'windowStartMs', tostring(window_start),
  'count', tostring(count),
  'blockedUntilMs', tostring(blocked_until)
)

local ttl_ms = window_ms
if blocked_until > now then
  local blocked_ttl_ms = blocked_until - now
  if blocked_ttl_ms > ttl_ms then
    ttl_ms = blocked_ttl_ms
  end
end
if ttl_ms < 1000 then
  ttl_ms = 1000
end
redis.call('PEXPIRE', key, ttl_ms)

return {blocked, retry_after_ms, attempts}
`;

function clampTtlSeconds(ttlSeconds: number): number {
  if (!Number.isFinite(ttlSeconds)) return 60;
  return Math.max(1, Math.min(Math.floor(ttlSeconds), 60 * 60 * 24 * 7)); // max 7 days
}

function normalizeInvalidAttemptPolicy(policy: BotChallengeInvalidAttemptPolicy): BotChallengeInvalidAttemptPolicy {
  return {
    maxInvalidAttempts: Math.max(1, Math.floor(policy.maxInvalidAttempts)),
    windowMs: Math.max(1_000, Math.floor(policy.windowMs)),
    backoffMs: Math.max(1_000, Math.floor(policy.backoffMs)),
  };
}

export class RedisBotChallengeStore implements BotChallengeStore {
  private readonly prefix: string;
  private registerInvalidAttemptSha: string | null = null;

  constructor(
    private readonly redis: Redis,
    options?: { keyPrefix?: string },
  ) {
    this.prefix = options?.keyPrefix ?? 'zt:gateway:bot-challenge:';

    this.redis.script('LOAD', REGISTER_INVALID_ATTEMPT_SCRIPT)
      .then((sha) => {
        this.registerInvalidAttemptSha = sha as string;
      })
      .catch(() => {
        this.registerInvalidAttemptSha = null;
      });
  }

  async setChallenge(ip: string, ttlSeconds: number, reason: string): Promise<BotChallengeEntry> {
    const ttl = clampTtlSeconds(ttlSeconds);
    const now = Date.now();
    const entry: BotChallengeEntry = {
      ip,
      reason,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + ttl * 1000).toISOString(),
    };
    await this.redis.setex(this.challengeKey(ip), ttl, JSON.stringify(entry));
    return entry;
  }

  async getChallenge(ip: string): Promise<BotChallengeEntry | null> {
    try {
      const raw = await this.redis.get(this.challengeKey(ip));
      if (!raw) return null;
      const entry = JSON.parse(raw) as BotChallengeEntry;
      if (Date.now() > Date.parse(entry.expiresAt)) {
        await this.redis.del(this.challengeKey(ip));
        return null;
      }
      return entry;
    } catch {
      return null;
    }
  }

  async clearChallenge(ip: string): Promise<void> {
    await this.redis.del(this.challengeKey(ip));
  }

  async getInvalidAttemptBackoffMs(ip: string): Promise<number> {
    try {
      const raw = await this.redis.hget(this.invalidAttemptKey(ip), 'blockedUntilMs');
      if (!raw) return 0;
      const blockedUntilMs = Number.parseInt(raw, 10);
      if (!Number.isFinite(blockedUntilMs)) return 0;
      return Math.max(0, blockedUntilMs - Date.now());
    } catch {
      return 0;
    }
  }

  async registerInvalidAttempt(
    ip: string,
    policyInput: BotChallengeInvalidAttemptPolicy,
  ): Promise<BotChallengeInvalidAttemptResult> {
    const policy = normalizeInvalidAttemptPolicy(policyInput);
    const result = await this.runRegisterInvalidAttempt(
      this.invalidAttemptKey(ip),
      Date.now(),
      policy,
    );
    return {
      blocked: result[0] === 1,
      retryAfterMs: Math.max(0, result[1]),
      attempts: Math.max(0, result[2]),
    };
  }

  async clearInvalidAttempts(ip: string): Promise<void> {
    await this.redis.del(this.invalidAttemptKey(ip));
  }

  private challengeKey(ip: string): string {
    return `${this.prefix}${ip}`;
  }

  private invalidAttemptKey(ip: string): string {
    return `${this.prefix}invalid:${ip}`;
  }

  private async runRegisterInvalidAttempt(
    key: string,
    nowMs: number,
    policy: BotChallengeInvalidAttemptPolicy,
  ): Promise<[number, number, number]> {
    if (!this.registerInvalidAttemptSha) {
      this.registerInvalidAttemptSha = (await this.redis.script('LOAD', REGISTER_INVALID_ATTEMPT_SCRIPT)) as string;
    }

    const args = [
      String(nowMs),
      String(policy.maxInvalidAttempts),
      String(policy.windowMs),
      String(policy.backoffMs),
    ];

    try {
      const raw = await this.redis.evalsha(this.registerInvalidAttemptSha, 1, key, ...args) as [unknown, unknown, unknown];
      return [
        Number(raw[0] ?? 0),
        Number(raw[1] ?? 0),
        Number(raw[2] ?? 0),
      ];
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (!message.includes('NOSCRIPT')) {
        throw err;
      }
      this.registerInvalidAttemptSha = (await this.redis.script('LOAD', REGISTER_INVALID_ATTEMPT_SCRIPT)) as string;
      const raw = await this.redis.evalsha(this.registerInvalidAttemptSha, 1, key, ...args) as [unknown, unknown, unknown];
      return [
        Number(raw[0] ?? 0),
        Number(raw[1] ?? 0),
        Number(raw[2] ?? 0),
      ];
    }
  }
}
