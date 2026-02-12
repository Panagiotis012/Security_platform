import type Redis from 'ioredis';
import type { IpReputationEntry, IpReputationStore } from './ip-reputation-store';

type LoggerLike = {
  debug?: (message: string, meta?: Record<string, unknown>) => void;
  warn?: (message: string, meta?: Record<string, unknown>) => void;
  error?: (message: string, meta?: Record<string, unknown>) => void;
};

const ADD_SCORE_SCRIPT = `
local key = KEYS[1]
local points = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local window_ms = tonumber(ARGV[3])

local score = tonumber(redis.call('HGET', key, 'score') or '0')
local window_start = tonumber(redis.call('HGET', key, 'windowStart') or '0')

if window_start == 0 or (now - window_start) > window_ms then
  score = 0
  window_start = now
end

score = score + points
redis.call('HSET', key, 'score', tostring(score), 'windowStart', tostring(window_start))
redis.call('PEXPIRE', key, window_ms)

return {score, window_start}
`;

export class RedisIpReputationStore implements IpReputationStore {
  private scriptSha: string | null = null;
  private readonly prefix: string;
  private readonly logger?: LoggerLike;

  constructor(
    private readonly redis: Redis,
    options?: {
      keyPrefix?: string;
      logger?: LoggerLike;
    }
  ) {
    this.prefix = options?.keyPrefix ?? 'zt:gateway:ip-reputation:';
    this.logger = options?.logger;

    this.redis.script('LOAD', ADD_SCORE_SCRIPT)
      .then((sha) => {
        this.scriptSha = sha as string;
        this.logger?.debug?.('Loaded IP reputation script', { sha: this.scriptSha });
      })
      .catch((err) => {
        this.logger?.warn?.('Failed to preload IP reputation script', {
          error: err instanceof Error ? err.message : String(err),
        });
      });
  }

  async addScore(ip: string, points: number, windowMs: number): Promise<IpReputationEntry> {
    const key = this.key(ip);
    const effectivePoints = Number.isFinite(points) ? points : 0;
    const effectiveWindowMs = Math.max(1_000, Math.floor(windowMs));
    const now = Date.now();
    const result = await this.runScript(key, effectivePoints, now, effectiveWindowMs);

    const score = Number(result[0] ?? 0);
    const windowStartMs = Number(result[1] ?? now);
    const windowExpiresAtMs = windowStartMs + effectiveWindowMs;

    return {
      ip,
      score,
      windowStartMs,
      windowExpiresAtMs,
    };
  }

  async reset(ip: string): Promise<void> {
    await this.redis.del(this.key(ip));
  }

  private key(ip: string): string {
    return `${this.prefix}${ip}`;
  }

  private async runScript(
    key: string,
    points: number,
    nowMs: number,
    windowMs: number,
  ): Promise<[number, number]> {
    if (!this.scriptSha) {
      this.scriptSha = (await this.redis.script('LOAD', ADD_SCORE_SCRIPT)) as string;
    }

    try {
      const result = (await this.redis.evalsha(
        this.scriptSha,
        1,
        key,
        String(points),
        String(nowMs),
        String(windowMs),
      )) as [number, number];
      return result;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (!msg.includes('NOSCRIPT')) {
        this.logger?.error?.('IP reputation script execution failed', { error: msg });
        throw err;
      }

      this.scriptSha = (await this.redis.script('LOAD', ADD_SCORE_SCRIPT)) as string;
      const result = (await this.redis.evalsha(
        this.scriptSha,
        1,
        key,
        String(points),
        String(nowMs),
        String(windowMs),
      )) as [number, number];
      return result;
    }
  }
}

