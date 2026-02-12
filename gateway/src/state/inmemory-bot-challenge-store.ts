import type {
  BotChallengeEntry,
  BotChallengeInvalidAttemptPolicy,
  BotChallengeInvalidAttemptResult,
  BotChallengeStore,
} from './bot-challenge-store';

interface InvalidAttemptState {
  windowStartMs: number;
  windowMs: number;
  count: number;
  blockedUntilMs: number;
}

function normalizeInvalidAttemptPolicy(policy: BotChallengeInvalidAttemptPolicy): BotChallengeInvalidAttemptPolicy {
  return {
    maxInvalidAttempts: Math.max(1, Math.floor(policy.maxInvalidAttempts)),
    windowMs: Math.max(1_000, Math.floor(policy.windowMs)),
    backoffMs: Math.max(1_000, Math.floor(policy.backoffMs)),
  };
}

export class InMemoryBotChallengeStore implements BotChallengeStore {
  private readonly entries = new Map<string, BotChallengeEntry>();
  private readonly invalidAttempts = new Map<string, InvalidAttemptState>();
  private readonly cleanupTimer: ReturnType<typeof setInterval>;

  constructor(cleanupIntervalMs: number = 30_000) {
    this.cleanupTimer = setInterval(() => this.cleanup(), cleanupIntervalMs);
    if (typeof this.cleanupTimer === 'object' && 'unref' in this.cleanupTimer) {
      this.cleanupTimer.unref();
    }
  }

  async setChallenge(ip: string, ttlSeconds: number, reason: string): Promise<BotChallengeEntry> {
    const now = Date.now();
    const ttlMs = Math.max(1_000, Math.floor(ttlSeconds * 1000));
    const entry: BotChallengeEntry = {
      ip,
      reason,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + ttlMs).toISOString(),
    };
    this.entries.set(ip, entry);
    return entry;
  }

  async getChallenge(ip: string): Promise<BotChallengeEntry | null> {
    const entry = this.entries.get(ip);
    if (!entry) return null;
    if (Date.now() > Date.parse(entry.expiresAt)) {
      this.entries.delete(ip);
      return null;
    }
    return entry;
  }

  async clearChallenge(ip: string): Promise<void> {
    this.entries.delete(ip);
  }

  async getInvalidAttemptBackoffMs(ip: string): Promise<number> {
    const state = this.invalidAttempts.get(ip);
    if (!state) return 0;

    const now = Date.now();
    const remainingMs = state.blockedUntilMs - now;
    if (remainingMs <= 0) {
      if (now - state.windowStartMs > state.windowMs) {
        this.invalidAttempts.delete(ip);
      } else {
        state.blockedUntilMs = 0;
      }
      return 0;
    }

    return remainingMs;
  }

  async registerInvalidAttempt(
    ip: string,
    policyInput: BotChallengeInvalidAttemptPolicy,
  ): Promise<BotChallengeInvalidAttemptResult> {
    const now = Date.now();
    const policy = normalizeInvalidAttemptPolicy(policyInput);

    let state = this.invalidAttempts.get(ip);
    if (!state || now - state.windowStartMs > policy.windowMs) {
      state = {
        windowStartMs: now,
        windowMs: policy.windowMs,
        count: 0,
        blockedUntilMs: 0,
      };
    }

    state.windowMs = policy.windowMs;

    if (state.blockedUntilMs > now) {
      this.invalidAttempts.set(ip, state);
      return {
        blocked: true,
        retryAfterMs: state.blockedUntilMs - now,
        attempts: state.count,
      };
    }

    state.count += 1;
    const attempts = state.count;

    if (state.count >= policy.maxInvalidAttempts) {
      state.count = 0;
      state.windowStartMs = now;
      state.blockedUntilMs = now + policy.backoffMs;
      this.invalidAttempts.set(ip, state);
      return {
        blocked: true,
        retryAfterMs: policy.backoffMs,
        attempts,
      };
    }

    this.invalidAttempts.set(ip, state);
    return {
      blocked: false,
      retryAfterMs: 0,
      attempts,
    };
  }

  async clearInvalidAttempts(ip: string): Promise<void> {
    this.invalidAttempts.delete(ip);
  }

  destroy(): void {
    clearInterval(this.cleanupTimer);
    this.entries.clear();
    this.invalidAttempts.clear();
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [ip, entry] of this.entries.entries()) {
      if (now > Date.parse(entry.expiresAt)) {
        this.entries.delete(ip);
      }
    }

    for (const [ip, entry] of this.invalidAttempts.entries()) {
      if (entry.blockedUntilMs <= now && now - entry.windowStartMs > entry.windowMs) {
        this.invalidAttempts.delete(ip);
      }
    }
  }
}
