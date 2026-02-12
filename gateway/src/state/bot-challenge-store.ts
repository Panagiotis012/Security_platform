export interface BotChallengeEntry {
  ip: string;
  reason: string;
  createdAt: string;
  expiresAt: string;
}

export interface BotChallengeInvalidAttemptPolicy {
  maxInvalidAttempts: number;
  windowMs: number;
  backoffMs: number;
}

export interface BotChallengeInvalidAttemptResult {
  blocked: boolean;
  retryAfterMs: number;
  attempts: number;
}

export interface BotChallengeStore {
  setChallenge(ip: string, ttlSeconds: number, reason: string): Promise<BotChallengeEntry>;
  getChallenge(ip: string): Promise<BotChallengeEntry | null>;
  clearChallenge(ip: string): Promise<void>;
  getInvalidAttemptBackoffMs(ip: string): Promise<number>;
  registerInvalidAttempt(
    ip: string,
    policy: BotChallengeInvalidAttemptPolicy,
  ): Promise<BotChallengeInvalidAttemptResult>;
  clearInvalidAttempts(ip: string): Promise<void>;
}
