import {
  type IpBlockEntry,
  type SecurityStateStore,
  type StepUpEntry,
  type ThrottleEntry,
} from './security-state-store';

function nowIso(): string {
  return new Date().toISOString();
}

export class InMemorySecurityStateStore implements SecurityStateStore {
  private readonly ipBlocks = new Map<string, IpBlockEntry>();
  private readonly stepUp = new Map<string, StepUpEntry>();
  private readonly throttles = new Map<string, ThrottleEntry>();

  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly cleanupIntervalMs: number = 30_000) {
    this.cleanupTimer = setInterval(() => this.cleanup(), this.cleanupIntervalMs);
    if (this.cleanupTimer.unref) this.cleanupTimer.unref();
  }

  async blockIps(
    ips: string[],
    ttlSeconds: number,
    meta: { reason: string; alertId?: string },
  ): Promise<IpBlockEntry[]> {
    const now = nowIso();
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
    const entries: IpBlockEntry[] = [];

    for (const ip of ips) {
      const entry: IpBlockEntry = {
        ip,
        blockedAt: now,
        expiresAt,
        reason: meta.reason,
        alertId: meta.alertId,
      };
      this.ipBlocks.set(ip, entry);
      entries.push(entry);
    }

    return entries;
  }

  async isIpBlocked(ip: string): Promise<IpBlockEntry | null> {
    const entry = this.ipBlocks.get(ip);
    if (!entry) return null;
    if (Date.now() > Date.parse(entry.expiresAt)) {
      this.ipBlocks.delete(ip);
      return null;
    }
    return entry;
  }

  async unblockIp(ip: string): Promise<void> {
    this.ipBlocks.delete(ip);
  }

  async listBlockedIps(limit: number = 1000): Promise<IpBlockEntry[]> {
    const now = Date.now();
    const out: IpBlockEntry[] = [];
    for (const [ip, entry] of this.ipBlocks.entries()) {
      if (now > Date.parse(entry.expiresAt)) {
        this.ipBlocks.delete(ip);
        continue;
      }
      out.push(entry);
    }
    out.sort((a, b) => Date.parse(b.expiresAt) - Date.parse(a.expiresAt));
    return out.slice(0, Math.max(1, Math.floor(limit)));
  }

  async requireStepUp(
    userId: string,
    requiredLevel: number,
    ttlSeconds: number,
    meta: { reason: string; alertId?: string },
  ): Promise<StepUpEntry> {
    const entry: StepUpEntry = {
      userId,
      requiredLevel,
      flaggedAt: nowIso(),
      expiresAt: new Date(Date.now() + ttlSeconds * 1000).toISOString(),
      reason: meta.reason,
      alertId: meta.alertId,
    };
    this.stepUp.set(userId, entry);
    return entry;
  }

  async getStepUpRequirement(userId: string): Promise<StepUpEntry | null> {
    const entry = this.stepUp.get(userId);
    if (!entry) return null;
    if (Date.now() > Date.parse(entry.expiresAt)) {
      this.stepUp.delete(userId);
      return null;
    }
    return entry;
  }

  async clearStepUpRequirement(userId: string): Promise<void> {
    this.stepUp.delete(userId);
  }

  async throttleUser(
    userId: string,
    reducedRatePercent: number,
    ttlSeconds: number,
    meta: { reason: string; alertId?: string },
  ): Promise<ThrottleEntry> {
    const entry: ThrottleEntry = {
      userId,
      reducedRatePercent,
      throttledAt: nowIso(),
      expiresAt: new Date(Date.now() + ttlSeconds * 1000).toISOString(),
      reason: meta.reason,
      alertId: meta.alertId,
    };
    this.throttles.set(userId, entry);
    return entry;
  }

  async getThrottle(userId: string): Promise<ThrottleEntry | null> {
    const entry = this.throttles.get(userId);
    if (!entry) return null;
    if (Date.now() > Date.parse(entry.expiresAt)) {
      this.throttles.delete(userId);
      return null;
    }
    return entry;
  }

  async clearThrottle(userId: string): Promise<void> {
    this.throttles.delete(userId);
  }

  public destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.ipBlocks.clear();
    this.stepUp.clear();
    this.throttles.clear();
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [ip, entry] of this.ipBlocks) {
      if (now > Date.parse(entry.expiresAt)) this.ipBlocks.delete(ip);
    }
    for (const [userId, entry] of this.stepUp) {
      if (now > Date.parse(entry.expiresAt)) this.stepUp.delete(userId);
    }
    for (const [userId, entry] of this.throttles) {
      if (now > Date.parse(entry.expiresAt)) this.throttles.delete(userId);
    }
  }
}
