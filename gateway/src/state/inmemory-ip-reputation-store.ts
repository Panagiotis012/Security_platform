import type { IpReputationEntry, IpReputationStore } from './ip-reputation-store';

interface MutableEntry {
  score: number;
  windowStartMs: number;
  windowExpiresAtMs: number;
}

export class InMemoryIpReputationStore implements IpReputationStore {
  private readonly entries = new Map<string, MutableEntry>();
  private readonly cleanupTimer: ReturnType<typeof setInterval>;

  constructor(cleanupIntervalMs: number = 60_000) {
    this.cleanupTimer = setInterval(() => this.cleanup(), cleanupIntervalMs);
    if (typeof this.cleanupTimer === 'object' && 'unref' in this.cleanupTimer) {
      this.cleanupTimer.unref();
    }
  }

  async addScore(ip: string, points: number, windowMs: number): Promise<IpReputationEntry> {
    const now = Date.now();
    const effectivePoints = Number.isFinite(points) ? points : 0;
    const effectiveWindowMs = Math.max(1_000, Math.floor(windowMs));

    let entry = this.entries.get(ip);
    if (!entry || now > entry.windowExpiresAtMs) {
      entry = {
        score: 0,
        windowStartMs: now,
        windowExpiresAtMs: now + effectiveWindowMs,
      };
    }

    entry.score += effectivePoints;
    this.entries.set(ip, entry);

    return {
      ip,
      score: entry.score,
      windowStartMs: entry.windowStartMs,
      windowExpiresAtMs: entry.windowExpiresAtMs,
    };
  }

  async reset(ip: string): Promise<void> {
    this.entries.delete(ip);
  }

  public destroy(): void {
    clearInterval(this.cleanupTimer);
    this.entries.clear();
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [ip, entry] of this.entries.entries()) {
      if (now > entry.windowExpiresAtMs) {
        this.entries.delete(ip);
      }
    }
  }
}

