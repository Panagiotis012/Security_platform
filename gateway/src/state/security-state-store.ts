export interface IpBlockEntry {
  ip: string;
  blockedAt: string;
  expiresAt: string;
  reason: string;
  alertId?: string;
}

export interface StepUpEntry {
  userId: string;
  requiredLevel: number;
  flaggedAt: string;
  expiresAt: string;
  reason: string;
  alertId?: string;
}

export interface ThrottleEntry {
  userId: string;
  reducedRatePercent: number;
  throttledAt: string;
  expiresAt: string;
  reason: string;
  alertId?: string;
}

export interface SecurityStateStore {
  // IP blocklist
  blockIps(ips: string[], ttlSeconds: number, meta: { reason: string; alertId?: string }): Promise<IpBlockEntry[]>;
  isIpBlocked(ip: string): Promise<IpBlockEntry | null>;
  unblockIp(ip: string): Promise<void>;
  listBlockedIps(limit?: number): Promise<IpBlockEntry[]>;

  // Step-up requirements
  requireStepUp(userId: string, requiredLevel: number, ttlSeconds: number, meta: { reason: string; alertId?: string }): Promise<StepUpEntry>;
  getStepUpRequirement(userId: string): Promise<StepUpEntry | null>;
  clearStepUpRequirement(userId: string): Promise<void>;

  // Throttling
  throttleUser(userId: string, reducedRatePercent: number, ttlSeconds: number, meta: { reason: string; alertId?: string }): Promise<ThrottleEntry>;
  getThrottle(userId: string): Promise<ThrottleEntry | null>;
  clearThrottle(userId: string): Promise<void>;
}
