export interface IpReputationEntry {
  ip: string;
  score: number;
  windowStartMs: number;
  windowExpiresAtMs: number;
}

export interface IpReputationStore {
  addScore(ip: string, points: number, windowMs: number): Promise<IpReputationEntry>;
  reset(ip: string): Promise<void>;
}

