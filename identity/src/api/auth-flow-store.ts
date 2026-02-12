import type Redis from 'ioredis';

export interface AuthFlowState {
  provider: string;
  codeVerifier: string;
  nonce: string;
  redirectUri?: string;
  createdAt: number;
}

export interface AuthFlowStore {
  put(state: string, flow: AuthFlowState, ttlSeconds: number): Promise<void>;
  consume(state: string): Promise<AuthFlowState | null>;
}

export class InMemoryAuthFlowStore implements AuthFlowStore {
  private readonly flows = new Map<string, AuthFlowState>();
  private readonly cleanupTimer: ReturnType<typeof setInterval>;

  constructor(private readonly ttlMs: number) {
    this.cleanupTimer = setInterval(() => this.cleanup(), 60_000);
    this.cleanupTimer.unref();
  }

  async put(state: string, flow: AuthFlowState, _ttlSeconds: number): Promise<void> {
    void _ttlSeconds; // fixed TTL is configured via constructor
    this.flows.set(state, { ...flow });
  }

  async consume(state: string): Promise<AuthFlowState | null> {
    const flow = this.flows.get(state) ?? null;
    if (flow) this.flows.delete(state);
    if (!flow) return null;

    // Expired?
    if (flow.createdAt + this.ttlMs <= Date.now()) {
      return null;
    }

    return { ...flow };
  }

  destroy(): void {
    clearInterval(this.cleanupTimer);
    this.flows.clear();
  }

  private cleanup(): void {
    const cutoff = Date.now() - this.ttlMs;
    for (const [state, flow] of this.flows.entries()) {
      if (flow.createdAt < cutoff) this.flows.delete(state);
    }
  }
}

const CONSUME_SCRIPT = `
local key = KEYS[1]
local v = redis.call('GET', key)
if v then
  redis.call('DEL', key)
end
return v
`;

export class RedisAuthFlowStore implements AuthFlowStore {
  private readonly keyPrefix: string;
  private scriptSha: string | null = null;

  constructor(
    private readonly redis: Redis,
    options?: { keyPrefix?: string }
  ) {
    this.keyPrefix = options?.keyPrefix ?? 'zt:identity:oidcflow:';
    this.redis.script('LOAD', CONSUME_SCRIPT).then((sha) => {
      this.scriptSha = sha as string;
    }).catch(() => {
      // lazy-load on first consume
    });
  }

  async put(state: string, flow: AuthFlowState, ttlSeconds: number): Promise<void> {
    const ttl = Math.max(1, Math.min(Math.floor(ttlSeconds), 60 * 60));
    await this.redis.setex(this.key(state), ttl, JSON.stringify(flow));
  }

  async consume(state: string): Promise<AuthFlowState | null> {
    const key = this.key(state);
    if (!this.scriptSha) {
      this.scriptSha = (await this.redis.script('LOAD', CONSUME_SCRIPT)) as string;
    }

    const raw = await this.redis.evalsha(this.scriptSha, 1, key) as string | null;
    if (!raw) return null;
    try {
      return JSON.parse(raw) as AuthFlowState;
    } catch {
      return null;
    }
  }

  private key(state: string): string {
    return `${this.keyPrefix}${state}`;
  }
}
