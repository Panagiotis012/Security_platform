import type Redis from 'ioredis';
import type {
  SecurityControlsAuditChainPointers,
  SecurityControlsAuditEntry,
  SecurityControlsAuditHistorySnapshot,
  SecurityControlsAuditStore,
} from './security-controls-audit-store';

const APPEND_AUDIT_ENTRY_SCRIPT = `
local order_key = KEYS[1]
local anchor_key = KEYS[2]
local id = ARGV[1]
local payload = ARGV[2]
local entry_hash = ARGV[3]
local max_entries = tonumber(ARGV[4])
local entry_prefix = ARGV[5]
local entry_hash_prefix = ARGV[6]

redis.call('SET', entry_prefix .. id, payload)
redis.call('SET', entry_hash_prefix .. id, entry_hash)
redis.call('RPUSH', order_key, id)

local len = redis.call('LLEN', order_key)
if len > max_entries then
  local trim = len - max_entries
  for i = 1, trim do
    local removed_id = redis.call('LPOP', order_key)
    if removed_id then
      local removed_hash = redis.call('GET', entry_hash_prefix .. removed_id)
      if removed_hash then
        redis.call('SET', anchor_key, removed_hash)
      end
      redis.call('DEL', entry_prefix .. removed_id)
      redis.call('DEL', entry_hash_prefix .. removed_id)
    end
  end
  len = redis.call('LLEN', order_key)
end

local latest_id = redis.call('LINDEX', order_key, -1)
local latest_hash = ''
if latest_id then
  latest_hash = redis.call('GET', entry_hash_prefix .. latest_id) or ''
end
local anchor_hash = redis.call('GET', anchor_key) or ''

return {len, anchor_hash, latest_hash}
`;

function normalizeMaxEntries(maxEntries: number): number {
  if (!Number.isFinite(maxEntries)) return 10_000;
  return Math.max(1, Math.min(Math.floor(maxEntries), 100_000));
}

export class RedisSecurityControlsAuditStore implements SecurityControlsAuditStore {
  private readonly prefix: string;
  private appendScriptSha: string | null = null;

  constructor(
    private readonly redis: Redis,
    options?: { keyPrefix?: string },
  ) {
    this.prefix = options?.keyPrefix ?? 'zt:gateway:security-controls-audit:';
    this.redis.script('LOAD', APPEND_AUDIT_ENTRY_SCRIPT)
      .then((sha) => {
        this.appendScriptSha = sha as string;
      })
      .catch(() => {
        this.appendScriptSha = null;
      });
  }

  async getChainPointers(): Promise<SecurityControlsAuditChainPointers> {
    const pipeline = this.redis.pipeline();
    pipeline.llen(this.orderKey());
    pipeline.get(this.anchorKey());
    pipeline.lindex(this.orderKey(), -1);
    const result = await pipeline.exec();

    const total = Number(result?.[0]?.[1] ?? 0) || 0;
    const anchorRaw = result?.[1]?.[1];
    const latestIdRaw = result?.[2]?.[1];

    const anchorHash = typeof anchorRaw === 'string' && anchorRaw.length > 0 ? anchorRaw : null;
    const latestId = typeof latestIdRaw === 'string' && latestIdRaw.length > 0 ? latestIdRaw : null;
    if (!latestId) {
      return {
        total,
        anchorHash,
        latestEntryHash: null,
      };
    }

    const latestEntryHashRaw = await this.redis.get(this.entryHashKey(latestId));
    return {
      total,
      anchorHash,
      latestEntryHash: latestEntryHashRaw && latestEntryHashRaw.length > 0 ? latestEntryHashRaw : null,
    };
  }

  async append(
    entry: SecurityControlsAuditEntry,
    maxEntriesInput: number,
  ): Promise<SecurityControlsAuditChainPointers> {
    const maxEntries = normalizeMaxEntries(maxEntriesInput);
    const payload = JSON.stringify(entry);
    const args = [
      entry.id,
      payload,
      entry.entryHash,
      String(maxEntries),
      this.entryPrefix(),
      this.entryHashPrefix(),
    ];

    const raw = await this.runAppendScript(args);
    const total = Number(raw[0] ?? 0) || 0;
    const anchorHashRaw = typeof raw[1] === 'string' ? raw[1] : String(raw[1] ?? '');
    const latestHashRaw = typeof raw[2] === 'string' ? raw[2] : String(raw[2] ?? '');

    return {
      total,
      anchorHash: anchorHashRaw.length > 0 ? anchorHashRaw : null,
      latestEntryHash: latestHashRaw.length > 0 ? latestHashRaw : null,
    };
  }

  async listAll(): Promise<SecurityControlsAuditHistorySnapshot> {
    const [ids, anchorRaw] = await Promise.all([
      this.redis.lrange(this.orderKey(), 0, -1),
      this.redis.get(this.anchorKey()),
    ]);

    if (!ids || ids.length === 0) {
      return {
        total: 0,
        anchorHash: anchorRaw && anchorRaw.length > 0 ? anchorRaw : null,
        entries: [],
      };
    }

    const pipeline = this.redis.pipeline();
    for (const id of ids) {
      pipeline.get(this.entryKey(id));
    }
    const rawEntries = await pipeline.exec();

    const entries: SecurityControlsAuditEntry[] = [];
    for (const item of rawEntries ?? []) {
      const payload = item?.[1];
      if (typeof payload !== 'string' || payload.length === 0) continue;
      try {
        const parsed = JSON.parse(payload) as SecurityControlsAuditEntry;
        if (!parsed || typeof parsed !== 'object') continue;
        entries.push(parsed);
      } catch {
        continue;
      }
    }

    return {
      total: entries.length,
      anchorHash: anchorRaw && anchorRaw.length > 0 ? anchorRaw : null,
      entries,
    };
  }

  async getById(id: string): Promise<SecurityControlsAuditEntry | null> {
    const raw = await this.redis.get(this.entryKey(id));
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw) as SecurityControlsAuditEntry;
      return parsed && typeof parsed === 'object' ? parsed : null;
    } catch {
      return null;
    }
  }

  private async runAppendScript(args: string[]): Promise<[unknown, unknown, unknown]> {
    if (!this.appendScriptSha) {
      this.appendScriptSha = (await this.redis.script('LOAD', APPEND_AUDIT_ENTRY_SCRIPT)) as string;
    }

    try {
      return await this.redis.evalsha(
        this.appendScriptSha,
        2,
        this.orderKey(),
        this.anchorKey(),
        ...args,
      ) as [unknown, unknown, unknown];
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (!message.includes('NOSCRIPT')) {
        throw err;
      }

      this.appendScriptSha = (await this.redis.script('LOAD', APPEND_AUDIT_ENTRY_SCRIPT)) as string;
      return await this.redis.evalsha(
        this.appendScriptSha,
        2,
        this.orderKey(),
        this.anchorKey(),
        ...args,
      ) as [unknown, unknown, unknown];
    }
  }

  private orderKey(): string {
    return `${this.prefix}order`;
  }

  private anchorKey(): string {
    return `${this.prefix}anchor`;
  }

  private entryPrefix(): string {
    return `${this.prefix}entry:`;
  }

  private entryHashPrefix(): string {
    return `${this.prefix}entry-hash:`;
  }

  private entryKey(id: string): string {
    return `${this.entryPrefix()}${id}`;
  }

  private entryHashKey(id: string): string {
    return `${this.entryHashPrefix()}${id}`;
  }
}
