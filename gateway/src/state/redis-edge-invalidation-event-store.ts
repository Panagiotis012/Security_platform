import type Redis from 'ioredis';
import type {
  EdgeInvalidationEvent,
  EdgeInvalidationEventAppendInput,
  EdgeInvalidationEventListResult,
  EdgeInvalidationEventStore,
  EdgeInvalidationImportCursorAdvanceResult,
} from './edge-invalidation-event-store';

const APPEND_SCRIPT = `
local seq_key = KEYS[1]
local order_key = KEYS[2]
local event_prefix = KEYS[3]
local payload = ARGV[1]
local max_entries = tonumber(ARGV[2])

local next_cursor = redis.call('INCR', seq_key)
local cursor = tostring(next_cursor)
redis.call('ZADD', order_key, next_cursor, cursor)
redis.call('SET', event_prefix .. cursor, payload)

local count = redis.call('ZCARD', order_key)
if count > max_entries then
  local trim = count - max_entries
  local stale = redis.call('ZRANGE', order_key, 0, trim - 1)
  for _, stale_cursor in ipairs(stale) do
    redis.call('ZREM', order_key, stale_cursor)
    redis.call('DEL', event_prefix .. stale_cursor)
  end
end

return cursor
`;

const ADVANCE_IMPORTED_CURSOR_SCRIPT = `
local key = KEYS[1]
local source = ARGV[1]
local incoming = tonumber(ARGV[2])
local previous_raw = redis.call('HGET', key, source)
local previous = tonumber(previous_raw or '0')
if incoming > previous then
  redis.call('HSET', key, source, tostring(incoming))
  return {tostring(previous), tostring(incoming), 1}
end
return {tostring(previous), tostring(previous), 0}
`;

function normalizeMaxEntries(maxEntries: number): number {
  if (!Number.isFinite(maxEntries)) return 10_000;
  return Math.max(1, Math.min(Math.floor(maxEntries), 200_000));
}

function normalizeLimit(limit: number): number {
  if (!Number.isFinite(limit)) return 1000;
  return Math.max(1, Math.min(Math.floor(limit), 5000));
}

function normalizeCursor(value: string): string {
  const trimmed = String(value ?? '').trim();
  if (!/^\d{1,32}$/.test(trimmed)) return '0';
  return trimmed;
}

export class RedisEdgeInvalidationEventStore implements EdgeInvalidationEventStore {
  private readonly prefix: string;
  private appendScriptSha: string | null = null;
  private advanceCursorScriptSha: string | null = null;

  constructor(
    private readonly redis: Redis,
    options?: { keyPrefix?: string },
  ) {
    this.prefix = options?.keyPrefix ?? 'zt:gateway:edge-invalidation:';
    this.redis.script('LOAD', APPEND_SCRIPT)
      .then((sha) => {
        this.appendScriptSha = sha as string;
      })
      .catch(() => {
        this.appendScriptSha = null;
      });
    this.redis.script('LOAD', ADVANCE_IMPORTED_CURSOR_SCRIPT)
      .then((sha) => {
        this.advanceCursorScriptSha = sha as string;
      })
      .catch(() => {
        this.advanceCursorScriptSha = null;
      });
  }

  async append(event: EdgeInvalidationEventAppendInput, maxEntriesInput: number): Promise<EdgeInvalidationEvent> {
    const payload = JSON.stringify({
      eventId: event.eventId,
      source: event.source,
      occurredAt: event.occurredAt,
      actor: event.actor,
      correlationId: event.correlationId,
      kind: event.kind,
      payload: event.payload,
    });
    const maxEntries = normalizeMaxEntries(maxEntriesInput);
    const cursor = await this.runAppendScript([payload, String(maxEntries)]);
    return {
      cursor,
      eventId: event.eventId,
      source: event.source,
      occurredAt: event.occurredAt,
      actor: event.actor,
      correlationId: event.correlationId,
      kind: event.kind,
      payload: { ...event.payload },
    };
  }

  async listAfter(afterCursorInput: string, limitInput: number): Promise<EdgeInvalidationEventListResult> {
    const afterCursor = normalizeCursor(afterCursorInput);
    const limit = normalizeLimit(limitInput);

    const cursors = await this.redis.zrangebyscore(
      this.orderKey(),
      `(${afterCursor}`,
      '+inf',
      'LIMIT',
      0,
      limit,
    );
    if (!cursors || cursors.length === 0) {
      return {
        entries: [],
        nextCursor: afterCursor,
      };
    }

    const pipeline = this.redis.pipeline();
    for (const cursor of cursors) {
      pipeline.get(this.eventKey(cursor));
    }
    const raw = await pipeline.exec();

    const entries: EdgeInvalidationEvent[] = [];
    for (let i = 0; i < cursors.length; i += 1) {
      const cursor = cursors[i];
      const payload = raw?.[i]?.[1];
      if (typeof payload !== 'string' || !cursor) continue;
      try {
        const parsed = JSON.parse(payload) as Omit<EdgeInvalidationEvent, 'cursor'>;
        if (!parsed || typeof parsed !== 'object') continue;
        entries.push({
          cursor,
          eventId: String(parsed.eventId ?? ''),
          source: String(parsed.source ?? ''),
          occurredAt: String(parsed.occurredAt ?? ''),
          actor: String(parsed.actor ?? ''),
          correlationId:
            typeof parsed.correlationId === 'string' && parsed.correlationId.length > 0
              ? parsed.correlationId
              : undefined,
          kind: parsed.kind,
          payload: (parsed.payload && typeof parsed.payload === 'object')
            ? { ...parsed.payload }
            : {},
        });
      } catch {
        continue;
      }
    }

    return {
      entries,
      nextCursor: entries.length > 0
        ? entries[entries.length - 1]?.cursor ?? afterCursor
        : afterCursor,
    };
  }

  async latestCursor(): Promise<string> {
    const raw = await this.redis.get(this.seqKey());
    return normalizeCursor(raw ?? '0');
  }

  async getImportedCursor(source: string): Promise<string> {
    const raw = await this.redis.hget(this.importedCursorKey(), source);
    return normalizeCursor(raw ?? '0');
  }

  async advanceImportedCursor(source: string, cursor: string): Promise<EdgeInvalidationImportCursorAdvanceResult> {
    const normalizedCursor = normalizeCursor(cursor);
    const raw = await this.runAdvanceImportedCursorScript(source, normalizedCursor);
    const previousCursor = normalizeCursor(String(raw[0] ?? '0'));
    const currentCursor = normalizeCursor(String(raw[1] ?? previousCursor));
    const updated = Number(raw[2] ?? 0) === 1;
    return {
      source,
      previousCursor,
      currentCursor,
      updated,
    };
  }

  private async runAppendScript(args: string[]): Promise<string> {
    if (!this.appendScriptSha) {
      this.appendScriptSha = (await this.redis.script('LOAD', APPEND_SCRIPT)) as string;
    }
    try {
      const result = await this.redis.evalsha(
        this.appendScriptSha,
        3,
        this.seqKey(),
        this.orderKey(),
        this.eventPrefix(),
        ...args,
      );
      return normalizeCursor(String(result ?? '0'));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!message.includes('NOSCRIPT')) throw error;
      this.appendScriptSha = (await this.redis.script('LOAD', APPEND_SCRIPT)) as string;
      const result = await this.redis.evalsha(
        this.appendScriptSha,
        3,
        this.seqKey(),
        this.orderKey(),
        this.eventPrefix(),
        ...args,
      );
      return normalizeCursor(String(result ?? '0'));
    }
  }

  private async runAdvanceImportedCursorScript(
    source: string,
    cursor: string,
  ): Promise<[unknown, unknown, unknown]> {
    if (!this.advanceCursorScriptSha) {
      this.advanceCursorScriptSha = (await this.redis.script('LOAD', ADVANCE_IMPORTED_CURSOR_SCRIPT)) as string;
    }
    try {
      return await this.redis.evalsha(
        this.advanceCursorScriptSha,
        1,
        this.importedCursorKey(),
        source,
        cursor,
      ) as [unknown, unknown, unknown];
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!message.includes('NOSCRIPT')) throw error;
      this.advanceCursorScriptSha = (await this.redis.script('LOAD', ADVANCE_IMPORTED_CURSOR_SCRIPT)) as string;
      return await this.redis.evalsha(
        this.advanceCursorScriptSha,
        1,
        this.importedCursorKey(),
        source,
        cursor,
      ) as [unknown, unknown, unknown];
    }
  }

  private seqKey(): string {
    return `${this.prefix}seq`;
  }

  private orderKey(): string {
    return `${this.prefix}order`;
  }

  private eventPrefix(): string {
    return `${this.prefix}event:`;
  }

  private eventKey(cursor: string): string {
    return `${this.eventPrefix()}${cursor}`;
  }

  private importedCursorKey(): string {
    return `${this.prefix}imported-cursors`;
  }
}
