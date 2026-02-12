import type {
  EdgeInvalidationEvent,
  EdgeInvalidationEventAppendInput,
  EdgeInvalidationEventListResult,
  EdgeInvalidationEventStore,
  EdgeInvalidationImportCursorAdvanceResult,
} from './edge-invalidation-event-store';

function normalizeMaxEntries(maxEntries: number): number {
  if (!Number.isFinite(maxEntries)) return 10_000;
  return Math.max(1, Math.min(Math.floor(maxEntries), 200_000));
}

function normalizeLimit(limit: number): number {
  if (!Number.isFinite(limit)) return 1000;
  return Math.max(1, Math.min(Math.floor(limit), 5000));
}

function parseCursor(value: string): bigint {
  if (!/^\d{1,32}$/.test(value)) return 0n;
  try {
    return BigInt(value);
  } catch {
    return 0n;
  }
}

export class InMemoryEdgeInvalidationEventStore implements EdgeInvalidationEventStore {
  private readonly entries: EdgeInvalidationEvent[] = [];
  private nextCursor = 0n;
  private readonly importedCursors = new Map<string, string>();

  async append(
    event: EdgeInvalidationEventAppendInput,
    maxEntriesInput: number,
  ): Promise<EdgeInvalidationEvent> {
    const maxEntries = normalizeMaxEntries(maxEntriesInput);
    this.nextCursor += 1n;
    const stored: EdgeInvalidationEvent = {
      cursor: this.nextCursor.toString(),
      eventId: event.eventId,
      source: event.source,
      occurredAt: event.occurredAt,
      actor: event.actor,
      correlationId: event.correlationId,
      kind: event.kind,
      payload: { ...event.payload },
    };
    this.entries.push(stored);

    if (this.entries.length > maxEntries) {
      const trimCount = this.entries.length - maxEntries;
      this.entries.splice(0, trimCount);
    }

    return {
      ...stored,
      payload: { ...stored.payload },
    };
  }

  async listAfter(afterCursorInput: string, limitInput: number): Promise<EdgeInvalidationEventListResult> {
    const afterCursor = parseCursor(afterCursorInput);
    const limit = normalizeLimit(limitInput);
    const entries = this.entries
      .filter((entry) => parseCursor(entry.cursor) > afterCursor)
      .slice(0, limit)
      .map((entry) => ({
        ...entry,
        payload: { ...entry.payload },
      }));

    const nextCursor = entries.length > 0
      ? entries[entries.length - 1]?.cursor ?? afterCursorInput
      : afterCursorInput;
    return {
      entries,
      nextCursor: nextCursor || '0',
    };
  }

  async latestCursor(): Promise<string> {
    return this.nextCursor.toString();
  }

  async getImportedCursor(source: string): Promise<string> {
    return this.importedCursors.get(source) ?? '0';
  }

  async advanceImportedCursor(source: string, cursor: string): Promise<EdgeInvalidationImportCursorAdvanceResult> {
    const previousCursor = this.importedCursors.get(source) ?? '0';
    const previous = parseCursor(previousCursor);
    const incoming = parseCursor(cursor);
    const updated = incoming > previous;
    const currentCursor = updated ? incoming.toString() : previousCursor;
    if (updated) {
      this.importedCursors.set(source, currentCursor);
    }
    return {
      source,
      previousCursor,
      currentCursor,
      updated,
    };
  }

  destroy(): void {
    this.entries.length = 0;
    this.nextCursor = 0n;
    this.importedCursors.clear();
  }
}
