export type EdgeInvalidationEventKind = 'purge' | 'version_set';

export interface EdgeInvalidationEvent {
  cursor: string;
  eventId: string;
  source: string;
  occurredAt: string;
  actor: string;
  correlationId?: string;
  kind: EdgeInvalidationEventKind;
  payload: Record<string, unknown>;
}

export interface EdgeInvalidationEventAppendInput {
  eventId: string;
  source: string;
  occurredAt: string;
  actor: string;
  correlationId?: string;
  kind: EdgeInvalidationEventKind;
  payload: Record<string, unknown>;
}

export interface EdgeInvalidationEventListResult {
  entries: EdgeInvalidationEvent[];
  nextCursor: string;
}

export interface EdgeInvalidationImportCursorAdvanceResult {
  source: string;
  previousCursor: string;
  currentCursor: string;
  updated: boolean;
}

export interface EdgeInvalidationEventStore {
  append(
    event: EdgeInvalidationEventAppendInput,
    maxEntries: number,
  ): Promise<EdgeInvalidationEvent>;
  listAfter(afterCursor: string, limit: number): Promise<EdgeInvalidationEventListResult>;
  latestCursor(): Promise<string>;
  getImportedCursor(source: string): Promise<string>;
  advanceImportedCursor(
    source: string,
    cursor: string,
  ): Promise<EdgeInvalidationImportCursorAdvanceResult>;
}
