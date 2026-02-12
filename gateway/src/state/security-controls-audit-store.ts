export interface SecurityControlsAuditEntry {
  id: string;
  changedAt: string;
  actor: string;
  correlationId: string;
  patch: Record<string, unknown>;
  snapshotHash: string;
  previousEntryHash: string | null;
  entryHash: string;
  signature: string;
}

export interface SecurityControlsAuditChainPointers {
  total: number;
  anchorHash: string | null;
  latestEntryHash: string | null;
}

export interface SecurityControlsAuditHistorySnapshot {
  total: number;
  anchorHash: string | null;
  entries: SecurityControlsAuditEntry[];
}

export interface SecurityControlsAuditStore {
  getChainPointers(): Promise<SecurityControlsAuditChainPointers>;
  append(entry: SecurityControlsAuditEntry, maxEntries: number): Promise<SecurityControlsAuditChainPointers>;
  listAll(): Promise<SecurityControlsAuditHistorySnapshot>;
  getById(id: string): Promise<SecurityControlsAuditEntry | null>;
}
