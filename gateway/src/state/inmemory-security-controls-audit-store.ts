import type {
  SecurityControlsAuditChainPointers,
  SecurityControlsAuditEntry,
  SecurityControlsAuditHistorySnapshot,
  SecurityControlsAuditStore,
} from './security-controls-audit-store';

function normalizeMaxEntries(maxEntries: number): number {
  if (!Number.isFinite(maxEntries)) return 10_000;
  return Math.max(1, Math.min(Math.floor(maxEntries), 100_000));
}

export class InMemorySecurityControlsAuditStore implements SecurityControlsAuditStore {
  private readonly entries: SecurityControlsAuditEntry[] = [];
  private readonly byId = new Map<string, SecurityControlsAuditEntry>();
  private anchorHash: string | null = null;

  async getChainPointers(): Promise<SecurityControlsAuditChainPointers> {
    const latest = this.entries.at(-1);
    return {
      total: this.entries.length,
      anchorHash: this.anchorHash,
      latestEntryHash: latest ? latest.entryHash : null,
    };
  }

  async append(
    entry: SecurityControlsAuditEntry,
    maxEntriesInput: number,
  ): Promise<SecurityControlsAuditChainPointers> {
    const maxEntries = normalizeMaxEntries(maxEntriesInput);
    this.entries.push(entry);
    this.byId.set(entry.id, entry);

    if (this.entries.length > maxEntries) {
      const trimCount = this.entries.length - maxEntries;
      const removed = this.entries.splice(0, trimCount);
      for (const item of removed) {
        this.byId.delete(item.id);
      }
      const anchor = removed.at(-1)?.entryHash;
      if (anchor) {
        this.anchorHash = anchor;
      }
    }

    return this.getChainPointers();
  }

  async listAll(): Promise<SecurityControlsAuditHistorySnapshot> {
    return {
      total: this.entries.length,
      anchorHash: this.anchorHash,
      entries: [...this.entries],
    };
  }

  async getById(id: string): Promise<SecurityControlsAuditEntry | null> {
    return this.byId.get(id) ?? null;
  }

  destroy(): void {
    this.entries.length = 0;
    this.byId.clear();
    this.anchorHash = null;
  }
}
