// ─── File-backed Audit Store (Append-only + Tamper-evident) ───
//
// This is a pragmatic persistence layer for local/dev and single-node deployments.
// It keeps the same security guarantees as InMemoryAuditStore:
//   - append-only (no update/delete)
//   - tamper-evident hash chain over canonical JSON
//
// IMPORTANT: This is not a replacement for true WORM storage. In production,
// back this onto immutable object storage (S3 Object Lock / GCS Bucket Lock),
// or a database with immutability controls and external checkpoints.

import fs from 'fs';
import path from 'path';
import winston from 'winston';
import type { HashChainEntry } from './hash-chain';
import { TamperEvidentLog } from './hash-chain';
import type {
  AuditStore,
  AuditEvent,
  AuditQueryFilters,
  Decision,
} from './audit-store';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  defaultMeta: { service: 'file-audit-store' },
  transports: [new winston.transports.Console()],
});

export interface FileAuditStoreOptions {
  filePath: string;
  /** fsync after every append (stronger durability, slower). */
  fsyncOnAppend: boolean;
}

export class FileAuditStore implements AuditStore {
  private readonly filePath: string;
  private readonly fsyncOnAppend: boolean;

  private events: AuditEvent[] = [];
  private hashChain: TamperEvidentLog<string>;

  // Indexes for efficient querying
  private byActor: Map<string, number[]> = new Map();
  private byAction: Map<string, number[]> = new Map();
  private byResource: Map<string, number[]> = new Map();
  private byDecision: Map<Decision, number[]> = new Map();
  private byIp: Map<string, number[]> = new Map();
  private byCorrelation: Map<string, number[]> = new Map();

  constructor(options: FileAuditStoreOptions) {
    this.filePath = options.filePath;
    this.fsyncOnAppend = options.fsyncOnAppend;
    this.hashChain = new TamperEvidentLog<string>();

    this.loadFromDisk();

    logger.info('FileAuditStore initialized', {
      filePath: this.filePath,
      events: this.events.length,
      fsyncOnAppend: this.fsyncOnAppend,
    });
  }

  async append(event: AuditEvent): Promise<{ index: number; hash: string }> {
    const index = this.events.length;
    this.validateSchemaVersion(event.version);

    const frozenEvent = Object.freeze({ ...event });
    this.events.push(frozenEvent);

    const canonicalJson = JSON.stringify(frozenEvent);
    const chainEntry = this.hashChain.append(canonicalJson);

    this.addToIndex(this.byActor, frozenEvent.actor.id, index);
    this.addToIndex(this.byAction, frozenEvent.action, index);
    this.addToIndex(this.byResource, `${frozenEvent.resource.type}:${frozenEvent.resource.id}`, index);
    this.addToIndex(this.byDecision, frozenEvent.result.decision, index);
    if (frozenEvent.context.ip) {
      this.addToIndex(this.byIp, frozenEvent.context.ip, index);
    }
    if (frozenEvent.correlationId) {
      this.addToIndex(this.byCorrelation, frozenEvent.correlationId, index);
    }

    this.appendLineToDisk(canonicalJson);

    return { index, hash: chainEntry.hash };
  }

  async query(filters: AuditQueryFilters): Promise<{ events: AuditEvent[]; total: number }> {
    let candidateIndices: Set<number> | null = null;

    if (filters.actorId) {
      candidateIndices = this.intersect(candidateIndices, new Set(this.byActor.get(filters.actorId) || []));
    }
    if (filters.action) {
      candidateIndices = this.intersect(candidateIndices, new Set(this.byAction.get(filters.action) || []));
    }
    if (filters.actions && filters.actions.length > 0) {
      const actionIndices = new Set<number>();
      for (const action of filters.actions) {
        const indices = this.byAction.get(action) || [];
        indices.forEach((i) => actionIndices.add(i));
      }
      candidateIndices = this.intersect(candidateIndices, actionIndices);
    }
    if (filters.resourceType || filters.resourceId) {
      if (filters.resourceType && filters.resourceId) {
        const key = `${filters.resourceType}:${filters.resourceId}`;
        candidateIndices = this.intersect(candidateIndices, new Set(this.byResource.get(key) || []));
      }
    }
    if (filters.decision) {
      candidateIndices = this.intersect(candidateIndices, new Set(this.byDecision.get(filters.decision) || []));
    }
    if (filters.decisions && filters.decisions.length > 0) {
      const decisionIndices = new Set<number>();
      for (const d of filters.decisions) {
        const indices = this.byDecision.get(d) || [];
        indices.forEach((i) => decisionIndices.add(i));
      }
      candidateIndices = this.intersect(candidateIndices, decisionIndices);
    }
    if (filters.ip) {
      candidateIndices = this.intersect(candidateIndices, new Set(this.byIp.get(filters.ip) || []));
    }
    if (filters.correlationId) {
      candidateIndices = this.intersect(candidateIndices, new Set(this.byCorrelation.get(filters.correlationId) || []));
    }

    const indices = candidateIndices
      ? Array.from(candidateIndices).sort((a, b) => a - b)
      : Array.from({ length: this.events.length }, (_, i) => i);

    const matchingEvents: AuditEvent[] = [];
    for (const idx of indices) {
      const ev = this.events[idx];
      if (!ev) continue;

      if (filters.actorType && ev.actor.type !== filters.actorType) continue;
      if (filters.resourceType && ev.resource.type !== filters.resourceType) continue;

      if (filters.minRiskScore !== undefined && (ev.riskScore ?? 0) < filters.minRiskScore) continue;
      if (filters.maxRiskScore !== undefined && (ev.riskScore ?? 0) > filters.maxRiskScore) continue;

      if (filters.fromTimestamp && ev.timestamp < filters.fromTimestamp) continue;
      if (filters.toTimestamp && ev.timestamp > filters.toTimestamp) continue;

      matchingEvents.push(ev);
    }

    const total = matchingEvents.length;
    const offset = filters.offset ?? 0;
    const limit = filters.limit ?? 100;
    const paged = matchingEvents.slice(offset, offset + limit);

    return { events: paged, total };
  }

  async exportRange(from: string, to: string): Promise<AuditEvent[]> {
    return this.events.filter((e) => e.timestamp >= from && e.timestamp <= to);
  }

  getChainHead(): HashChainEntry<string> | null {
    return this.hashChain.getHead();
  }

  verifyIntegrity(fromIndex?: number, toIndex?: number): { valid: boolean; brokenAtIndex?: number } {
    const result = this.hashChain.verify(fromIndex, toIndex);
    return { valid: result.valid, brokenAtIndex: result.brokenAtIndex };
  }

  getCount(): number {
    return this.events.length;
  }

  getEventsInWindow(windowMs: number): AuditEvent[] {
    const cutoff = new Date(Date.now() - windowMs).toISOString();
    const results: AuditEvent[] = [];
    for (let i = this.events.length - 1; i >= 0; i--) {
      if (this.events[i].timestamp < cutoff) break;
      results.push(this.events[i]);
    }
    return results.reverse();
  }

  // ─── Disk I/O ──────────────────────────────────────────────────────────

  private loadFromDisk(): void {
    try {
      const dir = path.dirname(this.filePath);
      fs.mkdirSync(dir, { recursive: true });

      if (!fs.existsSync(this.filePath)) {
        return;
      }

      const content = fs.readFileSync(this.filePath, 'utf8');
      const lines = content.split('\n').filter(Boolean);

      for (const line of lines) {
        try {
          const parsed = JSON.parse(line) as AuditEvent;
          const idx = this.events.length;
          const frozen = Object.freeze({ ...parsed });
          this.events.push(frozen);

          // Rebuild chain and indexes.
          const canonicalJson = JSON.stringify(frozen);
          this.hashChain.append(canonicalJson);

          this.addToIndex(this.byActor, frozen.actor.id, idx);
          this.addToIndex(this.byAction, frozen.action, idx);
          this.addToIndex(this.byResource, `${frozen.resource.type}:${frozen.resource.id}`, idx);
          this.addToIndex(this.byDecision, frozen.result.decision, idx);
          if (frozen.context.ip) this.addToIndex(this.byIp, frozen.context.ip, idx);
          if (frozen.correlationId) this.addToIndex(this.byCorrelation, frozen.correlationId, idx);
        } catch {
          // Ignore corrupted lines but keep going; integrity verification should catch this.
          logger.warn('Failed to parse audit log line (ignored)', {
            filePath: this.filePath,
          });
        }
      }
    } catch (err) {
      logger.error('Failed to initialize FileAuditStore', {
        filePath: this.filePath,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  private appendLineToDisk(line: string): void {
    try {
      fs.appendFileSync(this.filePath, line + '\n', 'utf8');
      if (this.fsyncOnAppend) {
        const fd = fs.openSync(this.filePath, 'r');
        try {
          fs.fsyncSync(fd);
        } finally {
          fs.closeSync(fd);
        }
      }
    } catch (err) {
      // Append failures are serious but should not crash the plane by default.
      // The audit pipeline should alert on this and degrade.
      logger.error('Failed to append audit event to disk', {
        filePath: this.filePath,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  // ─── Helpers ───────────────────────────────────────────────────────────

  private addToIndex(map: Map<string, number[]>, key: string, index: number): void {
    const existing = map.get(key);
    if (existing) existing.push(index);
    else map.set(key, [index]);
  }

  private intersect(current: Set<number> | null, incoming: Set<number>): Set<number> {
    if (current === null) return incoming;
    const result = new Set<number>();
    for (const idx of incoming) {
      if (current.has(idx)) result.add(idx);
    }
    return result;
  }

  private validateSchemaVersion(version: string): void {
    const supportedVersions = ['1', '1.0', '1.1', '2', '2.0'];
    if (!supportedVersions.includes(version)) {
      logger.warn('Unknown audit event schema version, storing anyway for forward compatibility', { version });
    }
  }
}

