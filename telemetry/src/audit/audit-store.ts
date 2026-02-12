// ─── Audit Store: Append-Only Log Storage ───
// In production, this would back onto a WORM (Write Once, Read Many) bucket such as
// AWS S3 Object Lock, Azure Immutable Blob, or GCS Bucket Lock.
// The InMemoryAuditStore preserves the same interface guarantees:
//   - Append only: no update() or delete() methods exist
//   - Schema versioning for backward compatibility
//   - Rich querying for investigation and compliance

import winston from 'winston';
import type { HashChainEntry } from './hash-chain';
import { TamperEvidentLog } from './hash-chain';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  defaultMeta: { service: 'audit-store' },
  transports: [new winston.transports.Console()],
});

// ─── Audit Event Schema Types ───

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Decision = 'ALLOW' | 'DENY' | 'CHALLENGE' | 'ERROR';

export interface AuditActor {
  type: 'user' | 'service' | 'system' | 'api-key';
  id: string;
  sessionId?: string;
  deviceId?: string;
}

export interface AuditSubject {
  type: string;
  id: string;
}

export interface AuditResource {
  type: string;
  id: string;
  attributes?: Record<string, unknown>;
}

export interface AuditResult {
  decision: Decision;
  reason?: string;
  policyId?: string;
}

export interface AuditGeoLocation {
  country?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
}

export interface AuditContext {
  ip?: string;
  asn?: string;
  userAgent?: string;
  geoLocation?: AuditGeoLocation;
}

export interface AuditEvent {
  id: string;
  version: string;
  timestamp: string;
  correlationId?: string;
  actor: AuditActor;
  subject: AuditSubject;
  action: string;
  resource: AuditResource;
  result: AuditResult;
  context: AuditContext;
  riskScore?: number;
  metadata?: Record<string, unknown>;
}

// ─── Query Filters ───

export interface AuditQueryFilters {
  actorId?: string;
  actorType?: AuditActor['type'];
  action?: string;
  actions?: string[];
  resourceType?: string;
  resourceId?: string;
  decision?: Decision;
  decisions?: Decision[];
  minRiskScore?: number;
  maxRiskScore?: number;
  fromTimestamp?: string;
  toTimestamp?: string;
  correlationId?: string;
  ip?: string;
  limit?: number;
  offset?: number;
}

// ─── Audit Store Interface ───

export interface AuditStore {
  /** Append an event. No update or delete methods exist by design. */
  append(event: AuditEvent): Promise<{ index: number; hash: string }>;

  /** Query events with filters. Returns matching events in chronological order. */
  query(filters: AuditQueryFilters): Promise<{ events: AuditEvent[]; total: number }>;

  /** Export events in a time range for compliance reporting. */
  exportRange(from: string, to: string): Promise<AuditEvent[]>;

  /** Get the latest hash chain entry for external verification. */
  getChainHead(): HashChainEntry<string> | null;

  /** Verify hash chain integrity for a segment. */
  verifyIntegrity(fromIndex?: number, toIndex?: number): { valid: boolean; brokenAtIndex?: number };

  /** Get total event count. */
  getCount(): number;
}

// ─── In-Memory Audit Store Implementation ───

export class InMemoryAuditStore implements AuditStore {
  private events: AuditEvent[] = [];
  private hashChain: TamperEvidentLog<string>;

  // Indexes for efficient querying
  private byActor: Map<string, number[]> = new Map();
  private byAction: Map<string, number[]> = new Map();
  private byResource: Map<string, number[]> = new Map();
  private byDecision: Map<Decision, number[]> = new Map();
  private byIp: Map<string, number[]> = new Map();
  private byCorrelation: Map<string, number[]> = new Map();

  constructor() {
    this.hashChain = new TamperEvidentLog<string>();
    logger.info('InMemoryAuditStore initialized (append-only, tamper-evident)');
  }

  async append(event: AuditEvent): Promise<{ index: number; hash: string }> {
    const index = this.events.length;

    // Ensure schema version compatibility
    this.validateSchemaVersion(event.version);

    // Store the event (immutable - we freeze it)
    const frozenEvent = Object.freeze({ ...event });
    this.events.push(frozenEvent);

    // Append the event ID to the hash chain for tamper evidence
    // We hash the entire canonical JSON of the event
    const canonicalJson = JSON.stringify(frozenEvent);
    const chainEntry = this.hashChain.append(canonicalJson);

    // Update indexes
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

    logger.debug('Audit event appended', {
      eventId: frozenEvent.id,
      index,
      action: frozenEvent.action,
      chainHash: chainEntry.hash.slice(0, 16) + '...',
    });

    return { index, hash: chainEntry.hash };
  }

  async query(filters: AuditQueryFilters): Promise<{ events: AuditEvent[]; total: number }> {
    let candidateIndices: Set<number> | null = null;

    // Use indexes to narrow candidates
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

    // If no index was used, scan all
    const indices = candidateIndices
      ? Array.from(candidateIndices).sort((a, b) => a - b)
      : Array.from({ length: this.events.length }, (_, i) => i);

    // Apply remaining filters
    const matchingEvents: AuditEvent[] = [];
    for (const idx of indices) {
      const event = this.events[idx];
      if (!event) continue;

      if (filters.actorType && event.actor.type !== filters.actorType) continue;
      if (filters.resourceType && event.resource.type !== filters.resourceType) continue;

      if (filters.minRiskScore !== undefined && (event.riskScore ?? 0) < filters.minRiskScore) continue;
      if (filters.maxRiskScore !== undefined && (event.riskScore ?? 0) > filters.maxRiskScore) continue;

      if (filters.fromTimestamp && event.timestamp < filters.fromTimestamp) continue;
      if (filters.toTimestamp && event.timestamp > filters.toTimestamp) continue;

      matchingEvents.push(event);
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
    return {
      valid: result.valid,
      brokenAtIndex: result.brokenAtIndex,
    };
  }

  getCount(): number {
    return this.events.length;
  }

  /**
   * Get all events within a time window (used by detection engine).
   * Optimized: scans from the end since recent events are most relevant.
   */
  getEventsInWindow(windowMs: number): AuditEvent[] {
    const cutoff = new Date(Date.now() - windowMs).toISOString();
    const results: AuditEvent[] = [];

    // Scan backward for efficiency (events are in chronological order)
    for (let i = this.events.length - 1; i >= 0; i--) {
      if (this.events[i].timestamp < cutoff) break;
      results.push(this.events[i]);
    }

    return results.reverse();
  }

  // ─── Private helpers ───

  private addToIndex(map: Map<string, number[]>, key: string, index: number): void {
    const existing = map.get(key);
    if (existing) {
      existing.push(index);
    } else {
      map.set(key, [index]);
    }
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
