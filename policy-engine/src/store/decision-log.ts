import { v4 as uuidv4 } from 'uuid';
import type {
  PolicyRequest,
  PolicyDecision,
  DecisionLogEntry,
  DecisionQuery,
} from '../models/policy-schema';
import { createLogger } from '../utils/logger';
import config from '../../config/default';

const logger = createLogger('decision-log');

/**
 * DecisionLogger interface defines the contract for decision logging backends.
 */
export interface DecisionLogger {
  log(request: PolicyRequest, decision: PolicyDecision): Promise<DecisionLogEntry>;
  query(filters: DecisionQuery): Promise<{ entries: DecisionLogEntry[]; total: number }>;
  export(filters: DecisionQuery): Promise<DecisionLogEntry[]>;
  getStats(): Promise<DecisionLogStats>;
}

export interface DecisionLogStats {
  totalDecisions: number;
  totalAllows: number;
  totalDenies: number;
  averageEvaluationTimeMs: number;
  oldestEntry: string | null;
  newestEntry: string | null;
}

/**
 * InMemoryDecisionLogger implements append-only decision logging
 * with query and export capabilities for compliance.
 */
export class InMemoryDecisionLogger implements DecisionLogger {
  /** Append-only log entries */
  private entries: DecisionLogEntry[] = [];

  /** Index: actorId -> entry indices for fast lookup */
  private actorIndex: Map<string, number[]> = new Map();

  /** Index: correlationId -> entry index */
  private correlationIndex: Map<string, number> = new Map();

  /** Maximum entries to retain in memory */
  private maxEntries: number;

  constructor(maxEntries?: number) {
    this.maxEntries = maxEntries ?? config.logging.decisionLogMaxEntries;
  }

  /**
   * Log a policy decision. Append-only: entries are never modified after creation.
   * Every ALLOW and DENY is logged.
   */
  async log(request: PolicyRequest, decision: PolicyDecision): Promise<DecisionLogEntry> {
    const entry: DecisionLogEntry = {
      id: uuidv4(),
      timestamp: decision.timestamp,
      correlationId: decision.correlationId ?? request.correlationId ?? uuidv4(),
      actor: {
        id: request.actor.id,
        roles: [...request.actor.roles],
        attributes: { ...request.actor.attributes },
      },
      action: request.action,
      resource: {
        type: request.resource.type,
        id: request.resource.id,
        attributes: config.logging.includeAttributes
          ? { ...request.resource.attributes }
          : {},
      },
      environment: request.environment
        ? {
            ip: request.environment.ip,
            time: request.environment.time,
            deviceId: request.environment.deviceId,
            sessionId: request.environment.sessionId,
            stepUpLevel: request.environment.stepUpLevel,
          }
        : undefined,
      decision: decision.decision,
      policyId: decision.policyId,
      reason: decision.reason,
      evaluationTimeMs: decision.evaluationTimeMs,
    };

    // Enforce max entries - evict oldest if at capacity
    if (this.entries.length >= this.maxEntries) {
      this.evictOldest();
    }

    const index = this.entries.length;
    this.entries.push(entry);

    // Update indexes
    if (!this.actorIndex.has(entry.actor.id)) {
      this.actorIndex.set(entry.actor.id, []);
    }
    this.actorIndex.get(entry.actor.id)!.push(index);

    this.correlationIndex.set(entry.correlationId, index);

    logger.debug('Decision logged', {
      entryId: entry.id,
      actorId: entry.actor.id,
      action: entry.action,
      decision: entry.decision,
      evaluationTimeMs: entry.evaluationTimeMs,
    });

    return entry;
  }

  /**
   * Query decision logs with filtering and pagination.
   */
  async query(filters: DecisionQuery): Promise<{ entries: DecisionLogEntry[]; total: number }> {
    let results: DecisionLogEntry[];

    // Optimize: if correlationId is specified, use index for direct lookup
    if (filters.correlationId) {
      const idx = this.correlationIndex.get(filters.correlationId);
      if (idx !== undefined && idx < this.entries.length) {
        results = [this.entries[idx]];
      } else {
        results = [];
      }
    }
    // Optimize: if actorId is specified, use actor index
    else if (filters.actorId) {
      const indices = this.actorIndex.get(filters.actorId) ?? [];
      results = indices
        .filter((i) => i < this.entries.length)
        .map((i) => this.entries[i]);
    }
    // Full scan for other filters
    else {
      results = [...this.entries];
    }

    // Apply remaining filters
    results = this.applyFilters(results, filters);

    // Sort by timestamp descending (newest first)
    results.sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );

    const total = results.length;
    const offset = filters.offset ?? 0;
    const limit = filters.limit ?? 100;
    const paged = results.slice(offset, offset + limit);

    return { entries: paged, total };
  }

  /**
   * Export all matching entries for compliance purposes.
   * No pagination limit - returns all matches.
   */
  async export(filters: DecisionQuery): Promise<DecisionLogEntry[]> {
    let results = [...this.entries];
    results = this.applyFilters(results, filters);
    results.sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );
    return results;
  }

  /**
   * Get aggregate statistics about the decision log.
   */
  async getStats(): Promise<DecisionLogStats> {
    if (this.entries.length === 0) {
      return {
        totalDecisions: 0,
        totalAllows: 0,
        totalDenies: 0,
        averageEvaluationTimeMs: 0,
        oldestEntry: null,
        newestEntry: null,
      };
    }

    let totalAllows = 0;
    let totalDenies = 0;
    let totalEvalTime = 0;

    for (const entry of this.entries) {
      if (entry.decision === 'ALLOW') totalAllows++;
      else totalDenies++;
      totalEvalTime += entry.evaluationTimeMs;
    }

    // Entries are appended in order, so first is oldest, last is newest
    const sortedByTime = [...this.entries].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    return {
      totalDecisions: this.entries.length,
      totalAllows,
      totalDenies,
      averageEvaluationTimeMs:
        Math.round((totalEvalTime / this.entries.length) * 1000) / 1000,
      oldestEntry: sortedByTime[0].timestamp,
      newestEntry: sortedByTime[sortedByTime.length - 1].timestamp,
    };
  }

  /**
   * Apply query filters to a set of entries.
   */
  private applyFilters(entries: DecisionLogEntry[], filters: DecisionQuery): DecisionLogEntry[] {
    let results = entries;

    if (filters.actorId) {
      results = results.filter((e) => e.actor.id === filters.actorId);
    }

    if (filters.action) {
      results = results.filter((e) => e.action === filters.action);
    }

    if (filters.resourceType) {
      results = results.filter((e) => e.resource.type === filters.resourceType);
    }

    if (filters.resourceId) {
      results = results.filter((e) => e.resource.id === filters.resourceId);
    }

    if (filters.decision) {
      results = results.filter((e) => e.decision === filters.decision);
    }

    if (filters.fromTime) {
      const from = new Date(filters.fromTime).getTime();
      results = results.filter((e) => new Date(e.timestamp).getTime() >= from);
    }

    if (filters.toTime) {
      const to = new Date(filters.toTime).getTime();
      results = results.filter((e) => new Date(e.timestamp).getTime() <= to);
    }

    return results;
  }

  /**
   * Evict the oldest 10% of entries when at capacity.
   * Rebuilds indexes after eviction.
   */
  private evictOldest(): void {
    const evictCount = Math.max(1, Math.floor(this.maxEntries * 0.1));
    this.entries.splice(0, evictCount);

    // Rebuild indexes after eviction
    this.rebuildIndexes();

    logger.info('Decision log eviction completed', {
      evicted: evictCount,
      remaining: this.entries.length,
    });
  }

  /**
   * Rebuild all indexes from scratch.
   */
  private rebuildIndexes(): void {
    this.actorIndex.clear();
    this.correlationIndex.clear();

    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i];

      if (!this.actorIndex.has(entry.actor.id)) {
        this.actorIndex.set(entry.actor.id, []);
      }
      this.actorIndex.get(entry.actor.id)!.push(i);

      this.correlationIndex.set(entry.correlationId, i);
    }
  }
}
