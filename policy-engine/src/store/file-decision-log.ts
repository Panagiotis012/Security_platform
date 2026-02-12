import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { v4 as uuidv4 } from 'uuid';
import type {
  PolicyRequest,
  PolicyDecision,
  DecisionLogEntry,
  DecisionQuery,
} from '../models/policy-schema';
import { createLogger } from '../utils/logger';
import config from '../../config/default';
import type { DecisionLogger, DecisionLogStats } from './decision-log';

const logger = createLogger('file-decision-log');

export interface FileDecisionLoggerOptions {
  filePath: string;
}

export class FileDecisionLogger implements DecisionLogger {
  private readonly filePath: string;

  constructor(options: FileDecisionLoggerOptions) {
    this.filePath = options.filePath;
    this.ensureDir();
  }

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

    await this.appendLine(JSON.stringify(entry));
    return entry;
  }

  async query(filters: DecisionQuery): Promise<{ entries: DecisionLogEntry[]; total: number }> {
    const entries = await this.scan(filters);
    entries.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    const total = entries.length;
    const offset = filters.offset ?? 0;
    const limit = filters.limit ?? 100;
    return { entries: entries.slice(offset, offset + limit), total };
  }

  async export(filters: DecisionQuery): Promise<DecisionLogEntry[]> {
    const entries = await this.scan(filters);
    entries.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    return entries;
  }

  async getStats(): Promise<DecisionLogStats> {
    const entries = await this.scan({});
    if (entries.length === 0) {
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
    let oldest: string | null = null;
    let newest: string | null = null;

    for (const entry of entries) {
      if (entry.decision === 'ALLOW') totalAllows++;
      else totalDenies++;

      totalEvalTime += entry.evaluationTimeMs;

      if (!oldest || entry.timestamp < oldest) oldest = entry.timestamp;
      if (!newest || entry.timestamp > newest) newest = entry.timestamp;
    }

    return {
      totalDecisions: entries.length,
      totalAllows,
      totalDenies,
      averageEvaluationTimeMs:
        Math.round((totalEvalTime / entries.length) * 1000) / 1000,
      oldestEntry: oldest,
      newestEntry: newest,
    };
  }

  // -----------------------------------------------------------------------
  // Internals
  // -----------------------------------------------------------------------

  private ensureDir(): void {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    } catch (err) {
      logger.error('Failed to create decision log directory', {
        filePath: this.filePath,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  private async appendLine(line: string): Promise<void> {
    this.ensureDir();
    await fs.promises.appendFile(this.filePath, `${line}\n`, { encoding: 'utf8', mode: 0o600 });
  }

  private async scan(filters: Partial<DecisionQuery>): Promise<DecisionLogEntry[]> {
    if (!fs.existsSync(this.filePath)) return [];

    const stream = fs.createReadStream(this.filePath, { encoding: 'utf8' });
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

    const results: DecisionLogEntry[] = [];

    for await (const line of rl) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      let entry: DecisionLogEntry;
      try {
        entry = JSON.parse(trimmed) as DecisionLogEntry;
      } catch {
        continue;
      }

      if (!this.matches(entry, filters)) continue;
      results.push(entry);
    }

    return results;
  }

  private matches(entry: DecisionLogEntry, filters: Partial<DecisionQuery>): boolean {
    if (filters.actorId && entry.actor.id !== filters.actorId) return false;
    if (filters.action && entry.action !== filters.action) return false;
    if (filters.resourceType && entry.resource.type !== filters.resourceType) return false;
    if (filters.resourceId && entry.resource.id !== filters.resourceId) return false;
    if (filters.decision && entry.decision !== filters.decision) return false;
    if (filters.correlationId && entry.correlationId !== filters.correlationId) return false;

    if (filters.fromTime) {
      const from = new Date(filters.fromTime).getTime();
      if (new Date(entry.timestamp).getTime() < from) return false;
    }
    if (filters.toTime) {
      const to = new Date(filters.toTime).getTime();
      if (new Date(entry.timestamp).getTime() > to) return false;
    }

    return true;
  }
}

