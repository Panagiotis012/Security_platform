import { v4 as uuidv4 } from 'uuid';
import type {
  Policy,
  CreatePolicyInput,
  UpdatePolicyInput,
  PolicyListFilters,
} from '../models/policy-schema';
import { createLogger } from '../utils/logger';

const logger = createLogger('policy-store');

/**
 * PolicyStore interface defines the contract for policy storage backends.
 */
export interface PolicyStore {
  create(input: CreatePolicyInput): Promise<Policy>;
  update(id: string, input: UpdatePolicyInput): Promise<Policy>;
  delete(id: string): Promise<void>;
  findById(id: string): Promise<Policy | null>;
  findApplicable(action: string, resource: string): Promise<Policy[]>;
  list(filters: PolicyListFilters): Promise<{ policies: Policy[]; total: number }>;
  getVersionHistory(id: string): Promise<Policy[]>;
  loadDefaults(policies: Omit<Policy, 'createdAt' | 'updatedAt'>[]): Promise<void>;
}

/**
 * InMemoryPolicyStore implements PolicyStore with in-memory storage.
 * Includes indexing by action and resource patterns for fast lookup,
 * version history tracking, and soft-delete with audit trail.
 */
export class InMemoryPolicyStore implements PolicyStore {
  /** Primary storage: id -> current policy */
  private policies: Map<string, Policy> = new Map();

  /** Version history: id -> array of historical versions */
  private versionHistory: Map<string, Policy[]> = new Map();

  /** Index: action pattern -> set of policy IDs */
  private actionIndex: Map<string, Set<string>> = new Map();

  /** Index: resource pattern -> set of policy IDs */
  private resourceIndex: Map<string, Set<string>> = new Map();

  /** Audit log for deletions */
  private deletionAudit: Array<{
    policyId: string;
    policyName: string;
    deletedAt: string;
    deletedVersion: number;
  }> = [];

  /**
   * Create a new policy. Assigns a UUID if not provided.
   */
  async create(input: CreatePolicyInput): Promise<Policy> {
    const now = new Date().toISOString();
    const policy: Policy = {
      ...input,
      id: input.id ?? uuidv4(),
      version: 1,
      enabled: input.enabled ?? true,
      priority: input.priority ?? 0,
      createdAt: now,
      updatedAt: now,
      deletedAt: null,
    };

    if (this.policies.has(policy.id)) {
      throw new PolicyStoreError(`Policy with id "${policy.id}" already exists`, 'CONFLICT');
    }

    this.policies.set(policy.id, policy);
    this.indexPolicy(policy);
    this.versionHistory.set(policy.id, [{ ...policy }]);

    logger.info('Policy created', { policyId: policy.id, name: policy.name });
    return policy;
  }

  /**
   * Update an existing policy. Increments version and preserves history.
   */
  async update(id: string, input: UpdatePolicyInput): Promise<Policy> {
    const existing = this.policies.get(id);
    if (!existing || existing.deletedAt) {
      throw new PolicyStoreError(`Policy "${id}" not found`, 'NOT_FOUND');
    }

    // Remove old indexes
    this.deindexPolicy(existing);

    const updated: Policy = {
      ...existing,
      ...input,
      id: existing.id, // Cannot change ID
      version: existing.version + 1,
      createdAt: existing.createdAt,
      updatedAt: new Date().toISOString(),
    };

    this.policies.set(id, updated);
    this.indexPolicy(updated);

    // Append to version history
    const history = this.versionHistory.get(id) ?? [];
    history.push({ ...updated });
    this.versionHistory.set(id, history);

    logger.info('Policy updated', {
      policyId: id,
      name: updated.name,
      version: updated.version,
    });

    return updated;
  }

  /**
   * Soft-delete a policy. Marks it with a deletedAt timestamp
   * and removes it from indexes, but keeps it in storage for audit.
   */
  async delete(id: string): Promise<void> {
    const existing = this.policies.get(id);
    if (!existing) {
      throw new PolicyStoreError(`Policy "${id}" not found`, 'NOT_FOUND');
    }

    if (existing.deletedAt) {
      throw new PolicyStoreError(`Policy "${id}" is already deleted`, 'CONFLICT');
    }

    this.deindexPolicy(existing);

    const now = new Date().toISOString();
    const deleted: Policy = {
      ...existing,
      deletedAt: now,
      updatedAt: now,
      version: existing.version + 1,
    };

    this.policies.set(id, deleted);

    // Record in deletion audit
    this.deletionAudit.push({
      policyId: id,
      policyName: existing.name,
      deletedAt: now,
      deletedVersion: deleted.version,
    });

    // Append to version history
    const history = this.versionHistory.get(id) ?? [];
    history.push({ ...deleted });
    this.versionHistory.set(id, history);

    logger.info('Policy soft-deleted', { policyId: id, name: existing.name });
  }

  /**
   * Find a policy by ID. Returns null if not found or soft-deleted.
   */
  async findById(id: string): Promise<Policy | null> {
    const policy = this.policies.get(id);
    if (!policy || policy.deletedAt) {
      return null;
    }
    return policy;
  }

  /**
   * Find all applicable policies for a given action and resource.
   * Uses indexes for fast lookup, then filters by pattern matching.
   * Only returns enabled, non-deleted policies.
   */
  async findApplicable(action: string, resource: string): Promise<Policy[]> {
    const candidateIds = new Set<string>();

    // Find policies indexed by action patterns that could match
    for (const [pattern, policyIds] of this.actionIndex) {
      if (this.patternCouldMatch(pattern, action)) {
        for (const id of policyIds) {
          candidateIds.add(id);
        }
      }
    }

    // If no action matches found, check wildcard policies
    const wildcardActionPolicies = this.actionIndex.get('*');
    if (wildcardActionPolicies) {
      for (const id of wildcardActionPolicies) {
        candidateIds.add(id);
      }
    }

    // Collect candidate policies and filter by resource pattern
    const results: Policy[] = [];

    for (const id of candidateIds) {
      const policy = this.policies.get(id);
      if (!policy || policy.deletedAt || !policy.enabled) {
        continue;
      }

      // Verify action actually matches
      const actionMatches = policy.actions.some((p) => this.patternCouldMatch(p, action));
      if (!actionMatches) {
        continue;
      }

      // Verify resource matches
      const resourceMatches = policy.resources.some(
        (p) => this.patternCouldMatch(p, resource) || this.patternCouldMatch(p, resource.split(':')[0])
      );
      if (!resourceMatches) {
        continue;
      }

      results.push(policy);
    }

    // Also check for policies with wildcard resources that we might have missed
    const wildcardResourcePolicies = this.resourceIndex.get('*');
    if (wildcardResourcePolicies) {
      for (const id of wildcardResourcePolicies) {
        if (candidateIds.has(id)) continue; // Already checked

        const policy = this.policies.get(id);
        if (!policy || policy.deletedAt || !policy.enabled) continue;

        const actionMatches = policy.actions.some((p) => this.patternCouldMatch(p, action));
        if (actionMatches && !results.includes(policy)) {
          results.push(policy);
        }
      }
    }

    return results;
  }

  /**
   * List policies with optional filtering and pagination.
   */
  async list(filters: PolicyListFilters): Promise<{ policies: Policy[]; total: number }> {
    let results = Array.from(this.policies.values()).filter((p) => !p.deletedAt);

    // Apply filters
    if (filters.effect !== undefined) {
      results = results.filter((p) => p.effect === filters.effect);
    }

    if (filters.enabled !== undefined) {
      results = results.filter((p) => p.enabled === filters.enabled);
    }

    if (filters.action) {
      const actionFilter = filters.action;
      results = results.filter((p) =>
        p.actions.some((a) => this.patternCouldMatch(a, actionFilter) || a.includes(actionFilter))
      );
    }

    if (filters.resource) {
      const resourceFilter = filters.resource;
      results = results.filter((p) =>
        p.resources.some(
          (r) => this.patternCouldMatch(r, resourceFilter) || r.includes(resourceFilter)
        )
      );
    }

    // Sort by priority descending, then by name
    results.sort((a, b) => {
      if (b.priority !== a.priority) return b.priority - a.priority;
      return a.name.localeCompare(b.name);
    });

    const total = results.length;
    const offset = filters.offset ?? 0;
    const limit = filters.limit ?? 50;
    const paged = results.slice(offset, offset + limit);

    return { policies: paged, total };
  }

  /**
   * Get the version history of a policy.
   */
  async getVersionHistory(id: string): Promise<Policy[]> {
    return this.versionHistory.get(id) ?? [];
  }

  /**
   * Load default/seed policies into the store.
   */
  async loadDefaults(policies: Omit<Policy, 'createdAt' | 'updatedAt'>[]): Promise<void> {
    for (const policyInput of policies) {
      const existing = this.policies.get(policyInput.id);
      if (existing) {
        logger.debug('Skipping existing default policy', {
          policyId: policyInput.id,
          name: policyInput.name,
        });
        continue;
      }

      const now = new Date().toISOString();
      const policy: Policy = {
        ...policyInput,
        createdAt: now,
        updatedAt: now,
        enabled: policyInput.enabled ?? true,
        priority: policyInput.priority ?? 0,
        deletedAt: policyInput.deletedAt ?? null,
      };

      this.policies.set(policy.id, policy);
      this.indexPolicy(policy);
      this.versionHistory.set(policy.id, [{ ...policy }]);

      logger.info('Default policy loaded', { policyId: policy.id, name: policy.name });
    }
  }

  // ─── Persistence helpers ─────────────────────────────────────────────────

  /**
   * Export full internal state (including soft-deleted policies and version history).
   * Used by durable wrappers (file/redis snapshots).
   */
  exportState(): PolicyStoreStateV1 {
    const versionHistoryObj: Record<string, Policy[]> = {};
    for (const [id, history] of this.versionHistory.entries()) {
      versionHistoryObj[id] = deepCopy(history);
    }

    return {
      schemaVersion: 1,
      policies: deepCopy(Array.from(this.policies.values())),
      versionHistory: versionHistoryObj,
      deletionAudit: deepCopy(this.deletionAudit),
    };
  }

  /**
   * Import a previously exported state snapshot. Rebuilds indexes.
   */
  importState(state: PolicyStoreStateV1): void {
    if (!state || state.schemaVersion !== 1) {
      throw new PolicyStoreError('Unsupported policy store snapshot', 'VALIDATION');
    }

    this.policies = new Map();
    this.versionHistory = new Map();
    this.actionIndex = new Map();
    this.resourceIndex = new Map();
    this.deletionAudit = [];

    for (const p of state.policies ?? []) {
      const policy = deepCopy(p);
      this.policies.set(policy.id, policy);
      if (!policy.deletedAt) {
        this.indexPolicy(policy);
      }
    }

    for (const [id, history] of Object.entries(state.versionHistory ?? {})) {
      this.versionHistory.set(id, deepCopy(history));
    }

    this.deletionAudit = deepCopy(state.deletionAudit ?? []);
  }

  // ─── Index management ────────────────────────────────────────────────────

  /**
   * Add a policy to the action and resource indexes.
   */
  private indexPolicy(policy: Policy): void {
    for (const action of policy.actions) {
      const key = this.normalizeIndexKey(action);
      if (!this.actionIndex.has(key)) {
        this.actionIndex.set(key, new Set());
      }
      this.actionIndex.get(key)!.add(policy.id);
    }

    for (const resource of policy.resources) {
      const key = this.normalizeIndexKey(resource);
      if (!this.resourceIndex.has(key)) {
        this.resourceIndex.set(key, new Set());
      }
      this.resourceIndex.get(key)!.add(policy.id);
    }
  }

  /**
   * Remove a policy from all indexes.
   */
  private deindexPolicy(policy: Policy): void {
    for (const action of policy.actions) {
      const key = this.normalizeIndexKey(action);
      this.actionIndex.get(key)?.delete(policy.id);
    }

    for (const resource of policy.resources) {
      const key = this.normalizeIndexKey(resource);
      this.resourceIndex.get(key)?.delete(policy.id);
    }
  }

  /**
   * Normalize an index key. Wildcard patterns are stored as-is for matching.
   */
  private normalizeIndexKey(pattern: string): string {
    return pattern.toLowerCase();
  }

  /**
   * Check if a pattern could match a value using glob-style matching.
   */
  private patternCouldMatch(pattern: string, value: string): boolean {
    const lowerPattern = pattern.toLowerCase();
    const lowerValue = value.toLowerCase();

    if (lowerPattern === lowerValue) return true;
    if (lowerPattern === '*') return true;

    // Convert glob to regex
    let regexStr = '^';
    for (let i = 0; i < lowerPattern.length; i++) {
      const ch = lowerPattern[i];
      switch (ch) {
        case '*':
          if (i + 1 < lowerPattern.length && lowerPattern[i + 1] === '*') {
            regexStr += '.*';
            i++;
          } else {
            regexStr += '[^:]*';
          }
          break;
        case '?':
          regexStr += '[^:]';
          break;
        case '.':
        case '(':
        case ')':
        case '[':
        case ']':
        case '{':
        case '}':
        case '+':
        case '^':
        case '$':
        case '|':
        case '\\':
          regexStr += '\\' + ch;
          break;
        default:
          regexStr += ch;
      }
    }
    regexStr += '$';

    try {
      return new RegExp(regexStr).test(lowerValue);
    } catch {
      return lowerPattern === lowerValue;
    }
  }
}

export interface PolicyStoreStateV1 {
  schemaVersion: 1;
  policies: Policy[];
  versionHistory: Record<string, Policy[]>;
  deletionAudit: Array<{
    policyId: string;
    policyName: string;
    deletedAt: string;
    deletedVersion: number;
  }>;
}

function deepCopy<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/**
 * Custom error class for PolicyStore operations.
 */
export class PolicyStoreError extends Error {
  public readonly code: 'NOT_FOUND' | 'CONFLICT' | 'VALIDATION' | 'INTERNAL';

  constructor(message: string, code: 'NOT_FOUND' | 'CONFLICT' | 'VALIDATION' | 'INTERNAL' = 'INTERNAL') {
    super(message);
    this.name = 'PolicyStoreError';
    this.code = code;
  }
}
