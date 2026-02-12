/**
 * Policy models for the Zero Trust security platform.
 *
 * A Policy defines a set of conditions under which an action on a resource is
 * allowed or denied.  Conditions can express both RBAC (role-based) and ABAC
 * (attribute-based) constraints.
 *
 * PolicyDecision captures the outcome of evaluating one or more policies
 * against a specific request context.
 */

import { z } from 'zod';

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export const PolicyEffect = {
  Allow: 'allow',
  Deny: 'deny',
} as const;
export type PolicyEffect = (typeof PolicyEffect)[keyof typeof PolicyEffect];

export const ConditionOperator = {
  Equals: 'equals',
  NotEquals: 'notEquals',
  In: 'in',
  NotIn: 'notIn',
  Contains: 'contains',
  StartsWith: 'startsWith',
  EndsWith: 'endsWith',
  GreaterThan: 'greaterThan',
  LessThan: 'lessThan',
  GreaterThanOrEqual: 'greaterThanOrEqual',
  LessThanOrEqual: 'lessThanOrEqual',
  Exists: 'exists',
  NotExists: 'notExists',
  IpInCidr: 'ipInCidr',
  DateBefore: 'dateBefore',
  DateAfter: 'dateAfter',
} as const;
export type ConditionOperator =
  (typeof ConditionOperator)[keyof typeof ConditionOperator];

// ---------------------------------------------------------------------------
// Zod schemas
// ---------------------------------------------------------------------------

export const AttributeConditionSchema = z.object({
  /** The attribute path to evaluate (e.g. "context.ip", "actor.department"). */
  field: z.string().min(1).max(256),
  /** Comparison operator. */
  operator: z.enum([
    'equals',
    'notEquals',
    'in',
    'notIn',
    'contains',
    'startsWith',
    'endsWith',
    'greaterThan',
    'lessThan',
    'greaterThanOrEqual',
    'lessThanOrEqual',
    'exists',
    'notExists',
    'ipInCidr',
    'dateBefore',
    'dateAfter',
  ]),
  /** The value(s) to compare against. */
  value: z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.array(z.union([z.string(), z.number()])),
  ]),
});

export const RBACConditionSchema = z.object({
  /** Roles required (ANY of these grants access). */
  roles: z.array(z.string().min(1).max(128)).min(1),
});

export const ConditionsSchema = z.object({
  /** Role-based conditions (RBAC). */
  rbac: RBACConditionSchema.optional(),
  /** Attribute-based conditions (ABAC). All must be satisfied (AND logic). */
  abac: z.array(AttributeConditionSchema).optional(),
  /** Time-based: policy applies only during this window (ISO 8601). */
  timeWindow: z
    .object({
      start: z.string().datetime({ offset: true }).optional(),
      end: z.string().datetime({ offset: true }).optional(),
      /** Recurring schedule in cron-like format (optional). */
      schedule: z.string().max(128).optional(),
    })
    .optional(),
});

export const PolicySchema = z.object({
  /** Unique policy identifier. */
  id: z.string().min(1).max(256),
  /** Monotonically increasing version number. */
  version: z.number().int().positive(),
  /** Human-readable name. */
  name: z.string().min(1).max(256),
  /** Description of the policy's intent. */
  description: z.string().max(2048).optional(),
  /** Whether this policy allows or denies matching requests. */
  effect: z.enum(['allow', 'deny']),
  /** Conditions that must hold for this policy to apply. */
  conditions: ConditionsSchema,
  /** Actions this policy governs (e.g. "read", "write", "admin:*"). Supports wildcards. */
  actions: z.array(z.string().min(1).max(256)).min(1),
  /** Resources this policy governs (e.g. "arn:service:resource/*"). Supports wildcards. */
  resources: z.array(z.string().min(1).max(512)).min(1),
  /** Priority for conflict resolution.  Lower number = higher priority. */
  priority: z.number().int().min(0).max(10000).default(1000),
  /** Whether this policy is currently active. */
  enabled: z.boolean().default(true),
  /** ISO 8601 timestamps. */
  createdAt: z.string().datetime({ offset: true }),
  updatedAt: z.string().datetime({ offset: true }),
  /** Optional metadata (tags, owner, etc.). */
  metadata: z.record(z.string(), z.unknown()).optional(),
});

// ---------------------------------------------------------------------------
// TypeScript types (inferred from Zod)
// ---------------------------------------------------------------------------

export type AttributeCondition = z.infer<typeof AttributeConditionSchema>;
export type RBACCondition = z.infer<typeof RBACConditionSchema>;
export type Conditions = z.infer<typeof ConditionsSchema>;
export type Policy = z.infer<typeof PolicySchema>;

// ---------------------------------------------------------------------------
// PolicyDecision
// ---------------------------------------------------------------------------

export const PolicyDecisionSchema = z.object({
  /** ID of the policy that produced this decision. */
  policyId: z.string().min(1).max(256),
  /** The policy's name (for human readability in logs). */
  policyName: z.string().max(256).optional(),
  /** The resulting decision. */
  decision: z.enum(['allow', 'deny', 'error', 'not_applicable']),
  /** Human-readable reason for the decision. */
  reason: z.string().max(1024).optional(),
  /** When the decision was made. */
  timestamp: z.string().datetime({ offset: true }),
  /** How long the policy evaluation took (ms). */
  evaluationTimeMs: z.number().nonnegative(),
});

export type PolicyDecision = z.infer<typeof PolicyDecisionSchema>;

// ---------------------------------------------------------------------------
// Aggregated evaluation result
// ---------------------------------------------------------------------------

export const PolicyEvaluationResultSchema = z.object({
  /** The final decision after evaluating all applicable policies. */
  finalDecision: z.enum(['allow', 'deny', 'error']),
  /** Individual decisions from each evaluated policy. */
  decisions: z.array(PolicyDecisionSchema),
  /** The determining policy (highest-priority matching policy). */
  determiningPolicyId: z.string().max(256).optional(),
  /** Total evaluation time across all policies (ms). */
  totalEvaluationTimeMs: z.number().nonnegative(),
  /** Correlation ID for tracing. */
  correlationId: z.string().uuid().optional(),
});

export type PolicyEvaluationResult = z.infer<
  typeof PolicyEvaluationResultSchema
>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Validate a raw object as a Policy.  Returns a discriminated union.
 */
export function parsePolicy(
  data: unknown,
): { success: true; policy: Policy } | { success: false; errors: z.ZodError } {
  const result = PolicySchema.safeParse(data);
  if (result.success) {
    return { success: true, policy: result.data };
  }
  return { success: false, errors: result.error };
}

/**
 * Check whether an action string matches a policy action pattern.
 * Supports trailing wildcards (e.g. "admin:*" matches "admin:delete").
 */
export function actionMatchesPattern(
  action: string,
  pattern: string,
): boolean {
  if (pattern === '*') return true;

  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1); // e.g. "admin:"
    return action.startsWith(prefix) || action === pattern.slice(0, -2);
  }

  if (pattern.endsWith('*')) {
    const prefix = pattern.slice(0, -1);
    return action.startsWith(prefix);
  }

  return action === pattern;
}

/**
 * Check whether a resource identifier matches a policy resource pattern.
 * Supports trailing wildcards.
 */
export function resourceMatchesPattern(
  resource: string,
  pattern: string,
): boolean {
  if (pattern === '*') return true;

  if (pattern.endsWith('*')) {
    const prefix = pattern.slice(0, -1);
    return resource.startsWith(prefix);
  }

  return resource === pattern;
}
