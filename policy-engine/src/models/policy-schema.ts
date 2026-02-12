import { z } from 'zod';

// ─── Enums ───────────────────────────────────────────────────────────────────

export const PolicyEffect = z.enum(['ALLOW', 'DENY']);
export type PolicyEffect = z.infer<typeof PolicyEffect>;

export const DecisionResult = z.enum(['ALLOW', 'DENY']);
export type DecisionResult = z.infer<typeof DecisionResult>;

export const ConditionOperator = z.enum([
  'StringEquals',
  'StringNotEquals',
  'StringLike',
  'IpAddress',
  'NotIpAddress',
  'DateGreaterThan',
  'DateLessThan',
  'NumericEquals',
  'NumericGreaterThan',
  'NumericLessThan',
  'Bool',
  'ArrayContains',
  'ArrayContainsAll',
]);
export type ConditionOperator = z.infer<typeof ConditionOperator>;

// ─── Condition schemas ───────────────────────────────────────────────────────

export const ConditionValue = z.union([
  z.string(),
  z.number(),
  z.boolean(),
  z.array(z.string()),
  z.array(z.number()),
]);
export type ConditionValue = z.infer<typeof ConditionValue>;

export const SingleCondition = z.object({
  operator: ConditionOperator,
  field: z.string(),
  value: ConditionValue,
});
export type SingleCondition = z.infer<typeof SingleCondition>;

export type ConditionNode =
  | { type: 'single'; condition: SingleCondition }
  | { type: 'and'; conditions: ConditionNode[] }
  | { type: 'or'; conditions: ConditionNode[] }
  | { type: 'not'; condition: ConditionNode };

export const ConditionNodeSchema: z.ZodType<ConditionNode> = z.lazy(() =>
  z.discriminatedUnion('type', [
    z.object({
      type: z.literal('single'),
      condition: SingleCondition,
    }),
    z.object({
      type: z.literal('and'),
      conditions: z.array(ConditionNodeSchema),
    }),
    z.object({
      type: z.literal('or'),
      conditions: z.array(ConditionNodeSchema),
    }),
    z.object({
      type: z.literal('not'),
      condition: ConditionNodeSchema,
    }),
  ])
);

// ─── Time-based condition helpers ────────────────────────────────────────────

export const TimeRange = z.object({
  startHour: z.number().int().min(0).max(23),
  endHour: z.number().int().min(0).max(23),
  timezone: z.string().default('UTC'),
  daysOfWeek: z.array(z.number().int().min(0).max(6)).optional(), // 0=Sunday
});
export type TimeRange = z.infer<typeof TimeRange>;

// ─── Subject definition ─────────────────────────────────────────────────────

export const PolicySubject = z.object({
  roles: z.array(z.string()).optional(),
  attributes: z.record(z.string(), ConditionValue).optional(),
});
export type PolicySubject = z.infer<typeof PolicySubject>;

// ─── Policy schema ──────────────────────────────────────────────────────────

export const PolicySchema = z.object({
  id: z.string().uuid(),
  version: z.number().int().min(1).default(1),
  name: z.string().min(1).max(256),
  description: z.string().max(2048).optional(),
  effect: PolicyEffect,
  subjects: PolicySubject.optional(),
  actions: z.array(z.string().min(1)).min(1),
  resources: z.array(z.string().min(1)).min(1),
  conditions: ConditionNodeSchema.optional(),
  priority: z.number().int().min(0).max(1000).default(0),
  enabled: z.boolean().default(true),
  createdAt: z.string().datetime().optional(),
  updatedAt: z.string().datetime().optional(),
  deletedAt: z.string().datetime().optional().nullable(),
  metadata: z.record(z.string(), z.string()).optional(),
});
export type Policy = z.infer<typeof PolicySchema>;

export const CreatePolicyInput = PolicySchema.omit({
  id: true,
  version: true,
  createdAt: true,
  updatedAt: true,
  deletedAt: true,
}).extend({
  id: z.string().uuid().optional(),
});
export type CreatePolicyInput = z.infer<typeof CreatePolicyInput>;

export const UpdatePolicyInput = PolicySchema.partial().omit({
  id: true,
  version: true,
  createdAt: true,
  updatedAt: true,
  deletedAt: true,
});
export type UpdatePolicyInput = z.infer<typeof UpdatePolicyInput>;

// ─── Policy request (evaluation input) ──────────────────────────────────────

export const ActorSchema = z.object({
  id: z.string().min(1),
  roles: z.array(z.string()).default([]),
  attributes: z.record(z.string(), ConditionValue).default({}),
});
export type Actor = z.infer<typeof ActorSchema>;

export const ResourceSchema = z.object({
  type: z.string().min(1),
  id: z.string().min(1),
  attributes: z.record(z.string(), ConditionValue).default({}),
});
export type Resource = z.infer<typeof ResourceSchema>;

export const EnvironmentSchema = z.object({
  ip: z.string().optional(),
  time: z.string().datetime().optional(),
  deviceId: z.string().optional(),
  sessionId: z.string().optional(),
  stepUpLevel: z.number().int().min(0).max(3).optional(),
  custom: z.record(z.string(), ConditionValue).optional(),
});
export type Environment = z.infer<typeof EnvironmentSchema>;

export const PolicyRequestSchema = z.object({
  actor: ActorSchema,
  action: z.string().min(1),
  resource: ResourceSchema,
  environment: EnvironmentSchema.optional(),
  correlationId: z.string().optional(),
});
export type PolicyRequest = z.infer<typeof PolicyRequestSchema>;

// ─── Policy decision (evaluation output) ────────────────────────────────────

export const PolicyDecisionSchema = z.object({
  decision: DecisionResult,
  policyId: z.string().nullable(),
  reason: z.string(),
  timestamp: z.string().datetime(),
  evaluationTimeMs: z.number(),
  correlationId: z.string().optional(),
  matchedPolicies: z.array(z.string()).optional(),
});
export type PolicyDecision = z.infer<typeof PolicyDecisionSchema>;

// ─── Decision log entry ─────────────────────────────────────────────────────

export const DecisionLogEntrySchema = z.object({
  id: z.string().uuid(),
  timestamp: z.string().datetime(),
  correlationId: z.string(),
  actor: ActorSchema,
  action: z.string(),
  resource: ResourceSchema,
  environment: EnvironmentSchema.optional(),
  decision: DecisionResult,
  policyId: z.string().nullable(),
  reason: z.string(),
  evaluationTimeMs: z.number(),
});
export type DecisionLogEntry = z.infer<typeof DecisionLogEntrySchema>;

// ─── Decision query filters ─────────────────────────────────────────────────

export const DecisionQuerySchema = z.object({
  actorId: z.string().optional(),
  action: z.string().optional(),
  resourceType: z.string().optional(),
  resourceId: z.string().optional(),
  decision: DecisionResult.optional(),
  fromTime: z.string().datetime().optional(),
  toTime: z.string().datetime().optional(),
  correlationId: z.string().optional(),
  limit: z.number().int().min(1).max(1000).default(100),
  offset: z.number().int().min(0).default(0),
});
export type DecisionQuery = z.infer<typeof DecisionQuerySchema>;

// ─── Policy list filters ────────────────────────────────────────────────────

export const PolicyListFiltersSchema = z.object({
  effect: PolicyEffect.optional(),
  enabled: z.boolean().optional(),
  action: z.string().optional(),
  resource: z.string().optional(),
  limit: z.number().int().min(1).max(500).default(50),
  offset: z.number().int().min(0).default(0),
});
export type PolicyListFilters = z.infer<typeof PolicyListFiltersSchema>;
