/**
 * Unified audit event schema for the Zero Trust security platform.
 *
 * Every security-relevant action across the platform emits an AuditEvent.
 * The schema is Zod-validated so producers cannot emit malformed events, and
 * consumers can safely deserialize without additional checks.
 *
 * Schema versioning: the `version` field tracks the schema version.
 * V1 is the initial release; V2 adds `context.geoLocation` and `tags`.
 * Consumers should be forward-compatible (ignore unknown fields) and
 * backward-compatible (handle missing optional fields).
 *
 * PII redaction: use `redactAuditEvent` before persisting to any store
 * that is not classified for PII.
 */

import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { PIIRedactor } from '../logging/pii-redactor';

// ---------------------------------------------------------------------------
// Enums & constants
// ---------------------------------------------------------------------------

export const AuditSchemaVersion = {
  V1: 'v1',
  V2: 'v2',
} as const;

export type AuditSchemaVersion =
  (typeof AuditSchemaVersion)[keyof typeof AuditSchemaVersion];

export const CURRENT_AUDIT_SCHEMA_VERSION: AuditSchemaVersion =
  AuditSchemaVersion.V2;

export const ActorType = {
  User: 'user',
  Service: 'service',
  System: 'system',
  External: 'external',
} as const;
export type ActorType = (typeof ActorType)[keyof typeof ActorType];

export const SubjectType = {
  User: 'user',
  Group: 'group',
  Service: 'service',
  Resource: 'resource',
} as const;
export type SubjectType = (typeof SubjectType)[keyof typeof SubjectType];

export const AuditDecision = {
  Allow: 'allow',
  Deny: 'deny',
  Error: 'error',
} as const;
export type AuditDecision = (typeof AuditDecision)[keyof typeof AuditDecision];

// ---------------------------------------------------------------------------
// Zod schemas
// ---------------------------------------------------------------------------

export const ActorSchema = z.object({
  type: z.enum(['user', 'service', 'system', 'external']),
  id: z.string().min(1).max(256),
  sessionId: z.string().max(256).optional(),
  deviceId: z.string().max(256).optional(),
});

export const SubjectSchema = z.object({
  type: z.enum(['user', 'group', 'service', 'resource']),
  id: z.string().min(1).max(256),
});

export const ResourceSchema = z.object({
  type: z.string().min(1).max(128),
  id: z.string().min(1).max(512),
  attributes: z.record(z.string(), z.unknown()).optional(),
});

export const ResultSchema = z.object({
  decision: z.enum(['allow', 'deny', 'error']),
  reason: z.string().max(1024).optional(),
  policyId: z.string().max(256).optional(),
});

export const GeoLocationSchema = z.object({
  country: z.string().max(3).optional(),
  region: z.string().max(128).optional(),
  city: z.string().max(128).optional(),
  latitude: z.number().min(-90).max(90).optional(),
  longitude: z.number().min(-180).max(180).optional(),
});

export const AuditContextSchema = z.object({
  ip: z
    .string()
    .max(45) // IPv6 max length
    .optional(),
  asn: z.string().max(32).optional(),
  userAgent: z.string().max(1024).optional(),
  geoLocation: GeoLocationSchema.optional(),
});

// V1 schema
const AuditEventBaseSchema = z.object({
  id: z.string().uuid(),
  version: z.enum(['v1', 'v2']),
  timestamp: z.string().datetime({ offset: true }),
  correlationId: z.string().uuid().optional(),
  actor: ActorSchema,
  subject: SubjectSchema.optional(),
  action: z.string().min(1).max(256),
  resource: ResourceSchema,
  result: ResultSchema,
  context: AuditContextSchema.optional(),
  riskScore: z.number().min(0).max(100).optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

// V2 adds tags.
export const AuditEventV2Additions = z.object({
  tags: z.array(z.string().max(64)).max(20).optional(),
});

export const AuditEventSchema = AuditEventBaseSchema.merge(
  AuditEventV2Additions,
);

// ---------------------------------------------------------------------------
// TypeScript types (inferred from Zod)
// ---------------------------------------------------------------------------

export type Actor = z.infer<typeof ActorSchema>;
export type Subject = z.infer<typeof SubjectSchema>;
export type Resource = z.infer<typeof ResourceSchema>;
export type AuditResult = z.infer<typeof ResultSchema>;
export type GeoLocation = z.infer<typeof GeoLocationSchema>;
export type AuditContext = z.infer<typeof AuditContextSchema>;
export type AuditEvent = z.infer<typeof AuditEventSchema>;

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

export interface AuditEventInput {
  actor: Actor;
  action: string;
  resource: Resource;
  result: AuditResult;
  subject?: Subject;
  context?: AuditContext;
  riskScore?: number;
  correlationId?: string;
  metadata?: Record<string, unknown>;
  tags?: string[];
}

/**
 * Create a validated AuditEvent from caller-supplied fields.
 * Automatically fills `id`, `version`, and `timestamp`.
 */
export function createAuditEvent(input: AuditEventInput): AuditEvent {
  const raw: Record<string, unknown> = {
    id: uuidv4(),
    version: CURRENT_AUDIT_SCHEMA_VERSION,
    timestamp: new Date().toISOString(),
    correlationId: input.correlationId,
    actor: input.actor,
    subject: input.subject,
    action: input.action,
    resource: input.resource,
    result: input.result,
    context: input.context,
    riskScore: input.riskScore,
    metadata: input.metadata,
    tags: input.tags,
  };

  // Validate – throws ZodError on invalid data.
  return AuditEventSchema.parse(raw);
}

/**
 * Parse and validate an AuditEvent from an untrusted source (e.g. message
 * queue payload). Returns a discriminated result so callers can decide how
 * to handle validation failures.
 */
export function parseAuditEvent(
  data: unknown,
): { success: true; event: AuditEvent } | { success: false; errors: z.ZodError } {
  const result = AuditEventSchema.safeParse(data);
  if (result.success) {
    return { success: true, event: result.data };
  }
  return { success: false, errors: result.error };
}

// ---------------------------------------------------------------------------
// PII redaction helper
// ---------------------------------------------------------------------------

const auditRedactor = new PIIRedactor({
  allowedFields: [
    // Fields that are operationally necessary and not PII.
    'id',
    'version',
    'timestamp',
    'correlationId',
    'action',
    'decision',
    'reason',
    'policyId',
    'riskScore',
    'type',
    'asn',
    'tags',
  ],
});

/**
 * Return a copy of the audit event with PII-sensitive fields redacted.
 * Safe for storage in non-PII-classified data stores.
 */
export function redactAuditEvent(event: AuditEvent): AuditEvent {
  return auditRedactor.redact(event) as AuditEvent;
}
