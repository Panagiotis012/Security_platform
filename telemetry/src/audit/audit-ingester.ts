// ─── Audit Log Ingester ───
// Validates, enriches, and stores audit events with tamper-evident guarantees.
// Pipeline: Validate (Zod) → PII Redact → Enrich (geoIP, ASN, risk score) → Store (append-only)

import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import winston from 'winston';
import config from '../../config/default';
import type { AuditEvent, AuditStore} from './audit-store';
import { InMemoryAuditStore } from './audit-store';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  defaultMeta: { service: 'audit-ingester' },
  transports: [new winston.transports.Console()],
});

// ─── Zod Schema for Unified Audit Events ───

const AuditActorSchema = z.object({
  type: z.enum(['user', 'service', 'system', 'api-key']),
  id: z.string().min(1),
  sessionId: z.string().optional(),
  deviceId: z.string().optional(),
});

const AuditSubjectSchema = z.object({
  type: z.string().min(1),
  id: z.string().min(1),
});

const AuditResourceSchema = z.object({
  type: z.string().min(1),
  id: z.string().min(1),
  attributes: z.record(z.unknown()).optional(),
});

const AuditResultSchema = z.object({
  decision: z.enum(['ALLOW', 'DENY', 'CHALLENGE', 'ERROR']),
  reason: z.string().optional(),
  policyId: z.string().optional(),
});

const GeoLocationSchema = z.object({
  country: z.string().optional(),
  region: z.string().optional(),
  city: z.string().optional(),
  latitude: z.number().optional(),
  longitude: z.number().optional(),
  timezone: z.string().optional(),
});

const AuditContextSchema = z.object({
  ip: z.string().optional(),
  asn: z.string().optional(),
  userAgent: z.string().optional(),
  geoLocation: GeoLocationSchema.optional(),
});

const AuditEventInputSchema = z.object({
  id: z.string().uuid().optional(), // Auto-generated if not provided
  version: z.string().default('1'),
  timestamp: z.string().datetime().optional(), // Auto-generated if not provided
  correlationId: z.string().optional(),
  actor: AuditActorSchema,
  subject: AuditSubjectSchema,
  action: z.string().min(1),
  resource: AuditResourceSchema,
  result: AuditResultSchema,
  context: AuditContextSchema.default({}),
  riskScore: z.number().min(0).max(100).optional(),
  metadata: z.record(z.unknown()).optional(),
});

export type AuditEventInput = z.infer<typeof AuditEventInputSchema>;

// ─── GeoIP Lookup ───

interface GeoIPResult {
  country?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
}

function lookupGeoIP(ip: string): GeoIPResult {
  try {
    // Dynamically require geoip-lite to handle missing module gracefully
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const geoip = require('geoip-lite');
    const geo = geoip.lookup(ip);
    if (!geo) return {};
    return {
      country: geo.country || undefined,
      region: geo.region || undefined,
      city: geo.city || undefined,
      latitude: geo.ll?.[0],
      longitude: geo.ll?.[1],
      timezone: geo.timezone || undefined,
    };
  } catch {
    // geoip-lite not available; return empty
    return {};
  }
}

// ─── ASN Lookup (simplified) ───

function lookupASN(ip: string): string | undefined {
  // In production this would use a MaxMind ASN database or similar.
  // Here we provide a basic mapping for well-known ranges.
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const geoip = require('geoip-lite');
    const geo = geoip.lookup(ip);
    // geoip-lite doesn't provide ASN directly, but we can note the org
    if (geo && geo.country) {
      return `AS-UNKNOWN (${geo.country})`;
    }
  } catch {
    // noop
  }
  return undefined;
}

// ─── Risk Score Calculator ───

function calculateRiskScore(event: AuditEvent): number {
  let score = 0;

  // Denied actions are inherently riskier
  if (event.result.decision === 'DENY') score += 20;
  if (event.result.decision === 'ERROR') score += 10;

  // High-value actions
  const highValueActions = [
    'admin.role.assign', 'admin.user.delete', 'admin.policy.modify',
    'token.create', 'credential.rotate', 'data.export', 'data.bulk-read',
    'session.elevate', 'config.modify',
  ];
  if (highValueActions.some((a) => event.action.includes(a))) {
    score += 25;
  }

  // Sensitive resource types
  const sensitiveResources = ['admin-panel', 'secrets', 'credentials', 'audit-log', 'policy', 'keys'];
  if (sensitiveResources.some((r) => event.resource.type.includes(r))) {
    score += 15;
  }

  // Service accounts doing unusual things
  if (event.actor.type === 'service' && event.result.decision === 'DENY') {
    score += 15;
  }

  // No session context (could indicate token replay or API misuse)
  if (!event.actor.sessionId && event.actor.type === 'user') {
    score += 10;
  }

  // Missing IP context
  if (!event.context.ip) {
    score += 5;
  }

  // Unusual hours (UTC midnight to 6am)
  const hour = new Date(event.timestamp).getUTCHours();
  if (hour >= config.detectionThresholds.anomalousAccessPattern.unusualHoursStart &&
      hour < config.detectionThresholds.anomalousAccessPattern.unusualHoursEnd) {
    score += 10;
  }

  return Math.min(100, Math.max(0, score));
}

// ─── PII Redaction ───

function redactPII(data: Record<string, unknown>): Record<string, unknown> {
  const redacted = { ...data };
  const piiFields = config.piiFields;

  for (const key of Object.keys(redacted)) {
    const lowerKey = key.toLowerCase();
    if (piiFields.some((pii) => lowerKey.includes(pii.toLowerCase()))) {
      const value = redacted[key];
      if (typeof value === 'string') {
        if (lowerKey.includes('email')) {
          // Partially redact email: keep first char and domain
          const parts = value.split('@');
          if (parts.length === 2) {
            redacted[key] = `${parts[0][0]}***@${parts[1]}`;
          } else {
            redacted[key] = '[REDACTED]';
          }
        } else if (lowerKey.includes('phone')) {
          // Keep last 4 digits
          redacted[key] = `***${value.slice(-4)}`;
        } else {
          redacted[key] = '[REDACTED]';
        }
      } else {
        redacted[key] = '[REDACTED]';
      }
    }

    // Recurse into nested objects
    if (typeof redacted[key] === 'object' && redacted[key] !== null && !Array.isArray(redacted[key])) {
      redacted[key] = redactPII(redacted[key] as Record<string, unknown>);
    }
  }

  return redacted;
}

// ─── Audit Ingester ───

export class AuditIngester {
  private store: AuditStore & { getEventsInWindow?(windowMs: number): AuditEvent[] };
  private ingestionCount = 0;
  private validationErrors = 0;

  constructor(store?: AuditStore & { getEventsInWindow?(windowMs: number): AuditEvent[] }) {
    this.store = store || new InMemoryAuditStore();
  }

  /**
   * Ingest an audit event through the full pipeline:
   * Validate -> PII Redact -> Enrich -> Store
   */
  async ingest(input: unknown): Promise<{ success: boolean; event?: AuditEvent; error?: string }> {
    // 1. Validate against unified audit schema
    const validation = AuditEventInputSchema.safeParse(input);
    if (!validation.success) {
      this.validationErrors++;
      const errorMessage = validation.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
      logger.warn('Audit event validation failed', { errors: errorMessage });
      return { success: false, error: `Validation failed: ${errorMessage}` };
    }

    const validatedInput = validation.data;

    // 2. Assign ID and timestamp if not provided
    const event: AuditEvent = {
      id: validatedInput.id || uuidv4(),
      version: validatedInput.version,
      timestamp: validatedInput.timestamp || new Date().toISOString(),
      correlationId: validatedInput.correlationId,
      actor: validatedInput.actor,
      subject: validatedInput.subject,
      action: validatedInput.action,
      resource: validatedInput.resource,
      result: validatedInput.result,
      context: validatedInput.context,
      riskScore: validatedInput.riskScore,
      metadata: validatedInput.metadata,
    };

    // 3. PII Redaction at source before storage
    if (event.metadata) {
      event.metadata = redactPII(event.metadata);
    }
    if (event.resource.attributes) {
      event.resource.attributes = redactPII(event.resource.attributes as Record<string, unknown>);
    }

    // 4. Enrich with GeoIP and ASN data
    if (event.context.ip) {
      const geoResult = lookupGeoIP(event.context.ip);
      if (geoResult.country) {
        event.context.geoLocation = {
          ...event.context.geoLocation,
          ...geoResult,
        };
      }

      if (!event.context.asn) {
        event.context.asn = lookupASN(event.context.ip);
      }
    }

    // 5. Calculate risk score if not provided
    if (event.riskScore === undefined || event.riskScore === null) {
      event.riskScore = calculateRiskScore(event);
    }

    // 6. Store in append-only log with hash chain
    try {
      const { index, hash } = await this.store.append(event);
      this.ingestionCount++;

      logger.info('Audit event ingested', {
        eventId: event.id,
        action: event.action,
        actor: event.actor.id,
        decision: event.result.decision,
        riskScore: event.riskScore,
        index,
        chainHash: hash.slice(0, 16) + '...',
      });

      return { success: true, event };
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown storage error';
      logger.error('Failed to store audit event', { error: message, eventId: event.id });
      return { success: false, error: `Storage error: ${message}` };
    }
  }

  /**
   * Batch ingest multiple events. Returns results for each.
   */
  async ingestBatch(inputs: unknown[]): Promise<{ success: boolean; event?: AuditEvent; error?: string }[]> {
    const results = [];
    for (const input of inputs) {
      results.push(await this.ingest(input));
    }
    return results;
  }

  /**
   * Get the underlying store (for detection engine and queries).
   */
  getStore(): AuditStore & { getEventsInWindow?(windowMs: number): AuditEvent[] } {
    return this.store;
  }

  /**
   * Get ingestion metrics.
   */
  getMetrics(): { ingested: number; validationErrors: number } {
    return {
      ingested: this.ingestionCount,
      validationErrors: this.validationErrors,
    };
  }
}
