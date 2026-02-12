import type { Request, Response } from 'express';
import { Router } from 'express';
import { createHash, createHmac, randomUUID, timingSafeEqual } from 'crypto';
import { z } from 'zod';
import { InMemoryInternalAuthReplayStore, type InternalAuthReplayStore } from '@zerotrust/shared';
import type { IpBlockEntry, SecurityStateStore } from '../state/security-state-store';
import type { EdgeCacheStore } from '../state/edge-cache-store';
import type {
  ControlPlaneAuditEvent,
  ControlPlaneAuditStore,
} from '../state/control-plane-audit-store';
import { InMemoryControlPlaneAuditStore } from '../state/inmemory-control-plane-audit-store';
import type {
  EdgeInvalidationEvent,
  EdgeInvalidationEventKind,
  EdgeInvalidationEventStore,
} from '../state/edge-invalidation-event-store';
import { InMemoryEdgeInvalidationEventStore } from '../state/inmemory-edge-invalidation-event-store';
import {
  InMemorySecurityControlsAuditStore,
} from '../state/inmemory-security-controls-audit-store';
import type {
  SecurityControlsAuditEntry,
  SecurityControlsAuditStore,
} from '../state/security-controls-audit-store';
import {
  signAbuseIntelBundle,
  verifySignedAbuseIntelBundle,
  type SignedAbuseIntelBundle,
} from './abuse-intel-signing';
import {
  signSecurityControlsHistoryBundle,
  verifySignedSecurityControlsHistoryBundle,
  type SignedSecurityControlsHistoryBundle,
  type SecurityControlsHistoryBundleEntry,
} from './security-controls-history-signing';
import {
  signEdgeCacheVersionBundle,
  verifySignedEdgeCacheVersionBundle,
  type EdgeCacheVersionBundleEntry,
  type EdgeCacheVersionImportStrategy,
  type SignedEdgeCacheVersionBundle,
} from './edge-cache-version-signing';
import {
  signEdgeInvalidationBundle,
  verifySignedEdgeInvalidationBundle,
  type EdgeInvalidationBundleEntry,
  type SignedEdgeInvalidationBundle,
} from './edge-invalidation-signing';
import {
  signControlPlaneAuditBundle,
  verifySignedControlPlaneAuditBundle,
  type ControlPlaneAuditBundleEntry,
  type SignedControlPlaneAuditBundle,
} from './control-plane-audit-signing';
import {
  signUpstreamRoutingPolicyBundle,
  verifySignedUpstreamRoutingPolicyBundle,
  type SignedUpstreamRoutingPolicyBundle,
} from './upstream-policy-signing';
import {
  signRoutePolicyBundle,
  verifySignedRoutePolicyBundle,
  type SignedRoutePolicyBundle,
} from './route-policy-signing';
import {
  RoutePolicyManager,
  type RoutePolicyIssue,
  type RoutePolicyPatchUpdate,
} from '../proxy/route-policy-manager';
import {
  UpstreamRoutingPolicyManager,
  type UpstreamRoutingPolicyIssue,
} from '../proxy/upstream-policy-manager';
import {
  GatewayConfigSchema,
  type GatewayConfig,
  type RouteConfig,
  type UpstreamService,
} from '../../config/default';

const BlockIpSchema = z.object({
  ip: z.string().min(1).optional(),
  ips: z.array(z.string().min(1)).min(1).optional(),
  ttlSeconds: z.number().int().positive().max(60 * 60 * 24 * 30).default(30 * 60),
  reason: z.string().min(1).max(512).default('automated response'),
  alertId: z.string().min(1).max(128).optional(),
}).refine((v) => Boolean(v.ip) || Boolean(v.ips && v.ips.length > 0), {
  message: 'ip or ips is required',
});

const RequireStepUpSchema = z.object({
  userId: z.string().min(1).max(256),
  requiredLevel: z.number().int().min(1).max(2).default(1),
  ttlSeconds: z.number().int().positive().max(60 * 60 * 24 * 30).default(60 * 60),
  reason: z.string().min(1).max(512).default('automated response'),
  alertId: z.string().min(1).max(128).optional(),
});

const ThrottleUserSchema = z.object({
  userId: z.string().min(1).max(256),
  reducedRatePercent: z.number().int().min(1).max(100),
  ttlSeconds: z.number().int().positive().max(60 * 60 * 24 * 30).default(30 * 60),
  reason: z.string().min(1).max(512).default('automated response'),
  alertId: z.string().min(1).max(128).optional(),
});

const AbuseIntelImportSchema = z.object({
  source: z.string().min(1).max(128).default('peer-gateway'),
  minTtlSeconds: z.number().int().min(1).max(60 * 60 * 24).default(60),
  entries: z.array(z.object({
    ip: z.string().min(1).max(128),
    ttlSeconds: z.number().int().positive().max(60 * 60 * 24 * 30).optional(),
    expiresAt: z.string().datetime().optional(),
    reason: z.string().min(1).max(512).optional(),
    alertId: z.string().min(1).max(128).optional(),
  })).min(1).max(5000),
});

const SignedAbuseIntelImportSchema = z.object({
  source: z.string().min(1).max(128),
  bundleId: z.string().min(1).max(128),
  keyId: z.string().min(1).max(128),
  generatedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  minTtlSeconds: z.number().int().min(1).max(60 * 60 * 24),
  entries: AbuseIntelImportSchema.shape.entries,
  signature: z.string().min(1).max(256),
});

const EdgeCachePurgeSchema = z.object({
  key: z.string().min(1).max(1024).optional(),
  routePath: z.string().min(1).max(512).optional(),
  tags: z.array(z.string().min(1).max(128)).min(1).max(128).optional(),
  all: z.boolean().default(false),
  maxDelete: z.number().int().positive().max(100_000).default(10_000),
}).superRefine((value, ctx) => {
  const targets =
    Number(value.key ? 1 : 0) +
    Number(value.routePath ? 1 : 0) +
    Number(value.tags && value.tags.length > 0 ? 1 : 0) +
    Number(value.all ? 1 : 0);
  if (targets === 0) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'one of key, routePath, tags, or all=true is required',
    });
  }
  if (targets > 1) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'key, routePath, tags, and all are mutually exclusive',
    });
  }
});

const EdgeCacheVersionSchema = z.object({
  routePath: z.string().min(1).max(512),
});

const EdgeCacheVersionBundleEntrySchema = z.object({
  routePath: z.string().min(1).max(512),
  version: z.string().regex(/^\d{1,32}$/),
});

const EdgeCacheVersionImportSchema = z.object({
  source: z.string().min(1).max(128).default('peer-gateway'),
  strategy: z.enum(['max', 'overwrite']).default('max'),
  entries: z.array(EdgeCacheVersionBundleEntrySchema).min(1).max(5000),
});

const SignedEdgeCacheVersionBundleSchema = z.object({
  source: z.string().min(1).max(128),
  bundleId: z.string().min(1).max(128),
  keyId: z.string().min(1).max(128),
  generatedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  strategy: z.enum(['max', 'overwrite']).optional(),
  entries: z.array(EdgeCacheVersionBundleEntrySchema).min(1).max(5000),
  signature: z.string().min(1).max(256),
});

const EdgeInvalidationEventKindSchema = z.enum(['purge', 'version_set']);

const EdgeInvalidationBundleEntrySchema = z.object({
  cursor: z.string().regex(/^\d{1,32}$/),
  eventId: z.string().min(1).max(128),
  source: z.string().min(1).max(128),
  occurredAt: z.string().datetime(),
  actor: z.string().min(1).max(256),
  correlationId: z.string().min(1).max(256).optional(),
  kind: EdgeInvalidationEventKindSchema,
  payload: z.record(z.string(), z.unknown()),
});

const SignedEdgeInvalidationBundleSchema = z.object({
  source: z.string().min(1).max(128),
  bundleId: z.string().min(1).max(128),
  keyId: z.string().min(1).max(128),
  generatedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  fromCursor: z.string().regex(/^\d{1,32}$/),
  toCursor: z.string().regex(/^\d{1,32}$/),
  entries: z.array(EdgeInvalidationBundleEntrySchema).min(1).max(5000),
  signature: z.string().min(1).max(256),
});

const EdgeInvalidationImportSchema = z.object({
  source: z.string().min(1).max(128).default('peer-gateway'),
  fromCursor: z.string().regex(/^\d{1,32}$/).default('0'),
  toCursor: z.string().regex(/^\d{1,32}$/).optional(),
  entries: z.array(EdgeInvalidationBundleEntrySchema).min(1).max(5000),
});

const EdgeInvalidationVersionSetPayloadSchema = z.object({
  routePath: z.string().min(1).max(512),
  version: z.string().regex(/^\d{1,32}$/),
});

const ControlPlaneAuditMethodSchema = z.enum(['POST', 'PUT', 'PATCH', 'DELETE']);
const ControlPlaneAuditOutcomeSchema = z.enum(['success', 'failure']);

const ControlPlaneAuditBundleEntrySchema = z.object({
  cursor: z.string().regex(/^\d{1,32}$/),
  eventId: z.string().min(1).max(128),
  source: z.string().min(1).max(128),
  occurredAt: z.string().datetime(),
  actor: z.string().min(1).max(256),
  correlationId: z.string().min(1).max(256).optional(),
  method: ControlPlaneAuditMethodSchema,
  path: z.string().min(1).max(1024).refine((value) => value.startsWith('/internal/'), {
    message: 'path must start with /internal/',
  }),
  statusCode: z.number().int().min(100).max(599),
  outcome: ControlPlaneAuditOutcomeSchema,
  requestBodyHash: z.string().length(64).regex(/^[a-f0-9]+$/),
  requestContentLength: z.number().int().min(0).optional(),
  idempotencyKey: z.string().min(1).max(128).optional(),
  permissionScope: z.string().min(1).max(128).optional(),
});

const SignedControlPlaneAuditBundleSchema = z.object({
  source: z.string().min(1).max(128),
  bundleId: z.string().min(1).max(128),
  keyId: z.string().min(1).max(128),
  generatedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  fromCursor: z.string().regex(/^\d{1,32}$/),
  toCursor: z.string().regex(/^\d{1,32}$/),
  entries: z.array(ControlPlaneAuditBundleEntrySchema).min(1).max(5000),
  signature: z.string().min(1).max(256),
});

const ControlPlaneAuditImportSchema = z.object({
  source: z.string().min(1).max(128).default('peer-gateway'),
  fromCursor: z.string().regex(/^\d{1,32}$/).default('0'),
  toCursor: z.string().regex(/^\d{1,32}$/).optional(),
  entries: z.array(ControlPlaneAuditBundleEntrySchema).min(1).max(5000),
});

const UpstreamRoutingPolicyPatchSchema = z.object({
  upstreams: z.record(
    z.string().min(1).max(128).regex(/^[A-Za-z0-9._:-]+$/),
    z.record(z.string(), z.unknown()),
  ).refine((value) => Object.keys(value).length > 0, {
    message: 'at least one upstream patch is required',
  }),
  ifRevision: z.string().min(1).max(256).optional(),
  dryRun: z.boolean().optional().default(false),
});

const UpstreamRoutingPolicyImportSchema = z.object({
  source: z.string().min(1).max(128).default('peer-gateway'),
  revision: z.string().regex(/^ur:[a-f0-9]{32}$/),
  upstreams: z.record(
    z.string().min(1).max(128).regex(/^[A-Za-z0-9._:-]+$/),
    z.record(z.string(), z.unknown()),
  ),
});

const SignedUpstreamRoutingPolicyBundleSchema = z.object({
  source: z.string().min(1).max(128),
  bundleId: z.string().min(1).max(128),
  keyId: z.string().min(1).max(128),
  generatedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  revision: z.string().regex(/^ur:[a-f0-9]{32}$/),
  upstreams: UpstreamRoutingPolicyImportSchema.shape.upstreams,
  signature: z.string().min(1).max(256),
});

const RoutePolicyPatchUpdateSchema = z.object({
  path: z.string().min(1).max(1024).refine((value) => value.startsWith('/'), {
    message: 'path must start with /',
  }),
  method: z.string().min(1).max(16).optional(),
  patch: z.record(z.string(), z.unknown()),
});

const RoutePolicyPatchSchema = z.object({
  updates: z.array(RoutePolicyPatchUpdateSchema).min(1).max(5000),
  ifRevision: z.string().regex(/^rr:[a-f0-9]{32}$/).optional(),
  dryRun: z.boolean().optional().default(false),
});

const RoutePolicyImportSchema = z.object({
  source: z.string().min(1).max(128).default('peer-gateway'),
  revision: z.string().regex(/^rr:[a-f0-9]{32}$/),
  routes: z.array(z.record(z.string(), z.unknown())).max(5000),
});

const SignedRoutePolicyBundleSchema = z.object({
  source: z.string().min(1).max(128),
  bundleId: z.string().min(1).max(128),
  keyId: z.string().min(1).max(128),
  generatedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  revision: z.string().regex(/^rr:[a-f0-9]{32}$/),
  routes: RoutePolicyImportSchema.shape.routes,
  signature: z.string().min(1).max(256),
});

const SecurityControlsHistoryBundleEntrySchema = z.object({
  changedAt: z.string().datetime(),
  actor: z.string().min(1).max(256),
  correlationId: z.string().min(1).max(256).optional(),
  patch: z.record(z.string(), z.unknown()),
  snapshotHash: z.string().length(64).regex(/^[a-f0-9]+$/).optional(),
});

const SignedSecurityControlsHistoryBundleSchema = z.object({
  source: z.string().min(1).max(128),
  bundleId: z.string().min(1).max(128),
  keyId: z.string().min(1).max(128),
  generatedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  entries: z.array(SecurityControlsHistoryBundleEntrySchema).min(1).max(5000),
  signature: z.string().min(1).max(256),
});

const SecurityControlsHistoryImportSchema = z.object({
  source: z.string().min(1).max(128).default('peer-gateway'),
  entries: z.array(SecurityControlsHistoryBundleEntrySchema).min(1).max(5000),
});

type PlainAbuseIntelImport = z.infer<typeof AbuseIntelImportSchema>;
type EdgeCachePurgeRequest = z.infer<typeof EdgeCachePurgeSchema>;
type EdgeCacheVersionRequest = z.infer<typeof EdgeCacheVersionSchema>;
type EdgeCacheVersionImportRequest = z.infer<typeof EdgeCacheVersionImportSchema>;
type EdgeInvalidationImportRequest = z.infer<typeof EdgeInvalidationImportSchema>;
type UpstreamRoutingPolicyImportRequest = z.infer<typeof UpstreamRoutingPolicyImportSchema>;
type RoutePolicyImportRequest = z.infer<typeof RoutePolicyImportSchema>;
export type { SecurityControlsAuditEntry } from '../state/security-controls-audit-store';

interface InternalRoutesOptions {
  abuseIntel?: GatewayConfig['adaptiveDefense']['abuseIntel'];
  abuseIntelReplayStore?: InternalAuthReplayStore;
  mutationReplayStore?: InternalAuthReplayStore;
  edgeCache?: GatewayConfig['edgeCache'];
  edgeCacheStore?: EdgeCacheStore;
  edgeInvalidationEventStore?: EdgeInvalidationEventStore;
  edgeInvalidationMaxEntries?: number;
  controlPlaneAuditStore?: ControlPlaneAuditStore;
  controlPlaneAuditMaxEntries?: number;
  routePolicyManager?: RoutePolicyManager;
  upstreamPolicyManager?: UpstreamRoutingPolicyManager;
  securityControlsAuditStore?: SecurityControlsAuditStore;
  securityControlsAuditMaxEntries?: number;
  gatewayConfig?: GatewayConfig;
}

type AbuseIntelConfig = GatewayConfig['adaptiveDefense']['abuseIntel'];
type SecurityControlsHistorySignedBundle = z.infer<typeof SignedSecurityControlsHistoryBundleSchema>;
type EdgeInvalidationSignedBundle = z.infer<typeof SignedEdgeInvalidationBundleSchema>;
type ControlPlaneAuditSignedBundle = z.infer<typeof SignedControlPlaneAuditBundleSchema>;
type UpstreamRoutingPolicySignedBundle = z.infer<typeof SignedUpstreamRoutingPolicyBundleSchema>;
type RoutePolicySignedBundle = z.infer<typeof SignedRoutePolicyBundleSchema>;

interface SecurityControlsHistoryBundleConfig {
  sourceId: string;
  exportMaxEntries: number;
  defaultBundleTtlSeconds: number;
  signExports: boolean;
  requireSignedImports: boolean;
  signingKeyId: string;
  signingSecret: string;
  allowedSources: string[];
  allowedKeyIds: string[];
  keyring: Record<string, string>;
  replayProtectionEnabled: boolean;
  replayCacheMaxEntries: number;
  maxSkewSeconds: number;
}

interface EdgeCacheVersionBundleConfig {
  sourceId: string;
  exportMaxEntries: number;
  defaultBundleTtlSeconds: number;
  signExports: boolean;
  requireSignedImports: boolean;
  signingKeyId: string;
  signingSecret: string;
  allowedSources: string[];
  allowedKeyIds: string[];
  keyring: Record<string, string>;
  replayProtectionEnabled: boolean;
  replayCacheMaxEntries: number;
  maxSkewSeconds: number;
}

interface EdgeInvalidationBundleConfig {
  sourceId: string;
  exportMaxEntries: number;
  defaultBundleTtlSeconds: number;
  signExports: boolean;
  requireSignedImports: boolean;
  signingKeyId: string;
  signingSecret: string;
  allowedSources: string[];
  allowedKeyIds: string[];
  keyring: Record<string, string>;
  replayProtectionEnabled: boolean;
  replayCacheMaxEntries: number;
  maxSkewSeconds: number;
}

interface ControlPlaneAuditBundleConfig {
  sourceId: string;
  exportMaxEntries: number;
  defaultBundleTtlSeconds: number;
  signExports: boolean;
  requireSignedImports: boolean;
  signingKeyId: string;
  signingSecret: string;
  allowedSources: string[];
  allowedKeyIds: string[];
  keyring: Record<string, string>;
  replayProtectionEnabled: boolean;
  replayCacheMaxEntries: number;
  maxSkewSeconds: number;
}

interface UpstreamRoutingPolicyBundleConfig {
  sourceId: string;
  defaultBundleTtlSeconds: number;
  signExports: boolean;
  requireSignedImports: boolean;
  signingKeyId: string;
  signingSecret: string;
  allowedSources: string[];
  allowedKeyIds: string[];
  keyring: Record<string, string>;
  replayProtectionEnabled: boolean;
  replayCacheMaxEntries: number;
  maxSkewSeconds: number;
}

interface RoutePolicyBundleConfig {
  sourceId: string;
  defaultBundleTtlSeconds: number;
  signExports: boolean;
  requireSignedImports: boolean;
  signingKeyId: string;
  signingSecret: string;
  allowedSources: string[];
  allowedKeyIds: string[];
  keyring: Record<string, string>;
  replayProtectionEnabled: boolean;
  replayCacheMaxEntries: number;
  maxSkewSeconds: number;
}

interface InternalMutationIdempotencyConfig {
  enabled: boolean;
  ttlSeconds: number;
  replayCacheMaxEntries: number;
}

export interface InternalControlPlaneApiKeyConfig {
  secret: string;
  scopes: string[];
}

export interface InternalControlPlaneConfig {
  enabled: boolean;
  requireApiKeyForMutations: boolean;
  callerRoles: Record<string, string[]>;
  apiKeys: Record<string, InternalControlPlaneApiKeyConfig>;
  apiKeyIdHeader: string;
  apiKeySecretHeader: string;
}

const DEFAULT_ABUSE_INTEL_CONFIG: AbuseIntelConfig = {
  enabled: true,
  sourceId: 'gateway-edge',
  exportMaxEntries: 1000,
  defaultBundleTtlSeconds: 900,
  signExports: true,
  requireSignedImports: true,
  signingKeyId: 'gateway-abuse-v1',
  signingSecret: '',
  allowedSources: [],
  allowedKeyIds: [],
  keyring: {},
  replayProtectionEnabled: true,
  replayCacheMaxEntries: 50_000,
  maxSkewSeconds: 300,
};

const DEFAULT_SECURITY_CONTROLS_HISTORY_BUNDLE_CONFIG: SecurityControlsHistoryBundleConfig = {
  sourceId: 'gateway-edge',
  exportMaxEntries: 1000,
  defaultBundleTtlSeconds: 900,
  signExports: true,
  requireSignedImports: true,
  signingKeyId: 'gateway-controls-v1',
  signingSecret: '',
  allowedSources: [],
  allowedKeyIds: ['gateway-controls-v1'],
  keyring: {},
  replayProtectionEnabled: true,
  replayCacheMaxEntries: 50_000,
  maxSkewSeconds: 300,
};

const DEFAULT_EDGE_CACHE_VERSION_BUNDLE_CONFIG: EdgeCacheVersionBundleConfig = {
  sourceId: 'gateway-edge',
  exportMaxEntries: 1000,
  defaultBundleTtlSeconds: 900,
  signExports: true,
  requireSignedImports: true,
  signingKeyId: 'gateway-edge-cache-v1',
  signingSecret: '',
  allowedSources: [],
  allowedKeyIds: ['gateway-edge-cache-v1'],
  keyring: {},
  replayProtectionEnabled: true,
  replayCacheMaxEntries: 50_000,
  maxSkewSeconds: 300,
};

const DEFAULT_EDGE_INVALIDATION_BUNDLE_CONFIG: EdgeInvalidationBundleConfig = {
  sourceId: 'gateway-edge',
  exportMaxEntries: 1000,
  defaultBundleTtlSeconds: 900,
  signExports: true,
  requireSignedImports: true,
  signingKeyId: 'gateway-edge-invalidation-v1',
  signingSecret: '',
  allowedSources: [],
  allowedKeyIds: ['gateway-edge-invalidation-v1'],
  keyring: {},
  replayProtectionEnabled: true,
  replayCacheMaxEntries: 50_000,
  maxSkewSeconds: 300,
};

const DEFAULT_CONTROL_PLANE_AUDIT_BUNDLE_CONFIG: ControlPlaneAuditBundleConfig = {
  sourceId: 'gateway-edge',
  exportMaxEntries: 1000,
  defaultBundleTtlSeconds: 900,
  signExports: true,
  requireSignedImports: true,
  signingKeyId: 'gateway-control-plane-audit-v1',
  signingSecret: '',
  allowedSources: [],
  allowedKeyIds: ['gateway-control-plane-audit-v1'],
  keyring: {},
  replayProtectionEnabled: true,
  replayCacheMaxEntries: 50_000,
  maxSkewSeconds: 300,
};

const DEFAULT_UPSTREAM_ROUTING_POLICY_BUNDLE_CONFIG: UpstreamRoutingPolicyBundleConfig = {
  sourceId: 'gateway-edge',
  defaultBundleTtlSeconds: 900,
  signExports: true,
  requireSignedImports: true,
  signingKeyId: 'gateway-upstream-routing-v1',
  signingSecret: '',
  allowedSources: [],
  allowedKeyIds: ['gateway-upstream-routing-v1'],
  keyring: {},
  replayProtectionEnabled: true,
  replayCacheMaxEntries: 50_000,
  maxSkewSeconds: 300,
};

const DEFAULT_ROUTE_POLICY_BUNDLE_CONFIG: RoutePolicyBundleConfig = {
  sourceId: 'gateway-edge',
  defaultBundleTtlSeconds: 900,
  signExports: true,
  requireSignedImports: true,
  signingKeyId: 'gateway-route-policy-v1',
  signingSecret: '',
  allowedSources: [],
  allowedKeyIds: ['gateway-route-policy-v1'],
  keyring: {},
  replayProtectionEnabled: true,
  replayCacheMaxEntries: 50_000,
  maxSkewSeconds: 300,
};

const DEFAULT_INTERNAL_MUTATION_IDEMPOTENCY_CONFIG: InternalMutationIdempotencyConfig = {
  enabled: true,
  ttlSeconds: 15 * 60,
  replayCacheMaxEntries: 50_000,
};

const DEFAULT_INTERNAL_CONTROL_PLANE_CONFIG: InternalControlPlaneConfig = {
  enabled: false,
  requireApiKeyForMutations: false,
  callerRoles: {},
  apiKeys: {},
  apiKeyIdHeader: 'x-internal-api-key-id',
  apiKeySecretHeader: 'x-internal-api-key',
};

const SecurityControlsPatchSchema = z.object({
  waf: z.record(z.string(), z.unknown()).optional(),
  botManagement: z.record(z.string(), z.unknown()).optional(),
  accessControl: z.record(z.string(), z.unknown()).optional(),
}).superRefine((value, ctx) => {
  if (!value.waf && !value.botManagement && !value.accessControl) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'at least one of waf, botManagement, or accessControl is required',
    });
  }
});

type SecurityControlsPatch = z.infer<typeof SecurityControlsPatchSchema>;

const SecurityControlsPatchRequestEnvelopeSchema = z.object({
  patch: SecurityControlsPatchSchema,
  ifRevision: z.string().min(1).max(512).optional(),
  dryRun: z.boolean().optional().default(false),
});

const SECURITY_CONTROLS_HISTORY_DEFAULT_LIMIT = 100;
const SECURITY_CONTROLS_HISTORY_LIMIT_MAX = 5000;
const SECURITY_CONTROLS_HISTORY_DEFAULT_MAX_ENTRIES = 10_000;
const SECURITY_CONTROLS_REVISION_FALLBACK = 'r0:genesis';
const EDGE_INVALIDATION_DEFAULT_LIMIT = 100;
const EDGE_INVALIDATION_LIMIT_MAX = 5000;
const EDGE_INVALIDATION_DEFAULT_MAX_ENTRIES = 100_000;
const EDGE_INVALIDATION_CURSOR_PATTERN = /^\d{1,32}$/;
const CONTROL_PLANE_AUDIT_DEFAULT_LIMIT = 100;
const CONTROL_PLANE_AUDIT_LIMIT_MAX = 5000;
const CONTROL_PLANE_AUDIT_DEFAULT_MAX_ENTRIES = 200_000;
const CONTROL_PLANE_AUDIT_CURSOR_PATTERN = /^\d{1,32}$/;
const INTERNAL_MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._:-]{8,128}$/;
const localMutationReplayStores = new Map<number, InMemoryInternalAuthReplayStore>();

export interface AbuseIntelExportPayload {
  generatedAt: string;
  entryCount: number;
  entries: IpBlockEntry[];
}

export async function buildAbuseIntelExport(
  state: SecurityStateStore,
  limit: number,
): Promise<AbuseIntelExportPayload> {
  const entries = await state.listBlockedIps(Math.max(1, Math.min(Math.floor(limit), 5000)));
  return {
    generatedAt: new Date().toISOString(),
    entryCount: entries.length,
    entries,
  };
}

export async function applyAbuseIntelImport(
  state: SecurityStateStore,
  payload: PlainAbuseIntelImport,
): Promise<{ imported: number; skipped: number; importedIps: string[] }> {
  const now = Date.now();
  let imported = 0;
  let skipped = 0;
  const importedIps: string[] = [];
  const seen = new Set<string>();

  for (const entry of payload.entries) {
    const ip = entry.ip.trim();
    if (!ip || seen.has(ip)) {
      skipped += 1;
      continue;
    }
    seen.add(ip);

    let ttlSeconds = entry.ttlSeconds ?? 0;
    if (!ttlSeconds && entry.expiresAt) {
      ttlSeconds = Math.floor((Date.parse(entry.expiresAt) - now) / 1000);
    }
    if (!ttlSeconds || ttlSeconds < payload.minTtlSeconds) {
      skipped += 1;
      continue;
    }

    await state.blockIps([ip], ttlSeconds, {
      reason: `abuse_intel:${payload.source}:${entry.reason ?? 'shared'}`,
      alertId: entry.alertId,
    });
    imported += 1;
    importedIps.push(ip);
  }

  return { imported, skipped, importedIps };
}

export async function applyEdgeCachePurge(
  store: EdgeCacheStore,
  payload: EdgeCachePurgeRequest,
): Promise<{ purged: number; mode: 'key' | 'route' | 'tags' | 'all' }> {
  if (payload.key) {
    const deleted = await store.delete(payload.key);
    return { purged: deleted ? 1 : 0, mode: 'key' };
  }
  if (payload.routePath) {
    const purged = await store.purgeRoute(payload.routePath, payload.maxDelete);
    return { purged, mode: 'route' };
  }
  if (payload.tags && payload.tags.length > 0) {
    const purged = await store.purgeTags(payload.tags, payload.maxDelete);
    return { purged, mode: 'tags' };
  }
  const purged = await store.clear(payload.maxDelete);
  return { purged, mode: 'all' };
}

export async function getEdgeCacheRouteVersion(
  store: EdgeCacheStore,
  payload: EdgeCacheVersionRequest,
): Promise<{ routePath: string; version: string }> {
  return {
    routePath: payload.routePath,
    version: await store.getRouteVersion(payload.routePath),
  };
}

export async function bumpEdgeCacheRouteVersion(
  store: EdgeCacheStore,
  payload: EdgeCacheVersionRequest,
): Promise<{
  routePath: string;
  previousVersion: string;
  currentVersion: string;
  bumpedAt: string;
}> {
  return store.bumpRouteVersion(payload.routePath);
}

export async function buildSignedAbuseIntelExport(
  state: SecurityStateStore,
  limit: number,
  config: AbuseIntelConfig,
): Promise<{ entryCount: number; bundle: SignedAbuseIntelBundle }> {
  const payload = await buildAbuseIntelExport(
    state,
    Math.min(Math.max(1, Math.floor(limit)), config.exportMaxEntries),
  );
  const nowMs = Date.now();
  const unsignedBundle: Omit<SignedAbuseIntelBundle, 'signature'> = {
    source: config.sourceId,
    bundleId: randomUUID(),
    keyId: config.signingKeyId,
    generatedAt: new Date(nowMs).toISOString(),
    expiresAt: new Date(nowMs + Math.max(1, config.defaultBundleTtlSeconds) * 1000).toISOString(),
    minTtlSeconds: 60,
    entries: payload.entries.map((entry) => ({
      ip: entry.ip,
      expiresAt: entry.expiresAt,
      reason: entry.reason,
      alertId: entry.alertId,
    })),
  };

  const bundle = signAbuseIntelBundle(unsignedBundle, config.signingSecret || '');
  return {
    entryCount: payload.entryCount,
    bundle,
  };
}

export interface EdgeCacheVersionExportPayload {
  generatedAt: string;
  entryCount: number;
  entries: EdgeCacheVersionBundleEntry[];
}

export async function buildEdgeCacheVersionExport(
  store: EdgeCacheStore,
  limit: number,
): Promise<EdgeCacheVersionExportPayload> {
  const normalizedLimit = Math.max(1, Math.min(Math.floor(limit), 5000));
  const entries = await store.listRouteVersions(normalizedLimit);
  return {
    generatedAt: new Date().toISOString(),
    entryCount: entries.length,
    entries,
  };
}

export async function buildSignedEdgeCacheVersionExport(
  store: EdgeCacheStore,
  limit: number,
  config: EdgeCacheVersionBundleConfig,
): Promise<{ entryCount: number; bundle: SignedEdgeCacheVersionBundle }> {
  const payload = await buildEdgeCacheVersionExport(
    store,
    Math.min(Math.max(1, Math.floor(limit)), config.exportMaxEntries),
  );
  const nowMs = Date.now();
  const unsignedBundle: Omit<SignedEdgeCacheVersionBundle, 'signature'> = {
    source: config.sourceId,
    bundleId: randomUUID(),
    keyId: config.signingKeyId,
    generatedAt: new Date(nowMs).toISOString(),
    expiresAt: new Date(nowMs + Math.max(1, config.defaultBundleTtlSeconds) * 1000).toISOString(),
    strategy: 'max',
    entries: payload.entries,
  };
  const bundle = signEdgeCacheVersionBundle(unsignedBundle, config.signingSecret || '');
  return {
    entryCount: payload.entryCount,
    bundle,
  };
}

function parseVersionBigInt(value: string): bigint | null {
  if (!/^\d{1,32}$/.test(value)) return null;
  try {
    return BigInt(value);
  } catch {
    return null;
  }
}

function shouldApplyImportedVersion(
  currentVersion: string,
  incomingVersion: string,
  strategy: EdgeCacheVersionImportStrategy,
): boolean {
  if (strategy === 'overwrite') {
    return currentVersion !== incomingVersion;
  }
  const currentNum = parseVersionBigInt(currentVersion);
  const incomingNum = parseVersionBigInt(incomingVersion);
  if (incomingNum === null) return false;
  if (currentNum === null) return currentVersion !== incomingVersion;
  return incomingNum > currentNum;
}

export async function applyEdgeCacheVersionImport(
  store: EdgeCacheStore,
  payload: Pick<EdgeCacheVersionImportRequest, 'source' | 'strategy' | 'entries'>,
): Promise<{
  imported: number;
  updated: number;
  skipped: number;
  applied: Array<{
    routePath: string;
    previousVersion: string;
    currentVersion: string;
    updated: boolean;
  }>;
}> {
  let imported = 0;
  let updated = 0;
  let skipped = 0;
  const seen = new Set<string>();
  const applied: Array<{
    routePath: string;
    previousVersion: string;
    currentVersion: string;
    updated: boolean;
  }> = [];

  for (const entry of payload.entries) {
    const routePath = entry.routePath.trim();
    if (!routePath || seen.has(routePath)) {
      skipped += 1;
      continue;
    }
    seen.add(routePath);

    const currentVersion = await store.getRouteVersion(routePath);
    const apply = shouldApplyImportedVersion(currentVersion, entry.version, payload.strategy);
    if (!apply) {
      skipped += 1;
      continue;
    }

    const result = await store.setRouteVersion(routePath, entry.version);
    imported += 1;
    if (result.updated) {
      updated += 1;
    }
    applied.push({
      routePath: result.routePath,
      previousVersion: result.previousVersion,
      currentVersion: result.currentVersion,
      updated: result.updated,
    });
  }

  return { imported, updated, skipped, applied };
}

export interface EdgeInvalidationExportPayload {
  source?: string;
  generatedAt: string;
  fromCursor: string;
  toCursor: string;
  entryCount: number;
  entries: EdgeInvalidationBundleEntry[];
}

export function buildEdgeInvalidationEventInput(input: {
  source: string;
  actor: string;
  correlationId?: string;
  kind: EdgeInvalidationEventKind;
  payload: Record<string, unknown>;
  eventId?: string;
  occurredAt?: string;
}): Omit<EdgeInvalidationEvent, 'cursor'> {
  return {
    eventId: input.eventId ?? randomUUID(),
    source: input.source,
    occurredAt: input.occurredAt ?? new Date().toISOString(),
    actor: input.actor,
    correlationId: input.correlationId,
    kind: input.kind,
    payload: { ...input.payload },
  };
}

export async function buildEdgeInvalidationExport(
  store: EdgeInvalidationEventStore,
  afterCursor: string,
  limit: number,
  source?: string,
): Promise<EdgeInvalidationExportPayload> {
  const normalizedAfterCursor = normalizeEdgeInvalidationCursor(afterCursor, '0');
  const normalizedLimit = Math.max(1, Math.min(Math.floor(limit), 5000));
  const listed = await store.listAfter(normalizedAfterCursor, normalizedLimit);
  const filteredEntries = source
    ? listed.entries.filter((entry) => entry.source === source)
    : listed.entries;
  const entries = filteredEntries.map((entry) => ({
    cursor: entry.cursor,
    eventId: entry.eventId,
    source: entry.source,
    occurredAt: entry.occurredAt,
    actor: entry.actor,
    correlationId: entry.correlationId,
    kind: entry.kind,
    payload: entry.payload,
  }));
  return {
    source,
    generatedAt: new Date().toISOString(),
    fromCursor: normalizedAfterCursor,
    toCursor: listed.nextCursor,
    entryCount: entries.length,
    entries,
  };
}

export async function buildSignedEdgeInvalidationExport(
  store: EdgeInvalidationEventStore,
  afterCursor: string,
  limit: number,
  config: EdgeInvalidationBundleConfig,
): Promise<{ entryCount: number; bundle: SignedEdgeInvalidationBundle }> {
  const payload = await buildEdgeInvalidationExport(
    store,
    afterCursor,
    Math.min(Math.max(1, Math.floor(limit)), config.exportMaxEntries),
    config.sourceId,
  );
  if (payload.entryCount <= 0) {
    throw new Error('edge_invalidation_empty_export');
  }
  const nowMs = Date.now();
  const unsignedBundle: Omit<SignedEdgeInvalidationBundle, 'signature'> = {
    source: config.sourceId,
    bundleId: randomUUID(),
    keyId: config.signingKeyId,
    generatedAt: new Date(nowMs).toISOString(),
    expiresAt: new Date(nowMs + Math.max(1, config.defaultBundleTtlSeconds) * 1000).toISOString(),
    fromCursor: payload.fromCursor,
    toCursor: payload.toCursor,
    entries: payload.entries,
  };
  const bundle = signEdgeInvalidationBundle(unsignedBundle, config.signingSecret || '');
  return {
    entryCount: payload.entryCount,
    bundle,
  };
}

async function replayEdgeInvalidationEvent(
  edgeCacheStore: EdgeCacheStore,
  event: EdgeInvalidationBundleEntry,
): Promise<boolean> {
  if (event.kind === 'purge') {
    const parsed = EdgeCachePurgeSchema.safeParse(event.payload);
    if (!parsed.success) {
      return false;
    }
    await applyEdgeCachePurge(edgeCacheStore, parsed.data);
    return true;
  }

  if (event.kind === 'version_set') {
    const parsed = EdgeInvalidationVersionSetPayloadSchema.safeParse(event.payload);
    if (!parsed.success) {
      return false;
    }
    const currentVersion = await edgeCacheStore.getRouteVersion(parsed.data.routePath);
    const shouldSet = shouldApplyImportedVersion(currentVersion, parsed.data.version, 'max');
    if (shouldSet) {
      await edgeCacheStore.setRouteVersion(parsed.data.routePath, parsed.data.version);
    }
    return true;
  }

  return false;
}

export async function applyEdgeInvalidationImport(
  eventStore: EdgeInvalidationEventStore,
  edgeCacheStore: EdgeCacheStore,
  payload: Pick<EdgeInvalidationImportRequest, 'source' | 'entries' | 'fromCursor' | 'toCursor'>,
  options: {
    maxEntries: number;
    localSourceId: string;
  },
): Promise<{
  imported: number;
  applied: number;
  skipped: number;
  latestImportedCursor: string;
  appended: number;
}> {
  if (payload.source === options.localSourceId) {
    const latestImportedCursor = await eventStore.getImportedCursor(payload.source);
    return {
      imported: 0,
      applied: 0,
      skipped: payload.entries.length,
      latestImportedCursor,
      appended: 0,
    };
  }

  const maxEntries = Math.max(100, Math.min(Math.floor(options.maxEntries), 500_000));
  const sortedEntries = [...payload.entries]
    .sort((a, b) => {
      const left = parseEdgeInvalidationCursorBigInt(a.cursor);
      const right = parseEdgeInvalidationCursorBigInt(b.cursor);
      if (left === right) return 0;
      return left < right ? -1 : 1;
    });
  let imported = 0;
  let applied = 0;
  let skipped = 0;
  let appended = 0;
  let importedCursor = normalizeEdgeInvalidationCursor(
    await eventStore.getImportedCursor(payload.source),
    '0',
  );
  let importedCursorBig = parseEdgeInvalidationCursorBigInt(importedCursor);

  for (const entry of sortedEntries) {
    if (entry.source !== payload.source) {
      skipped += 1;
      continue;
    }

    const entryCursor = normalizeEdgeInvalidationCursor(entry.cursor, '0');
    const entryCursorBig = parseEdgeInvalidationCursorBigInt(entryCursor);
    if (entryCursorBig <= importedCursorBig) {
      skipped += 1;
      continue;
    }

    imported += 1;
    const replayed = await replayEdgeInvalidationEvent(edgeCacheStore, entry);
    if (replayed) {
      applied += 1;
    } else {
      skipped += 1;
    }

    await eventStore.append({
      eventId: entry.eventId,
      source: entry.source,
      occurredAt: entry.occurredAt,
      actor: `federated:${payload.source}:${entry.actor}`,
      correlationId: entry.correlationId ?? `import:${payload.source}`,
      kind: entry.kind,
      payload: entry.payload,
    }, maxEntries);
    appended += 1;

    const advance = await eventStore.advanceImportedCursor(payload.source, entryCursor);
    importedCursor = advance.currentCursor;
    importedCursorBig = parseEdgeInvalidationCursorBigInt(importedCursor);
  }

  return {
    imported,
    applied,
    skipped,
    latestImportedCursor: importedCursor,
    appended,
  };
}

export interface ControlPlaneAuditExportPayload {
  source?: string;
  generatedAt: string;
  fromCursor: string;
  toCursor: string;
  entryCount: number;
  entries: ControlPlaneAuditBundleEntry[];
}

export function buildControlPlaneAuditEventInput(input: {
  source: string;
  actor: string;
  correlationId?: string;
  method: string;
  path: string;
  statusCode: number;
  outcome: 'success' | 'failure';
  requestBodyHash: string;
  requestContentLength?: number;
  idempotencyKey?: string;
  permissionScope?: string;
  eventId?: string;
  occurredAt?: string;
}): Omit<ControlPlaneAuditEvent, 'cursor'> {
  return {
    eventId: input.eventId ?? randomUUID(),
    source: input.source,
    occurredAt: input.occurredAt ?? new Date().toISOString(),
    actor: input.actor,
    correlationId: input.correlationId,
    method: input.method.toUpperCase(),
    path: input.path,
    statusCode: input.statusCode,
    outcome: input.outcome,
    requestBodyHash: input.requestBodyHash,
    requestContentLength: input.requestContentLength,
    idempotencyKey: input.idempotencyKey,
    permissionScope: input.permissionScope,
  };
}

export async function buildControlPlaneAuditExport(
  store: ControlPlaneAuditStore,
  afterCursor: string,
  limit: number,
  source?: string,
): Promise<ControlPlaneAuditExportPayload> {
  const normalizedAfterCursor = normalizeControlPlaneAuditCursor(afterCursor, '0');
  const normalizedLimit = Math.max(1, Math.min(Math.floor(limit), 5000));
  const listed = await store.listAfter(normalizedAfterCursor, normalizedLimit);
  const filteredEntries = source
    ? listed.entries.filter((entry) => entry.source === source)
    : listed.entries;
  const entries = filteredEntries.map((entry) => ({
    cursor: entry.cursor,
    eventId: entry.eventId,
    source: entry.source,
    occurredAt: entry.occurredAt,
    actor: entry.actor,
    correlationId: entry.correlationId,
    method: entry.method,
    path: entry.path,
    statusCode: entry.statusCode,
    outcome: entry.outcome,
    requestBodyHash: entry.requestBodyHash,
    requestContentLength: entry.requestContentLength,
    idempotencyKey: entry.idempotencyKey,
    permissionScope: entry.permissionScope,
  }));
  return {
    source,
    generatedAt: new Date().toISOString(),
    fromCursor: normalizedAfterCursor,
    toCursor: listed.nextCursor,
    entryCount: entries.length,
    entries,
  };
}

export async function buildSignedControlPlaneAuditExport(
  store: ControlPlaneAuditStore,
  afterCursor: string,
  limit: number,
  config: ControlPlaneAuditBundleConfig,
): Promise<{ entryCount: number; bundle: SignedControlPlaneAuditBundle }> {
  const payload = await buildControlPlaneAuditExport(
    store,
    afterCursor,
    Math.min(Math.max(1, Math.floor(limit)), config.exportMaxEntries),
    config.sourceId,
  );
  if (payload.entryCount <= 0) {
    throw new Error('control_plane_audit_empty_export');
  }
  const nowMs = Date.now();
  const unsignedBundle: Omit<SignedControlPlaneAuditBundle, 'signature'> = {
    source: config.sourceId,
    bundleId: randomUUID(),
    keyId: config.signingKeyId,
    generatedAt: new Date(nowMs).toISOString(),
    expiresAt: new Date(nowMs + Math.max(1, config.defaultBundleTtlSeconds) * 1000).toISOString(),
    fromCursor: payload.fromCursor,
    toCursor: payload.toCursor,
    entries: payload.entries,
  };
  const bundle = signControlPlaneAuditBundle(unsignedBundle, config.signingSecret || '');
  return {
    entryCount: payload.entryCount,
    bundle,
  };
}

export async function applyControlPlaneAuditImport(
  eventStore: ControlPlaneAuditStore,
  payload: {
    source: string;
    fromCursor: string;
    toCursor?: string;
    entries: ControlPlaneAuditBundleEntry[];
  },
  options: {
    maxEntries: number;
    localSourceId: string;
  },
): Promise<{
  imported: number;
  skipped: number;
  latestImportedCursor: string;
  appended: number;
}> {
  if (payload.source === options.localSourceId) {
    const latestImportedCursor = await eventStore.getImportedCursor(payload.source);
    return {
      imported: 0,
      skipped: payload.entries.length,
      latestImportedCursor,
      appended: 0,
    };
  }

  const maxEntries = Math.max(100, Math.min(Math.floor(options.maxEntries), 500_000));
  const sortedEntries = [...payload.entries]
    .sort((a, b) => {
      const left = parseControlPlaneAuditCursorBigInt(a.cursor);
      const right = parseControlPlaneAuditCursorBigInt(b.cursor);
      if (left === right) return 0;
      return left < right ? -1 : 1;
    });
  let imported = 0;
  let skipped = 0;
  let appended = 0;
  let importedCursor = normalizeControlPlaneAuditCursor(
    await eventStore.getImportedCursor(payload.source),
    '0',
  );
  let importedCursorBig = parseControlPlaneAuditCursorBigInt(importedCursor);

  for (const entry of sortedEntries) {
    if (entry.source !== payload.source) {
      skipped += 1;
      continue;
    }

    const entryCursor = normalizeControlPlaneAuditCursor(entry.cursor, '0');
    const entryCursorBig = parseControlPlaneAuditCursorBigInt(entryCursor);
    if (entryCursorBig <= importedCursorBig) {
      skipped += 1;
      continue;
    }

    imported += 1;
    await eventStore.append({
      eventId: entry.eventId,
      source: entry.source,
      occurredAt: entry.occurredAt,
      actor: `federated:${payload.source}:${entry.actor}`,
      correlationId: entry.correlationId ?? `import:${payload.source}`,
      method: entry.method,
      path: entry.path,
      statusCode: entry.statusCode,
      outcome: entry.outcome,
      requestBodyHash: entry.requestBodyHash,
      requestContentLength: entry.requestContentLength,
      idempotencyKey: entry.idempotencyKey,
      permissionScope: entry.permissionScope,
    }, maxEntries);
    appended += 1;

    const advance = await eventStore.advanceImportedCursor(payload.source, entryCursor);
    importedCursor = advance.currentCursor;
    importedCursorBig = parseControlPlaneAuditCursorBigInt(importedCursor);
  }

  return {
    imported,
    skipped,
    latestImportedCursor: importedCursor,
    appended,
  };
}

export interface UpstreamRoutingPolicyExportPayload {
  source?: string;
  generatedAt: string;
  revision: string;
  upstreamCount: number;
  upstreams: Record<string, UpstreamService>;
}

function normalizeUpstreamPolicyObject(
  upstreams: Record<string, Record<string, unknown>>,
): Record<string, UpstreamService> {
  return upstreams as unknown as Record<string, UpstreamService>;
}

export function buildUpstreamRoutingPolicyExport(
  manager: UpstreamRoutingPolicyManager,
  source?: string,
): UpstreamRoutingPolicyExportPayload {
  const snapshot = manager.getSnapshot();
  return {
    source,
    generatedAt: new Date().toISOString(),
    revision: snapshot.revision,
    upstreamCount: snapshot.upstreamCount,
    upstreams: snapshot.upstreams,
  };
}

export async function buildSignedUpstreamRoutingPolicyExport(
  manager: UpstreamRoutingPolicyManager,
  config: UpstreamRoutingPolicyBundleConfig,
): Promise<{ upstreamCount: number; bundle: SignedUpstreamRoutingPolicyBundle }> {
  const payload = buildUpstreamRoutingPolicyExport(manager, config.sourceId);
  const nowMs = Date.now();
  const unsignedBundle: Omit<SignedUpstreamRoutingPolicyBundle, 'signature'> = {
    source: config.sourceId,
    bundleId: randomUUID(),
    keyId: config.signingKeyId,
    generatedAt: new Date(nowMs).toISOString(),
    expiresAt: new Date(nowMs + Math.max(1, config.defaultBundleTtlSeconds) * 1000).toISOString(),
    revision: payload.revision,
    upstreams: payload.upstreams as unknown as Record<string, Record<string, unknown>>,
  };
  const bundle = signUpstreamRoutingPolicyBundle(unsignedBundle, config.signingSecret || '');
  return {
    upstreamCount: payload.upstreamCount,
    bundle,
  };
}

export function applyUpstreamRoutingPolicyImport(
  manager: UpstreamRoutingPolicyManager,
  payload: Pick<UpstreamRoutingPolicyImportRequest, 'revision' | 'upstreams'>,
): (
  | {
      ok: true;
      changed: boolean;
      skipped: boolean;
      previousRevision: string;
      revision: string;
      changedUpstreams: string[];
    }
  | {
      ok: false;
      issues: UpstreamRoutingPolicyIssue[];
    }
) {
  const candidate = normalizeUpstreamPolicyObject(payload.upstreams);
  if (!manager.isRevisionCompatible(payload.revision, candidate)) {
    return {
      ok: false,
      issues: [{
        path: 'revision',
        message: 'revision does not match provided upstream policy snapshot',
      }],
    };
  }

  const result = manager.replaceAll(candidate);
  if (!result.ok) {
    return {
      ok: false,
      issues: result.issues,
    };
  }
  return {
    ok: true,
    changed: result.changed,
    skipped: !result.changed,
    previousRevision: result.previousRevision,
    revision: result.revision,
    changedUpstreams: result.changedUpstreams,
  };
}

export interface RoutePolicyExportPayload {
  source?: string;
  generatedAt: string;
  revision: string;
  routeCount: number;
  routes: RouteConfig[];
}

function normalizeRoutePolicyArray(
  routes: Array<Record<string, unknown>>,
): RouteConfig[] {
  return routes as unknown as RouteConfig[];
}

export function buildRoutePolicyExport(
  manager: RoutePolicyManager,
  source?: string,
): RoutePolicyExportPayload {
  const snapshot = manager.getSnapshot();
  return {
    source,
    generatedAt: new Date().toISOString(),
    revision: snapshot.revision,
    routeCount: snapshot.routeCount,
    routes: snapshot.routes,
  };
}

export async function buildSignedRoutePolicyExport(
  manager: RoutePolicyManager,
  config: RoutePolicyBundleConfig,
): Promise<{ routeCount: number; bundle: SignedRoutePolicyBundle }> {
  const payload = buildRoutePolicyExport(manager, config.sourceId);
  const nowMs = Date.now();
  const unsignedBundle: Omit<SignedRoutePolicyBundle, 'signature'> = {
    source: config.sourceId,
    bundleId: randomUUID(),
    keyId: config.signingKeyId,
    generatedAt: new Date(nowMs).toISOString(),
    expiresAt: new Date(nowMs + Math.max(1, config.defaultBundleTtlSeconds) * 1000).toISOString(),
    revision: payload.revision,
    routes: payload.routes as unknown as Array<Record<string, unknown>>,
  };
  const bundle = signRoutePolicyBundle(unsignedBundle, config.signingSecret || '');
  return {
    routeCount: payload.routeCount,
    bundle,
  };
}

export function applyRoutePolicyImport(
  manager: RoutePolicyManager,
  payload: Pick<RoutePolicyImportRequest, 'revision' | 'routes'>,
): (
  | {
      ok: true;
      changed: boolean;
      skipped: boolean;
      previousRevision: string;
      revision: string;
      changedRoutes: string[];
    }
  | {
      ok: false;
      issues: RoutePolicyIssue[];
    }
) {
  const candidate = normalizeRoutePolicyArray(payload.routes);
  if (!manager.isRevisionCompatible(payload.revision, candidate)) {
    return {
      ok: false,
      issues: [{
        path: 'revision',
        message: 'revision does not match provided route policy snapshot',
      }],
    };
  }

  const result = manager.replaceAll(candidate);
  if (!result.ok) {
    return {
      ok: false,
      issues: result.issues,
    };
  }
  return {
    ok: true,
    changed: result.changed,
    skipped: !result.changed,
    previousRevision: result.previousRevision,
    revision: result.revision,
    changedRoutes: result.changedRoutes,
  };
}

function resolveInternalMutationActor(req: Request): string {
  return String(
    req.headers['x-internal-caller'] ??
    req.headers['x-caller-id'] ??
    'unknown',
  );
}

function resolveInternalCorrelationId(req: Request): string {
  return String(req.headers['x-correlation-id'] ?? 'unknown');
}

async function appendEdgeInvalidationEventSafe(
  store: EdgeInvalidationEventStore,
  payload: Omit<EdgeInvalidationEvent, 'cursor'>,
  maxEntries: number,
): Promise<{ eventLogged: true; eventCursor: string } | { eventLogged: false; eventCursor: null }> {
  try {
    const event = await store.append(payload, maxEntries);
    return { eventLogged: true, eventCursor: event.cursor };
  } catch {
    return { eventLogged: false, eventCursor: null };
  }
}

async function appendVersionSetInvalidationEventsSafe(
  store: EdgeInvalidationEventStore,
  input: {
    source: string;
    actor: string;
    correlationId: string;
    applied: Array<{ routePath: string; currentVersion: string }>;
  },
  maxEntries: number,
): Promise<{ eventLogged: boolean; eventCursors: string[] }> {
  try {
    const cursors: string[] = [];
    for (const entry of input.applied) {
      const event = await store.append(
        buildEdgeInvalidationEventInput({
          source: input.source,
          actor: input.actor,
          correlationId: input.correlationId,
          kind: 'version_set',
          payload: {
            routePath: entry.routePath,
            version: entry.currentVersion,
          },
        }),
        maxEntries,
      );
      cursors.push(event.cursor);
    }
    return { eventLogged: true, eventCursors: cursors };
  } catch {
    return { eventLogged: false, eventCursors: [] };
  }
}

export interface SecurityControlsHistoryExportPayload {
  generatedAt: string;
  entryCount: number;
  entries: SecurityControlsHistoryBundleEntry[];
}

export async function buildSecurityControlsHistoryExport(
  auditStore: SecurityControlsAuditStore,
  limit: number,
): Promise<SecurityControlsHistoryExportPayload> {
  const history = await auditStore.listAll();
  const normalizedLimit = Math.max(1, Math.min(Math.floor(limit), 5000));
  const start = Math.max(0, history.entries.length - normalizedLimit);
  const entries = history.entries.slice(start).map((entry) => ({
    changedAt: entry.changedAt,
    actor: entry.actor,
    correlationId: entry.correlationId,
    patch: entry.patch,
    snapshotHash: entry.snapshotHash,
  }));
  return {
    generatedAt: new Date().toISOString(),
    entryCount: entries.length,
    entries,
  };
}

export async function buildSignedSecurityControlsHistoryExport(
  auditStore: SecurityControlsAuditStore,
  limit: number,
  config: SecurityControlsHistoryBundleConfig,
): Promise<{ entryCount: number; bundle: SignedSecurityControlsHistoryBundle }> {
  const payload = await buildSecurityControlsHistoryExport(
    auditStore,
    Math.min(Math.max(1, Math.floor(limit)), config.exportMaxEntries),
  );
  const nowMs = Date.now();
  const unsignedBundle: Omit<SignedSecurityControlsHistoryBundle, 'signature'> = {
    source: config.sourceId,
    bundleId: randomUUID(),
    keyId: config.signingKeyId,
    generatedAt: new Date(nowMs).toISOString(),
    expiresAt: new Date(nowMs + Math.max(1, config.defaultBundleTtlSeconds) * 1000).toISOString(),
    entries: payload.entries,
  };
  const bundle = signSecurityControlsHistoryBundle(unsignedBundle, config.signingSecret || '');
  return {
    entryCount: payload.entryCount,
    bundle,
  };
}

export async function applySecurityControlsHistoryImport(
  auditStore: SecurityControlsAuditStore,
  payload: {
    source: string;
    entries: SecurityControlsHistoryBundleEntry[];
  },
  options: {
    signingSecret: string;
    maxEntries: number;
    fallbackSnapshotHash: string;
  },
): Promise<{ imported: number; skipped: number; importedIds: string[] }> {
  let chain = await auditStore.getChainPointers();
  let imported = 0;
  let skipped = 0;
  const importedIds: string[] = [];

  for (const bundleEntry of payload.entries) {
    const patchParsed = SecurityControlsPatchSchema.safeParse(bundleEntry.patch);
    if (!patchParsed.success) {
      skipped += 1;
      continue;
    }

    const previousEntryHash = chain.latestEntryHash ?? chain.anchorHash;
    const auditEntry = buildSecurityControlsAuditEntry({
      patch: patchParsed.data,
      snapshotHash: bundleEntry.snapshotHash ?? options.fallbackSnapshotHash,
      previousEntryHash,
      actor: `federated:${payload.source}:${bundleEntry.actor}`,
      correlationId: bundleEntry.correlationId ?? `import:${payload.source}`,
      signingSecret: options.signingSecret,
      changedAt: bundleEntry.changedAt,
    });
    chain = await auditStore.append(auditEntry, options.maxEntries);
    imported += 1;
    importedIds.push(auditEntry.id);
  }

  return { imported, skipped, importedIds };
}

function resolveAbuseIntelConfig(options?: InternalRoutesOptions): AbuseIntelConfig {
  return {
    ...DEFAULT_ABUSE_INTEL_CONFIG,
    ...(options?.abuseIntel ?? {}),
  };
}

function parseBooleanEnv(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (!raw) return fallback;
  const normalized = raw.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

function parseIntegerEnv(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(parsed, max));
}

function parseCsvEnv(name: string): string[] {
  const raw = process.env[name];
  if (!raw) return [];
  return raw
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
}

function parseKeyringEnv(raw: string | undefined): Record<string, string> {
  if (!raw) return {};
  const keyring: Record<string, string> = {};
  const items = raw
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  for (const item of items) {
    const sep = item.includes(':') ? ':' : item.includes('=') ? '=' : '';
    if (!sep) continue;
    const idx = item.indexOf(sep);
    if (idx <= 0) continue;
    const key = item.slice(0, idx).trim();
    const secret = item.slice(idx + 1).trim();
    if (!key || !secret) continue;
    keyring[key] = secret;
  }
  return keyring;
}

function parseJsonEnv<T>(name: string, fallback: T): T {
  const raw = process.env[name];
  if (!raw || !raw.trim()) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function resolveSecurityControlsHistoryBundleConfig(
  signingSecretFallback: string,
): SecurityControlsHistoryBundleConfig {
  const sourceId = String(
    process.env['SECURITY_CONTROLS_HISTORY_BUNDLE_SOURCE_ID'] ??
      DEFAULT_SECURITY_CONTROLS_HISTORY_BUNDLE_CONFIG.sourceId,
  ).trim() || DEFAULT_SECURITY_CONTROLS_HISTORY_BUNDLE_CONFIG.sourceId;
  const allowedSourcesFromEnv = parseCsvEnv('SECURITY_CONTROLS_HISTORY_BUNDLE_ALLOWED_SOURCES');
  const allowedKeyIdsFromEnv = parseCsvEnv('SECURITY_CONTROLS_HISTORY_BUNDLE_ALLOWED_KEY_IDS');
  const signingSecret = String(
    process.env['SECURITY_CONTROLS_HISTORY_BUNDLE_SIGNING_SECRET'] ?? signingSecretFallback,
  ).trim();
  const keyring = parseKeyringEnv(process.env['SECURITY_CONTROLS_HISTORY_BUNDLE_KEYRING']);

  const config: SecurityControlsHistoryBundleConfig = {
    sourceId,
    exportMaxEntries: parseIntegerEnv(
      'SECURITY_CONTROLS_HISTORY_BUNDLE_EXPORT_MAX_ENTRIES',
      DEFAULT_SECURITY_CONTROLS_HISTORY_BUNDLE_CONFIG.exportMaxEntries,
      1,
      5000,
    ),
    defaultBundleTtlSeconds: parseIntegerEnv(
      'SECURITY_CONTROLS_HISTORY_BUNDLE_DEFAULT_TTL_SECONDS',
      DEFAULT_SECURITY_CONTROLS_HISTORY_BUNDLE_CONFIG.defaultBundleTtlSeconds,
      1,
      60 * 60 * 24,
    ),
    signExports: parseBooleanEnv(
      'SECURITY_CONTROLS_HISTORY_BUNDLE_SIGN_EXPORTS',
      DEFAULT_SECURITY_CONTROLS_HISTORY_BUNDLE_CONFIG.signExports,
    ),
    requireSignedImports: parseBooleanEnv(
      'SECURITY_CONTROLS_HISTORY_BUNDLE_REQUIRE_SIGNED_IMPORTS',
      DEFAULT_SECURITY_CONTROLS_HISTORY_BUNDLE_CONFIG.requireSignedImports,
    ),
    signingKeyId: String(
      process.env['SECURITY_CONTROLS_HISTORY_BUNDLE_SIGNING_KEY_ID'] ??
        DEFAULT_SECURITY_CONTROLS_HISTORY_BUNDLE_CONFIG.signingKeyId,
    ).trim() || DEFAULT_SECURITY_CONTROLS_HISTORY_BUNDLE_CONFIG.signingKeyId,
    signingSecret,
    allowedSources: allowedSourcesFromEnv.length > 0 ? allowedSourcesFromEnv : [sourceId],
    allowedKeyIds:
      allowedKeyIdsFromEnv.length > 0
        ? allowedKeyIdsFromEnv
        : DEFAULT_SECURITY_CONTROLS_HISTORY_BUNDLE_CONFIG.allowedKeyIds,
    keyring,
    replayProtectionEnabled: parseBooleanEnv(
      'SECURITY_CONTROLS_HISTORY_BUNDLE_REPLAY_PROTECTION_ENABLED',
      DEFAULT_SECURITY_CONTROLS_HISTORY_BUNDLE_CONFIG.replayProtectionEnabled,
    ),
    replayCacheMaxEntries: parseIntegerEnv(
      'SECURITY_CONTROLS_HISTORY_BUNDLE_REPLAY_CACHE_MAX_ENTRIES',
      DEFAULT_SECURITY_CONTROLS_HISTORY_BUNDLE_CONFIG.replayCacheMaxEntries,
      1,
      500_000,
    ),
    maxSkewSeconds: parseIntegerEnv(
      'SECURITY_CONTROLS_HISTORY_BUNDLE_MAX_SKEW_SECONDS',
      DEFAULT_SECURITY_CONTROLS_HISTORY_BUNDLE_CONFIG.maxSkewSeconds,
      1,
      24 * 60 * 60,
    ),
  };

  if (Object.keys(config.keyring).length === 0 && config.signingSecret && config.allowedKeyIds.length > 0) {
    const fallbackKeyring: Record<string, string> = {};
    for (const keyId of config.allowedKeyIds) {
      fallbackKeyring[keyId] = config.signingSecret;
    }
    config.keyring = fallbackKeyring;
  }

  return config;
}

function resolveEdgeCacheVersionBundleConfig(): EdgeCacheVersionBundleConfig {
  const sourceId = String(
    process.env['EDGE_CACHE_VERSION_BUNDLE_SOURCE_ID'] ??
      DEFAULT_EDGE_CACHE_VERSION_BUNDLE_CONFIG.sourceId,
  ).trim() || DEFAULT_EDGE_CACHE_VERSION_BUNDLE_CONFIG.sourceId;
  const allowedSourcesFromEnv = parseCsvEnv('EDGE_CACHE_VERSION_BUNDLE_ALLOWED_SOURCES');
  const allowedKeyIdsFromEnv = parseCsvEnv('EDGE_CACHE_VERSION_BUNDLE_ALLOWED_KEY_IDS');
  const signingSecret = String(
    process.env['EDGE_CACHE_VERSION_BUNDLE_SIGNING_SECRET'] ??
      DEFAULT_EDGE_CACHE_VERSION_BUNDLE_CONFIG.signingSecret,
  ).trim();
  const keyring = parseKeyringEnv(process.env['EDGE_CACHE_VERSION_BUNDLE_KEYRING']);

  const config: EdgeCacheVersionBundleConfig = {
    sourceId,
    exportMaxEntries: parseIntegerEnv(
      'EDGE_CACHE_VERSION_BUNDLE_EXPORT_MAX_ENTRIES',
      DEFAULT_EDGE_CACHE_VERSION_BUNDLE_CONFIG.exportMaxEntries,
      1,
      5000,
    ),
    defaultBundleTtlSeconds: parseIntegerEnv(
      'EDGE_CACHE_VERSION_BUNDLE_DEFAULT_TTL_SECONDS',
      DEFAULT_EDGE_CACHE_VERSION_BUNDLE_CONFIG.defaultBundleTtlSeconds,
      1,
      60 * 60 * 24,
    ),
    signExports: parseBooleanEnv(
      'EDGE_CACHE_VERSION_BUNDLE_SIGN_EXPORTS',
      DEFAULT_EDGE_CACHE_VERSION_BUNDLE_CONFIG.signExports,
    ),
    requireSignedImports: parseBooleanEnv(
      'EDGE_CACHE_VERSION_BUNDLE_REQUIRE_SIGNED_IMPORTS',
      DEFAULT_EDGE_CACHE_VERSION_BUNDLE_CONFIG.requireSignedImports,
    ),
    signingKeyId: String(
      process.env['EDGE_CACHE_VERSION_BUNDLE_SIGNING_KEY_ID'] ??
        DEFAULT_EDGE_CACHE_VERSION_BUNDLE_CONFIG.signingKeyId,
    ).trim() || DEFAULT_EDGE_CACHE_VERSION_BUNDLE_CONFIG.signingKeyId,
    signingSecret,
    allowedSources: allowedSourcesFromEnv.length > 0 ? allowedSourcesFromEnv : [sourceId],
    allowedKeyIds:
      allowedKeyIdsFromEnv.length > 0
        ? allowedKeyIdsFromEnv
        : DEFAULT_EDGE_CACHE_VERSION_BUNDLE_CONFIG.allowedKeyIds,
    keyring,
    replayProtectionEnabled: parseBooleanEnv(
      'EDGE_CACHE_VERSION_BUNDLE_REPLAY_PROTECTION_ENABLED',
      DEFAULT_EDGE_CACHE_VERSION_BUNDLE_CONFIG.replayProtectionEnabled,
    ),
    replayCacheMaxEntries: parseIntegerEnv(
      'EDGE_CACHE_VERSION_BUNDLE_REPLAY_CACHE_MAX_ENTRIES',
      DEFAULT_EDGE_CACHE_VERSION_BUNDLE_CONFIG.replayCacheMaxEntries,
      1,
      500_000,
    ),
    maxSkewSeconds: parseIntegerEnv(
      'EDGE_CACHE_VERSION_BUNDLE_MAX_SKEW_SECONDS',
      DEFAULT_EDGE_CACHE_VERSION_BUNDLE_CONFIG.maxSkewSeconds,
      1,
      24 * 60 * 60,
    ),
  };

  if (Object.keys(config.keyring).length === 0 && config.signingSecret && config.allowedKeyIds.length > 0) {
    const fallbackKeyring: Record<string, string> = {};
    for (const keyId of config.allowedKeyIds) {
      fallbackKeyring[keyId] = config.signingSecret;
    }
    config.keyring = fallbackKeyring;
  }

  return config;
}

function resolveEdgeInvalidationBundleConfig(): EdgeInvalidationBundleConfig {
  const sourceId = String(
    process.env['EDGE_INVALIDATION_BUNDLE_SOURCE_ID'] ??
      DEFAULT_EDGE_INVALIDATION_BUNDLE_CONFIG.sourceId,
  ).trim() || DEFAULT_EDGE_INVALIDATION_BUNDLE_CONFIG.sourceId;
  const allowedSourcesFromEnv = parseCsvEnv('EDGE_INVALIDATION_BUNDLE_ALLOWED_SOURCES');
  const allowedKeyIdsFromEnv = parseCsvEnv('EDGE_INVALIDATION_BUNDLE_ALLOWED_KEY_IDS');
  const signingSecret = String(
    process.env['EDGE_INVALIDATION_BUNDLE_SIGNING_SECRET'] ??
      DEFAULT_EDGE_INVALIDATION_BUNDLE_CONFIG.signingSecret,
  ).trim();
  const keyring = parseKeyringEnv(process.env['EDGE_INVALIDATION_BUNDLE_KEYRING']);

  const config: EdgeInvalidationBundleConfig = {
    sourceId,
    exportMaxEntries: parseIntegerEnv(
      'EDGE_INVALIDATION_BUNDLE_EXPORT_MAX_ENTRIES',
      DEFAULT_EDGE_INVALIDATION_BUNDLE_CONFIG.exportMaxEntries,
      1,
      5000,
    ),
    defaultBundleTtlSeconds: parseIntegerEnv(
      'EDGE_INVALIDATION_BUNDLE_DEFAULT_TTL_SECONDS',
      DEFAULT_EDGE_INVALIDATION_BUNDLE_CONFIG.defaultBundleTtlSeconds,
      1,
      60 * 60 * 24,
    ),
    signExports: parseBooleanEnv(
      'EDGE_INVALIDATION_BUNDLE_SIGN_EXPORTS',
      DEFAULT_EDGE_INVALIDATION_BUNDLE_CONFIG.signExports,
    ),
    requireSignedImports: parseBooleanEnv(
      'EDGE_INVALIDATION_BUNDLE_REQUIRE_SIGNED_IMPORTS',
      DEFAULT_EDGE_INVALIDATION_BUNDLE_CONFIG.requireSignedImports,
    ),
    signingKeyId: String(
      process.env['EDGE_INVALIDATION_BUNDLE_SIGNING_KEY_ID'] ??
        DEFAULT_EDGE_INVALIDATION_BUNDLE_CONFIG.signingKeyId,
    ).trim() || DEFAULT_EDGE_INVALIDATION_BUNDLE_CONFIG.signingKeyId,
    signingSecret,
    allowedSources: allowedSourcesFromEnv.length > 0 ? allowedSourcesFromEnv : [sourceId],
    allowedKeyIds:
      allowedKeyIdsFromEnv.length > 0
        ? allowedKeyIdsFromEnv
        : DEFAULT_EDGE_INVALIDATION_BUNDLE_CONFIG.allowedKeyIds,
    keyring,
    replayProtectionEnabled: parseBooleanEnv(
      'EDGE_INVALIDATION_BUNDLE_REPLAY_PROTECTION_ENABLED',
      DEFAULT_EDGE_INVALIDATION_BUNDLE_CONFIG.replayProtectionEnabled,
    ),
    replayCacheMaxEntries: parseIntegerEnv(
      'EDGE_INVALIDATION_BUNDLE_REPLAY_CACHE_MAX_ENTRIES',
      DEFAULT_EDGE_INVALIDATION_BUNDLE_CONFIG.replayCacheMaxEntries,
      1,
      500_000,
    ),
    maxSkewSeconds: parseIntegerEnv(
      'EDGE_INVALIDATION_BUNDLE_MAX_SKEW_SECONDS',
      DEFAULT_EDGE_INVALIDATION_BUNDLE_CONFIG.maxSkewSeconds,
      1,
      24 * 60 * 60,
    ),
  };

  if (Object.keys(config.keyring).length === 0 && config.signingSecret && config.allowedKeyIds.length > 0) {
    const fallbackKeyring: Record<string, string> = {};
    for (const keyId of config.allowedKeyIds) {
      fallbackKeyring[keyId] = config.signingSecret;
    }
    config.keyring = fallbackKeyring;
  }

  return config;
}

function resolveControlPlaneAuditBundleConfig(): ControlPlaneAuditBundleConfig {
  const sourceId = String(
    process.env['CONTROL_PLANE_AUDIT_BUNDLE_SOURCE_ID'] ??
      DEFAULT_CONTROL_PLANE_AUDIT_BUNDLE_CONFIG.sourceId,
  ).trim() || DEFAULT_CONTROL_PLANE_AUDIT_BUNDLE_CONFIG.sourceId;
  const allowedSourcesFromEnv = parseCsvEnv('CONTROL_PLANE_AUDIT_BUNDLE_ALLOWED_SOURCES');
  const allowedKeyIdsFromEnv = parseCsvEnv('CONTROL_PLANE_AUDIT_BUNDLE_ALLOWED_KEY_IDS');
  const signingSecret = String(
    process.env['CONTROL_PLANE_AUDIT_BUNDLE_SIGNING_SECRET'] ??
      DEFAULT_CONTROL_PLANE_AUDIT_BUNDLE_CONFIG.signingSecret,
  ).trim();
  const keyring = parseKeyringEnv(process.env['CONTROL_PLANE_AUDIT_BUNDLE_KEYRING']);

  const config: ControlPlaneAuditBundleConfig = {
    sourceId,
    exportMaxEntries: parseIntegerEnv(
      'CONTROL_PLANE_AUDIT_BUNDLE_EXPORT_MAX_ENTRIES',
      DEFAULT_CONTROL_PLANE_AUDIT_BUNDLE_CONFIG.exportMaxEntries,
      1,
      5000,
    ),
    defaultBundleTtlSeconds: parseIntegerEnv(
      'CONTROL_PLANE_AUDIT_BUNDLE_DEFAULT_TTL_SECONDS',
      DEFAULT_CONTROL_PLANE_AUDIT_BUNDLE_CONFIG.defaultBundleTtlSeconds,
      1,
      60 * 60 * 24,
    ),
    signExports: parseBooleanEnv(
      'CONTROL_PLANE_AUDIT_BUNDLE_SIGN_EXPORTS',
      DEFAULT_CONTROL_PLANE_AUDIT_BUNDLE_CONFIG.signExports,
    ),
    requireSignedImports: parseBooleanEnv(
      'CONTROL_PLANE_AUDIT_BUNDLE_REQUIRE_SIGNED_IMPORTS',
      DEFAULT_CONTROL_PLANE_AUDIT_BUNDLE_CONFIG.requireSignedImports,
    ),
    signingKeyId: String(
      process.env['CONTROL_PLANE_AUDIT_BUNDLE_SIGNING_KEY_ID'] ??
        DEFAULT_CONTROL_PLANE_AUDIT_BUNDLE_CONFIG.signingKeyId,
    ).trim() || DEFAULT_CONTROL_PLANE_AUDIT_BUNDLE_CONFIG.signingKeyId,
    signingSecret,
    allowedSources: allowedSourcesFromEnv.length > 0 ? allowedSourcesFromEnv : [sourceId],
    allowedKeyIds:
      allowedKeyIdsFromEnv.length > 0
        ? allowedKeyIdsFromEnv
        : DEFAULT_CONTROL_PLANE_AUDIT_BUNDLE_CONFIG.allowedKeyIds,
    keyring,
    replayProtectionEnabled: parseBooleanEnv(
      'CONTROL_PLANE_AUDIT_BUNDLE_REPLAY_PROTECTION_ENABLED',
      DEFAULT_CONTROL_PLANE_AUDIT_BUNDLE_CONFIG.replayProtectionEnabled,
    ),
    replayCacheMaxEntries: parseIntegerEnv(
      'CONTROL_PLANE_AUDIT_BUNDLE_REPLAY_CACHE_MAX_ENTRIES',
      DEFAULT_CONTROL_PLANE_AUDIT_BUNDLE_CONFIG.replayCacheMaxEntries,
      1,
      500_000,
    ),
    maxSkewSeconds: parseIntegerEnv(
      'CONTROL_PLANE_AUDIT_BUNDLE_MAX_SKEW_SECONDS',
      DEFAULT_CONTROL_PLANE_AUDIT_BUNDLE_CONFIG.maxSkewSeconds,
      1,
      24 * 60 * 60,
    ),
  };

  if (Object.keys(config.keyring).length === 0 && config.signingSecret && config.allowedKeyIds.length > 0) {
    const fallbackKeyring: Record<string, string> = {};
    for (const keyId of config.allowedKeyIds) {
      fallbackKeyring[keyId] = config.signingSecret;
    }
    config.keyring = fallbackKeyring;
  }

  return config;
}

function resolveUpstreamRoutingPolicyBundleConfig(): UpstreamRoutingPolicyBundleConfig {
  const sourceId = String(
    process.env['UPSTREAM_ROUTING_POLICY_BUNDLE_SOURCE_ID'] ??
      DEFAULT_UPSTREAM_ROUTING_POLICY_BUNDLE_CONFIG.sourceId,
  ).trim() || DEFAULT_UPSTREAM_ROUTING_POLICY_BUNDLE_CONFIG.sourceId;
  const allowedSourcesFromEnv = parseCsvEnv('UPSTREAM_ROUTING_POLICY_BUNDLE_ALLOWED_SOURCES');
  const allowedKeyIdsFromEnv = parseCsvEnv('UPSTREAM_ROUTING_POLICY_BUNDLE_ALLOWED_KEY_IDS');
  const signingSecret = String(
    process.env['UPSTREAM_ROUTING_POLICY_BUNDLE_SIGNING_SECRET'] ??
      DEFAULT_UPSTREAM_ROUTING_POLICY_BUNDLE_CONFIG.signingSecret,
  ).trim();
  const keyring = parseKeyringEnv(process.env['UPSTREAM_ROUTING_POLICY_BUNDLE_KEYRING']);

  const config: UpstreamRoutingPolicyBundleConfig = {
    sourceId,
    defaultBundleTtlSeconds: parseIntegerEnv(
      'UPSTREAM_ROUTING_POLICY_BUNDLE_DEFAULT_TTL_SECONDS',
      DEFAULT_UPSTREAM_ROUTING_POLICY_BUNDLE_CONFIG.defaultBundleTtlSeconds,
      1,
      60 * 60 * 24,
    ),
    signExports: parseBooleanEnv(
      'UPSTREAM_ROUTING_POLICY_BUNDLE_SIGN_EXPORTS',
      DEFAULT_UPSTREAM_ROUTING_POLICY_BUNDLE_CONFIG.signExports,
    ),
    requireSignedImports: parseBooleanEnv(
      'UPSTREAM_ROUTING_POLICY_BUNDLE_REQUIRE_SIGNED_IMPORTS',
      DEFAULT_UPSTREAM_ROUTING_POLICY_BUNDLE_CONFIG.requireSignedImports,
    ),
    signingKeyId: String(
      process.env['UPSTREAM_ROUTING_POLICY_BUNDLE_SIGNING_KEY_ID'] ??
        DEFAULT_UPSTREAM_ROUTING_POLICY_BUNDLE_CONFIG.signingKeyId,
    ).trim() || DEFAULT_UPSTREAM_ROUTING_POLICY_BUNDLE_CONFIG.signingKeyId,
    signingSecret,
    allowedSources: allowedSourcesFromEnv.length > 0 ? allowedSourcesFromEnv : [sourceId],
    allowedKeyIds:
      allowedKeyIdsFromEnv.length > 0
        ? allowedKeyIdsFromEnv
        : DEFAULT_UPSTREAM_ROUTING_POLICY_BUNDLE_CONFIG.allowedKeyIds,
    keyring,
    replayProtectionEnabled: parseBooleanEnv(
      'UPSTREAM_ROUTING_POLICY_BUNDLE_REPLAY_PROTECTION_ENABLED',
      DEFAULT_UPSTREAM_ROUTING_POLICY_BUNDLE_CONFIG.replayProtectionEnabled,
    ),
    replayCacheMaxEntries: parseIntegerEnv(
      'UPSTREAM_ROUTING_POLICY_BUNDLE_REPLAY_CACHE_MAX_ENTRIES',
      DEFAULT_UPSTREAM_ROUTING_POLICY_BUNDLE_CONFIG.replayCacheMaxEntries,
      1,
      500_000,
    ),
    maxSkewSeconds: parseIntegerEnv(
      'UPSTREAM_ROUTING_POLICY_BUNDLE_MAX_SKEW_SECONDS',
      DEFAULT_UPSTREAM_ROUTING_POLICY_BUNDLE_CONFIG.maxSkewSeconds,
      1,
      24 * 60 * 60,
    ),
  };

  if (Object.keys(config.keyring).length === 0 && config.signingSecret && config.allowedKeyIds.length > 0) {
    const fallbackKeyring: Record<string, string> = {};
    for (const keyId of config.allowedKeyIds) {
      fallbackKeyring[keyId] = config.signingSecret;
    }
    config.keyring = fallbackKeyring;
  }

  return config;
}

function resolveRoutePolicyBundleConfig(): RoutePolicyBundleConfig {
  const sourceId = String(
    process.env['ROUTE_POLICY_BUNDLE_SOURCE_ID'] ??
      DEFAULT_ROUTE_POLICY_BUNDLE_CONFIG.sourceId,
  ).trim() || DEFAULT_ROUTE_POLICY_BUNDLE_CONFIG.sourceId;
  const allowedSourcesFromEnv = parseCsvEnv('ROUTE_POLICY_BUNDLE_ALLOWED_SOURCES');
  const allowedKeyIdsFromEnv = parseCsvEnv('ROUTE_POLICY_BUNDLE_ALLOWED_KEY_IDS');
  const signingSecret = String(
    process.env['ROUTE_POLICY_BUNDLE_SIGNING_SECRET'] ??
      DEFAULT_ROUTE_POLICY_BUNDLE_CONFIG.signingSecret,
  ).trim();
  const keyring = parseKeyringEnv(process.env['ROUTE_POLICY_BUNDLE_KEYRING']);

  const config: RoutePolicyBundleConfig = {
    sourceId,
    defaultBundleTtlSeconds: parseIntegerEnv(
      'ROUTE_POLICY_BUNDLE_DEFAULT_TTL_SECONDS',
      DEFAULT_ROUTE_POLICY_BUNDLE_CONFIG.defaultBundleTtlSeconds,
      1,
      60 * 60 * 24,
    ),
    signExports: parseBooleanEnv(
      'ROUTE_POLICY_BUNDLE_SIGN_EXPORTS',
      DEFAULT_ROUTE_POLICY_BUNDLE_CONFIG.signExports,
    ),
    requireSignedImports: parseBooleanEnv(
      'ROUTE_POLICY_BUNDLE_REQUIRE_SIGNED_IMPORTS',
      DEFAULT_ROUTE_POLICY_BUNDLE_CONFIG.requireSignedImports,
    ),
    signingKeyId: String(
      process.env['ROUTE_POLICY_BUNDLE_SIGNING_KEY_ID'] ??
        DEFAULT_ROUTE_POLICY_BUNDLE_CONFIG.signingKeyId,
    ).trim() || DEFAULT_ROUTE_POLICY_BUNDLE_CONFIG.signingKeyId,
    signingSecret,
    allowedSources: allowedSourcesFromEnv.length > 0 ? allowedSourcesFromEnv : [sourceId],
    allowedKeyIds:
      allowedKeyIdsFromEnv.length > 0
        ? allowedKeyIdsFromEnv
        : DEFAULT_ROUTE_POLICY_BUNDLE_CONFIG.allowedKeyIds,
    keyring,
    replayProtectionEnabled: parseBooleanEnv(
      'ROUTE_POLICY_BUNDLE_REPLAY_PROTECTION_ENABLED',
      DEFAULT_ROUTE_POLICY_BUNDLE_CONFIG.replayProtectionEnabled,
    ),
    replayCacheMaxEntries: parseIntegerEnv(
      'ROUTE_POLICY_BUNDLE_REPLAY_CACHE_MAX_ENTRIES',
      DEFAULT_ROUTE_POLICY_BUNDLE_CONFIG.replayCacheMaxEntries,
      1,
      500_000,
    ),
    maxSkewSeconds: parseIntegerEnv(
      'ROUTE_POLICY_BUNDLE_MAX_SKEW_SECONDS',
      DEFAULT_ROUTE_POLICY_BUNDLE_CONFIG.maxSkewSeconds,
      1,
      24 * 60 * 60,
    ),
  };

  if (Object.keys(config.keyring).length === 0 && config.signingSecret && config.allowedKeyIds.length > 0) {
    const fallbackKeyring: Record<string, string> = {};
    for (const keyId of config.allowedKeyIds) {
      fallbackKeyring[keyId] = config.signingSecret;
    }
    config.keyring = fallbackKeyring;
  }

  return config;
}

function resolveInternalMutationIdempotencyConfig(): InternalMutationIdempotencyConfig {
  return {
    enabled: parseBooleanEnv(
      'INTERNAL_MUTATION_IDEMPOTENCY_ENABLED',
      DEFAULT_INTERNAL_MUTATION_IDEMPOTENCY_CONFIG.enabled,
    ),
    ttlSeconds: parseIntegerEnv(
      'INTERNAL_MUTATION_IDEMPOTENCY_TTL_SECONDS',
      DEFAULT_INTERNAL_MUTATION_IDEMPOTENCY_CONFIG.ttlSeconds,
      1,
      24 * 60 * 60,
    ),
    replayCacheMaxEntries: parseIntegerEnv(
      'INTERNAL_MUTATION_IDEMPOTENCY_REPLAY_CACHE_MAX_ENTRIES',
      DEFAULT_INTERNAL_MUTATION_IDEMPOTENCY_CONFIG.replayCacheMaxEntries,
      1,
      500_000,
    ),
  };
}

function normalizeRoleList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value
      .map((item) => String(item).trim())
      .filter(Boolean);
  }
  if (typeof value === 'string') {
    return value
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean);
  }
  return [];
}

function resolveInternalControlPlaneConfig(): InternalControlPlaneConfig {
  const callerRolesRaw = parseJsonEnv<Record<string, unknown>>(
    'INTERNAL_CONTROL_PLANE_CALLER_ROLES_JSON',
    {},
  );
  const callerRoles: Record<string, string[]> = {};
  for (const [caller, rawRoles] of Object.entries(callerRolesRaw)) {
    const normalizedCaller = caller.trim().toLowerCase();
    if (!normalizedCaller) continue;
    const roles = normalizeRoleList(rawRoles);
    if (roles.length > 0) {
      callerRoles[normalizedCaller] = roles;
    }
  }

  const apiKeysRaw = parseJsonEnv<Array<{
    id?: unknown;
    secret?: unknown;
    scopes?: unknown;
  }>>('INTERNAL_CONTROL_PLANE_API_KEYS_JSON', []);
  const apiKeys: Record<string, InternalControlPlaneApiKeyConfig> = {};
  for (const item of apiKeysRaw) {
    const id = String(item?.id ?? '').trim();
    const secret = String(item?.secret ?? '').trim();
    if (!id || !secret) continue;
    const scopes = normalizeRoleList(item?.scopes);
    apiKeys[id] = {
      secret,
      scopes: scopes.length > 0 ? scopes : ['*'],
    };
  }

  return {
    enabled: parseBooleanEnv(
      'INTERNAL_CONTROL_PLANE_ENABLED',
      DEFAULT_INTERNAL_CONTROL_PLANE_CONFIG.enabled,
    ),
    requireApiKeyForMutations: parseBooleanEnv(
      'INTERNAL_CONTROL_PLANE_REQUIRE_API_KEY_FOR_MUTATIONS',
      DEFAULT_INTERNAL_CONTROL_PLANE_CONFIG.requireApiKeyForMutations,
    ),
    callerRoles,
    apiKeys,
    apiKeyIdHeader: String(
      process.env['INTERNAL_CONTROL_PLANE_API_KEY_ID_HEADER'] ??
      DEFAULT_INTERNAL_CONTROL_PLANE_CONFIG.apiKeyIdHeader,
    ).trim().toLowerCase() || DEFAULT_INTERNAL_CONTROL_PLANE_CONFIG.apiKeyIdHeader,
    apiKeySecretHeader: String(
      process.env['INTERNAL_CONTROL_PLANE_API_KEY_SECRET_HEADER'] ??
      DEFAULT_INTERNAL_CONTROL_PLANE_CONFIG.apiKeySecretHeader,
    ).trim().toLowerCase() || DEFAULT_INTERNAL_CONTROL_PLANE_CONFIG.apiKeySecretHeader,
  };
}

function hasSignedBundleShape(body: unknown): boolean {
  if (!body || typeof body !== 'object') return false;
  const candidate = body as Record<string, unknown>;
  return (
    typeof candidate['signature'] === 'string' ||
    typeof candidate['keyId'] === 'string' ||
    typeof candidate['bundleId'] === 'string'
  );
}

function getHeaderString(value: unknown): string {
  if (typeof value === 'string') return value;
  if (Array.isArray(value) && value.length > 0 && typeof value[0] === 'string') {
    return value[0];
  }
  return '';
}

export interface InternalMutationPermission {
  scope: string;
  role: string;
}

export function resolveInternalMutationPermission(path: string): InternalMutationPermission {
  if (path.startsWith('/internal/routes/policy')) {
    return {
      scope: 'route.write',
      role: 'route_admin',
    };
  }
  if (path.startsWith('/internal/upstreams/policy')) {
    return {
      scope: 'upstream.write',
      role: 'upstream_admin',
    };
  }
  if (path.startsWith('/internal/control-plane/audit')) {
    return {
      scope: 'audit.write',
      role: 'audit_admin',
    };
  }
  if (path.startsWith('/internal/security-controls')) {
    return {
      scope: 'security_controls.write',
      role: 'security_controls_admin',
    };
  }
  if (path.startsWith('/internal/edge-cache')) {
    return {
      scope: 'edge_cache.write',
      role: 'edge_cache_admin',
    };
  }
  if (path.startsWith('/internal/abuse-intel')) {
    return {
      scope: 'abuse_intel.write',
      role: 'abuse_intel_admin',
    };
  }
  if (
    path.startsWith('/internal/block-ip') ||
    path.startsWith('/internal/unblock-ip') ||
    path.startsWith('/internal/require-step-up') ||
    path.startsWith('/internal/clear-step-up') ||
    path.startsWith('/internal/throttle-user') ||
    path.startsWith('/internal/clear-throttle')
  ) {
    return {
      scope: 'enforcement.write',
      role: 'enforcement_admin',
    };
  }
  return {
    scope: 'internal.write',
    role: 'internal_operator',
  };
}

function hasMutationScope(scopes: string[], requiredScope: string): boolean {
  if (scopes.includes('*') || scopes.includes('control_plane.*')) return true;
  return scopes.includes(requiredScope);
}

export function authorizeInternalMutationRequest(
  req: Pick<Request, 'method' | 'path' | 'headers'>,
  config: InternalControlPlaneConfig,
): { ok: true; apiKeyId?: string } | { ok: false; status: number; body: Record<string, unknown> } {
  const method = req.method.toUpperCase();
  if (!INTERNAL_MUTATION_METHODS.has(method) || !config.enabled) {
    return { ok: true };
  }

  const permission = resolveInternalMutationPermission(req.path);
  const caller = (
    getHeaderString(req.headers['x-internal-caller']) ||
    getHeaderString(req.headers['x-caller-id']) ||
    ''
  ).trim().toLowerCase();
  const callerRoles = caller ? (config.callerRoles[caller] ?? []) : [];
  const roleAllowed = callerRoles.includes('control_plane_admin') || callerRoles.includes(permission.role);
  if (!roleAllowed) {
    return {
      ok: false,
      status: 403,
      body: {
        error: 'insufficient_control_plane_role',
        requiredRole: permission.role,
        requiredScope: permission.scope,
      },
    };
  }

  if (!config.requireApiKeyForMutations) {
    return { ok: true };
  }

  const keyId = getHeaderString(req.headers[config.apiKeyIdHeader]).trim();
  const providedSecret = getHeaderString(req.headers[config.apiKeySecretHeader]).trim();
  if (!keyId || !providedSecret) {
    return {
      ok: false,
      status: 401,
      body: {
        error: 'missing_control_plane_api_key',
      },
    };
  }

  const apiKey = config.apiKeys[keyId];
  if (!apiKey || !safeEquals(apiKey.secret, providedSecret)) {
    return {
      ok: false,
      status: 401,
      body: {
        error: 'invalid_control_plane_api_key',
      },
    };
  }

  if (!hasMutationScope(apiKey.scopes, permission.scope)) {
    return {
      ok: false,
      status: 403,
      body: {
        error: 'insufficient_control_plane_scope',
        requiredScope: permission.scope,
      },
    };
  }

  return { ok: true, apiKeyId: keyId };
}

function getOrCreateLocalMutationReplayStore(maxEntries: number): InMemoryInternalAuthReplayStore {
  const normalized = Math.max(1, Math.floor(maxEntries));
  const existing = localMutationReplayStores.get(normalized);
  if (existing) return existing;
  const store = new InMemoryInternalAuthReplayStore(normalized);
  localMutationReplayStores.set(normalized, store);
  return store;
}

export async function enforceMutationIdempotency(
  req: Request,
  replayStore: InternalAuthReplayStore | undefined,
  config: InternalMutationIdempotencyConfig,
): Promise<
{ ok: true; idempotencyKey: string | null } |
{ ok: false; status: number; body: Record<string, unknown> }
> {
  if (!config.enabled || !INTERNAL_MUTATION_METHODS.has(req.method.toUpperCase())) {
    return { ok: true, idempotencyKey: null };
  }

  const rawKey = getHeaderString(req.headers['idempotency-key']) || getHeaderString(req.headers['x-idempotency-key']);
  const idempotencyKey = rawKey.trim();
  if (!idempotencyKey) {
    return { ok: true, idempotencyKey: null };
  }
  if (!IDEMPOTENCY_KEY_PATTERN.test(idempotencyKey)) {
    return {
      ok: false,
      status: 400,
      body: {
        error: 'invalid_idempotency_key',
        details: [{ message: 'Idempotency-Key must match [A-Za-z0-9._:-]{8,128}' }],
      },
    };
  }

  const caller = getHeaderString(req.headers['x-internal-caller']) ||
    getHeaderString(req.headers['x-caller-id']) ||
    'unknown';
  const fingerprint = `${req.method.toUpperCase()}|${req.path}|${caller}|${idempotencyKey}`;
  const replayKey = createHash('sha256').update(fingerprint, 'utf8').digest('hex');
  const scopedReplayKey = `internal-mutation:${replayKey}`;
  const store = replayStore ?? getOrCreateLocalMutationReplayStore(config.replayCacheMaxEntries);
  try {
    const firstSeen = await store.consume(scopedReplayKey, config.ttlSeconds);
    if (!firstSeen) {
      return {
        ok: false,
        status: 409,
        body: {
          error: 'idempotency_conflict',
          details: [{ message: 'duplicate mutation request for Idempotency-Key' }],
        },
      };
    }
  } catch {
    return {
      ok: false,
      status: 503,
      body: {
        error: 'internal_mutation_replay_store_error',
      },
    };
  }

  return { ok: true, idempotencyKey };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function deepMerge(base: unknown, patch: unknown): unknown {
  if (patch === undefined) return base;
  if (Array.isArray(patch)) return [...patch];
  if (!isRecord(base) || !isRecord(patch)) return patch;

  const merged: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(patch)) {
    merged[key] = deepMerge(base[key], value);
  }
  return merged;
}

export function buildSecurityControlsSnapshot(config: GatewayConfig): {
  waf: GatewayConfig['waf'];
  botManagement: Omit<GatewayConfig['botManagement'], 'clearance'> & {
    clearance: Omit<GatewayConfig['botManagement']['clearance'], 'secret' | 'previousSecrets'> & {
      secretConfigured: boolean;
      previousSecretsConfigured: number;
    };
  };
  accessControl: GatewayConfig['accessControl'];
} {
  const clearancePublic = {
    enabled: config.botManagement.clearance.enabled,
    cookieName: config.botManagement.clearance.cookieName,
    ttlSeconds: config.botManagement.clearance.ttlSeconds,
    secure: config.botManagement.clearance.secure,
    httpOnly: config.botManagement.clearance.httpOnly,
    sameSite: config.botManagement.clearance.sameSite,
    path: config.botManagement.clearance.path,
    domain: config.botManagement.clearance.domain,
  };
  return {
    waf: config.waf,
    botManagement: {
      ...config.botManagement,
      clearance: {
        ...clearancePublic,
        secretConfigured: Boolean(config.botManagement.clearance.secret),
        previousSecretsConfigured: config.botManagement.clearance.previousSecrets.length,
      },
    },
    accessControl: config.accessControl,
  };
}

export function applySecurityControlsPatch(
  config: GatewayConfig,
  patch: SecurityControlsPatch,
): {
  ok: true;
  snapshot: ReturnType<typeof buildSecurityControlsSnapshot>;
} | {
  ok: false;
  issues: Array<{ path: string; message: string }>;
} {
  const preview = previewSecurityControlsPatch(config, patch);
  if (!preview.ok) {
    return preview;
  }

  config.waf = preview.nextControls.waf;
  config.botManagement = preview.nextControls.botManagement;
  config.accessControl = preview.nextControls.accessControl;

  return {
    ok: true,
    snapshot: preview.snapshot,
  };
}

export function previewSecurityControlsPatch(
  config: GatewayConfig,
  patch: SecurityControlsPatch,
): {
  ok: true;
  snapshot: ReturnType<typeof buildSecurityControlsSnapshot>;
  nextControls: Pick<GatewayConfig, 'waf' | 'botManagement' | 'accessControl'>;
} | {
  ok: false;
  issues: Array<{ path: string; message: string }>;
} {
  const merged = deepMerge(config as unknown as Record<string, unknown>, patch as Record<string, unknown>);
  const parsed = GatewayConfigSchema.safeParse(merged);
  if (!parsed.success) {
    return {
      ok: false,
      issues: parsed.error.issues.map((issue) => ({
        path: issue.path.join('.'),
        message: issue.message,
      })),
    };
  }

  return {
    ok: true,
    snapshot: buildSecurityControlsSnapshot(parsed.data),
    nextControls: {
      waf: parsed.data.waf,
      botManagement: parsed.data.botManagement,
      accessControl: parsed.data.accessControl,
    },
  };
}

function canonicalize(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'number' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalize(v)).join(',')}]`;
  }

  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const serializedFields = keys.map((key) => `${JSON.stringify(key)}:${canonicalize(obj[key])}`);
  return `{${serializedFields.join(',')}}`;
}

function sha256Hex(payload: unknown): string {
  return createHash('sha256')
    .update(canonicalize(payload), 'utf8')
    .digest('hex');
}

function hmacSha256Hex(secret: string, payload: unknown): string {
  return createHmac('sha256', secret)
    .update(canonicalize(payload), 'utf8')
    .digest('hex');
}

function safeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

export function sanitizeSecurityControlsPatchForHistory(patch: SecurityControlsPatch): Record<string, unknown> {
  const sanitized = deepMerge({}, patch) as Record<string, unknown>;
  const botManagement = sanitized['botManagement'];
  if (!isRecord(botManagement)) {
    return sanitized;
  }

  const clearance = botManagement['clearance'];
  if (!isRecord(clearance)) {
    return sanitized;
  }

  if (clearance['secret'] !== undefined) {
    clearance['secretConfigured'] = Boolean(String(clearance['secret']).trim());
    delete clearance['secret'];
  }
  if (Array.isArray(clearance['previousSecrets'])) {
    clearance['previousSecretsConfigured'] = clearance['previousSecrets'].length;
    delete clearance['previousSecrets'];
  }

  return sanitized;
}

function resolveSecurityControlsAuditSecret(config?: GatewayConfig): string {
  const envSecret = String(process.env['SECURITY_CONTROLS_AUDIT_SECRET'] ?? '').trim();
  if (envSecret) return envSecret;

  const configSecret = String(
    config?.internalAuth?.secret ??
    config?.adaptiveDefense?.abuseIntel?.signingSecret ??
    config?.adaptiveDefense?.challenge?.secret ??
    '',
  ).trim();
  if (configSecret) return configSecret;

  return `${randomUUID()}${randomUUID()}`;
}

function resolveSecurityControlsHistoryMaxEntries(): number {
  const parsed = Number.parseInt(process.env['SECURITY_CONTROLS_HISTORY_MAX_ENTRIES'] ?? '', 10);
  if (!Number.isFinite(parsed)) return SECURITY_CONTROLS_HISTORY_DEFAULT_MAX_ENTRIES;
  return Math.max(100, Math.min(parsed, 100_000));
}

function parseSecurityControlsHistoryLimit(rawLimit: unknown): number {
  const fallback = SECURITY_CONTROLS_HISTORY_DEFAULT_LIMIT;
  const parsed = typeof rawLimit === 'string' ? Number.parseInt(rawLimit, 10) : fallback;
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(1, Math.min(parsed, SECURITY_CONTROLS_HISTORY_LIMIT_MAX));
}

function resolveEdgeInvalidationMaxEntries(): number {
  const parsed = Number.parseInt(process.env['EDGE_INVALIDATION_LOG_MAX_ENTRIES'] ?? '', 10);
  if (!Number.isFinite(parsed)) return EDGE_INVALIDATION_DEFAULT_MAX_ENTRIES;
  return Math.max(100, Math.min(parsed, 500_000));
}

function parseEdgeInvalidationLimit(rawLimit: unknown): number {
  const fallback = EDGE_INVALIDATION_DEFAULT_LIMIT;
  const parsed = typeof rawLimit === 'string' ? Number.parseInt(rawLimit, 10) : fallback;
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(1, Math.min(parsed, EDGE_INVALIDATION_LIMIT_MAX));
}

function normalizeEdgeInvalidationCursor(rawCursor: unknown, fallback = '0'): string {
  const candidate = typeof rawCursor === 'string' ? rawCursor.trim() : fallback;
  if (!EDGE_INVALIDATION_CURSOR_PATTERN.test(candidate)) return fallback;
  return candidate;
}

function parseEdgeInvalidationCursorBigInt(value: string): bigint {
  if (!EDGE_INVALIDATION_CURSOR_PATTERN.test(value)) return 0n;
  try {
    return BigInt(value);
  } catch {
    return 0n;
  }
}

function resolveControlPlaneAuditMaxEntries(): number {
  const parsed = Number.parseInt(process.env['CONTROL_PLANE_AUDIT_MAX_ENTRIES'] ?? '', 10);
  if (!Number.isFinite(parsed)) return CONTROL_PLANE_AUDIT_DEFAULT_MAX_ENTRIES;
  return Math.max(1000, Math.min(parsed, 1_000_000));
}

function parseControlPlaneAuditLimit(rawLimit: unknown): number {
  const fallback = CONTROL_PLANE_AUDIT_DEFAULT_LIMIT;
  const parsed = typeof rawLimit === 'string' ? Number.parseInt(rawLimit, 10) : fallback;
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(1, Math.min(parsed, CONTROL_PLANE_AUDIT_LIMIT_MAX));
}

function normalizeControlPlaneAuditCursor(rawCursor: unknown, fallback = '0'): string {
  const candidate = typeof rawCursor === 'string' ? rawCursor.trim() : fallback;
  if (!CONTROL_PLANE_AUDIT_CURSOR_PATTERN.test(candidate)) return fallback;
  return candidate;
}

function parseControlPlaneAuditCursorBigInt(value: string): bigint {
  if (!CONTROL_PLANE_AUDIT_CURSOR_PATTERN.test(value)) return 0n;
  try {
    return BigInt(value);
  } catch {
    return 0n;
  }
}

export function buildSecurityControlsAuditEntry(input: {
  patch: SecurityControlsPatch;
  snapshot?: ReturnType<typeof buildSecurityControlsSnapshot>;
  snapshotHash?: string;
  previousEntryHash: string | null;
  actor: string;
  correlationId: string;
  signingSecret: string;
  changedAt?: string;
  nowMs?: number;
}): SecurityControlsAuditEntry {
  const id = randomUUID();
  const changedAt = input.changedAt ?? new Date(input.nowMs ?? Date.now()).toISOString();
  const sanitizedPatch = sanitizeSecurityControlsPatchForHistory(input.patch);
  const snapshotHash =
    input.snapshotHash ??
    (input.snapshot ? sha256Hex(input.snapshot) : sha256Hex({ patch: sanitizedPatch, changedAt }));

  const unsignedPayload = {
    id,
    changedAt,
    actor: input.actor,
    correlationId: input.correlationId,
    patch: sanitizedPatch,
    snapshotHash,
    previousEntryHash: input.previousEntryHash,
  };
  const entryHash = sha256Hex(unsignedPayload);
  const signature = hmacSha256Hex(input.signingSecret, { entryHash });

  return {
    ...unsignedPayload,
    entryHash,
    signature,
  };
}

export function buildSecurityControlsRevision(input: {
  total: number;
  latestEntryHash: string | null;
  anchorHash?: string | null;
}): string {
  const normalizedTotal = Math.max(0, Math.floor(input.total));
  const hash = (input.latestEntryHash || input.anchorHash || 'genesis').trim() || 'genesis';
  return `r${normalizedTotal}:${hash}`;
}

export function extractIfMatchRevisionHeader(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const first = value.split(',')[0]?.trim();
  if (!first || first === '*') return null;

  const weakStripped = first.startsWith('W/') ? first.slice(2).trim() : first;
  const token = weakStripped.startsWith('"') && weakStripped.endsWith('"')
    ? weakStripped.slice(1, -1).trim()
    : weakStripped.trim();

  if (!token || token.length > 512) return null;
  return token;
}

export function parseSecurityControlsPatchRequestBody(body: unknown): {
  ok: true;
  patch: SecurityControlsPatch;
  ifRevision?: string;
  dryRun: boolean;
} | {
  ok: false;
  issues: Array<{ path: string; message: string }>;
} {
  const envelopeCandidate = body as Record<string, unknown> | null;
  if (envelopeCandidate && typeof envelopeCandidate === 'object' && envelopeCandidate['patch'] !== undefined) {
    const parsedEnvelope = SecurityControlsPatchRequestEnvelopeSchema.safeParse(envelopeCandidate);
    if (!parsedEnvelope.success) {
      return {
        ok: false,
        issues: parsedEnvelope.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      };
    }
    return {
      ok: true,
      patch: parsedEnvelope.data.patch,
      ifRevision: parsedEnvelope.data.ifRevision,
      dryRun: parsedEnvelope.data.dryRun,
    };
  }

  const patchOnly = SecurityControlsPatchSchema.safeParse(body);
  if (!patchOnly.success) {
    return {
      ok: false,
      issues: patchOnly.error.issues.map((issue) => ({
        path: issue.path.join('.'),
        message: issue.message,
      })),
    };
  }

  const directRecord = body as Record<string, unknown> | null;
  const ifRevision = (directRecord && typeof directRecord['ifRevision'] === 'string')
    ? String(directRecord['ifRevision'])
    : undefined;
  const dryRun = Boolean(directRecord && directRecord['dryRun'] === true);

  return {
    ok: true,
    patch: patchOnly.data,
    ifRevision,
    dryRun,
  };
}

export function verifySecurityControlsAuditChain(input: {
  entries: SecurityControlsAuditEntry[];
  signingSecret: string;
  initialPreviousEntryHash?: string | null;
}): {
  ok: true;
  checked: number;
  latestEntryHash: string | null;
} | {
  ok: false;
  checked: number;
  failedIndex: number;
  reason: string;
} {
  let previousEntryHash: string | null = input.initialPreviousEntryHash ?? null;

  for (const [index, entry] of input.entries.entries()) {
    if (entry.previousEntryHash !== previousEntryHash) {
      return {
        ok: false,
        checked: index + 1,
        failedIndex: index,
        reason: 'hash_chain_broken',
      };
    }

    const expectedHash = sha256Hex({
      id: entry.id,
      changedAt: entry.changedAt,
      actor: entry.actor,
      correlationId: entry.correlationId,
      patch: entry.patch,
      snapshotHash: entry.snapshotHash,
      previousEntryHash: entry.previousEntryHash,
    });
    if (!safeEquals(entry.entryHash, expectedHash)) {
      return {
        ok: false,
        checked: index + 1,
        failedIndex: index,
        reason: 'entry_hash_invalid',
      };
    }

    const expectedSignature = hmacSha256Hex(input.signingSecret, { entryHash: expectedHash });
    if (!safeEquals(entry.signature, expectedSignature)) {
      return {
        ok: false,
        checked: index + 1,
        failedIndex: index,
        reason: 'signature_invalid',
      };
    }

    previousEntryHash = expectedHash;
  }

  return {
    ok: true,
    checked: input.entries.length,
    latestEntryHash: previousEntryHash,
  };
}

export function createInternalRoutes(
  state: SecurityStateStore,
  options?: InternalRoutesOptions,
): Router {
  const router = Router();
  const abuseIntel = resolveAbuseIntelConfig(options);
  const securityControlsAuditSecret = resolveSecurityControlsAuditSecret(options?.gatewayConfig);
  const securityControlsHistoryMaxEntries =
    options?.securityControlsAuditMaxEntries ?? resolveSecurityControlsHistoryMaxEntries();
  const securityControlsAuditStore =
    options?.securityControlsAuditStore ?? new InMemorySecurityControlsAuditStore();
  const edgeInvalidationMaxEntries =
    options?.edgeInvalidationMaxEntries ?? resolveEdgeInvalidationMaxEntries();
  const edgeInvalidationStore =
    options?.edgeInvalidationEventStore ?? new InMemoryEdgeInvalidationEventStore();
  const controlPlaneAuditMaxEntries =
    options?.controlPlaneAuditMaxEntries ?? resolveControlPlaneAuditMaxEntries();
  const controlPlaneAuditStore =
    options?.controlPlaneAuditStore ?? new InMemoryControlPlaneAuditStore();
  const securityControlsHistoryBundle = resolveSecurityControlsHistoryBundleConfig(
    securityControlsAuditSecret,
  );
  const edgeCacheVersionBundle = resolveEdgeCacheVersionBundleConfig();
  const edgeInvalidationBundle = resolveEdgeInvalidationBundleConfig();
  const controlPlaneAuditBundle = resolveControlPlaneAuditBundleConfig();
  const routePolicyBundle = resolveRoutePolicyBundleConfig();
  const routePolicyManager = options?.routePolicyManager ??
    (options?.gatewayConfig ? new RoutePolicyManager(options.gatewayConfig) : undefined);
  const upstreamRoutingPolicyBundle = resolveUpstreamRoutingPolicyBundleConfig();
  const upstreamPolicyManager = options?.upstreamPolicyManager ??
    (options?.gatewayConfig ? new UpstreamRoutingPolicyManager(options.gatewayConfig) : undefined);
  const controlPlaneAccess = resolveInternalControlPlaneConfig();
  const mutationIdempotency = resolveInternalMutationIdempotencyConfig();

  router.use((req: Request, res: Response, next) => {
    const access = authorizeInternalMutationRequest(req, controlPlaneAccess);
    if (!access.ok) {
      res.status(access.status).json(access.body);
      return;
    }
    if (access.apiKeyId) {
      res.setHeader('X-Internal-Api-Key-Id', access.apiKeyId);
    }
    next();
  });

  router.use((req: Request, res: Response, next) => {
    void (async () => {
      const check = await enforceMutationIdempotency(
        req,
        options?.mutationReplayStore,
        mutationIdempotency,
      );
      if (!check.ok) {
        res.status(check.status).json(check.body);
        return;
      }
      if (check.idempotencyKey) {
        res.setHeader('X-Idempotency-Key', check.idempotencyKey);
      }
      next();
    })().catch(() => {
      res.status(503).json({ error: 'internal_mutation_replay_store_error' });
    });
  });

  router.use((req: Request, res: Response, next) => {
    const method = req.method.toUpperCase();
    if (!INTERNAL_MUTATION_METHODS.has(method)) {
      next();
      return;
    }

    const actor = resolveInternalMutationActor(req);
    const correlationId = resolveInternalCorrelationId(req);
    const permission = resolveInternalMutationPermission(req.path);
    const idempotencyKey =
      getHeaderString(req.headers['idempotency-key']) ||
      getHeaderString(req.headers['x-idempotency-key']) ||
      undefined;
    const requestBodyHash = sha256Hex(req.body ?? null);
    const contentLengthRaw = getHeaderString(req.headers['content-length']).trim();
    const parsedContentLength = contentLengthRaw ? Number.parseInt(contentLengthRaw, 10) : NaN;
    const requestContentLength =
      Number.isFinite(parsedContentLength) && parsedContentLength >= 0
        ? parsedContentLength
        : undefined;

    res.once('finish', () => {
      void controlPlaneAuditStore.append(
        buildControlPlaneAuditEventInput({
          source: controlPlaneAuditBundle.sourceId,
          actor,
          correlationId,
          method,
          path: req.path,
          statusCode: res.statusCode,
          outcome: res.statusCode >= 200 && res.statusCode < 400 ? 'success' : 'failure',
          requestBodyHash,
          requestContentLength,
          idempotencyKey,
          permissionScope: permission.scope,
        }),
        controlPlaneAuditMaxEntries,
      ).catch(() => {
        // Best-effort audit append. Internal mutation paths must not fail closed on log sink errors.
      });
    });

    next();
  });

  router.get('/internal/abuse-intel/export', async (req: Request, res: Response) => {
    const rawLimit = typeof req.query?.limit === 'string' ? req.query.limit : '1000';
    const parsedLimit = parseInt(rawLimit, 10);
    const limit = Number.isFinite(parsedLimit) ? parsedLimit : 1000;

    if (abuseIntel.enabled && abuseIntel.signExports) {
      if (!abuseIntel.signingSecret) {
        res.status(503).json({ error: 'abuse_intel_signing_unavailable' });
        return;
      }
      const signed = await buildSignedAbuseIntelExport(state, limit, abuseIntel);
      res.status(200).json({
        signed: true,
        entryCount: signed.entryCount,
        bundle: signed.bundle,
      });
      return;
    }

    const payload = await buildAbuseIntelExport(state, Math.min(limit, abuseIntel.exportMaxEntries));
    res.status(200).json({ signed: false, ...payload });
  });

  router.post('/internal/abuse-intel/import', async (req: Request, res: Response) => {
    if (hasSignedBundleShape(req.body)) {
      const signed = SignedAbuseIntelImportSchema.safeParse(req.body);
      if (!signed.success) {
        res.status(400).json({ error: 'invalid_request', details: signed.error.issues });
        return;
      }

      const verification = await verifySignedAbuseIntelBundle(
        signed.data,
        {
          keyring: abuseIntel.keyring,
          allowedSources: abuseIntel.allowedSources,
          allowedKeyIds: abuseIntel.allowedKeyIds,
          maxSkewSeconds: abuseIntel.maxSkewSeconds,
          replayProtectionEnabled: abuseIntel.replayProtectionEnabled,
          replayCacheMaxEntries: abuseIntel.replayCacheMaxEntries,
        },
        options?.abuseIntelReplayStore,
      );

      if (!verification.ok) {
        res.status(401).json({ error: 'invalid_signed_bundle', reason: verification.reason });
        return;
      }

      const result = await applyAbuseIntelImport(state, {
        source: signed.data.source,
        minTtlSeconds: signed.data.minTtlSeconds,
        entries: signed.data.entries,
      });
      res.status(200).json({
        source: signed.data.source,
        signed: true,
        imported: result.imported,
        skipped: result.skipped,
        importedIps: result.importedIps,
      });
      return;
    }

    if (abuseIntel.enabled && abuseIntel.requireSignedImports) {
      res.status(400).json({ error: 'signed_bundle_required' });
      return;
    }

    const parsed = AbuseIntelImportSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request', details: parsed.error.issues });
      return;
    }

    const result = await applyAbuseIntelImport(state, parsed.data);
    res.status(200).json({
      source: parsed.data.source,
      signed: false,
      imported: result.imported,
      skipped: result.skipped,
      importedIps: result.importedIps,
    });
  });

  router.get('/internal/control-plane/audit/events', async (req: Request, res: Response) => {
    const afterCursor = normalizeControlPlaneAuditCursor(req.query?.afterCursor, '0');
    const limit = parseControlPlaneAuditLimit(req.query?.limit);
    const source = typeof req.query?.source === 'string' && req.query.source.trim()
      ? req.query.source.trim()
      : undefined;

    try {
      const payload = await buildControlPlaneAuditExport(
        controlPlaneAuditStore,
        afterCursor,
        limit,
        source,
      );
      res.status(200).json(payload);
    } catch {
      res.status(503).json({ error: 'control_plane_audit_history_unavailable' });
    }
  });

  router.get('/internal/control-plane/audit/export', async (req: Request, res: Response) => {
    const afterCursor = normalizeControlPlaneAuditCursor(req.query?.afterCursor, '0');
    const limit = parseControlPlaneAuditLimit(req.query?.limit);

    try {
      if (controlPlaneAuditBundle.signExports) {
        if (!controlPlaneAuditBundle.signingSecret) {
          res.status(503).json({ error: 'control_plane_audit_signing_unavailable' });
          return;
        }

        const unsignedPayload = await buildControlPlaneAuditExport(
          controlPlaneAuditStore,
          afterCursor,
          Math.min(limit, controlPlaneAuditBundle.exportMaxEntries),
          controlPlaneAuditBundle.sourceId,
        );
        if (unsignedPayload.entryCount === 0) {
          res.status(200).json({ signed: false, ...unsignedPayload });
          return;
        }

        const signed = await buildSignedControlPlaneAuditExport(
          controlPlaneAuditStore,
          afterCursor,
          limit,
          controlPlaneAuditBundle,
        );
        res.status(200).json({
          signed: true,
          entryCount: signed.entryCount,
          bundle: signed.bundle,
        });
        return;
      }

      const payload = await buildControlPlaneAuditExport(
        controlPlaneAuditStore,
        afterCursor,
        Math.min(limit, controlPlaneAuditBundle.exportMaxEntries),
        controlPlaneAuditBundle.sourceId,
      );
      res.status(200).json({ signed: false, ...payload });
    } catch {
      res.status(503).json({ error: 'control_plane_audit_history_unavailable' });
    }
  });

  router.post('/internal/control-plane/audit/import', async (req: Request, res: Response) => {
    if (hasSignedBundleShape(req.body)) {
      const signed = SignedControlPlaneAuditBundleSchema.safeParse(req.body);
      if (!signed.success) {
        res.status(400).json({ error: 'invalid_request', details: signed.error.issues });
        return;
      }

      const verification = await verifySignedControlPlaneAuditBundle(
        signed.data as ControlPlaneAuditSignedBundle,
        {
          keyring: controlPlaneAuditBundle.keyring,
          allowedSources: controlPlaneAuditBundle.allowedSources,
          allowedKeyIds: controlPlaneAuditBundle.allowedKeyIds,
          maxSkewSeconds: controlPlaneAuditBundle.maxSkewSeconds,
          replayProtectionEnabled: controlPlaneAuditBundle.replayProtectionEnabled,
          replayCacheMaxEntries: controlPlaneAuditBundle.replayCacheMaxEntries,
        },
        options?.abuseIntelReplayStore,
      );
      if (!verification.ok) {
        res.status(401).json({ error: 'invalid_signed_bundle', reason: verification.reason });
        return;
      }

      try {
        const result = await applyControlPlaneAuditImport(
          controlPlaneAuditStore,
          {
            source: signed.data.source,
            fromCursor: signed.data.fromCursor,
            toCursor: signed.data.toCursor,
            entries: signed.data.entries,
          },
          {
            maxEntries: controlPlaneAuditMaxEntries,
            localSourceId: controlPlaneAuditBundle.sourceId,
          },
        );
        res.status(200).json({
          source: signed.data.source,
          signed: true,
          fromCursor: signed.data.fromCursor,
          toCursor: signed.data.toCursor,
          imported: result.imported,
          appended: result.appended,
          skipped: result.skipped,
          latestImportedCursor: result.latestImportedCursor,
        });
      } catch {
        res.status(503).json({ error: 'control_plane_audit_history_unavailable' });
      }
      return;
    }

    if (controlPlaneAuditBundle.requireSignedImports) {
      res.status(400).json({ error: 'signed_bundle_required' });
      return;
    }

    const parsed = ControlPlaneAuditImportSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request', details: parsed.error.issues });
      return;
    }

    try {
      const result = await applyControlPlaneAuditImport(
        controlPlaneAuditStore,
        parsed.data,
        {
          maxEntries: controlPlaneAuditMaxEntries,
          localSourceId: controlPlaneAuditBundle.sourceId,
        },
      );
      res.status(200).json({
        source: parsed.data.source,
        signed: false,
        fromCursor: parsed.data.fromCursor,
        toCursor: parsed.data.toCursor ?? result.latestImportedCursor,
        imported: result.imported,
        appended: result.appended,
        skipped: result.skipped,
        latestImportedCursor: result.latestImportedCursor,
      });
    } catch {
      res.status(503).json({ error: 'control_plane_audit_history_unavailable' });
    }
  });

  router.get('/internal/routes/policy', async (_req: Request, res: Response) => {
    if (!routePolicyManager) {
      res.status(503).json({ error: 'route_policy_unavailable' });
      return;
    }

    const payload = buildRoutePolicyExport(routePolicyManager);
    res.status(200).json(payload);
  });

  router.patch('/internal/routes/policy', async (req: Request, res: Response) => {
    if (!routePolicyManager) {
      res.status(503).json({ error: 'route_policy_unavailable' });
      return;
    }

    const parsed = RoutePolicyPatchSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request', details: parsed.error.issues });
      return;
    }

    const currentRevision = routePolicyManager.getRevision();
    if (parsed.data.ifRevision && parsed.data.ifRevision !== currentRevision) {
      res.status(409).json({
        error: 'revision_conflict',
        requestedRevision: parsed.data.ifRevision,
        currentRevision,
      });
      return;
    }

    const updates = parsed.data.updates as RoutePolicyPatchUpdate[];
    const preview = routePolicyManager.previewPatch(updates);
    if (!preview.ok) {
      res.status(400).json({
        error: 'invalid_route_policy_patch',
        details: preview.issues,
      });
      return;
    }

    if (parsed.data.dryRun) {
      res.status(200).json({
        updated: false,
        dryRun: true,
        currentRevision: preview.currentRevision,
        nextRevision: preview.nextRevision,
        changed: preview.changed,
        changedRoutes: preview.changedRoutes,
        routeCount: preview.routes.length,
      });
      return;
    }

    const result = routePolicyManager.applyPatch(updates);
    if (!result.ok) {
      res.status(400).json({
        error: 'invalid_route_policy_patch',
        details: result.issues,
      });
      return;
    }

    res.status(200).json({
      updated: result.changed,
      dryRun: false,
      previousRevision: result.previousRevision,
      revision: result.revision,
      changed: result.changed,
      changedRoutes: result.changedRoutes,
      routeCount: routePolicyManager.getSnapshot().routeCount,
    });
  });

  router.get('/internal/routes/policy/export', async (_req: Request, res: Response) => {
    if (!routePolicyManager) {
      res.status(503).json({ error: 'route_policy_unavailable' });
      return;
    }

    if (routePolicyBundle.signExports) {
      if (!routePolicyBundle.signingSecret) {
        res.status(503).json({ error: 'route_policy_signing_unavailable' });
        return;
      }
      const signed = await buildSignedRoutePolicyExport(routePolicyManager, routePolicyBundle);
      res.status(200).json({
        signed: true,
        routeCount: signed.routeCount,
        bundle: signed.bundle,
      });
      return;
    }

    const payload = buildRoutePolicyExport(routePolicyManager, routePolicyBundle.sourceId);
    res.status(200).json({ signed: false, ...payload });
  });

  router.post('/internal/routes/policy/import', async (req: Request, res: Response) => {
    if (!routePolicyManager) {
      res.status(503).json({ error: 'route_policy_unavailable' });
      return;
    }

    if (hasSignedBundleShape(req.body)) {
      const signed = SignedRoutePolicyBundleSchema.safeParse(req.body);
      if (!signed.success) {
        res.status(400).json({ error: 'invalid_request', details: signed.error.issues });
        return;
      }

      const verification = await verifySignedRoutePolicyBundle(
        signed.data as RoutePolicySignedBundle,
        {
          keyring: routePolicyBundle.keyring,
          allowedSources: routePolicyBundle.allowedSources,
          allowedKeyIds: routePolicyBundle.allowedKeyIds,
          maxSkewSeconds: routePolicyBundle.maxSkewSeconds,
          replayProtectionEnabled: routePolicyBundle.replayProtectionEnabled,
          replayCacheMaxEntries: routePolicyBundle.replayCacheMaxEntries,
        },
        options?.abuseIntelReplayStore,
      );
      if (!verification.ok) {
        res.status(401).json({ error: 'invalid_signed_bundle', reason: verification.reason });
        return;
      }

      const result = applyRoutePolicyImport(routePolicyManager, {
        revision: signed.data.revision,
        routes: signed.data.routes,
      });
      if (!result.ok) {
        res.status(400).json({
          error: 'invalid_route_policy_import',
          details: result.issues,
        });
        return;
      }

      res.status(200).json({
        source: signed.data.source,
        signed: true,
        changed: result.changed,
        skipped: result.skipped,
        previousRevision: result.previousRevision,
        revision: result.revision,
        changedRoutes: result.changedRoutes,
      });
      return;
    }

    if (routePolicyBundle.requireSignedImports) {
      res.status(400).json({ error: 'signed_bundle_required' });
      return;
    }

    const parsed = RoutePolicyImportSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request', details: parsed.error.issues });
      return;
    }

    const result = applyRoutePolicyImport(routePolicyManager, {
      revision: parsed.data.revision,
      routes: parsed.data.routes,
    });
    if (!result.ok) {
      res.status(400).json({
        error: 'invalid_route_policy_import',
        details: result.issues,
      });
      return;
    }

    res.status(200).json({
      source: parsed.data.source,
      signed: false,
      changed: result.changed,
      skipped: result.skipped,
      previousRevision: result.previousRevision,
      revision: result.revision,
      changedRoutes: result.changedRoutes,
    });
  });

  router.get('/internal/upstreams/policy', async (_req: Request, res: Response) => {
    if (!upstreamPolicyManager) {
      res.status(503).json({ error: 'upstream_routing_policy_unavailable' });
      return;
    }

    const payload = buildUpstreamRoutingPolicyExport(upstreamPolicyManager);
    res.status(200).json(payload);
  });

  router.patch('/internal/upstreams/policy', async (req: Request, res: Response) => {
    if (!upstreamPolicyManager) {
      res.status(503).json({ error: 'upstream_routing_policy_unavailable' });
      return;
    }

    const parsed = UpstreamRoutingPolicyPatchSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request', details: parsed.error.issues });
      return;
    }

    const currentRevision = upstreamPolicyManager.getRevision();
    if (parsed.data.ifRevision && parsed.data.ifRevision !== currentRevision) {
      res.status(409).json({
        error: 'revision_conflict',
        requestedRevision: parsed.data.ifRevision,
        currentRevision,
      });
      return;
    }

    const preview = upstreamPolicyManager.previewPatch(parsed.data.upstreams);
    if (!preview.ok) {
      res.status(400).json({
        error: 'invalid_upstream_policy_patch',
        details: preview.issues,
      });
      return;
    }

    if (parsed.data.dryRun) {
      res.status(200).json({
        updated: false,
        dryRun: true,
        currentRevision: preview.currentRevision,
        nextRevision: preview.nextRevision,
        changed: preview.changed,
        changedUpstreams: preview.changedUpstreams,
        upstreamCount: Object.keys(preview.upstreams).length,
      });
      return;
    }

    const result = upstreamPolicyManager.applyPatch(parsed.data.upstreams);
    if (!result.ok) {
      res.status(400).json({
        error: 'invalid_upstream_policy_patch',
        details: result.issues,
      });
      return;
    }

    res.status(200).json({
      updated: result.changed,
      dryRun: false,
      previousRevision: result.previousRevision,
      revision: result.revision,
      changed: result.changed,
      changedUpstreams: result.changedUpstreams,
      upstreamCount: Object.keys(upstreamPolicyManager.getSnapshot().upstreams).length,
    });
  });

  router.get('/internal/upstreams/policy/export', async (_req: Request, res: Response) => {
    if (!upstreamPolicyManager) {
      res.status(503).json({ error: 'upstream_routing_policy_unavailable' });
      return;
    }

    if (upstreamRoutingPolicyBundle.signExports) {
      if (!upstreamRoutingPolicyBundle.signingSecret) {
        res.status(503).json({ error: 'upstream_routing_policy_signing_unavailable' });
        return;
      }
      const signed = await buildSignedUpstreamRoutingPolicyExport(
        upstreamPolicyManager,
        upstreamRoutingPolicyBundle,
      );
      res.status(200).json({
        signed: true,
        upstreamCount: signed.upstreamCount,
        bundle: signed.bundle,
      });
      return;
    }

    const payload = buildUpstreamRoutingPolicyExport(
      upstreamPolicyManager,
      upstreamRoutingPolicyBundle.sourceId,
    );
    res.status(200).json({ signed: false, ...payload });
  });

  router.post('/internal/upstreams/policy/import', async (req: Request, res: Response) => {
    if (!upstreamPolicyManager) {
      res.status(503).json({ error: 'upstream_routing_policy_unavailable' });
      return;
    }

    if (hasSignedBundleShape(req.body)) {
      const signed = SignedUpstreamRoutingPolicyBundleSchema.safeParse(req.body);
      if (!signed.success) {
        res.status(400).json({ error: 'invalid_request', details: signed.error.issues });
        return;
      }

      const verification = await verifySignedUpstreamRoutingPolicyBundle(
        signed.data as UpstreamRoutingPolicySignedBundle,
        {
          keyring: upstreamRoutingPolicyBundle.keyring,
          allowedSources: upstreamRoutingPolicyBundle.allowedSources,
          allowedKeyIds: upstreamRoutingPolicyBundle.allowedKeyIds,
          maxSkewSeconds: upstreamRoutingPolicyBundle.maxSkewSeconds,
          replayProtectionEnabled: upstreamRoutingPolicyBundle.replayProtectionEnabled,
          replayCacheMaxEntries: upstreamRoutingPolicyBundle.replayCacheMaxEntries,
        },
        options?.abuseIntelReplayStore,
      );
      if (!verification.ok) {
        res.status(401).json({ error: 'invalid_signed_bundle', reason: verification.reason });
        return;
      }

      const result = applyUpstreamRoutingPolicyImport(upstreamPolicyManager, {
        revision: signed.data.revision,
        upstreams: signed.data.upstreams,
      });
      if (!result.ok) {
        res.status(400).json({
          error: 'invalid_upstream_policy_import',
          details: result.issues,
        });
        return;
      }

      res.status(200).json({
        source: signed.data.source,
        signed: true,
        changed: result.changed,
        skipped: result.skipped,
        previousRevision: result.previousRevision,
        revision: result.revision,
        changedUpstreams: result.changedUpstreams,
      });
      return;
    }

    if (upstreamRoutingPolicyBundle.requireSignedImports) {
      res.status(400).json({ error: 'signed_bundle_required' });
      return;
    }

    const parsed = UpstreamRoutingPolicyImportSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request', details: parsed.error.issues });
      return;
    }

    const result = applyUpstreamRoutingPolicyImport(upstreamPolicyManager, {
      revision: parsed.data.revision,
      upstreams: parsed.data.upstreams,
    });
    if (!result.ok) {
      res.status(400).json({
        error: 'invalid_upstream_policy_import',
        details: result.issues,
      });
      return;
    }

    res.status(200).json({
      source: parsed.data.source,
      signed: false,
      changed: result.changed,
      skipped: result.skipped,
      previousRevision: result.previousRevision,
      revision: result.revision,
      changedUpstreams: result.changedUpstreams,
    });
  });

  router.post('/internal/edge-cache/purge', async (req: Request, res: Response) => {
    if (!options?.edgeCache?.enabled || !options.edgeCacheStore) {
      res.status(503).json({ error: 'edge_cache_unavailable' });
      return;
    }

    const parsed = EdgeCachePurgeSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request', details: parsed.error.issues });
      return;
    }

    const result = await applyEdgeCachePurge(options.edgeCacheStore, parsed.data);
    const eventResult = await appendEdgeInvalidationEventSafe(
      edgeInvalidationStore,
      buildEdgeInvalidationEventInput({
        source: edgeInvalidationBundle.sourceId,
        actor: resolveInternalMutationActor(req),
        correlationId: resolveInternalCorrelationId(req),
        kind: 'purge',
        payload: parsed.data as unknown as Record<string, unknown>,
      }),
      edgeInvalidationMaxEntries,
    );
    res.status(200).json({
      purged: result.purged,
      mode: result.mode,
      maxDelete: parsed.data.maxDelete,
      eventLogged: eventResult.eventLogged,
      eventCursor: eventResult.eventCursor,
      target:
        parsed.data.key ??
        parsed.data.routePath ??
        (parsed.data.tags && parsed.data.tags.length > 0 ? parsed.data.tags : '*'),
    });
  });

  router.get('/internal/edge-cache/version', async (req: Request, res: Response) => {
    if (!options?.edgeCache?.enabled || !options.edgeCacheStore) {
      res.status(503).json({ error: 'edge_cache_unavailable' });
      return;
    }

    const parsed = EdgeCacheVersionSchema.safeParse({
      routePath: req.query?.routePath,
    });
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request', details: parsed.error.issues });
      return;
    }

    const version = await getEdgeCacheRouteVersion(options.edgeCacheStore, parsed.data);
    res.status(200).json(version);
  });

  router.post('/internal/edge-cache/version/bump', async (req: Request, res: Response) => {
    if (!options?.edgeCache?.enabled || !options.edgeCacheStore) {
      res.status(503).json({ error: 'edge_cache_unavailable' });
      return;
    }

    const parsed = EdgeCacheVersionSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request', details: parsed.error.issues });
      return;
    }

    const result = await bumpEdgeCacheRouteVersion(options.edgeCacheStore, parsed.data);
    const eventResult = await appendEdgeInvalidationEventSafe(
      edgeInvalidationStore,
      buildEdgeInvalidationEventInput({
        source: edgeInvalidationBundle.sourceId,
        actor: resolveInternalMutationActor(req),
        correlationId: resolveInternalCorrelationId(req),
        kind: 'version_set',
        payload: {
          routePath: result.routePath,
          version: result.currentVersion,
        },
      }),
      edgeInvalidationMaxEntries,
    );
    res.status(200).json({
      softPurged: true,
      eventLogged: eventResult.eventLogged,
      eventCursor: eventResult.eventCursor,
      ...result,
    });
  });

  router.get('/internal/edge-cache/version/export', async (req: Request, res: Response) => {
    if (!options?.edgeCache?.enabled || !options.edgeCacheStore) {
      res.status(503).json({ error: 'edge_cache_unavailable' });
      return;
    }

    const rawLimit = typeof req.query?.limit === 'string' ? req.query.limit : '1000';
    const parsedLimit = Number.parseInt(rawLimit, 10);
    const limit = Number.isFinite(parsedLimit) ? parsedLimit : 1000;

    if (edgeCacheVersionBundle.signExports) {
      if (!edgeCacheVersionBundle.signingSecret) {
        res.status(503).json({ error: 'edge_cache_version_signing_unavailable' });
        return;
      }
      const signed = await buildSignedEdgeCacheVersionExport(
        options.edgeCacheStore,
        limit,
        edgeCacheVersionBundle,
      );
      res.status(200).json({
        signed: true,
        entryCount: signed.entryCount,
        bundle: signed.bundle,
      });
      return;
    }

    const payload = await buildEdgeCacheVersionExport(
      options.edgeCacheStore,
      Math.min(limit, edgeCacheVersionBundle.exportMaxEntries),
    );
    res.status(200).json({ signed: false, ...payload });
  });

  router.post('/internal/edge-cache/version/import', async (req: Request, res: Response) => {
    if (!options?.edgeCache?.enabled || !options.edgeCacheStore) {
      res.status(503).json({ error: 'edge_cache_unavailable' });
      return;
    }

    if (hasSignedBundleShape(req.body)) {
      const signed = SignedEdgeCacheVersionBundleSchema.safeParse(req.body);
      if (!signed.success) {
        res.status(400).json({ error: 'invalid_request', details: signed.error.issues });
        return;
      }

      const verification = await verifySignedEdgeCacheVersionBundle(
        signed.data,
        {
          keyring: edgeCacheVersionBundle.keyring,
          allowedSources: edgeCacheVersionBundle.allowedSources,
          allowedKeyIds: edgeCacheVersionBundle.allowedKeyIds,
          maxSkewSeconds: edgeCacheVersionBundle.maxSkewSeconds,
          replayProtectionEnabled: edgeCacheVersionBundle.replayProtectionEnabled,
          replayCacheMaxEntries: edgeCacheVersionBundle.replayCacheMaxEntries,
        },
        options?.abuseIntelReplayStore,
      );
      if (!verification.ok) {
        res.status(401).json({ error: 'invalid_signed_bundle', reason: verification.reason });
        return;
      }

      const strategy = signed.data.strategy ?? 'max';
      const result = await applyEdgeCacheVersionImport(options.edgeCacheStore, {
        source: signed.data.source,
        strategy,
        entries: signed.data.entries,
      });
      const eventResult = await appendVersionSetInvalidationEventsSafe(
        edgeInvalidationStore,
        {
          source: edgeInvalidationBundle.sourceId,
          actor: resolveInternalMutationActor(req),
          correlationId: resolveInternalCorrelationId(req),
          applied: result.applied.map((entry) => ({
            routePath: entry.routePath,
            currentVersion: entry.currentVersion,
          })),
        },
        edgeInvalidationMaxEntries,
      );
      res.status(200).json({
        source: signed.data.source,
        signed: true,
        strategy,
        imported: result.imported,
        updated: result.updated,
        skipped: result.skipped,
        applied: result.applied,
        eventLogged: eventResult.eventLogged,
        eventCursors: eventResult.eventCursors,
      });
      return;
    }

    if (edgeCacheVersionBundle.requireSignedImports) {
      res.status(400).json({ error: 'signed_bundle_required' });
      return;
    }

    const parsed = EdgeCacheVersionImportSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request', details: parsed.error.issues });
      return;
    }

    const result = await applyEdgeCacheVersionImport(options.edgeCacheStore, {
      source: parsed.data.source,
      strategy: parsed.data.strategy,
      entries: parsed.data.entries,
    });
    const eventResult = await appendVersionSetInvalidationEventsSafe(
      edgeInvalidationStore,
      {
        source: edgeInvalidationBundle.sourceId,
        actor: resolveInternalMutationActor(req),
        correlationId: resolveInternalCorrelationId(req),
        applied: result.applied.map((entry) => ({
          routePath: entry.routePath,
          currentVersion: entry.currentVersion,
        })),
      },
      edgeInvalidationMaxEntries,
    );
    res.status(200).json({
      source: parsed.data.source,
      signed: false,
      strategy: parsed.data.strategy,
      imported: result.imported,
      updated: result.updated,
      skipped: result.skipped,
      applied: result.applied,
      eventLogged: eventResult.eventLogged,
      eventCursors: eventResult.eventCursors,
    });
  });

  router.get('/internal/edge-cache/invalidation/events', async (req: Request, res: Response) => {
    if (!options?.edgeCache?.enabled || !options.edgeCacheStore) {
      res.status(503).json({ error: 'edge_cache_unavailable' });
      return;
    }

    const afterCursor = normalizeEdgeInvalidationCursor(req.query?.afterCursor, '0');
    const limit = parseEdgeInvalidationLimit(req.query?.limit);

    try {
      const payload = await buildEdgeInvalidationExport(
        edgeInvalidationStore,
        afterCursor,
        limit,
      );
      res.status(200).json(payload);
    } catch {
      res.status(503).json({ error: 'edge_invalidation_history_unavailable' });
    }
  });

  router.get('/internal/edge-cache/invalidation/export', async (req: Request, res: Response) => {
    if (!options?.edgeCache?.enabled || !options.edgeCacheStore) {
      res.status(503).json({ error: 'edge_cache_unavailable' });
      return;
    }

    const afterCursor = normalizeEdgeInvalidationCursor(req.query?.afterCursor, '0');
    const limit = parseEdgeInvalidationLimit(req.query?.limit);

    try {
      if (edgeInvalidationBundle.signExports) {
        if (!edgeInvalidationBundle.signingSecret) {
          res.status(503).json({ error: 'edge_invalidation_signing_unavailable' });
          return;
        }

        const unsignedPayload = await buildEdgeInvalidationExport(
          edgeInvalidationStore,
          afterCursor,
          Math.min(limit, edgeInvalidationBundle.exportMaxEntries),
          edgeInvalidationBundle.sourceId,
        );
        if (unsignedPayload.entryCount === 0) {
          res.status(200).json({ signed: false, ...unsignedPayload });
          return;
        }

        const signed = await buildSignedEdgeInvalidationExport(
          edgeInvalidationStore,
          afterCursor,
          limit,
          edgeInvalidationBundle,
        );
        res.status(200).json({
          signed: true,
          entryCount: signed.entryCount,
          bundle: signed.bundle,
        });
        return;
      }

      const payload = await buildEdgeInvalidationExport(
        edgeInvalidationStore,
        afterCursor,
        Math.min(limit, edgeInvalidationBundle.exportMaxEntries),
        edgeInvalidationBundle.sourceId,
      );
      res.status(200).json({ signed: false, ...payload });
    } catch {
      res.status(503).json({ error: 'edge_invalidation_history_unavailable' });
    }
  });

  router.post('/internal/edge-cache/invalidation/import', async (req: Request, res: Response) => {
    if (!options?.edgeCache?.enabled || !options.edgeCacheStore) {
      res.status(503).json({ error: 'edge_cache_unavailable' });
      return;
    }

    if (hasSignedBundleShape(req.body)) {
      const signed = SignedEdgeInvalidationBundleSchema.safeParse(req.body);
      if (!signed.success) {
        res.status(400).json({ error: 'invalid_request', details: signed.error.issues });
        return;
      }

      const verification = await verifySignedEdgeInvalidationBundle(
        signed.data as EdgeInvalidationSignedBundle,
        {
          keyring: edgeInvalidationBundle.keyring,
          allowedSources: edgeInvalidationBundle.allowedSources,
          allowedKeyIds: edgeInvalidationBundle.allowedKeyIds,
          maxSkewSeconds: edgeInvalidationBundle.maxSkewSeconds,
          replayProtectionEnabled: edgeInvalidationBundle.replayProtectionEnabled,
          replayCacheMaxEntries: edgeInvalidationBundle.replayCacheMaxEntries,
        },
        options?.abuseIntelReplayStore,
      );
      if (!verification.ok) {
        res.status(401).json({ error: 'invalid_signed_bundle', reason: verification.reason });
        return;
      }

      try {
        const result = await applyEdgeInvalidationImport(
          edgeInvalidationStore,
          options.edgeCacheStore,
          {
            source: signed.data.source,
            fromCursor: signed.data.fromCursor,
            toCursor: signed.data.toCursor,
            entries: signed.data.entries,
          },
          {
            maxEntries: edgeInvalidationMaxEntries,
            localSourceId: edgeInvalidationBundle.sourceId,
          },
        );
        res.status(200).json({
          source: signed.data.source,
          signed: true,
          fromCursor: signed.data.fromCursor,
          toCursor: signed.data.toCursor,
          imported: result.imported,
          applied: result.applied,
          appended: result.appended,
          skipped: result.skipped,
          latestImportedCursor: result.latestImportedCursor,
        });
      } catch {
        res.status(503).json({ error: 'edge_invalidation_history_unavailable' });
      }
      return;
    }

    if (edgeInvalidationBundle.requireSignedImports) {
      res.status(400).json({ error: 'signed_bundle_required' });
      return;
    }

    const parsed = EdgeInvalidationImportSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request', details: parsed.error.issues });
      return;
    }

    try {
      const result = await applyEdgeInvalidationImport(
        edgeInvalidationStore,
        options.edgeCacheStore,
        parsed.data,
        {
          maxEntries: edgeInvalidationMaxEntries,
          localSourceId: edgeInvalidationBundle.sourceId,
        },
      );
      res.status(200).json({
        source: parsed.data.source,
        signed: false,
        fromCursor: parsed.data.fromCursor,
        toCursor: parsed.data.toCursor ?? result.latestImportedCursor,
        imported: result.imported,
        applied: result.applied,
        appended: result.appended,
        skipped: result.skipped,
        latestImportedCursor: result.latestImportedCursor,
      });
    } catch {
      res.status(503).json({ error: 'edge_invalidation_history_unavailable' });
    }
  });

  router.get('/internal/security-controls', async (_req: Request, res: Response) => {
    if (!options?.gatewayConfig) {
      res.status(503).json({ error: 'security_controls_unavailable' });
      return;
    }
    try {
      const pointers = await securityControlsAuditStore.getChainPointers();
      const revision = buildSecurityControlsRevision({
        total: pointers.total,
        latestEntryHash: pointers.latestEntryHash,
        anchorHash: pointers.anchorHash,
      });
      res.status(200).json({
        revision,
        controls: buildSecurityControlsSnapshot(options.gatewayConfig),
      });
    } catch {
      res.status(503).json({ error: 'security_controls_history_unavailable' });
    }
  });

  router.get('/internal/security-controls/history', async (req: Request, res: Response) => {
    try {
      const history = await securityControlsAuditStore.listAll();
      const limit = parseSecurityControlsHistoryLimit(req.query?.limit);
      const startIndex = Math.max(0, history.entries.length - limit);
      const entries = history.entries.slice(startIndex);
      const verification = verifySecurityControlsAuditChain({
        entries: history.entries,
        signingSecret: securityControlsAuditSecret,
        initialPreviousEntryHash: history.anchorHash,
      });
      const pointers = await securityControlsAuditStore.getChainPointers();
      const revision = buildSecurityControlsRevision({
        total: pointers.total,
        latestEntryHash: pointers.latestEntryHash,
        anchorHash: pointers.anchorHash,
      });

      res.status(200).json({
        total: history.total,
        returned: entries.length,
        limit,
        revision,
        verification,
        entries,
      });
    } catch {
      res.status(503).json({ error: 'security_controls_history_unavailable' });
    }
  });

  router.get('/internal/security-controls/history/verify', async (_req: Request, res: Response) => {
    try {
      const history = await securityControlsAuditStore.listAll();
      const verification = verifySecurityControlsAuditChain({
        entries: history.entries,
        signingSecret: securityControlsAuditSecret,
        initialPreviousEntryHash: history.anchorHash,
      });
      const pointers = await securityControlsAuditStore.getChainPointers();
      const revision = buildSecurityControlsRevision({
        total: pointers.total,
        latestEntryHash: pointers.latestEntryHash,
        anchorHash: pointers.anchorHash,
      });
      res.status(200).json({
        ...verification,
        total: history.total,
        revision,
      });
    } catch {
      res.status(503).json({ error: 'security_controls_history_unavailable' });
    }
  });

  router.get('/internal/security-controls/history/export', async (req: Request, res: Response) => {
    try {
      const rawLimit = typeof req.query?.limit === 'string' ? req.query.limit : '1000';
      const parsedLimit = Number.parseInt(rawLimit, 10);
      const limit = Number.isFinite(parsedLimit) ? parsedLimit : 1000;

      if (securityControlsHistoryBundle.signExports) {
        if (!securityControlsHistoryBundle.signingSecret) {
          res.status(503).json({ error: 'security_controls_history_signing_unavailable' });
          return;
        }
        const signed = await buildSignedSecurityControlsHistoryExport(
          securityControlsAuditStore,
          limit,
          securityControlsHistoryBundle,
        );
        res.status(200).json({
          signed: true,
          entryCount: signed.entryCount,
          bundle: signed.bundle,
        });
        return;
      }

      const payload = await buildSecurityControlsHistoryExport(
        securityControlsAuditStore,
        Math.min(limit, securityControlsHistoryBundle.exportMaxEntries),
      );
      res.status(200).json({ signed: false, ...payload });
    } catch {
      res.status(503).json({ error: 'security_controls_history_unavailable' });
    }
  });

  router.post('/internal/security-controls/history/import', async (req: Request, res: Response) => {
    const fallbackSnapshotHash = sha256Hex(
      options?.gatewayConfig
        ? buildSecurityControlsSnapshot(options.gatewayConfig)
        : { unavailable: true },
    );

    if (hasSignedBundleShape(req.body)) {
      const signed = SignedSecurityControlsHistoryBundleSchema.safeParse(req.body);
      if (!signed.success) {
        res.status(400).json({ error: 'invalid_request', details: signed.error.issues });
        return;
      }

      const verification = await verifySignedSecurityControlsHistoryBundle(
        signed.data as SecurityControlsHistorySignedBundle,
        {
          keyring: securityControlsHistoryBundle.keyring,
          allowedSources: securityControlsHistoryBundle.allowedSources,
          allowedKeyIds: securityControlsHistoryBundle.allowedKeyIds,
          maxSkewSeconds: securityControlsHistoryBundle.maxSkewSeconds,
          replayProtectionEnabled: securityControlsHistoryBundle.replayProtectionEnabled,
          replayCacheMaxEntries: securityControlsHistoryBundle.replayCacheMaxEntries,
        },
        options?.abuseIntelReplayStore,
      );
      if (!verification.ok) {
        res.status(401).json({ error: 'invalid_signed_bundle', reason: verification.reason });
        return;
      }

      try {
        const result = await applySecurityControlsHistoryImport(
          securityControlsAuditStore,
          {
            source: signed.data.source,
            entries: signed.data.entries,
          },
          {
            signingSecret: securityControlsAuditSecret,
            maxEntries: securityControlsHistoryMaxEntries,
            fallbackSnapshotHash,
          },
        );
        res.status(200).json({
          source: signed.data.source,
          signed: true,
          imported: result.imported,
          skipped: result.skipped,
          importedIds: result.importedIds,
        });
      } catch {
        res.status(503).json({ error: 'security_controls_history_unavailable' });
      }
      return;
    }

    if (securityControlsHistoryBundle.requireSignedImports) {
      res.status(400).json({ error: 'signed_bundle_required' });
      return;
    }

    const parsed = SecurityControlsHistoryImportSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request', details: parsed.error.issues });
      return;
    }

    try {
      const result = await applySecurityControlsHistoryImport(
        securityControlsAuditStore,
        {
          source: parsed.data.source,
          entries: parsed.data.entries,
        },
        {
          signingSecret: securityControlsAuditSecret,
          maxEntries: securityControlsHistoryMaxEntries,
          fallbackSnapshotHash,
        },
      );
      res.status(200).json({
        source: parsed.data.source,
        signed: false,
        imported: result.imported,
        skipped: result.skipped,
        importedIds: result.importedIds,
      });
    } catch {
      res.status(503).json({ error: 'security_controls_history_unavailable' });
    }
  });

  router.get('/internal/security-controls/history/:id', async (req: Request, res: Response) => {
    const id = String(req.params.id ?? '').trim();
    if (!id) {
      res.status(400).json({ error: 'invalid_request', details: [{ message: 'id is required' }] });
      return;
    }

    try {
      const entry = await securityControlsAuditStore.getById(id);
      if (!entry) {
        res.status(404).json({ error: 'not_found' });
        return;
      }

      res.status(200).json(entry);
    } catch {
      res.status(503).json({ error: 'security_controls_history_unavailable' });
    }
  });

  router.patch('/internal/security-controls', async (req: Request, res: Response) => {
    if (!options?.gatewayConfig) {
      res.status(503).json({ error: 'security_controls_unavailable' });
      return;
    }

    const parsedRequest = parseSecurityControlsPatchRequestBody(req.body);
    if (!parsedRequest.ok) {
      res.status(400).json({ error: 'invalid_request', details: parsedRequest.issues });
      return;
    }

    const headerRevision = extractIfMatchRevisionHeader(req.headers['if-match']);
    if (parsedRequest.ifRevision && headerRevision && parsedRequest.ifRevision !== headerRevision) {
      res.status(400).json({
        error: 'ambiguous_revision_precondition',
        details: [{
          message: 'ifRevision body field and If-Match header must match when both are provided',
        }],
      });
      return;
    }

    const expectedRevision = parsedRequest.ifRevision || headerRevision || null;
    const preview = previewSecurityControlsPatch(options.gatewayConfig, parsedRequest.patch);
    if (!preview.ok) {
      res.status(400).json({ error: 'invalid_security_controls_patch', details: preview.issues });
      return;
    }

    const actor = String(
      req.headers['x-internal-caller'] ??
      req.headers['x-caller-id'] ??
      'unknown',
    );
    const correlationId = String(req.headers['x-correlation-id'] ?? 'unknown');

    try {
      const chain = await securityControlsAuditStore.getChainPointers();
      const currentRevision = buildSecurityControlsRevision({
        total: chain.total,
        latestEntryHash: chain.latestEntryHash,
        anchorHash: chain.anchorHash,
      });
      if (expectedRevision && expectedRevision !== currentRevision) {
        res.status(409).json({
          error: 'revision_conflict',
          requestedRevision: expectedRevision,
          currentRevision,
        });
        return;
      }

      if (parsedRequest.dryRun) {
        res.status(200).json({
          updated: false,
          dryRun: true,
          revision: currentRevision || SECURITY_CONTROLS_REVISION_FALLBACK,
          snapshot: preview.snapshot,
        });
        return;
      }

      const previousEntryHash = chain.latestEntryHash ?? chain.anchorHash;
      const auditEntry = buildSecurityControlsAuditEntry({
        patch: parsedRequest.patch,
        snapshot: preview.snapshot,
        previousEntryHash,
        actor,
        correlationId,
        signingSecret: securityControlsAuditSecret,
      });
      const appendResult = await securityControlsAuditStore.append(
        auditEntry,
        securityControlsHistoryMaxEntries,
      );
      const revision = buildSecurityControlsRevision({
        total: appendResult.total,
        latestEntryHash: appendResult.latestEntryHash,
        anchorHash: appendResult.anchorHash,
      });

      options.gatewayConfig.waf = preview.nextControls.waf;
      options.gatewayConfig.botManagement = preview.nextControls.botManagement;
      options.gatewayConfig.accessControl = preview.nextControls.accessControl;

      res.status(200).json({
        updated: true,
        dryRun: false,
        revision,
        snapshot: preview.snapshot,
        audit: {
          id: auditEntry.id,
          changedAt: auditEntry.changedAt,
          entryHash: auditEntry.entryHash,
          signature: auditEntry.signature,
          total: appendResult.total,
        },
      });
    } catch {
      res.status(503).json({ error: 'security_controls_history_unavailable' });
    }
  });

  router.post('/internal/block-ip', async (req: Request, res: Response) => {
    const parsed = BlockIpSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request', details: parsed.error.issues });
      return;
    }

    const ips = parsed.data.ips ?? (parsed.data.ip ? [parsed.data.ip] : []);
    const entries = await state.blockIps(ips, parsed.data.ttlSeconds, {
      reason: parsed.data.reason,
      alertId: parsed.data.alertId,
    });

    res.status(200).json({ blocked: entries });
  });

  router.post('/internal/unblock-ip', async (req: Request, res: Response) => {
    const ip = typeof req.body?.ip === 'string' ? req.body.ip : '';
    if (!ip) {
      res.status(400).json({ error: 'invalid_request', details: [{ message: 'ip is required' }] });
      return;
    }
    await state.unblockIp(ip);
    res.status(200).json({ unblocked: ip });
  });

  router.post('/internal/require-step-up', async (req: Request, res: Response) => {
    const parsed = RequireStepUpSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request', details: parsed.error.issues });
      return;
    }

    const entry = await state.requireStepUp(
      parsed.data.userId,
      parsed.data.requiredLevel,
      parsed.data.ttlSeconds,
      { reason: parsed.data.reason, alertId: parsed.data.alertId }
    );

    res.status(200).json({ stepUp: entry });
  });

  router.post('/internal/clear-step-up', async (req: Request, res: Response) => {
    const userId = typeof req.body?.userId === 'string' ? req.body.userId : '';
    if (!userId) {
      res.status(400).json({ error: 'invalid_request', details: [{ message: 'userId is required' }] });
      return;
    }
    await state.clearStepUpRequirement(userId);
    res.status(200).json({ cleared: userId });
  });

  router.post('/internal/throttle-user', async (req: Request, res: Response) => {
    const parsed = ThrottleUserSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request', details: parsed.error.issues });
      return;
    }

    const entry = await state.throttleUser(
      parsed.data.userId,
      parsed.data.reducedRatePercent,
      parsed.data.ttlSeconds,
      { reason: parsed.data.reason, alertId: parsed.data.alertId }
    );

    res.status(200).json({ throttle: entry });
  });

  router.post('/internal/clear-throttle', async (req: Request, res: Response) => {
    const userId = typeof req.body?.userId === 'string' ? req.body.userId : '';
    if (!userId) {
      res.status(400).json({ error: 'invalid_request', details: [{ message: 'userId is required' }] });
      return;
    }
    await state.clearThrottle(userId);
    res.status(200).json({ cleared: userId });
  });

  return router;
}
