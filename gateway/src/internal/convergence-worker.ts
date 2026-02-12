import { randomUUID } from 'crypto';
import type { EdgeCacheStore } from '../state/edge-cache-store';
import type { ControlPlaneAuditStore } from '../state/control-plane-audit-store';
import type { EdgeInvalidationEventStore } from '../state/edge-invalidation-event-store';
import type { SecurityControlsAuditStore } from '../state/security-controls-audit-store';
import {
  applyControlPlaneAuditImport,
  applyEdgeCacheVersionImport,
  applyEdgeInvalidationImport,
  applyRoutePolicyImport,
  applySecurityControlsHistoryImport,
  applyUpstreamRoutingPolicyImport,
  buildControlPlaneAuditEventInput,
  buildSecurityControlsRevision,
} from './internal-routes';
import {
  type SignedEdgeCacheVersionBundle,
  type SignedEdgeCacheVersionBundleConfig,
  verifySignedEdgeCacheVersionBundle,
} from './edge-cache-version-signing';
import {
  type SignedSecurityControlsHistoryBundle,
  type SignedSecurityControlsHistoryBundleConfig,
  verifySignedSecurityControlsHistoryBundle,
} from './security-controls-history-signing';
import {
  type SignedEdgeInvalidationBundle,
  type SignedEdgeInvalidationBundleConfig,
  verifySignedEdgeInvalidationBundle,
} from './edge-invalidation-signing';
import {
  type SignedControlPlaneAuditBundle,
  type SignedControlPlaneAuditBundleConfig,
  verifySignedControlPlaneAuditBundle,
} from './control-plane-audit-signing';
import {
  type SignedRoutePolicyBundle,
  type SignedRoutePolicyBundleConfig,
  verifySignedRoutePolicyBundle,
} from './route-policy-signing';
import {
  type SignedUpstreamRoutingPolicyBundle,
  type SignedUpstreamRoutingPolicyBundleConfig,
  verifySignedUpstreamRoutingPolicyBundle,
} from './upstream-policy-signing';
import {
  signConvergenceTelemetryPayload,
  type SignedConvergenceTelemetry,
} from './convergence-telemetry-signing';
import type { RoutePolicyManager } from '../proxy/route-policy-manager';
import type { UpstreamRoutingPolicyManager } from '../proxy/upstream-policy-manager';

interface FetchResponseLike {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

interface ConvergenceFetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

type ConvergenceFetchFn = (url: string, init?: ConvergenceFetchInit) => Promise<FetchResponseLike>;

export interface ConvergenceSecurityControlsConfig {
  auditStore: SecurityControlsAuditStore;
  signingSecret: string;
  maxEntries: number;
  requireSignedImports: boolean;
  verification: SignedSecurityControlsHistoryBundleConfig;
}

export interface ConvergenceEdgeCacheConfig {
  store: EdgeCacheStore;
  requireSignedImports: boolean;
  verification: SignedEdgeCacheVersionBundleConfig;
  invalidation?: ConvergenceEdgeInvalidationConfig;
}

export interface ConvergenceControlPlaneAuditConfig {
  store: ControlPlaneAuditStore;
  maxEntries: number;
  localSourceId: string;
  requireSignedImports: boolean;
  verification: SignedControlPlaneAuditBundleConfig;
}

export interface ConvergenceUpstreamRoutingConfig {
  manager: UpstreamRoutingPolicyManager;
  requireSignedImports: boolean;
  verification: SignedUpstreamRoutingPolicyBundleConfig;
}

export interface ConvergenceRoutePolicyConfig {
  manager: RoutePolicyManager;
  requireSignedImports: boolean;
  verification: SignedRoutePolicyBundleConfig;
}

export interface ConvergencePolicyQuorumConfig {
  enabled: boolean;
  minPeers: number;
}

export interface ConvergenceAuditTrailConfig {
  store: ControlPlaneAuditStore;
  maxEntries: number;
  localSourceId: string;
  actor: string;
  signingKeyId: string;
  signingSecret: string;
  path: string;
  permissionScope: string;
}

export interface ConvergenceEdgeInvalidationConfig {
  eventStore: EdgeInvalidationEventStore;
  maxEntries: number;
  localSourceId: string;
  requireSignedImports: boolean;
  verification: SignedEdgeInvalidationBundleConfig;
}

export interface ConvergenceWorkerOptions {
  peers: string[];
  autoHeal: boolean;
  exportLimit: number;
  securityControls: ConvergenceSecurityControlsConfig;
  edgeCache?: ConvergenceEdgeCacheConfig;
  controlPlaneAudit?: ConvergenceControlPlaneAuditConfig;
  upstreamRouting?: ConvergenceUpstreamRoutingConfig;
  routePolicy?: ConvergenceRoutePolicyConfig;
  policyQuorum?: ConvergencePolicyQuorumConfig;
  auditTrail?: ConvergenceAuditTrailConfig;
  fetchFn?: ConvergenceFetchFn;
  requestHeaders?: Record<string, string>;
}

export interface ConvergencePeerResult {
  peer: string;
  securityControls: {
    localRevision: string;
    remoteRevision: string | null;
    driftDetected: boolean;
    healed: boolean;
    imported: number;
    skipped: number;
    error?: string;
  };
  edgeCache?: {
    driftDetected: boolean;
    healed: boolean;
    imported: number;
    updated: number;
    skipped: number;
    error?: string;
  };
  edgeInvalidation?: {
    source: string | null;
    localCursor: string;
    remoteCursor: string | null;
    driftDetected: boolean;
    healed: boolean;
    imported: number;
    applied: number;
    appended: number;
    skipped: number;
    pagesFetched: number;
    error?: string;
  };
  controlPlaneAudit?: {
    source: string | null;
    localCursor: string;
    remoteCursor: string | null;
    driftDetected: boolean;
    healed: boolean;
    imported: number;
    appended: number;
    skipped: number;
    pagesFetched: number;
    error?: string;
  };
  upstreamRouting?: {
    source: string | null;
    localRevision: string;
    remoteRevision: string | null;
    driftDetected: boolean;
    healed: boolean;
    changed: boolean;
    skipped: boolean;
    changedUpstreams: number;
    quorumVotes?: number;
    quorumRequired?: number;
    quorumSatisfied?: boolean;
    error?: string;
  };
  routePolicy?: {
    source: string | null;
    localRevision: string;
    remoteRevision: string | null;
    driftDetected: boolean;
    healed: boolean;
    changed: boolean;
    skipped: boolean;
    changedRoutes: number;
    quorumVotes?: number;
    quorumRequired?: number;
    quorumSatisfied?: boolean;
    error?: string;
  };
  telemetry?: SignedConvergenceTelemetry & {
    signedAt: string;
  };
  auditTrailError?: string;
}

export interface ConvergenceRunResult {
  startedAt: string;
  finishedAt: string;
  peers: number;
  driftsDetected: number;
  healedPeers: number;
  errors: number;
  results: ConvergencePeerResult[];
}

interface SecurityControlsExportBodyUnsigned {
  signed?: false;
  entries?: Array<{
    changedAt: string;
    actor: string;
    correlationId?: string;
    patch: Record<string, unknown>;
    snapshotHash?: string;
  }>;
}

interface EdgeCacheVersionExportBodyUnsigned {
  signed?: false;
  entries?: Array<{
    routePath: string;
    version: string;
  }>;
  strategy?: 'max' | 'overwrite';
}

interface EdgeInvalidationExportBodyUnsigned {
  signed?: false;
  source?: string;
  fromCursor?: string;
  toCursor?: string;
  entries?: Array<{
    cursor: string;
    eventId: string;
    source: string;
    occurredAt: string;
    actor: string;
    correlationId?: string;
    kind: 'purge' | 'version_set';
    payload: Record<string, unknown>;
  }>;
}

type EdgeInvalidationEntries = NonNullable<EdgeInvalidationExportBodyUnsigned['entries']>;

interface ControlPlaneAuditExportBodyUnsigned {
  signed?: false;
  source?: string;
  fromCursor?: string;
  toCursor?: string;
  entries?: Array<{
    cursor: string;
    eventId: string;
    source: string;
    occurredAt: string;
    actor: string;
    correlationId?: string;
    method: 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    path: string;
    statusCode: number;
    outcome: 'success' | 'failure';
    requestBodyHash: string;
    requestContentLength?: number;
    idempotencyKey?: string;
    permissionScope?: string;
  }>;
}

type ControlPlaneAuditEntries = NonNullable<ControlPlaneAuditExportBodyUnsigned['entries']>;

interface UpstreamRoutingExportBodyUnsigned {
  signed?: false;
  source?: string;
  revision?: string;
  upstreams?: Record<string, Record<string, unknown>>;
}

interface RoutePolicyExportBodyUnsigned {
  signed?: false;
  source?: string;
  revision?: string;
  routes?: Array<Record<string, unknown>>;
}

function normalizeExportLimit(limit: number): number {
  if (!Number.isFinite(limit)) return 1000;
  return Math.max(1, Math.min(Math.floor(limit), 5000));
}

function normalizePeerUrl(value: string): string {
  return value.trim().replace(/\/+$/, '');
}

function parseVersionBigInt(value: string): bigint | null {
  if (!/^\d{1,32}$/.test(value)) return null;
  try {
    return BigInt(value);
  } catch {
    return null;
  }
}

function parseCursorBigInt(value: string): bigint {
  if (!/^\d{1,32}$/.test(value)) return 0n;
  try {
    return BigInt(value);
  } catch {
    return 0n;
  }
}

export function detectSecurityControlsDrift(localRevision: string, remoteRevision: string | null): boolean {
  if (!remoteRevision) return false;
  return localRevision !== remoteRevision;
}

export function detectEdgeCacheVersionDrift(
  localEntries: Array<{ routePath: string; version: string }>,
  remoteEntries: Array<{ routePath: string; version: string }>,
): boolean {
  const localMap = new Map<string, string>();
  for (const entry of localEntries) {
    localMap.set(entry.routePath, entry.version);
  }

  for (const remote of remoteEntries) {
    const localVersion = localMap.get(remote.routePath) ?? '0';
    const localNum = parseVersionBigInt(localVersion);
    const remoteNum = parseVersionBigInt(remote.version);
    if (remoteNum === null) continue;
    if (localNum === null || remoteNum > localNum) {
      return true;
    }
  }
  return false;
}

export function detectEdgeInvalidationCursorDrift(localCursor: string, remoteCursor: string | null): boolean {
  if (!remoteCursor) return false;
  return parseCursorBigInt(remoteCursor) > parseCursorBigInt(localCursor);
}

export function detectControlPlaneAuditCursorDrift(localCursor: string, remoteCursor: string | null): boolean {
  if (!remoteCursor) return false;
  return parseCursorBigInt(remoteCursor) > parseCursorBigInt(localCursor);
}

export function detectUpstreamRoutingDrift(localRevision: string, remoteRevision: string | null): boolean {
  if (!remoteRevision) return false;
  return localRevision !== remoteRevision;
}

export function detectRoutePolicyDrift(localRevision: string, remoteRevision: string | null): boolean {
  if (!remoteRevision) return false;
  return localRevision !== remoteRevision;
}

function normalizeQuorumMinPeers(value: number | undefined, peerCount: number): number {
  if (!Number.isFinite(value)) return Math.max(1, Math.min(2, peerCount));
  const parsed = Math.floor(value as number);
  return Math.max(1, Math.min(Math.max(1, peerCount), parsed));
}

function incrementRevisionVote(counter: Map<string, number>, revision: string): void {
  const current = counter.get(revision) ?? 0;
  counter.set(revision, current + 1);
}

function buildPeerTelemetryPayload(
  runId: string,
  result: ConvergencePeerResult,
  finishedAt: string,
): Record<string, unknown> {
  return {
    runId,
    peer: result.peer,
    finishedAt,
    securityControls: {
      driftDetected: result.securityControls.driftDetected,
      healed: result.securityControls.healed,
      remoteRevision: result.securityControls.remoteRevision,
      localRevision: result.securityControls.localRevision,
      imported: result.securityControls.imported,
      skipped: result.securityControls.skipped,
      error: result.securityControls.error,
    },
    edgeCache: result.edgeCache ? {
      driftDetected: result.edgeCache.driftDetected,
      healed: result.edgeCache.healed,
      imported: result.edgeCache.imported,
      updated: result.edgeCache.updated,
      skipped: result.edgeCache.skipped,
      error: result.edgeCache.error,
    } : undefined,
    edgeInvalidation: result.edgeInvalidation ? {
      driftDetected: result.edgeInvalidation.driftDetected,
      healed: result.edgeInvalidation.healed,
      imported: result.edgeInvalidation.imported,
      applied: result.edgeInvalidation.applied,
      appended: result.edgeInvalidation.appended,
      skipped: result.edgeInvalidation.skipped,
      pagesFetched: result.edgeInvalidation.pagesFetched,
      remoteCursor: result.edgeInvalidation.remoteCursor,
      localCursor: result.edgeInvalidation.localCursor,
      error: result.edgeInvalidation.error,
    } : undefined,
    controlPlaneAudit: result.controlPlaneAudit ? {
      driftDetected: result.controlPlaneAudit.driftDetected,
      healed: result.controlPlaneAudit.healed,
      imported: result.controlPlaneAudit.imported,
      appended: result.controlPlaneAudit.appended,
      skipped: result.controlPlaneAudit.skipped,
      pagesFetched: result.controlPlaneAudit.pagesFetched,
      remoteCursor: result.controlPlaneAudit.remoteCursor,
      localCursor: result.controlPlaneAudit.localCursor,
      error: result.controlPlaneAudit.error,
    } : undefined,
    routePolicy: result.routePolicy ? {
      driftDetected: result.routePolicy.driftDetected,
      healed: result.routePolicy.healed,
      changed: result.routePolicy.changed,
      skipped: result.routePolicy.skipped,
      changedRoutes: result.routePolicy.changedRoutes,
      remoteRevision: result.routePolicy.remoteRevision,
      localRevision: result.routePolicy.localRevision,
      quorumVotes: result.routePolicy.quorumVotes,
      quorumRequired: result.routePolicy.quorumRequired,
      quorumSatisfied: result.routePolicy.quorumSatisfied,
      error: result.routePolicy.error,
    } : undefined,
    upstreamRouting: result.upstreamRouting ? {
      driftDetected: result.upstreamRouting.driftDetected,
      healed: result.upstreamRouting.healed,
      changed: result.upstreamRouting.changed,
      skipped: result.upstreamRouting.skipped,
      changedUpstreams: result.upstreamRouting.changedUpstreams,
      remoteRevision: result.upstreamRouting.remoteRevision,
      localRevision: result.upstreamRouting.localRevision,
      quorumVotes: result.upstreamRouting.quorumVotes,
      quorumRequired: result.upstreamRouting.quorumRequired,
      quorumSatisfied: result.upstreamRouting.quorumSatisfied,
      error: result.upstreamRouting.error,
    } : undefined,
  };
}

async function fetchJson(
  fetchFn: ConvergenceFetchFn,
  url: string,
  init?: ConvergenceFetchInit,
): Promise<{ ok: true; status: number; data: unknown } | { ok: false; status: number; error: string }> {
  try {
    const response = await fetchFn(url, init);
    if (!response.ok) {
      return { ok: false, status: response.status, error: `http_${response.status}` };
    }
    const data = await response.json();
    return { ok: true, status: response.status, data };
  } catch (error) {
    return {
      ok: false,
      status: 0,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

async function resolveLocalSecurityRevision(auditStore: SecurityControlsAuditStore): Promise<string> {
  const pointers = await auditStore.getChainPointers();
  return buildSecurityControlsRevision({
    total: pointers.total,
    latestEntryHash: pointers.latestEntryHash,
    anchorHash: pointers.anchorHash,
  });
}

function normalizeCursor(value: unknown, fallback = '0'): string {
  if (typeof value !== 'string') return fallback;
  const trimmed = value.trim();
  if (!/^\d{1,32}$/.test(trimmed)) return fallback;
  return trimmed;
}

function normalizeEdgeInvalidationEntries(
  raw: unknown,
): Array<{
  cursor: string;
  eventId: string;
  source: string;
  occurredAt: string;
  actor: string;
  correlationId?: string;
  kind: 'purge' | 'version_set';
  payload: Record<string, unknown>;
}> {
  if (!Array.isArray(raw)) return [];
  const entries: Array<{
    cursor: string;
    eventId: string;
    source: string;
    occurredAt: string;
    actor: string;
    correlationId?: string;
    kind: 'purge' | 'version_set';
    payload: Record<string, unknown>;
  }> = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const record = item as Record<string, unknown>;
    const kind = record['kind'];
    if (kind !== 'purge' && kind !== 'version_set') continue;
    const cursor = normalizeCursor(record['cursor'], '');
    const eventId = String(record['eventId'] ?? '').trim();
    const source = String(record['source'] ?? '').trim();
    const occurredAt = String(record['occurredAt'] ?? '').trim();
    const actor = String(record['actor'] ?? '').trim();
    if (!cursor || !eventId || !source || !occurredAt || !actor) continue;
    const payload = record['payload'];
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) continue;
    const correlationId = String(record['correlationId'] ?? '').trim();
    entries.push({
      cursor,
      eventId,
      source,
      occurredAt,
      actor,
      correlationId: correlationId || undefined,
      kind,
      payload: payload as Record<string, unknown>,
    });
  }
  return entries;
}

function normalizeControlPlaneAuditEntries(
  raw: unknown,
): ControlPlaneAuditEntries {
  if (!Array.isArray(raw)) return [];
  const entries: ControlPlaneAuditEntries = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const record = item as Record<string, unknown>;
    const method = String(record['method'] ?? '').toUpperCase();
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) continue;
    const outcome = String(record['outcome'] ?? '').toLowerCase();
    if (outcome !== 'success' && outcome !== 'failure') continue;
    const cursor = normalizeCursor(record['cursor'], '');
    const eventId = String(record['eventId'] ?? '').trim();
    const source = String(record['source'] ?? '').trim();
    const occurredAt = String(record['occurredAt'] ?? '').trim();
    const actor = String(record['actor'] ?? '').trim();
    const path = String(record['path'] ?? '').trim();
    const requestBodyHash = String(record['requestBodyHash'] ?? '').trim().toLowerCase();
    const statusCode = Number(record['statusCode'] ?? 0);
    if (!cursor || !eventId || !source || !occurredAt || !actor || !path || !requestBodyHash) continue;
    if (!path.startsWith('/internal/')) continue;
    if (!Number.isFinite(statusCode) || statusCode < 100 || statusCode > 599) continue;
    if (!/^[a-f0-9]{64}$/.test(requestBodyHash)) continue;
    const correlationId = String(record['correlationId'] ?? '').trim();
    const requestContentLength = Number(record['requestContentLength'] ?? NaN);
    const idempotencyKey = String(record['idempotencyKey'] ?? '').trim();
    const permissionScope = String(record['permissionScope'] ?? '').trim();
    entries.push({
      cursor,
      eventId,
      source,
      occurredAt,
      actor,
      correlationId: correlationId || undefined,
      method: method as 'POST' | 'PUT' | 'PATCH' | 'DELETE',
      path,
      statusCode,
      outcome: outcome as 'success' | 'failure',
      requestBodyHash,
      requestContentLength:
        Number.isFinite(requestContentLength) && requestContentLength >= 0
          ? requestContentLength
          : undefined,
      idempotencyKey: idempotencyKey || undefined,
      permissionScope: permissionScope || undefined,
    });
  }
  return entries;
}

async function fetchEdgeInvalidationPage(
  fetchFn: ConvergenceFetchFn,
  peer: string,
  afterCursor: string,
  limit: number,
  headers: Record<string, string>,
  config: ConvergenceEdgeInvalidationConfig,
): Promise<
{ ok: true; source: string; fromCursor: string; toCursor: string; entries: EdgeInvalidationEntries } |
{ ok: false; error: string }
> {
  const queryAfter = encodeURIComponent(afterCursor);
  const response = await fetchJson(
    fetchFn,
    `${peer}/internal/edge-cache/invalidation/export?afterCursor=${queryAfter}&limit=${limit}`,
    { headers },
  );
  if (!response.ok) {
    return { ok: false, error: `edge_invalidation_export_failed:${response.error}` };
  }

  const payload = response.data as Record<string, unknown>;
  if (payload['signed'] === true) {
    const bundle = payload['bundle'] as SignedEdgeInvalidationBundle | undefined;
    if (!bundle) {
      return { ok: false, error: 'edge_invalidation_bundle_missing' };
    }
    const verified = await verifySignedEdgeInvalidationBundle(bundle, config.verification);
    if (!verified.ok) {
      return { ok: false, error: `edge_invalidation_bundle_invalid:${verified.reason}` };
    }
    return {
      ok: true,
      source: bundle.source,
      fromCursor: normalizeCursor(bundle.fromCursor),
      toCursor: normalizeCursor(bundle.toCursor),
      entries: bundle.entries,
    };
  }

  const unsigned = payload as EdgeInvalidationExportBodyUnsigned;
  const entries = normalizeEdgeInvalidationEntries(unsigned.entries);
  let source =
    String(unsigned.source ?? '').trim() ||
    String(entries[0]?.source ?? '').trim();
  const fromCursor = normalizeCursor(unsigned.fromCursor, afterCursor);
  const toCursor = normalizeCursor(unsigned.toCursor, fromCursor);

  if (config.requireSignedImports && !(entries.length === 0 && toCursor === fromCursor)) {
    return { ok: false, error: 'edge_invalidation_signed_bundle_required' };
  }
  if (!source && entries.length === 0 && toCursor === fromCursor) {
    source = 'peer';
  }
  if (!source) {
    return { ok: false, error: 'edge_invalidation_source_missing' };
  }

  return {
    ok: true,
    source,
    fromCursor,
    toCursor,
    entries,
  };
}

async function fetchControlPlaneAuditPage(
  fetchFn: ConvergenceFetchFn,
  peer: string,
  afterCursor: string,
  limit: number,
  headers: Record<string, string>,
  config: ConvergenceControlPlaneAuditConfig,
): Promise<
{ ok: true; source: string; fromCursor: string; toCursor: string; entries: ControlPlaneAuditEntries } |
{ ok: false; error: string }
> {
  const queryAfter = encodeURIComponent(afterCursor);
  const response = await fetchJson(
    fetchFn,
    `${peer}/internal/control-plane/audit/export?afterCursor=${queryAfter}&limit=${limit}`,
    { headers },
  );
  if (!response.ok) {
    return { ok: false, error: `control_plane_audit_export_failed:${response.error}` };
  }

  const payload = response.data as Record<string, unknown>;
  if (payload['signed'] === true) {
    const bundle = payload['bundle'] as SignedControlPlaneAuditBundle | undefined;
    if (!bundle) {
      return { ok: false, error: 'control_plane_audit_bundle_missing' };
    }
    const verified = await verifySignedControlPlaneAuditBundle(bundle, config.verification);
    if (!verified.ok) {
      return { ok: false, error: `control_plane_audit_bundle_invalid:${verified.reason}` };
    }
    return {
      ok: true,
      source: bundle.source,
      fromCursor: normalizeCursor(bundle.fromCursor),
      toCursor: normalizeCursor(bundle.toCursor),
      entries: normalizeControlPlaneAuditEntries(bundle.entries),
    };
  }

  const unsigned = payload as ControlPlaneAuditExportBodyUnsigned;
  const entries = normalizeControlPlaneAuditEntries(unsigned.entries);
  let source =
    String(unsigned.source ?? '').trim() ||
    String(entries[0]?.source ?? '').trim();
  const fromCursor = normalizeCursor(unsigned.fromCursor, afterCursor);
  const toCursor = normalizeCursor(unsigned.toCursor, fromCursor);

  if (config.requireSignedImports && !(entries.length === 0 && toCursor === fromCursor)) {
    return { ok: false, error: 'control_plane_audit_signed_bundle_required' };
  }
  if (!source && entries.length === 0 && toCursor === fromCursor) {
    source = 'peer';
  }
  if (!source) {
    return { ok: false, error: 'control_plane_audit_source_missing' };
  }

  return {
    ok: true,
    source,
    fromCursor,
    toCursor,
    entries,
  };
}

function normalizeUpstreamRoutingPolicies(
  raw: unknown,
): Record<string, Record<string, unknown>> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return {};
  }
  const output: Record<string, Record<string, unknown>> = {};
  for (const [name, value] of Object.entries(raw as Record<string, unknown>)) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) continue;
    output[name] = value as Record<string, unknown>;
  }
  return output;
}

function normalizeRoutePolicies(raw: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(raw)) return [];
  const output: Array<Record<string, unknown>> = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
    output.push(item as Record<string, unknown>);
  }
  return output;
}

async function fetchUpstreamRoutingSnapshot(
  fetchFn: ConvergenceFetchFn,
  peer: string,
  headers: Record<string, string>,
  config: ConvergenceUpstreamRoutingConfig,
): Promise<
{ ok: true; source: string; revision: string; upstreams: Record<string, Record<string, unknown>> } |
{ ok: false; error: string }
> {
  const response = await fetchJson(
    fetchFn,
    `${peer}/internal/upstreams/policy/export`,
    { headers },
  );
  if (!response.ok) {
    return { ok: false, error: `upstream_routing_export_failed:${response.error}` };
  }

  const payload = response.data as Record<string, unknown>;
  if (payload['signed'] === true) {
    const bundle = payload['bundle'] as SignedUpstreamRoutingPolicyBundle | undefined;
    if (!bundle) {
      return { ok: false, error: 'upstream_routing_bundle_missing' };
    }
    const verified = await verifySignedUpstreamRoutingPolicyBundle(bundle, config.verification);
    if (!verified.ok) {
      return { ok: false, error: `upstream_routing_bundle_invalid:${verified.reason}` };
    }
    return {
      ok: true,
      source: bundle.source,
      revision: bundle.revision,
      upstreams: normalizeUpstreamRoutingPolicies(bundle.upstreams),
    };
  }

  if (config.requireSignedImports) {
    return { ok: false, error: 'upstream_routing_signed_bundle_required' };
  }

  const unsigned = payload as UpstreamRoutingExportBodyUnsigned;
  const revision = String(unsigned.revision ?? '').trim();
  const upstreams = normalizeUpstreamRoutingPolicies(unsigned.upstreams);
  if (!revision || !/^ur:[a-f0-9]{32}$/.test(revision)) {
    return { ok: false, error: 'upstream_routing_revision_missing' };
  }

  return {
    ok: true,
    source: String(unsigned.source ?? 'peer').trim() || 'peer',
    revision,
    upstreams,
  };
}

async function fetchRoutePolicySnapshot(
  fetchFn: ConvergenceFetchFn,
  peer: string,
  headers: Record<string, string>,
  config: ConvergenceRoutePolicyConfig,
): Promise<
{ ok: true; source: string; revision: string; routes: Array<Record<string, unknown>> } |
{ ok: false; error: string }
> {
  const response = await fetchJson(
    fetchFn,
    `${peer}/internal/routes/policy/export`,
    { headers },
  );
  if (!response.ok) {
    return { ok: false, error: `route_policy_export_failed:${response.error}` };
  }

  const payload = response.data as Record<string, unknown>;
  if (payload['signed'] === true) {
    const bundle = payload['bundle'] as SignedRoutePolicyBundle | undefined;
    if (!bundle) {
      return { ok: false, error: 'route_policy_bundle_missing' };
    }
    const verified = await verifySignedRoutePolicyBundle(bundle, config.verification);
    if (!verified.ok) {
      return { ok: false, error: `route_policy_bundle_invalid:${verified.reason}` };
    }
    return {
      ok: true,
      source: bundle.source,
      revision: bundle.revision,
      routes: normalizeRoutePolicies(bundle.routes),
    };
  }

  if (config.requireSignedImports) {
    return { ok: false, error: 'route_policy_signed_bundle_required' };
  }

  const unsigned = payload as RoutePolicyExportBodyUnsigned;
  const revision = String(unsigned.revision ?? '').trim();
  if (!revision || !/^rr:[a-f0-9]{32}$/.test(revision)) {
    return { ok: false, error: 'route_policy_revision_missing' };
  }

  return {
    ok: true,
    source: String(unsigned.source ?? 'peer').trim() || 'peer',
    revision,
    routes: normalizeRoutePolicies(unsigned.routes),
  };
}

export async function runConvergenceOnce(options: ConvergenceWorkerOptions): Promise<ConvergenceRunResult> {
  const startedAt = new Date().toISOString();
  const runId = randomUUID();
  const fetchFn: ConvergenceFetchFn = options.fetchFn ?? (async (url, init) => {
    const response = await fetch(url, init);
    return {
      ok: response.ok,
      status: response.status,
      json: () => response.json(),
    };
  });
  const peers = options.peers.map(normalizePeerUrl).filter(Boolean);
  const limit = normalizeExportLimit(options.exportLimit);
  const headers = options.requestHeaders ?? {};
  const fallbackSnapshotHash = '0'.repeat(64);
  const results: ConvergencePeerResult[] = [];
  let driftsDetected = 0;
  let healedPeers = 0;
  let errors = 0;
  const quorumEnabled = options.policyQuorum?.enabled === true;
  const quorumRequired = normalizeQuorumMinPeers(options.policyQuorum?.minPeers, peers.length);
  type RemoteUpstreamSnapshot = Awaited<ReturnType<typeof fetchUpstreamRoutingSnapshot>>;
  type RemoteRouteSnapshot = Awaited<ReturnType<typeof fetchRoutePolicySnapshot>>;
  const upstreamSnapshots = new Map<string, RemoteUpstreamSnapshot>();
  const routeSnapshots = new Map<string, RemoteRouteSnapshot>();
  const upstreamRevisionVotes = new Map<string, number>();
  const routeRevisionVotes = new Map<string, number>();

  if (quorumEnabled) {
    for (const peer of peers) {
      if (options.upstreamRouting) {
        const snapshot = await fetchUpstreamRoutingSnapshot(
          fetchFn,
          peer,
          headers,
          options.upstreamRouting,
        );
        upstreamSnapshots.set(peer, snapshot);
        if (snapshot.ok) {
          incrementRevisionVote(upstreamRevisionVotes, snapshot.revision);
        }
      }
      if (options.routePolicy) {
        const snapshot = await fetchRoutePolicySnapshot(
          fetchFn,
          peer,
          headers,
          options.routePolicy,
        );
        routeSnapshots.set(peer, snapshot);
        if (snapshot.ok) {
          incrementRevisionVote(routeRevisionVotes, snapshot.revision);
        }
      }
    }
  }

  for (const peer of peers) {
    const localRevisionBefore = await resolveLocalSecurityRevision(options.securityControls.auditStore);
    const result: ConvergencePeerResult = {
      peer,
      securityControls: {
        localRevision: localRevisionBefore,
        remoteRevision: null,
        driftDetected: false,
        healed: false,
        imported: 0,
        skipped: 0,
      },
    };
    if (options.edgeCache) {
      result.edgeCache = {
        driftDetected: false,
        healed: false,
        imported: 0,
        updated: 0,
        skipped: 0,
      };
      if (options.edgeCache.invalidation) {
        result.edgeInvalidation = {
          source: null,
          localCursor: '0',
          remoteCursor: null,
          driftDetected: false,
          healed: false,
          imported: 0,
          applied: 0,
          appended: 0,
          skipped: 0,
          pagesFetched: 0,
        };
      }
    }
    if (options.controlPlaneAudit) {
      result.controlPlaneAudit = {
        source: null,
        localCursor: '0',
        remoteCursor: null,
        driftDetected: false,
        healed: false,
        imported: 0,
        appended: 0,
        skipped: 0,
        pagesFetched: 0,
      };
    }
    if (options.upstreamRouting) {
      result.upstreamRouting = {
        source: null,
        localRevision: options.upstreamRouting.manager.getRevision(),
        remoteRevision: null,
        driftDetected: false,
        healed: false,
        changed: false,
        skipped: false,
        changedUpstreams: 0,
      };
    }
    if (options.routePolicy) {
      result.routePolicy = {
        source: null,
        localRevision: options.routePolicy.manager.getRevision(),
        remoteRevision: null,
        driftDetected: false,
        healed: false,
        changed: false,
        skipped: false,
        changedRoutes: 0,
      };
    }

    const remoteControls = await fetchJson(
      fetchFn,
      `${peer}/internal/security-controls`,
      { headers },
    );
    if (!remoteControls.ok) {
      result.securityControls.error = `security_controls_unavailable:${remoteControls.error}`;
      errors += 1;
      results.push(result);
      continue;
    }
    const remoteRevision = String((remoteControls.data as Record<string, unknown>)['revision'] ?? '').trim() || null;
    result.securityControls.remoteRevision = remoteRevision;
    result.securityControls.driftDetected = detectSecurityControlsDrift(localRevisionBefore, remoteRevision);
    if (result.securityControls.driftDetected) {
      driftsDetected += 1;
    }

    if (result.securityControls.driftDetected && options.autoHeal) {
      const remoteHistory = await fetchJson(
        fetchFn,
        `${peer}/internal/security-controls/history/export?limit=${limit}`,
        { headers },
      );
      if (!remoteHistory.ok) {
        result.securityControls.error = `security_controls_history_export_failed:${remoteHistory.error}`;
        errors += 1;
      } else {
        const payload = remoteHistory.data as Record<string, unknown>;
        if (payload['signed'] === true) {
          const bundle = payload['bundle'] as SignedSecurityControlsHistoryBundle | undefined;
          if (!bundle) {
            result.securityControls.error = 'security_controls_history_bundle_missing';
            errors += 1;
          } else {
            const verified = await verifySignedSecurityControlsHistoryBundle(
              bundle,
              options.securityControls.verification,
            );
            if (!verified.ok) {
              result.securityControls.error = `security_controls_history_bundle_invalid:${verified.reason}`;
              errors += 1;
            } else {
              const imported = await applySecurityControlsHistoryImport(
                options.securityControls.auditStore,
                {
                  source: bundle.source,
                  entries: bundle.entries,
                },
                {
                  signingSecret: options.securityControls.signingSecret,
                  maxEntries: options.securityControls.maxEntries,
                  fallbackSnapshotHash,
                },
              );
              result.securityControls.imported = imported.imported;
              result.securityControls.skipped = imported.skipped;
            }
          }
        } else if (options.securityControls.requireSignedImports) {
          result.securityControls.error = 'security_controls_history_signed_bundle_required';
          errors += 1;
        } else {
          const unsigned = payload as SecurityControlsExportBodyUnsigned;
          const entries = Array.isArray(unsigned.entries) ? unsigned.entries : [];
          const imported = await applySecurityControlsHistoryImport(
            options.securityControls.auditStore,
            {
              source: 'peer',
              entries,
            },
            {
              signingSecret: options.securityControls.signingSecret,
              maxEntries: options.securityControls.maxEntries,
              fallbackSnapshotHash,
            },
          );
          result.securityControls.imported = imported.imported;
          result.securityControls.skipped = imported.skipped;
        }
      }
    }

    const localRevisionAfter = await resolveLocalSecurityRevision(options.securityControls.auditStore);
    result.securityControls.healed =
      Boolean(result.securityControls.driftDetected) &&
      Boolean(result.securityControls.remoteRevision) &&
      result.securityControls.remoteRevision === localRevisionAfter;
    result.securityControls.localRevision = localRevisionAfter;

    if (options.edgeCache && result.edgeCache) {
      const remoteEdge = await fetchJson(
        fetchFn,
        `${peer}/internal/edge-cache/version/export?limit=${limit}`,
        { headers },
      );
      if (!remoteEdge.ok) {
        result.edgeCache.error = `edge_cache_version_export_failed:${remoteEdge.error}`;
        errors += 1;
      } else {
        const payload = remoteEdge.data as Record<string, unknown>;
        const localVersions = await options.edgeCache.store.listRouteVersions(limit);
        if (payload['signed'] === true) {
          const bundle = payload['bundle'] as SignedEdgeCacheVersionBundle | undefined;
          if (!bundle) {
            result.edgeCache.error = 'edge_cache_version_bundle_missing';
            errors += 1;
          } else {
            result.edgeCache.driftDetected = detectEdgeCacheVersionDrift(localVersions, bundle.entries);
            if (result.edgeCache.driftDetected) {
              driftsDetected += 1;
            }
            if (options.autoHeal && result.edgeCache.driftDetected) {
              const verified = await verifySignedEdgeCacheVersionBundle(
                bundle,
                options.edgeCache.verification,
              );
              if (!verified.ok) {
                result.edgeCache.error = `edge_cache_version_bundle_invalid:${verified.reason}`;
                errors += 1;
              } else {
                const imported = await applyEdgeCacheVersionImport(options.edgeCache.store, {
                  source: bundle.source,
                  strategy: bundle.strategy ?? 'max',
                  entries: bundle.entries,
                });
                result.edgeCache.imported = imported.imported;
                result.edgeCache.updated = imported.updated;
                result.edgeCache.skipped = imported.skipped;
              }
            }
          }
        } else if (options.edgeCache.requireSignedImports) {
          result.edgeCache.error = 'edge_cache_version_signed_bundle_required';
          errors += 1;
        } else {
          const unsigned = payload as EdgeCacheVersionExportBodyUnsigned;
          const entries = Array.isArray(unsigned.entries) ? unsigned.entries : [];
          result.edgeCache.driftDetected = detectEdgeCacheVersionDrift(localVersions, entries);
          if (result.edgeCache.driftDetected) {
            driftsDetected += 1;
          }
          if (options.autoHeal && result.edgeCache.driftDetected) {
            const imported = await applyEdgeCacheVersionImport(options.edgeCache.store, {
              source: 'peer',
              strategy: unsigned.strategy ?? 'max',
              entries,
            });
            result.edgeCache.imported = imported.imported;
            result.edgeCache.updated = imported.updated;
            result.edgeCache.skipped = imported.skipped;
          }
        }

        if (result.edgeCache.driftDetected) {
          const after = await options.edgeCache.store.listRouteVersions(limit);
          result.edgeCache.healed = !detectEdgeCacheVersionDrift(after, (
            payload['signed'] === true
              ? ((payload['bundle'] as SignedEdgeCacheVersionBundle | undefined)?.entries ?? [])
              : ((payload as EdgeCacheVersionExportBodyUnsigned).entries ?? [])
          ));
        }
      }
    }

    if (options.edgeCache?.invalidation && result.edgeInvalidation) {
      const invalidation = options.edgeCache.invalidation;
      const maxPages = 200;
      let source: string | null = null;
      let currentAfter = '0';
      let remoteCursor: string | null = null;
      let fatalError = false;

      for (let page = 0; page < maxPages; page += 1) {
        const requestAfter = currentAfter;
        const pageResult = await fetchEdgeInvalidationPage(
          fetchFn,
          peer,
          requestAfter,
          limit,
          headers,
          invalidation,
        );
        result.edgeInvalidation.pagesFetched += 1;

        if (!pageResult.ok) {
          result.edgeInvalidation.error = pageResult.error;
          errors += 1;
          fatalError = true;
          break;
        }

        remoteCursor = pageResult.toCursor;
        result.edgeInvalidation.remoteCursor = remoteCursor;

        if (!source) {
          source = pageResult.source;
          result.edgeInvalidation.source = source;
          const localCursor = normalizeCursor(await invalidation.eventStore.getImportedCursor(source), '0');
          result.edgeInvalidation.localCursor = localCursor;
          result.edgeInvalidation.driftDetected = detectEdgeInvalidationCursorDrift(
            localCursor,
            remoteCursor,
          );
          if (result.edgeInvalidation.driftDetected) {
            driftsDetected += 1;
          }

          if (requestAfter !== localCursor) {
            currentAfter = localCursor;
            continue;
          }
        }

        if (source !== pageResult.source) {
          result.edgeInvalidation.error = 'edge_invalidation_source_changed';
          errors += 1;
          fatalError = true;
          break;
        }

        if (!options.autoHeal || !result.edgeInvalidation.driftDetected) {
          break;
        }

        const imported = await applyEdgeInvalidationImport(
          invalidation.eventStore,
          options.edgeCache.store,
          {
            source,
            fromCursor: pageResult.fromCursor,
            toCursor: pageResult.toCursor,
            entries: pageResult.entries,
          },
          {
            maxEntries: invalidation.maxEntries,
            localSourceId: invalidation.localSourceId,
          },
        );
        result.edgeInvalidation.imported += imported.imported;
        result.edgeInvalidation.applied += imported.applied;
        result.edgeInvalidation.appended += imported.appended;
        result.edgeInvalidation.skipped += imported.skipped;
        result.edgeInvalidation.localCursor = imported.latestImportedCursor;

        const progressed = parseCursorBigInt(pageResult.toCursor) > parseCursorBigInt(requestAfter);
        if (!progressed) {
          break;
        }
        currentAfter = pageResult.toCursor;
      }

      if (!fatalError && result.edgeInvalidation.driftDetected && options.autoHeal) {
        if (source) {
          const localCursor = normalizeCursor(await invalidation.eventStore.getImportedCursor(source), '0');
          result.edgeInvalidation.localCursor = localCursor;
          result.edgeInvalidation.healed = !detectEdgeInvalidationCursorDrift(localCursor, remoteCursor);
        } else {
          result.edgeInvalidation.healed = true;
        }
      }
    }

    if (options.controlPlaneAudit && result.controlPlaneAudit) {
      const audit = options.controlPlaneAudit;
      const maxPages = 200;
      let source: string | null = null;
      let currentAfter = '0';
      let remoteCursor: string | null = null;
      let fatalError = false;

      for (let page = 0; page < maxPages; page += 1) {
        const requestAfter = currentAfter;
        const pageResult = await fetchControlPlaneAuditPage(
          fetchFn,
          peer,
          requestAfter,
          limit,
          headers,
          audit,
        );
        result.controlPlaneAudit.pagesFetched += 1;

        if (!pageResult.ok) {
          result.controlPlaneAudit.error = pageResult.error;
          errors += 1;
          fatalError = true;
          break;
        }

        remoteCursor = pageResult.toCursor;
        result.controlPlaneAudit.remoteCursor = remoteCursor;

        if (!source) {
          source = pageResult.source;
          result.controlPlaneAudit.source = source;
          const localCursor = normalizeCursor(await audit.store.getImportedCursor(source), '0');
          result.controlPlaneAudit.localCursor = localCursor;
          result.controlPlaneAudit.driftDetected = detectControlPlaneAuditCursorDrift(
            localCursor,
            remoteCursor,
          );
          if (result.controlPlaneAudit.driftDetected) {
            driftsDetected += 1;
          }

          if (requestAfter !== localCursor) {
            currentAfter = localCursor;
            continue;
          }
        }

        if (source !== pageResult.source) {
          result.controlPlaneAudit.error = 'control_plane_audit_source_changed';
          errors += 1;
          fatalError = true;
          break;
        }

        if (!options.autoHeal || !result.controlPlaneAudit.driftDetected) {
          break;
        }

        const imported = await applyControlPlaneAuditImport(
          audit.store,
          {
            source,
            fromCursor: pageResult.fromCursor,
            toCursor: pageResult.toCursor,
            entries: pageResult.entries,
          },
          {
            maxEntries: audit.maxEntries,
            localSourceId: audit.localSourceId,
          },
        );
        result.controlPlaneAudit.imported += imported.imported;
        result.controlPlaneAudit.appended += imported.appended;
        result.controlPlaneAudit.skipped += imported.skipped;
        result.controlPlaneAudit.localCursor = imported.latestImportedCursor;

        const progressed = parseCursorBigInt(pageResult.toCursor) > parseCursorBigInt(requestAfter);
        if (!progressed) {
          break;
        }
        currentAfter = pageResult.toCursor;
      }

      if (!fatalError && result.controlPlaneAudit.driftDetected && options.autoHeal) {
        if (source) {
          const localCursor = normalizeCursor(await audit.store.getImportedCursor(source), '0');
          result.controlPlaneAudit.localCursor = localCursor;
          result.controlPlaneAudit.healed = !detectControlPlaneAuditCursorDrift(localCursor, remoteCursor);
        } else {
          result.controlPlaneAudit.healed = true;
        }
      }
    }

    if (options.upstreamRouting && result.upstreamRouting) {
      const upstreamRouting = options.upstreamRouting;
      const localRevision = upstreamRouting.manager.getRevision();
      result.upstreamRouting.localRevision = localRevision;

      const prefetched = upstreamSnapshots.get(peer);
      const remote = prefetched ?? await fetchUpstreamRoutingSnapshot(
        fetchFn,
        peer,
        headers,
        upstreamRouting,
      );
      upstreamSnapshots.set(peer, remote);
      if (!prefetched && remote.ok) {
        incrementRevisionVote(upstreamRevisionVotes, remote.revision);
      }
      if (!remote.ok) {
        result.upstreamRouting.error = remote.error;
        errors += 1;
      } else {
        result.upstreamRouting.source = remote.source;
        result.upstreamRouting.remoteRevision = remote.revision;
        result.upstreamRouting.driftDetected = detectUpstreamRoutingDrift(
          localRevision,
          remote.revision,
        );
        if (result.upstreamRouting.driftDetected) {
          driftsDetected += 1;
        }

        if (options.autoHeal && result.upstreamRouting.driftDetected) {
          if (quorumEnabled) {
            const votes = upstreamRevisionVotes.get(remote.revision) ?? 0;
            result.upstreamRouting.quorumVotes = votes;
            result.upstreamRouting.quorumRequired = quorumRequired;
            result.upstreamRouting.quorumSatisfied = votes >= quorumRequired;
            if (votes < quorumRequired) {
              result.upstreamRouting.skipped = true;
              result.upstreamRouting.error = `upstream_routing_quorum_not_met:${votes}/${quorumRequired}`;
            }
          }
          if (!quorumEnabled || result.upstreamRouting.quorumSatisfied) {
            const imported = applyUpstreamRoutingPolicyImport(
              upstreamRouting.manager,
              {
                revision: remote.revision,
                upstreams: remote.upstreams,
              },
            );
            if (!imported.ok) {
              result.upstreamRouting.error = imported.issues
                .map((issue) => `${issue.path}:${issue.message}`)
                .join(';') || 'upstream_routing_import_invalid';
              errors += 1;
            } else {
              result.upstreamRouting.changed = imported.changed;
              result.upstreamRouting.skipped = imported.skipped;
              result.upstreamRouting.changedUpstreams = imported.changedUpstreams.length;
            }
          } else {
            result.upstreamRouting.changed = false;
            result.upstreamRouting.changedUpstreams = 0;
          }
        }

        const localAfter = upstreamRouting.manager.getRevision();
        result.upstreamRouting.localRevision = localAfter;
        result.upstreamRouting.healed =
          result.upstreamRouting.driftDetected &&
          options.autoHeal &&
          localAfter === remote.revision;
      }
    }

    if (options.routePolicy && result.routePolicy) {
      const routePolicy = options.routePolicy;
      const localRevision = routePolicy.manager.getRevision();
      result.routePolicy.localRevision = localRevision;

      const prefetched = routeSnapshots.get(peer);
      const remote = prefetched ?? await fetchRoutePolicySnapshot(
        fetchFn,
        peer,
        headers,
        routePolicy,
      );
      routeSnapshots.set(peer, remote);
      if (!prefetched && remote.ok) {
        incrementRevisionVote(routeRevisionVotes, remote.revision);
      }
      if (!remote.ok) {
        result.routePolicy.error = remote.error;
        errors += 1;
      } else {
        result.routePolicy.source = remote.source;
        result.routePolicy.remoteRevision = remote.revision;
        result.routePolicy.driftDetected = detectRoutePolicyDrift(
          localRevision,
          remote.revision,
        );
        if (result.routePolicy.driftDetected) {
          driftsDetected += 1;
        }

        if (options.autoHeal && result.routePolicy.driftDetected) {
          if (quorumEnabled) {
            const votes = routeRevisionVotes.get(remote.revision) ?? 0;
            result.routePolicy.quorumVotes = votes;
            result.routePolicy.quorumRequired = quorumRequired;
            result.routePolicy.quorumSatisfied = votes >= quorumRequired;
            if (votes < quorumRequired) {
              result.routePolicy.skipped = true;
              result.routePolicy.error = `route_policy_quorum_not_met:${votes}/${quorumRequired}`;
            }
          }
          if (!quorumEnabled || result.routePolicy.quorumSatisfied) {
            const imported = applyRoutePolicyImport(
              routePolicy.manager,
              {
                revision: remote.revision,
                routes: remote.routes,
              },
            );
            if (!imported.ok) {
              result.routePolicy.error = imported.issues
                .map((issue) => `${issue.path}:${issue.message}`)
                .join(';') || 'route_policy_import_invalid';
              errors += 1;
            } else {
              result.routePolicy.changed = imported.changed;
              result.routePolicy.skipped = imported.skipped;
              result.routePolicy.changedRoutes = imported.changedRoutes.length;
            }
          } else {
            result.routePolicy.changed = false;
            result.routePolicy.changedRoutes = 0;
          }
        }

        const localAfter = routePolicy.manager.getRevision();
        result.routePolicy.localRevision = localAfter;
        result.routePolicy.healed =
          result.routePolicy.driftDetected &&
          options.autoHeal &&
          localAfter === remote.revision;
      }
    }

    if (options.auditTrail) {
      const finishedAt = new Date().toISOString();
      const payload = buildPeerTelemetryPayload(runId, result, finishedAt);
      const telemetry = signConvergenceTelemetryPayload(
        payload,
        options.auditTrail.signingKeyId,
        options.auditTrail.signingSecret,
      );
      result.telemetry = {
        ...telemetry,
        signedAt: finishedAt,
      };

      const peerErrored = Boolean(
        result.securityControls.error ||
        result.edgeCache?.error ||
        result.edgeInvalidation?.error ||
        result.controlPlaneAudit?.error ||
        result.routePolicy?.error ||
        result.upstreamRouting?.error,
      );
      const requestBody = JSON.stringify({ payload, telemetry });
      try {
        await options.auditTrail.store.append(
          buildControlPlaneAuditEventInput({
            source: options.auditTrail.localSourceId,
            actor: options.auditTrail.actor,
            correlationId: runId,
            method: 'POST',
            path: options.auditTrail.path,
            statusCode: peerErrored ? 207 : 200,
            outcome: peerErrored ? 'failure' : 'success',
            requestBodyHash: telemetry.payloadHash,
            requestContentLength: Buffer.byteLength(requestBody, 'utf8'),
            idempotencyKey: `convergence:${runId}:${peer}`,
            permissionScope: options.auditTrail.permissionScope,
          }),
          options.auditTrail.maxEntries,
        );
      } catch (error) {
        result.auditTrailError = error instanceof Error ? error.message : String(error);
        errors += 1;
      }
    }

    if (
      (result.securityControls.driftDetected && result.securityControls.healed) ||
      (result.edgeCache?.driftDetected && result.edgeCache.healed) ||
      (result.edgeInvalidation?.driftDetected && result.edgeInvalidation.healed) ||
      (result.controlPlaneAudit?.driftDetected && result.controlPlaneAudit.healed) ||
      (result.upstreamRouting?.driftDetected && result.upstreamRouting.healed) ||
      (result.routePolicy?.driftDetected && result.routePolicy.healed)
    ) {
      healedPeers += 1;
    }

    results.push(result);
  }

  return {
    startedAt,
    finishedAt: new Date().toISOString(),
    peers: peers.length,
    driftsDetected,
    healedPeers,
    errors,
    results,
  };
}
