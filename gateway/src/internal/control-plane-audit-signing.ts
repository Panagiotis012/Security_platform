import crypto from 'crypto';
import { InMemoryInternalAuthReplayStore, type InternalAuthReplayStore } from '@zerotrust/shared';

export interface ControlPlaneAuditBundleEntry {
  cursor: string;
  eventId: string;
  source: string;
  occurredAt: string;
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
}

export interface SignedControlPlaneAuditBundle {
  source: string;
  bundleId: string;
  keyId: string;
  generatedAt: string;
  expiresAt: string;
  fromCursor: string;
  toCursor: string;
  entries: ControlPlaneAuditBundleEntry[];
  signature: string;
}

export interface SignedControlPlaneAuditBundleConfig {
  keyring: Record<string, string>;
  allowedSources?: string[];
  allowedKeyIds?: string[];
  maxSkewSeconds: number;
  replayProtectionEnabled: boolean;
  replayCacheMaxEntries: number;
}

const localReplayStores = new Map<number, InMemoryInternalAuthReplayStore>();
const KEY_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const CURSOR_PATTERN = /^\d{1,32}$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const METHOD_SET = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const OUTCOME_SET = new Set(['success', 'failure']);

export function signControlPlaneAuditBundle(
  payload: Omit<SignedControlPlaneAuditBundle, 'signature'>,
  secret: string,
): SignedControlPlaneAuditBundle {
  const signature = computeControlPlaneAuditBundleSignature(payload, secret);
  return { ...payload, signature };
}

export async function verifySignedControlPlaneAuditBundle(
  bundle: SignedControlPlaneAuditBundle,
  config: SignedControlPlaneAuditBundleConfig,
  replayStore?: InternalAuthReplayStore,
): Promise<{ ok: true } | { ok: false; reason: string }> {
  if (!bundle.signature || bundle.signature.trim().length === 0) {
    return { ok: false, reason: 'missing_signature' };
  }
  if (!bundle.keyId || !KEY_PATTERN.test(bundle.keyId)) {
    return { ok: false, reason: 'invalid_key_id' };
  }
  if (!bundle.source || !KEY_PATTERN.test(bundle.source)) {
    return { ok: false, reason: 'invalid_source' };
  }
  if (!bundle.bundleId || !KEY_PATTERN.test(bundle.bundleId)) {
    return { ok: false, reason: 'invalid_bundle_id' };
  }
  if (!bundle.fromCursor || !CURSOR_PATTERN.test(bundle.fromCursor)) {
    return { ok: false, reason: 'invalid_from_cursor' };
  }
  if (!bundle.toCursor || !CURSOR_PATTERN.test(bundle.toCursor)) {
    return { ok: false, reason: 'invalid_to_cursor' };
  }
  if (!Array.isArray(bundle.entries) || bundle.entries.length === 0) {
    return { ok: false, reason: 'missing_entries' };
  }
  for (const entry of bundle.entries) {
    if (!entry || typeof entry !== 'object') {
      return { ok: false, reason: 'invalid_entry' };
    }
    if (!entry.cursor || !CURSOR_PATTERN.test(entry.cursor)) {
      return { ok: false, reason: 'invalid_event_cursor' };
    }
    if (!entry.eventId || !KEY_PATTERN.test(entry.eventId)) {
      return { ok: false, reason: 'invalid_event_id' };
    }
    if (!entry.source || !KEY_PATTERN.test(entry.source)) {
      return { ok: false, reason: 'invalid_event_source' };
    }
    if (!entry.occurredAt || !Number.isFinite(Date.parse(entry.occurredAt))) {
      return { ok: false, reason: 'invalid_event_timestamp' };
    }
    if (!entry.actor || entry.actor.trim().length === 0) {
      return { ok: false, reason: 'invalid_event_actor' };
    }
    if (!METHOD_SET.has(String(entry.method ?? '').toUpperCase())) {
      return { ok: false, reason: 'invalid_event_method' };
    }
    if (!entry.path || !entry.path.startsWith('/internal/')) {
      return { ok: false, reason: 'invalid_event_path' };
    }
    if (!Number.isFinite(entry.statusCode) || entry.statusCode < 100 || entry.statusCode > 599) {
      return { ok: false, reason: 'invalid_event_status_code' };
    }
    if (!OUTCOME_SET.has(entry.outcome)) {
      return { ok: false, reason: 'invalid_event_outcome' };
    }
    if (!entry.requestBodyHash || !HASH_PATTERN.test(entry.requestBodyHash)) {
      return { ok: false, reason: 'invalid_request_body_hash' };
    }
    if (
      entry.requestContentLength !== undefined &&
      (!Number.isFinite(entry.requestContentLength) || entry.requestContentLength < 0)
    ) {
      return { ok: false, reason: 'invalid_request_content_length' };
    }
  }

  const allowedSources = new Set((config.allowedSources ?? []).map((v) => v.trim()).filter(Boolean));
  if (allowedSources.size > 0 && !allowedSources.has(bundle.source)) {
    return { ok: false, reason: 'source_not_allowed' };
  }

  const allowedKeyIds = new Set((config.allowedKeyIds ?? []).map((v) => v.trim()).filter(Boolean));
  if (allowedKeyIds.size > 0 && !allowedKeyIds.has(bundle.keyId)) {
    return { ok: false, reason: 'key_id_not_allowed' };
  }

  const secret = config.keyring[bundle.keyId];
  if (!secret) {
    return { ok: false, reason: 'key_id_unknown' };
  }

  const generatedAtMs = Date.parse(bundle.generatedAt);
  const expiresAtMs = Date.parse(bundle.expiresAt);
  if (!Number.isFinite(generatedAtMs) || !Number.isFinite(expiresAtMs)) {
    return { ok: false, reason: 'invalid_timestamp' };
  }
  if (expiresAtMs <= generatedAtMs) {
    return { ok: false, reason: 'invalid_expiry' };
  }

  const now = Date.now();
  const maxSkewMs = Math.max(1, Math.floor(config.maxSkewSeconds * 1000));
  if (generatedAtMs > now + maxSkewMs) {
    return { ok: false, reason: 'generated_at_in_future' };
  }
  if (now - generatedAtMs > maxSkewMs) {
    return { ok: false, reason: 'bundle_too_old' };
  }
  if (now > expiresAtMs) {
    return { ok: false, reason: 'bundle_expired' };
  }

  const expectedSig = computeControlPlaneAuditBundleSignature(stripSignature(bundle), secret);
  if (!timingSafeEqual(bundle.signature, expectedSig)) {
    return { ok: false, reason: 'signature_invalid' };
  }

  if (config.replayProtectionEnabled) {
    const ttlSeconds = Math.max(1, Math.ceil((expiresAtMs - now) / 1000));
    const key = `control-plane-audit:${bundle.source}:${bundle.bundleId}:${bundle.keyId}`;
    const store = replayStore ?? getOrCreateLocalReplayStore(config.replayCacheMaxEntries);
    try {
      const firstSeen = await store.consume(key, ttlSeconds);
      if (!firstSeen) {
        return { ok: false, reason: 'bundle_replay_detected' };
      }
    } catch {
      return { ok: false, reason: 'replay_store_error' };
    }
  }

  return { ok: true };
}

export function computeControlPlaneAuditBundleSignature(
  payload: Omit<SignedControlPlaneAuditBundle, 'signature'>,
  secret: string,
): string {
  const canonical = canonicalize(payload);
  return crypto
    .createHmac('sha256', secret)
    .update(canonical, 'utf8')
    .digest('hex');
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
  const fields = keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`);
  return `{${fields.join(',')}}`;
}

function stripSignature(
  bundle: SignedControlPlaneAuditBundle,
): Omit<SignedControlPlaneAuditBundle, 'signature'> {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { signature, ...unsigned } = bundle;
  return unsigned;
}

function timingSafeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function getOrCreateLocalReplayStore(maxEntries: number): InMemoryInternalAuthReplayStore {
  const normalized = Math.max(1, Math.floor(maxEntries));
  const existing = localReplayStores.get(normalized);
  if (existing) return existing;

  const store = new InMemoryInternalAuthReplayStore(normalized);
  localReplayStores.set(normalized, store);
  return store;
}
