import crypto from 'crypto';
import { InMemoryInternalAuthReplayStore, type InternalAuthReplayStore } from '@zerotrust/shared';
import type { EdgeInvalidationEventKind } from '../state/edge-invalidation-event-store';

export interface EdgeInvalidationBundleEntry {
  cursor: string;
  eventId: string;
  source: string;
  occurredAt: string;
  actor: string;
  correlationId?: string;
  kind: EdgeInvalidationEventKind;
  payload: Record<string, unknown>;
}

export interface SignedEdgeInvalidationBundle {
  source: string;
  bundleId: string;
  keyId: string;
  generatedAt: string;
  expiresAt: string;
  fromCursor: string;
  toCursor: string;
  entries: EdgeInvalidationBundleEntry[];
  signature: string;
}

export interface SignedEdgeInvalidationBundleConfig {
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
const EVENT_KIND_SET = new Set<EdgeInvalidationEventKind>(['purge', 'version_set']);

export function signEdgeInvalidationBundle(
  payload: Omit<SignedEdgeInvalidationBundle, 'signature'>,
  secret: string,
): SignedEdgeInvalidationBundle {
  const signature = computeEdgeInvalidationBundleSignature(payload, secret);
  return { ...payload, signature };
}

export async function verifySignedEdgeInvalidationBundle(
  bundle: SignedEdgeInvalidationBundle,
  config: SignedEdgeInvalidationBundleConfig,
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
    if (!EVENT_KIND_SET.has(entry.kind)) {
      return { ok: false, reason: 'invalid_event_kind' };
    }
    if (!entry.payload || typeof entry.payload !== 'object' || Array.isArray(entry.payload)) {
      return { ok: false, reason: 'invalid_event_payload' };
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

  const expectedSig = computeEdgeInvalidationBundleSignature(stripSignature(bundle), secret);
  if (!timingSafeEqual(bundle.signature, expectedSig)) {
    return { ok: false, reason: 'signature_invalid' };
  }

  if (config.replayProtectionEnabled) {
    const ttlSeconds = Math.max(1, Math.ceil((expiresAtMs - now) / 1000));
    const key = `edge-invalidation:${bundle.source}:${bundle.bundleId}:${bundle.keyId}`;
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

export function computeEdgeInvalidationBundleSignature(
  payload: Omit<SignedEdgeInvalidationBundle, 'signature'>,
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
  bundle: SignedEdgeInvalidationBundle,
): Omit<SignedEdgeInvalidationBundle, 'signature'> {
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
