import crypto from 'crypto';
import { InMemoryInternalAuthReplayStore, type InternalAuthReplayStore } from '@zerotrust/shared';

export interface SignedRoutePolicyBundle {
  source: string;
  bundleId: string;
  keyId: string;
  generatedAt: string;
  expiresAt: string;
  revision: string;
  routes: Array<Record<string, unknown>>;
  signature: string;
}

export interface SignedRoutePolicyBundleConfig {
  keyring: Record<string, string>;
  allowedSources?: string[];
  allowedKeyIds?: string[];
  maxSkewSeconds: number;
  replayProtectionEnabled: boolean;
  replayCacheMaxEntries: number;
}

const KEY_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const REVISION_PATTERN = /^rr:[a-f0-9]{32}$/;
const localReplayStores = new Map<number, InMemoryInternalAuthReplayStore>();

function canonicalize(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'number' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const fields = keys.map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`);
  return `{${fields.join(',')}}`;
}

function stripSignature(
  bundle: SignedRoutePolicyBundle,
): Omit<SignedRoutePolicyBundle, 'signature'> {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { signature, ...unsigned } = bundle;
  return unsigned;
}

function timingSafeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function getOrCreateLocalReplayStore(maxEntries: number): InMemoryInternalAuthReplayStore {
  const normalized = Math.max(1, Math.floor(maxEntries));
  const existing = localReplayStores.get(normalized);
  if (existing) return existing;

  const store = new InMemoryInternalAuthReplayStore(normalized);
  localReplayStores.set(normalized, store);
  return store;
}

export function computeRoutePolicyBundleSignature(
  payload: Omit<SignedRoutePolicyBundle, 'signature'>,
  secret: string,
): string {
  return crypto
    .createHmac('sha256', secret)
    .update(canonicalize(payload), 'utf8')
    .digest('hex');
}

export function signRoutePolicyBundle(
  payload: Omit<SignedRoutePolicyBundle, 'signature'>,
  secret: string,
): SignedRoutePolicyBundle {
  return {
    ...payload,
    signature: computeRoutePolicyBundleSignature(payload, secret),
  };
}

export async function verifySignedRoutePolicyBundle(
  bundle: SignedRoutePolicyBundle,
  config: SignedRoutePolicyBundleConfig,
  replayStore?: InternalAuthReplayStore,
): Promise<{ ok: true } | { ok: false; reason: string }> {
  if (!bundle.signature || bundle.signature.trim().length === 0) {
    return { ok: false, reason: 'missing_signature' };
  }
  if (!bundle.source || !KEY_PATTERN.test(bundle.source)) {
    return { ok: false, reason: 'invalid_source' };
  }
  if (!bundle.bundleId || !KEY_PATTERN.test(bundle.bundleId)) {
    return { ok: false, reason: 'invalid_bundle_id' };
  }
  if (!bundle.keyId || !KEY_PATTERN.test(bundle.keyId)) {
    return { ok: false, reason: 'invalid_key_id' };
  }
  if (!bundle.revision || !REVISION_PATTERN.test(bundle.revision)) {
    return { ok: false, reason: 'invalid_revision' };
  }
  if (!Array.isArray(bundle.routes)) {
    return { ok: false, reason: 'invalid_routes' };
  }

  const allowedSources = new Set((config.allowedSources ?? []).map((value) => value.trim()).filter(Boolean));
  if (allowedSources.size > 0 && !allowedSources.has(bundle.source)) {
    return { ok: false, reason: 'source_not_allowed' };
  }

  const allowedKeyIds = new Set((config.allowedKeyIds ?? []).map((value) => value.trim()).filter(Boolean));
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

  const expected = computeRoutePolicyBundleSignature(stripSignature(bundle), secret);
  if (!timingSafeEqual(expected, bundle.signature)) {
    return { ok: false, reason: 'signature_invalid' };
  }

  if (config.replayProtectionEnabled) {
    const ttlSeconds = Math.max(1, Math.ceil((expiresAtMs - now) / 1000));
    const replayKey = `route-policy:${bundle.source}:${bundle.bundleId}:${bundle.keyId}`;
    const store = replayStore ?? getOrCreateLocalReplayStore(config.replayCacheMaxEntries);
    try {
      const firstSeen = await store.consume(replayKey, ttlSeconds);
      if (!firstSeen) {
        return { ok: false, reason: 'bundle_replay_detected' };
      }
    } catch {
      return { ok: false, reason: 'replay_store_error' };
    }
  }

  return { ok: true };
}

