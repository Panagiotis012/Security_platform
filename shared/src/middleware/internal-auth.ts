/**
 * Internal service-to-service authentication.
 *
 * This is a pragmatic control for "internal-only" plane APIs (PDP, telemetry,
 * supply-chain, identity APIs) to prevent unauthenticated lateral movement if
 * a network boundary is misconfigured.
 *
 * Mechanism: HMAC-SHA256 over
 * (timestamp + method + path + bodySha256 + nonce + callerId + audience).
 *
 * Headers:
 * - X-Internal-Timestamp: unix epoch seconds
 * - X-Internal-Content-SHA256: hex sha256 of raw request body (empty body => sha256(""))
 * - X-Internal-Nonce: random request nonce (recommended, required in strict mode)
 * - X-Internal-Caller: caller identity (recommended, required in strict mode)
 * - X-Internal-Audience: target service identity (recommended for anti-confusion)
 * - X-Internal-Key-Id: shared-secret key id for rotation (recommended in strict mode)
 * - X-Internal-Signature:
 *     hex HMAC-SHA256(secret, `${ts}.${method}.${path}.${bodySha256}.${nonce}.${callerId}.${audience}.${keyId}`)
 *
 * Notes:
 * - This is not a replacement for mTLS or workload identity JWTs; it's a strong
 *   baseline that is easy to deploy.
 * - Callers should capture raw body bytes (e.g. via express.json verify hook) and
 *   set `req.rawBody` as a Buffer for best integrity.
 */

import crypto from 'crypto';
import type Redis from 'ioredis';

export const INTERNAL_AUTH_HEADERS = {
  Timestamp: 'x-internal-timestamp',
  ContentSha256: 'x-internal-content-sha256',
  Nonce: 'x-internal-nonce',
  Caller: 'x-internal-caller',
  Audience: 'x-internal-audience',
  KeyId: 'x-internal-key-id',
  Signature: 'x-internal-signature',
} as const;

export interface InternalAuthOptions {
  enabled: boolean;
  secret: string;
  allowedSkewSeconds: number;
  /** Paths that never require internal auth (health/ready/etc). */
  exemptPaths: string[];
  /** Require nonce-based signatures (recommended for replay protection). */
  requireNonce?: boolean;
  /** Require caller identity header. */
  requireCallerId?: boolean;
  /** Allowed internal callers for this service. */
  allowedCallerIds?: string[];
  /** Required audience value for this receiving service. */
  expectedAudience?: string | string[];
  /** Require key-id header (recommended for key rotation). */
  requireKeyId?: boolean;
  /** Allowed key ids for this receiver. */
  allowedKeyIds?: string[];
  /** Optional keyring for key-id based verification. */
  keyring?: Record<string, string>;
  /** Enable replay detection cache for nonce-bearing requests. */
  replayProtectionEnabled?: boolean;
  /** Max entries in replay cache. */
  replayCacheMaxEntries?: number;
}

export interface InternalAuthRequestLike {
  method: string;
  path: string;
  headers: Record<string, unknown>;
  rawBody?: Buffer;
}

export interface InternalAuthReplayStore {
  consume(replayKey: string, ttlSeconds: number): Promise<boolean>;
}

/**
 * In-memory replay store (single-process).
 * Suitable for local development or single-instance deployments.
 */
export class InMemoryInternalAuthReplayStore implements InternalAuthReplayStore {
  private readonly cache = new Map<string, number>();
  private cleanupTick = 0;
  private readonly maxEntries: number;

  constructor(maxEntries = 50_000) {
    this.maxEntries = Math.max(1, maxEntries);
  }

  async consume(replayKey: string, ttlSeconds: number): Promise<boolean> {
    const nowSeconds = Math.floor(Date.now() / 1000);
    this.cleanupTick++;

    if (this.cleanupTick % 64 === 0) {
      for (const [key, expiresAt] of this.cache.entries()) {
        if (expiresAt <= nowSeconds) {
          this.cache.delete(key);
        }
      }
    }

    const existing = this.cache.get(replayKey);
    if (existing !== undefined && existing > nowSeconds) {
      return false;
    }
    if (existing !== undefined) {
      this.cache.delete(replayKey);
    }

    this.cache.set(replayKey, nowSeconds + Math.max(1, ttlSeconds));

    if (this.cache.size > this.maxEntries) {
      const overflow = this.cache.size - this.maxEntries;
      let removed = 0;
      for (const key of this.cache.keys()) {
        this.cache.delete(key);
        removed++;
        if (removed >= overflow) break;
      }
    }

    return true;
  }
}

/**
 * Redis-backed replay store (multi-instance).
 * Uses SET key value EX ttl NX for atomic first-seen semantics.
 */
export class RedisInternalAuthReplayStore implements InternalAuthReplayStore {
  private readonly redis: Redis;
  private readonly keyPrefix: string;

  constructor(redisClient: Redis, options?: { keyPrefix?: string }) {
    this.redis = redisClient;
    this.keyPrefix = options?.keyPrefix ?? 'zt:internal-auth:replay:';
  }

  async consume(replayKey: string, ttlSeconds: number): Promise<boolean> {
    const key = `${this.keyPrefix}${replayKey}`;
    const ttl = Math.max(1, Math.ceil(ttlSeconds));
    const result = await this.redis.set(key, '1', 'EX', ttl, 'NX');
    return result === 'OK';
  }
}

export function sha256Hex(data: Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function hmacSha256Hex(secret: string, data: string): string {
  return crypto.createHmac('sha256', secret).update(data, 'utf8').digest('hex');
}

export function buildInternalSignatureInput(
  timestampSeconds: string,
  method: string,
  path: string,
  bodySha256Hex: string,
  nonce?: string,
  callerId?: string,
  audience?: string,
  keyId?: string,
): string {
  if (nonce && nonce.length > 0) {
    let base = `${timestampSeconds}.${method.toUpperCase()}.${path}.${bodySha256Hex}.${nonce}`;
    if (callerId && callerId.length > 0) {
      base += `.${callerId}`;
      if (audience && audience.length > 0) {
        base += `.${audience}`;
      }
      if (keyId && keyId.length > 0) {
        base += `.${keyId}`;
      }
    }
    return base;
  }
  // Backward-compatible legacy input (without nonce).
  return `${timestampSeconds}.${method.toUpperCase()}.${path}.${bodySha256Hex}`;
}

const DEFAULT_REPLAY_CACHE_MAX_ENTRIES = 50_000;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const PRINCIPAL_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const KEY_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const replayNonceCache = new Map<string, number>();
let replayCleanupTick = 0;

function cleanupReplayCache(nowSeconds: number): void {
  replayCleanupTick++;
  // Amortized cleanup to keep verification cheap.
  if (replayCleanupTick % 64 !== 0) return;

  for (const [nonce, expiresAt] of replayNonceCache.entries()) {
    if (expiresAt <= nowSeconds) {
      replayNonceCache.delete(nonce);
    }
  }
}

function consumeReplayNonce(
  nonce: string,
  nowSeconds: number,
  ttlSeconds: number,
  maxEntries: number,
): boolean {
  const expiresAt = replayNonceCache.get(nonce);
  if (expiresAt !== undefined && expiresAt > nowSeconds) {
    return false;
  }
  if (expiresAt !== undefined) {
    replayNonceCache.delete(nonce);
  }

  replayNonceCache.set(nonce, nowSeconds + ttlSeconds);

  if (replayNonceCache.size > maxEntries) {
    const overflow = replayNonceCache.size - maxEntries;
    let removed = 0;
    for (const key of replayNonceCache.keys()) {
      replayNonceCache.delete(key);
      removed++;
      if (removed >= overflow) break;
    }
  }

  return true;
}

function buildReplayKey(nonce: string, caller?: string, audience?: string, keyId?: string): string {
  return `${nonce}|${caller || '_'}|${audience || '_'}|${keyId || '_'}`;
}

function resolveVerificationSecret(
  options: InternalAuthOptions,
  keyId: string,
): { ok: true; secret: string } | { ok: false; reason: string } {
  if (keyId) {
    const keyring = options.keyring ?? {};
    if (Object.keys(keyring).length > 0) {
      const secret = keyring[keyId];
      if (!secret) {
        return { ok: false, reason: 'internal_key_id_unknown' };
      }
      return { ok: true, secret };
    }
  }

  if (!options.secret) {
    return { ok: false, reason: 'internal_secret_unavailable' };
  }
  return { ok: true, secret: options.secret };
}

export function computeInternalAuthHeaders(
  req: Pick<InternalAuthRequestLike, 'method' | 'path' | 'rawBody'>,
  secret: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
  nonce: string = crypto.randomBytes(16).toString('hex'),
  callerId?: string,
  audience?: string,
  keyId?: string,
): Record<string, string> {
  const timestamp = String(nowSeconds);
  const raw = req.rawBody ?? Buffer.alloc(0);
  const bodySha = sha256Hex(raw);
  const input = buildInternalSignatureInput(
    timestamp,
    req.method,
    req.path,
    bodySha,
    nonce,
    callerId,
    audience,
    keyId,
  );
  const sig = hmacSha256Hex(secret, input);
  const headers: Record<string, string> = {
    [INTERNAL_AUTH_HEADERS.Timestamp]: timestamp,
    [INTERNAL_AUTH_HEADERS.ContentSha256]: bodySha,
    [INTERNAL_AUTH_HEADERS.Nonce]: nonce,
    [INTERNAL_AUTH_HEADERS.Signature]: sig,
  };
  if (callerId && callerId.length > 0) {
    headers[INTERNAL_AUTH_HEADERS.Caller] = callerId;
  }
  if (audience && audience.length > 0) {
    headers[INTERNAL_AUTH_HEADERS.Audience] = audience;
  }
  if (keyId && keyId.length > 0) {
    headers[INTERNAL_AUTH_HEADERS.KeyId] = keyId;
  }
  return {
    ...headers,
  };
}

export function verifyInternalAuth(
  req: InternalAuthRequestLike,
  options: InternalAuthOptions,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): { ok: true } | { ok: false; reason: string } {
  if (!options.enabled) return { ok: true };
  // Allow callers to pass `req.path` as `originalUrl` (path + query) for signature coverage.
  // Exemptions should match by path only (ignores query string).
  const pathOnly = req.path.split('?')[0] ?? req.path;
  if (options.exemptPaths.includes(pathOnly)) return { ok: true };

  const ts = String(req.headers[INTERNAL_AUTH_HEADERS.Timestamp] ?? '').trim();
  const providedBodySha = String(req.headers[INTERNAL_AUTH_HEADERS.ContentSha256] ?? '').trim();
  const providedNonce = String(req.headers[INTERNAL_AUTH_HEADERS.Nonce] ?? '').trim();
  const providedCaller = String(req.headers[INTERNAL_AUTH_HEADERS.Caller] ?? '').trim();
  const providedAudience = String(req.headers[INTERNAL_AUTH_HEADERS.Audience] ?? '').trim();
  const providedKeyId = String(req.headers[INTERNAL_AUTH_HEADERS.KeyId] ?? '').trim();
  const providedSig = String(req.headers[INTERNAL_AUTH_HEADERS.Signature] ?? '').trim();

  if (!ts || !providedBodySha || !providedSig) {
    return { ok: false, reason: 'missing_internal_auth_headers' };
  }

  const requireNonce = options.requireNonce === true;
  if (requireNonce && !providedNonce) {
    return { ok: false, reason: 'missing_internal_nonce' };
  }
  if (providedNonce && !NONCE_PATTERN.test(providedNonce)) {
    return { ok: false, reason: 'invalid_internal_nonce' };
  }

  const requireCallerId = options.requireCallerId === true;
  if (requireCallerId && !providedCaller) {
    return { ok: false, reason: 'missing_internal_caller' };
  }
  if (providedCaller && !PRINCIPAL_PATTERN.test(providedCaller)) {
    return { ok: false, reason: 'invalid_internal_caller' };
  }

  if (providedAudience && !PRINCIPAL_PATTERN.test(providedAudience)) {
    return { ok: false, reason: 'invalid_internal_audience' };
  }
  if (options.expectedAudience !== undefined) {
    if (!providedAudience) {
      return { ok: false, reason: 'missing_internal_audience' };
    }
    const expected = new Set(
      (Array.isArray(options.expectedAudience) ? options.expectedAudience : [options.expectedAudience])
        .map((s) => s.trim())
        .filter(Boolean),
    );
    if (expected.size > 0 && !expected.has(providedAudience)) {
      return { ok: false, reason: 'internal_audience_mismatch' };
    }
  }

  if (providedCaller && options.allowedCallerIds && options.allowedCallerIds.length > 0) {
    const allowed = new Set(options.allowedCallerIds.map((s) => s.trim()).filter(Boolean));
    if (!allowed.has(providedCaller)) {
      return { ok: false, reason: 'internal_caller_not_allowed' };
    }
  }

  const requireKeyId = options.requireKeyId === true;
  if (requireKeyId && !providedKeyId) {
    return { ok: false, reason: 'missing_internal_key_id' };
  }
  if (providedKeyId && !KEY_ID_PATTERN.test(providedKeyId)) {
    return { ok: false, reason: 'invalid_internal_key_id' };
  }
  if (providedKeyId && options.allowedKeyIds && options.allowedKeyIds.length > 0) {
    const allowed = new Set(options.allowedKeyIds.map((s) => s.trim()).filter(Boolean));
    if (!allowed.has(providedKeyId)) {
      return { ok: false, reason: 'internal_key_id_not_allowed' };
    }
  }

  const resolvedSecret = resolveVerificationSecret(options, providedKeyId);
  if (!resolvedSecret.ok) {
    return resolvedSecret;
  }

  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum) || tsNum <= 0) {
    return { ok: false, reason: 'invalid_internal_timestamp' };
  }

  if (Math.abs(nowSeconds - tsNum) > options.allowedSkewSeconds) {
    return { ok: false, reason: 'internal_timestamp_out_of_window' };
  }

  const raw = req.rawBody ?? Buffer.alloc(0);
  const computedBodySha = sha256Hex(raw);
  if (!timingSafeEqualHex(computedBodySha, providedBodySha)) {
    return { ok: false, reason: 'internal_body_sha_mismatch' };
  }

  const input = buildInternalSignatureInput(
    ts,
    req.method,
    req.path,
    computedBodySha,
    providedNonce || undefined,
    providedCaller || undefined,
    providedAudience || undefined,
    providedKeyId || undefined,
  );
  const expectedSig = hmacSha256Hex(resolvedSecret.secret, input);

  if (!timingSafeEqualHex(expectedSig, providedSig)) {
    return { ok: false, reason: 'internal_signature_invalid' };
  }

  const replayProtectionEnabled = options.replayProtectionEnabled !== false;
  if (replayProtectionEnabled && providedNonce) {
    cleanupReplayCache(nowSeconds);
    const maxEntries = Math.max(
      1,
      Number.isFinite(options.replayCacheMaxEntries)
        ? Number(options.replayCacheMaxEntries)
        : DEFAULT_REPLAY_CACHE_MAX_ENTRIES,
    );
    const ttlSeconds = Math.max(1, options.allowedSkewSeconds);
    const replayKey = buildReplayKey(
      providedNonce,
      providedCaller || undefined,
      providedAudience || undefined,
      providedKeyId || undefined,
    );
    const ok = consumeReplayNonce(replayKey, nowSeconds, ttlSeconds, maxEntries);
    if (!ok) {
      return { ok: false, reason: 'internal_replay_detected' };
    }
  }

  return { ok: true };
}

export async function verifyInternalAuthAsync(
  req: InternalAuthRequestLike,
  options: InternalAuthOptions,
  replayStore?: InternalAuthReplayStore,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): Promise<{ ok: true } | { ok: false; reason: string }> {
  if (!options.enabled) return { ok: true };
  const pathOnly = req.path.split('?')[0] ?? req.path;
  if (options.exemptPaths.includes(pathOnly)) return { ok: true };

  const ts = String(req.headers[INTERNAL_AUTH_HEADERS.Timestamp] ?? '').trim();
  const providedBodySha = String(req.headers[INTERNAL_AUTH_HEADERS.ContentSha256] ?? '').trim();
  const providedNonce = String(req.headers[INTERNAL_AUTH_HEADERS.Nonce] ?? '').trim();
  const providedCaller = String(req.headers[INTERNAL_AUTH_HEADERS.Caller] ?? '').trim();
  const providedAudience = String(req.headers[INTERNAL_AUTH_HEADERS.Audience] ?? '').trim();
  const providedKeyId = String(req.headers[INTERNAL_AUTH_HEADERS.KeyId] ?? '').trim();
  const providedSig = String(req.headers[INTERNAL_AUTH_HEADERS.Signature] ?? '').trim();

  if (!ts || !providedBodySha || !providedSig) {
    return { ok: false, reason: 'missing_internal_auth_headers' };
  }

  const requireNonce = options.requireNonce === true;
  if (requireNonce && !providedNonce) {
    return { ok: false, reason: 'missing_internal_nonce' };
  }
  if (providedNonce && !NONCE_PATTERN.test(providedNonce)) {
    return { ok: false, reason: 'invalid_internal_nonce' };
  }

  const requireCallerId = options.requireCallerId === true;
  if (requireCallerId && !providedCaller) {
    return { ok: false, reason: 'missing_internal_caller' };
  }
  if (providedCaller && !PRINCIPAL_PATTERN.test(providedCaller)) {
    return { ok: false, reason: 'invalid_internal_caller' };
  }

  if (providedAudience && !PRINCIPAL_PATTERN.test(providedAudience)) {
    return { ok: false, reason: 'invalid_internal_audience' };
  }
  if (options.expectedAudience !== undefined) {
    if (!providedAudience) {
      return { ok: false, reason: 'missing_internal_audience' };
    }
    const expected = new Set(
      (Array.isArray(options.expectedAudience) ? options.expectedAudience : [options.expectedAudience])
        .map((s) => s.trim())
        .filter(Boolean),
    );
    if (expected.size > 0 && !expected.has(providedAudience)) {
      return { ok: false, reason: 'internal_audience_mismatch' };
    }
  }

  if (providedCaller && options.allowedCallerIds && options.allowedCallerIds.length > 0) {
    const allowed = new Set(options.allowedCallerIds.map((s) => s.trim()).filter(Boolean));
    if (!allowed.has(providedCaller)) {
      return { ok: false, reason: 'internal_caller_not_allowed' };
    }
  }

  const requireKeyId = options.requireKeyId === true;
  if (requireKeyId && !providedKeyId) {
    return { ok: false, reason: 'missing_internal_key_id' };
  }
  if (providedKeyId && !KEY_ID_PATTERN.test(providedKeyId)) {
    return { ok: false, reason: 'invalid_internal_key_id' };
  }
  if (providedKeyId && options.allowedKeyIds && options.allowedKeyIds.length > 0) {
    const allowed = new Set(options.allowedKeyIds.map((s) => s.trim()).filter(Boolean));
    if (!allowed.has(providedKeyId)) {
      return { ok: false, reason: 'internal_key_id_not_allowed' };
    }
  }

  const resolvedSecret = resolveVerificationSecret(options, providedKeyId);
  if (!resolvedSecret.ok) {
    return resolvedSecret;
  }

  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum) || tsNum <= 0) {
    return { ok: false, reason: 'invalid_internal_timestamp' };
  }

  if (Math.abs(nowSeconds - tsNum) > options.allowedSkewSeconds) {
    return { ok: false, reason: 'internal_timestamp_out_of_window' };
  }

  const raw = req.rawBody ?? Buffer.alloc(0);
  const computedBodySha = sha256Hex(raw);
  if (!timingSafeEqualHex(computedBodySha, providedBodySha)) {
    return { ok: false, reason: 'internal_body_sha_mismatch' };
  }

  const input = buildInternalSignatureInput(
    ts,
    req.method,
    req.path,
    computedBodySha,
    providedNonce || undefined,
    providedCaller || undefined,
    providedAudience || undefined,
    providedKeyId || undefined,
  );
  const expectedSig = hmacSha256Hex(resolvedSecret.secret, input);

  if (!timingSafeEqualHex(expectedSig, providedSig)) {
    return { ok: false, reason: 'internal_signature_invalid' };
  }

  const replayProtectionEnabled = options.replayProtectionEnabled !== false;
  if (replayProtectionEnabled && providedNonce) {
    const ttlSeconds = Math.max(1, options.allowedSkewSeconds);
    const replayKey = buildReplayKey(
      providedNonce,
      providedCaller || undefined,
      providedAudience || undefined,
      providedKeyId || undefined,
    );

    try {
      let ok: boolean;
      if (replayStore) {
        ok = await replayStore.consume(replayKey, ttlSeconds);
      } else {
        cleanupReplayCache(nowSeconds);
        const maxEntries = Math.max(
          1,
          Number.isFinite(options.replayCacheMaxEntries)
            ? Number(options.replayCacheMaxEntries)
            : DEFAULT_REPLAY_CACHE_MAX_ENTRIES,
        );
        ok = consumeReplayNonce(replayKey, nowSeconds, ttlSeconds, maxEntries);
      }
      if (!ok) {
        return { ok: false, reason: 'internal_replay_detected' };
      }
    } catch {
      return { ok: false, reason: 'internal_replay_store_error' };
    }
  }

  return { ok: true };
}

function timingSafeEqualHex(a: string, b: string): boolean {
  try {
    const ab = Buffer.from(a, 'hex');
    const bb = Buffer.from(b, 'hex');
    if (ab.length !== bb.length) return false;
    return crypto.timingSafeEqual(ab, bb);
  } catch {
    return false;
  }
}
