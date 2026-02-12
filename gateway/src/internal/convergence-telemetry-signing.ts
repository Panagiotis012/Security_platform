import crypto from 'crypto';

export interface SignedConvergenceTelemetry {
  keyId: string;
  algorithm: 'hmac-sha256';
  payloadHash: string;
  signature: string;
}

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

function timingSafeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

export function hashConvergenceTelemetryPayload(payload: unknown): string {
  return crypto
    .createHash('sha256')
    .update(canonicalize(payload), 'utf8')
    .digest('hex');
}

export function signConvergenceTelemetryPayload(
  payload: unknown,
  keyId: string,
  secret: string,
): SignedConvergenceTelemetry {
  const payloadHash = hashConvergenceTelemetryPayload(payload);
  const signature = crypto
    .createHmac('sha256', secret)
    .update(`${keyId}:${payloadHash}`, 'utf8')
    .digest('hex');
  return {
    keyId,
    algorithm: 'hmac-sha256',
    payloadHash,
    signature,
  };
}

export function verifyConvergenceTelemetryPayload(
  payload: unknown,
  signed: SignedConvergenceTelemetry,
  keyring: Record<string, string>,
): { ok: true } | { ok: false; reason: string } {
  if (!signed.keyId || !/^[A-Za-z0-9._:-]{1,128}$/.test(signed.keyId)) {
    return { ok: false, reason: 'invalid_key_id' };
  }
  if (signed.algorithm !== 'hmac-sha256') {
    return { ok: false, reason: 'invalid_algorithm' };
  }
  if (!/^[a-f0-9]{64}$/.test(signed.payloadHash)) {
    return { ok: false, reason: 'invalid_payload_hash' };
  }
  if (!/^[a-f0-9]{64}$/.test(signed.signature)) {
    return { ok: false, reason: 'invalid_signature' };
  }

  const secret = keyring[signed.keyId];
  if (!secret) {
    return { ok: false, reason: 'key_id_unknown' };
  }

  const payloadHash = hashConvergenceTelemetryPayload(payload);
  if (!timingSafeEqual(payloadHash, signed.payloadHash)) {
    return { ok: false, reason: 'payload_hash_mismatch' };
  }

  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(`${signed.keyId}:${payloadHash}`, 'utf8')
    .digest('hex');
  if (!timingSafeEqual(expectedSignature, signed.signature)) {
    return { ok: false, reason: 'signature_invalid' };
  }

  return { ok: true };
}
