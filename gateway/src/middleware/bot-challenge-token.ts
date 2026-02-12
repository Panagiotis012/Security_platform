import crypto from 'crypto';

interface ChallengePayload {
  ip: string;
  uaHash: string;
  iat: number;
  exp: number;
  nonce: string;
}

export interface ChallengeTokenIssueInput {
  ip: string;
  userAgent: string;
  ttlSeconds: number;
  secret: string;
}

export interface ChallengeTokenVerifyInput {
  token: string;
  ip: string;
  userAgent: string;
  secret: string;
}

export function issueChallengeToken(input: ChallengeTokenIssueInput): { token: string; expiresAtMs: number } {
  const ttlSeconds = Math.max(1, Math.floor(input.ttlSeconds));
  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttlSeconds;
  const payload: ChallengePayload = {
    ip: input.ip,
    uaHash: hashUserAgent(input.userAgent),
    iat: now,
    exp,
    nonce: crypto.randomBytes(16).toString('hex'),
  };

  const encodedPayload = base64UrlEncode(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signature = signPayload(encodedPayload, input.secret);
  return {
    token: `${encodedPayload}.${signature}`,
    expiresAtMs: exp * 1000,
  };
}

export function verifyChallengeToken(input: ChallengeTokenVerifyInput): { ok: true } | { ok: false; reason: string } {
  const parts = input.token.split('.');
  if (parts.length !== 2) return { ok: false, reason: 'malformed' };

  const encodedPayload = parts[0];
  const providedSig = parts[1];
  if (!encodedPayload || !providedSig) return { ok: false, reason: 'malformed' };

  const expectedSig = signPayload(encodedPayload, input.secret);
  if (!timingSafeEqual(providedSig, expectedSig)) {
    return { ok: false, reason: 'signature_invalid' };
  }

  let payload: ChallengePayload;
  try {
    const raw = base64UrlDecode(encodedPayload);
    payload = JSON.parse(raw.toString('utf8')) as ChallengePayload;
  } catch {
    return { ok: false, reason: 'payload_invalid' };
  }

  const now = Math.floor(Date.now() / 1000);
  if (!payload.exp || now > payload.exp) return { ok: false, reason: 'expired' };
  if (payload.ip !== input.ip) return { ok: false, reason: 'ip_mismatch' };
  if (payload.uaHash !== hashUserAgent(input.userAgent)) return { ok: false, reason: 'ua_mismatch' };

  return { ok: true };
}

function hashUserAgent(userAgent: string): string {
  const normalized = (userAgent || '').trim().toLowerCase();
  return crypto.createHash('sha256').update(normalized, 'utf8').digest('hex');
}

function signPayload(encodedPayload: string, secret: string): string {
  return base64UrlEncode(
    crypto
      .createHmac('sha256', secret)
      .update(encodedPayload, 'utf8')
      .digest(),
  );
}

function base64UrlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecode(value: string): Buffer {
  const padding = value.length % 4 === 0 ? '' : '='.repeat(4 - (value.length % 4));
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/') + padding;
  return Buffer.from(b64, 'base64');
}

function timingSafeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}
