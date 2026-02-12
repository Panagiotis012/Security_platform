import type { Request, Response, NextFunction, RequestHandler } from 'express';
import * as jose from 'jose';
import type { GatewayConfig } from '../../config/default';
import { createSecurityLogger } from './request-logger';
import { recordAuthAttempt } from '@zerotrust/shared';

/**
 * JWT validation middleware using JOSE (RFC 7515/7516/7517/7518).
 *
 * - Validates tokens from Authorization header (Bearer) or secure cookie
 * - Verifies signature via JWKS endpoint with caching
 * - Validates: exp, iat, iss, aud, nbf claims
 * - Rejects tokens with: no exp, exp > max allowed, clock skew > 30s
 * - Token binding validation if present
 * - Attaches validated identity to request context
 * - Returns 401 with minimal info (no detail leakage)
 *
 * Uses the jose library for standards-compliant JWT handling,
 * including automatic JWKS key rotation and caching.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface GatewayIdentity {
  sub: string;
  tenantId?: string;
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
  roles: string[];
  scopes: string[];
  permissions: string[];
  stepUpLevel: number;
  tokenVersion?: number;
  tokenBindingHash?: string;
  jti?: string;
  raw: jose.JWTPayload;
}

// Extend Express Request (module augmentation).
declare module 'express-serve-static-core' {
  interface Request {
    identity?: GatewayIdentity;
    policyDecisionId?: string;
    wafRiskScore?: number;
    wafMatches?: string[];
  }
}

// ─── JWKS Cache ──────────────────────────────────────────────────────────────

let _jwks: ReturnType<typeof jose.createRemoteJWKSet>;
let _jwksInitialized = false;

function getJwks(config: GatewayConfig): ReturnType<typeof jose.createRemoteJWKSet> {
  if (!_jwksInitialized) {
    _jwks = jose.createRemoteJWKSet(new URL(config.jwt.jwksUri), {
      cooldownDuration: config.jwt.jwksCacheTtlMs,
      cacheMaxAge: config.jwt.jwksCacheTtlMs,
    });
    _jwksInitialized = true;
  }
  return _jwks;
}

// ─── Token Extraction ────────────────────────────────────────────────────────

function extractToken(req: Request, config: GatewayConfig): string | null {
  // Priority 1: Authorization header
  const authHeader = req.headers[config.jwt.headerName.toLowerCase()];
  if (typeof authHeader === 'string') {
    const scheme = config.jwt.headerScheme;
    if (authHeader.startsWith(scheme + ' ')) {
      const token = authHeader.substring(scheme.length + 1).trim();
      if (token.length > 0) {
        return token;
      }
    }
  }

  // Priority 2: Secure cookie
  if (req.cookies) {
    const cookieToken = req.cookies[config.jwt.cookieName];
    if (typeof cookieToken === 'string' && cookieToken.length > 0) {
      return cookieToken;
    }
  }

  return null;
}

// ─── Pre-validation Checks ───────────────────────────────────────────────────

/**
 * Perform structural checks on the token before signature verification.
 * This catches obviously invalid tokens without hitting the JWKS endpoint.
 */
function preValidateToken(token: string): { valid: boolean; reason?: string } {
  // JWT must have exactly 3 parts
  const parts = token.split('.');
  if (parts.length !== 3) {
    return { valid: false, reason: 'malformed_token_structure' };
  }

  // Each part must be non-empty base64url
  for (let i = 0; i < 3; i++) {
    const part = parts[i];
    if (!part || part.length === 0) {
      return { valid: false, reason: 'empty_token_segment' };
    }
    if (!/^[A-Za-z0-9_-]+$/.test(part)) {
      return { valid: false, reason: 'invalid_base64url' };
    }
  }

  // Decode header to check algorithm
  try {
    const headerJson = Buffer.from(parts[0]!, 'base64url').toString('utf8');
    const header = JSON.parse(headerJson) as { alg?: string; typ?: string };

    // Reject 'none' algorithm (alg: none attack)
    if (!header.alg || header.alg.toLowerCase() === 'none') {
      return { valid: false, reason: 'algorithm_none_rejected' };
    }

    // Reject symmetric algorithms (only asymmetric allowed for gateway tokens)
    if (header.alg.startsWith('HS')) {
      return { valid: false, reason: 'symmetric_algorithm_rejected' };
    }
  } catch {
    return { valid: false, reason: 'malformed_header' };
  }

  // Size check: tokens should not be excessively large
  if (token.length > 16384) { // 16KB max
    return { valid: false, reason: 'token_too_large' };
  }

  return { valid: true };
}

// ─── JWT Validation Middleware ────────────────────────────────────────────────

export function createJwtValidationMiddleware(config: GatewayConfig): RequestHandler {
  const securityLog = createSecurityLogger(config);
  const recordAuth = (result: 'success' | 'failure' | 'error'): void => {
    recordAuthAttempt(result, 'jwt', 'gateway');
  };

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const correlationId = (req.headers['x-correlation-id'] as string) || 'unknown';

    // Extract token from header or cookie
    const token = extractToken(req, config);

    if (!token) {
      recordAuth('failure');
      securityLog.warn({
        event: 'jwt_missing',
        correlationId,
        ip: req.ip,
        path: req.path,
        method: req.method,
      });
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    // Pre-validation (structural checks)
    const preCheck = preValidateToken(token);
    if (!preCheck.valid) {
      recordAuth('failure');
      securityLog.warn({
        event: 'jwt_prevalidation_failed',
        correlationId,
        ip: req.ip,
        path: req.path,
        method: req.method,
        reason: preCheck.reason,
      });
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    try {
      // Verify signature and decode claims
      const jwks = getJwks(config);
      const { payload, protectedHeader } = await jose.jwtVerify(token, jwks, {
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        algorithms: config.jwt.algorithms,
        clockTolerance: config.jwt.clockToleranceSeconds,
        maxTokenAge: `${config.jwt.maxTokenAgeSeconds}s`,
      });

      // ── Additional claim validation ─────────────────────────────────

      // Must have exp
      if (typeof payload.exp !== 'number') {
        recordAuth('failure');
        securityLog.warn({
          event: 'jwt_missing_exp',
          correlationId,
          ip: req.ip,
          path: req.path,
          sub: payload.sub,
        });
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      // Must have iat
      if (typeof payload.iat !== 'number') {
        recordAuth('failure');
        securityLog.warn({
          event: 'jwt_missing_iat',
          correlationId,
          ip: req.ip,
          path: req.path,
          sub: payload.sub,
        });
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      // Validate exp is not too far in the future (max token age)
      const now = Math.floor(Date.now() / 1000);
      const maxExpiry = now + config.jwt.maxTokenAgeSeconds;
      if (payload.exp > maxExpiry) {
        recordAuth('failure');
        securityLog.warn({
          event: 'jwt_exp_too_far',
          correlationId,
          ip: req.ip,
          path: req.path,
          sub: payload.sub,
          exp: payload.exp,
          maxAllowed: maxExpiry,
        });
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      // Validate iat is not in the future (with clock tolerance)
      if (payload.iat > now + config.jwt.clockToleranceSeconds) {
        recordAuth('failure');
        securityLog.warn({
          event: 'jwt_iat_future',
          correlationId,
          ip: req.ip,
          path: req.path,
          sub: payload.sub,
          iat: payload.iat,
        });
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      // ── Token binding validation ──────────────────────────────────
      const tokenBindingClaim = payload['cnf'] as { 'x5t#S256'?: string } | undefined;
      if (tokenBindingClaim?.['x5t#S256']) {
        // If token has a binding claim, validate it against the TLS certificate
        const tlsCertHash = req.headers['x-tls-client-cert-hash'] as string | undefined;
        if (!tlsCertHash || tlsCertHash !== tokenBindingClaim['x5t#S256']) {
          recordAuth('failure');
          securityLog.warn({
            event: 'jwt_token_binding_mismatch',
            correlationId,
            ip: req.ip,
            path: req.path,
            sub: payload.sub,
          });
          res.status(401).json({ error: 'Unauthorized' });
          return;
        }
      }

      // ── Extract identity claims ───────────────────────────────────
      const identity: GatewayIdentity = {
        sub: payload.sub || 'unknown',
        tenantId: extractTenantId(payload),
        iss: payload.iss || config.jwt.issuer,
        aud: payload.aud || config.jwt.audience,
        exp: payload.exp,
        iat: payload.iat,
        roles: extractStringArray(payload, 'roles'),
        scopes: extractStringArray(payload, 'scopes'),
        // Compatibility: some issuers use `scopes` instead of `permissions`.
        permissions: (() => {
          const perms = extractStringArray(payload, 'permissions');
          return perms.length > 0 ? perms : extractStringArray(payload, 'scopes');
        })(),
        stepUpLevel: typeof payload['step_up_level'] === 'number' ? payload['step_up_level'] : 0,
        tokenVersion: (() => {
          const rawTv = payload['tv'];
          if (typeof rawTv === 'number' && Number.isFinite(rawTv)) return rawTv;
          if (typeof rawTv === 'string') {
            const n = parseInt(rawTv, 10);
            return Number.isFinite(n) ? n : undefined;
          }
          return undefined;
        })(),
        tokenBindingHash: tokenBindingClaim?.['x5t#S256'],
        jti: typeof payload.jti === 'string' ? payload.jti : undefined,
        raw: payload,
      };

      // Attach to request context
      req.identity = identity;

      // Log successful validation at debug level
      securityLog.info({
        event: 'jwt_validated',
        correlationId,
        sub: identity.sub,
        roles: identity.roles,
        algorithm: protectedHeader.alg,
        path: req.path,
        method: req.method,
      });

      recordAuth('success');
      next();
    } catch (err) {
      // Map jose errors to security events without leaking details
      let reason = 'validation_failed';

      if (err instanceof jose.errors.JWTExpired) {
        reason = 'token_expired';
      } else if (err instanceof jose.errors.JWTClaimValidationFailed) {
        reason = 'claim_validation_failed';
      } else if (err instanceof jose.errors.JWSSignatureVerificationFailed) {
        reason = 'signature_invalid';
      } else if (err instanceof jose.errors.JWKSNoMatchingKey) {
        reason = 'no_matching_key';
      } else if (err instanceof jose.errors.JWKSMultipleMatchingKeys) {
        reason = 'multiple_matching_keys';
      } else if (err instanceof jose.errors.JWKSTimeout) {
        reason = 'jwks_timeout';
      }

      securityLog.warn({
        event: 'jwt_validation_failed',
        correlationId,
        ip: req.ip,
        path: req.path,
        method: req.method,
        reason,
        errorClass: err instanceof Error ? err.constructor.name : 'unknown',
      });

      recordAuth('failure');
      // Return 401 with minimal information — never leak why validation failed
      res.status(401).json({ error: 'Unauthorized' });
    }
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function extractStringArray(payload: jose.JWTPayload, claim: string): string[] {
  const value = payload[claim];
  if (Array.isArray(value)) {
    return value.filter((v): v is string => typeof v === 'string');
  }
  if (typeof value === 'string') {
    return value.split(/[\s,]+/).filter(Boolean);
  }
  return [];
}

function extractTenantId(payload: jose.JWTPayload): string | undefined {
  const candidates = [
    payload['tenant_id'],
    payload['tenant'],
    payload['tid'],
  ];
  for (const candidate of candidates) {
    if (typeof candidate !== 'string') continue;
    const value = candidate.trim();
    if (!value) continue;
    return value.slice(0, 128);
  }
  return undefined;
}
