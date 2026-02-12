/**
 * Token Service -- issues, validates, rotates, and revokes JWTs and refresh
 * tokens for the Identity Plane.
 *
 * Security invariants:
 *  - Access tokens are short-lived JWTs (max 15 min).
 *  - Refresh tokens are opaque, server-side, max 24 h, rotated on every use.
 *  - Refresh token reuse detection: if an already-rotated token is presented,
 *    the entire token family is revoked (indicates theft).
 *  - Tokens are NEVER issued without an expiry.
 *  - Optional token binding ties the JWT to a client certificate fingerprint.
 */

import * as jose from 'jose';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import { config } from '../../config/default';
import type { JWKSManager } from './jwks';
import type { TokenVersionStore } from './token-version-store';
import type { JtiRevocationStore } from './jti-revocation-store';
import {
  InMemoryRefreshTokenStore,
  type RefreshTokenStore,
} from './refresh-token-store';
import { createLogger } from '../logger';
import { readSecret } from '@zerotrust/shared';

const logger = createLogger('token-service');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_ACCESS_TTL_SECONDS = 900;    // 15 minutes hard cap
const MAX_REFRESH_TTL_SECONDS = 86400; // 24 hours hard cap

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AccessTokenClaims {
  /** JWT ID */
  jti: string;
  /** Subject (user id) */
  sub: string;
  /** Issuer */
  iss: string;
  /** Audience */
  aud: string;
  /** Issued-at (Unix epoch) */
  iat: number;
  /** Expiration (Unix epoch) */
  exp: number;
  /** Roles granted to the subject */
  roles: string[];
  /** OAuth scopes */
  scopes: string[];
  /** Step-up authentication level (0 = basic, 1 = MFA, 2 = recent MFA) */
  step_up_level: number;
  /** Session ID this token was issued under */
  sid?: string;
  /** Token binding: SHA-256 fingerprint of the client certificate */
  cnf?: { 'x5t#S256': string };
}

export interface RefreshTokenRecord {
  /** Opaque refresh token value (high-entropy random). */
  token: string;
  /** The token ID (used for revocation lookups). */
  tokenId: string;
  /** User this token belongs to. */
  userId: string;
  /** Session this token is bound to. */
  sessionId: string;
  /** Family ID -- all tokens in a rotation chain share this. */
  familyId: string;
  /** ISO-8601 creation timestamp. */
  createdAt: string;
  /** ISO-8601 absolute expiration. */
  expiresAt: string;
  /** Whether this token has already been consumed (rotated). */
  consumed: boolean;
}

export interface IssuedTokens {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresIn: number;
}

// ---------------------------------------------------------------------------
// Token Service
// ---------------------------------------------------------------------------

export class TokenService {
  private readonly jwks: JWKSManager;
  private readonly tokenVersions: TokenVersionStore;
  private readonly jtiRevocations: JtiRevocationStore;
  private readonly refreshTokens: RefreshTokenStore;
  private readonly refreshTokenHashSecret: string;

  /**
   * Refresh tokens are opaque and must never be stored in plaintext at rest.
   * We store them server-side keyed by a keyed-hash (HMAC) of the token value.
   */
  private readonly hashAlgorithm = 'sha256' as const;

  constructor(
    jwks: JWKSManager,
    deps: {
      tokenVersions: TokenVersionStore;
      jtiRevocations: JtiRevocationStore;
      refreshTokenStore?: RefreshTokenStore;
      refreshTokenHashSecret?: string;
    }
  ) {
    this.jwks = jwks;
    this.tokenVersions = deps.tokenVersions;
    this.jtiRevocations = deps.jtiRevocations;
    this.refreshTokens = deps.refreshTokenStore ?? new InMemoryRefreshTokenStore();
    this.refreshTokenHashSecret =
      deps.refreshTokenHashSecret ??
      readSecret('INTERNAL_SHARED_SECRET', { defaultValue: 'dev-refresh-secret-change-me' });
  }

  // -----------------------------------------------------------------------
  // Access Tokens
  // -----------------------------------------------------------------------

  /**
   * Issue a signed access token (JWT).
   *
   * @param userId        Subject identifier.
   * @param roles         Roles to embed in the token.
   * @param scopes        OAuth scopes to embed.
   * @param stepUpLevel   Step-up auth level (0-2).
   * @param sessionId     Optional session binding.
   * @param certFingerprint  Optional client cert SHA-256 fingerprint for token binding.
   */
  async issueAccessToken(
    userId: string,
    roles: string[],
    scopes: string[],
    stepUpLevel: number = 0,
    sessionId?: string,
    certFingerprint?: string,
  ): Promise<{ token: string; jti: string; expiresIn: number }> {
    const signingKey = this.jwks.getSigningKey();
    const jti = uuidv4();
    const ttl = Math.min(config.tokens.accessTokenTtlSeconds, MAX_ACCESS_TTL_SECONDS);
    const now = Math.floor(Date.now() / 1000);
    const tokenVersion = await this.tokenVersions.getVersion(userId);

    const payload: Record<string, unknown> = {
      jti,
      sub: userId,
      roles,
      scopes,
      step_up_level: stepUpLevel,
      tv: tokenVersion,
    };

    if (sessionId) {
      payload['sid'] = sessionId;
    }

    // Token binding via certificate confirmation claim (RFC 8705).
    if (certFingerprint) {
      payload['cnf'] = { 'x5t#S256': certFingerprint };
    }

    const token = await new jose.SignJWT(payload)
      .setProtectedHeader({ alg: signingKey.algorithm, kid: signingKey.kid, typ: 'at+jwt' })
      .setIssuer(config.tokens.issuer)
      .setAudience(config.tokens.audience)
      .setIssuedAt(now)
      .setExpirationTime(now + ttl)
      .setNotBefore(now)
      .sign(signingKey.privateKey);

    logger.info('Access token issued', { jti, userId, ttl });

    return { token, jti, expiresIn: ttl };
  }

  // -----------------------------------------------------------------------
  // Refresh Tokens
  // -----------------------------------------------------------------------

  /**
   * Issue an opaque refresh token stored server-side.
   */
  async issueRefreshToken(
    userId: string,
    sessionId: string,
    familyId?: string,
  ): Promise<RefreshTokenRecord> {
    const token = this.generateOpaqueToken();
    const tokenId = uuidv4();
    const ttl = Math.min(config.tokens.refreshTokenTtlSeconds, MAX_REFRESH_TTL_SECONDS);
    const now = new Date();

    const fid = familyId ?? uuidv4();

    const record: RefreshTokenRecord = {
      token,
      tokenId,
      userId,
      sessionId,
      familyId: fid,
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttl * 1000).toISOString(),
      consumed: false,
    };

    const tokenHash = this.hashRefreshToken(token);
    await this.refreshTokens.put(tokenHash, {
      tokenId,
      userId,
      sessionId,
      familyId: fid,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      consumed: false,
    }, ttl);

    logger.info('Refresh token issued', { tokenId, userId, familyId: fid });

    return record;
  }

  /**
   * Rotate a refresh token: consume the old one and issue a new one.
   *
   * If the old token has already been consumed (reuse detected), the entire
   * token family is revoked -- this indicates the token was stolen and
   * replayed.
   */
  async rotateRefreshToken(oldTokenValue: string): Promise<RefreshTokenRecord> {
    const oldHash = this.hashRefreshToken(oldTokenValue);
    const old = await this.refreshTokens.get(oldHash);
    if (!old) throw new TokenError('Refresh token not found', 'TOKEN_NOT_FOUND');

    // Check expiry.
    if (new Date(old.expiresAt).getTime() <= Date.now()) {
      await this.refreshTokens.revokeToken(oldHash);
      throw new TokenError('Refresh token expired', 'TOKEN_EXPIRED');
    }

    // Reuse detection: if the token was already consumed, revoke the entire
    // family and throw.
    const marked = await this.refreshTokens.markConsumed(oldHash);
    if (marked === 'already_consumed' || old.consumed) {
      logger.error('Refresh token reuse detected -- revoking family', {
        tokenId: old.tokenId,
        familyId: old.familyId,
        userId: old.userId,
      });
      await this.refreshTokens.revokeFamily(old.familyId);
      throw new TokenError(
        'Refresh token reuse detected. All tokens in this family have been revoked.',
        'TOKEN_REUSE',
      );
    }

    if (marked === 'not_found') {
      throw new TokenError('Refresh token not found', 'TOKEN_NOT_FOUND');
    }

    // Issue replacement in the same family.
    const newRecord = await this.issueRefreshToken(old.userId, old.sessionId, old.familyId);

    logger.info('Refresh token rotated', {
      oldTokenId: old.tokenId,
      newTokenId: newRecord.tokenId,
      familyId: old.familyId,
    });

    return newRecord;
  }

  // -----------------------------------------------------------------------
  // Revocation
  // -----------------------------------------------------------------------

  /**
   * Revoke a single access token by its JTI.
   */
  async revokeAccessToken(jti: string, expSeconds?: number): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const fallbackTtl = Math.min(config.tokens.accessTokenTtlSeconds, MAX_ACCESS_TTL_SECONDS);
    const ttl = expSeconds && expSeconds > now ? expSeconds - now : fallbackTtl;
    await this.jtiRevocations.revoke(jti, ttl);
    logger.info('Access token revoked', { jti, ttl });
  }

  /**
   * Revoke a refresh token by its opaque value.
   */
  async revokeRefreshToken(tokenValue: string): Promise<void> {
    const tokenHash = this.hashRefreshToken(tokenValue);
    await this.refreshTokens.revokeToken(tokenHash);
  }

  /**
   * Check whether an access token JTI has been revoked.
   */
  async isRevoked(jti: string): Promise<boolean> {
    return await this.jtiRevocations.isRevoked(jti);
  }

  /**
   * Revoke all current + future tokens for a user by bumping their token version.
   * This is the safest compromise response for stateless JWT systems.
   */
  async revokeUserTokens(userId: string): Promise<number> {
    // Critical: also revoke refresh tokens, otherwise an attacker can use a stolen
    // refresh token to mint fresh JWTs with the new token version.
    await this.refreshTokens.revokeUser(userId);
    const next = await this.tokenVersions.incrementVersion(userId);
    logger.warn('User token version incremented (global revoke)', { userId, tokenVersion: next });
    return next;
  }

  /**
   * Revoke all refresh tokens bound to a session (logout).
   */
  async revokeSessionRefreshTokens(sessionId: string): Promise<number> {
    return await this.refreshTokens.revokeSession(sessionId);
  }

  /**
   * Revoke an entire refresh token family (reuse response / incident response).
   */
  async revokeRefreshTokenFamily(familyId: string): Promise<number> {
    return await this.refreshTokens.revokeFamily(familyId);
  }

  // -----------------------------------------------------------------------
  // Validation
  // -----------------------------------------------------------------------

  /**
   * Validate an access token: verify signature, expiry, issuer, audience,
   * and revocation status.  Returns the decoded claims or throws.
   *
   * @param token             The raw JWT string.
   * @param certFingerprint   If the token has a `cnf` claim, the presented
   *                          certificate fingerprint must match.
   */
  async validateAccessToken(
    token: string,
    certFingerprint?: string,
  ): Promise<AccessTokenClaims> {
    // Build a local JWKS resolver from our published keys.
    const jwksData = await this.jwks.toJWKS();
    const localJWKS = jose.createLocalJWKSet(jwksData);

    let payload: jose.JWTPayload;
    try {
      const result = await jose.jwtVerify(token, localJWKS, {
        issuer: config.tokens.issuer,
        audience: config.tokens.audience,
        clockTolerance: 5, // 5 second clock skew tolerance
      });
      payload = result.payload;
    } catch (err) {
      if (err instanceof jose.errors.JWTExpired) {
        throw new TokenError('Access token expired', 'TOKEN_EXPIRED');
      }
      if (err instanceof jose.errors.JWTClaimValidationFailed) {
        throw new TokenError(
          `Token claim validation failed: ${err.message}`,
          'TOKEN_INVALID',
        );
      }
      throw new TokenError(
        `Token verification failed: ${(err as Error).message}`,
        'TOKEN_INVALID',
      );
    }

    const jti = payload['jti'] as string | undefined;
    if (!jti) {
      throw new TokenError('Token missing jti claim', 'TOKEN_INVALID');
    }

    // Revocation check.
    if (await this.isRevoked(jti)) {
      throw new TokenError('Token has been revoked', 'TOKEN_REVOKED');
    }

    // Token version check (global revoke support).
    const tokenVersion =
      typeof payload['tv'] === 'number'
        ? payload['tv']
        : typeof payload['tv'] === 'string'
          ? parseInt(payload['tv'] as string, 10)
          : 0;
    const currentVersion = await this.tokenVersions.getVersion(payload['sub'] as string);
    if (currentVersion !== tokenVersion) {
      throw new TokenError('Token has been revoked', 'TOKEN_REVOKED');
    }

    // Token binding check.
    const cnf = payload['cnf'] as { 'x5t#S256'?: string } | undefined;
    if (cnf?.['x5t#S256']) {
      if (!certFingerprint) {
        throw new TokenError(
          'Token requires certificate binding but no certificate presented',
          'TOKEN_BINDING_FAILED',
        );
      }
      if (cnf['x5t#S256'] !== certFingerprint) {
        throw new TokenError(
          'Certificate fingerprint does not match token binding',
          'TOKEN_BINDING_FAILED',
        );
      }
    }

    return {
      jti,
      sub: payload['sub'] as string,
      iss: payload['iss'] as string,
      aud: payload['aud'] as string,
      iat: payload['iat'] as number,
      exp: payload['exp'] as number,
      roles: (payload['roles'] as string[]) ?? [],
      scopes: (payload['scopes'] as string[]) ?? [],
      step_up_level: (payload['step_up_level'] as number) ?? 0,
      sid: payload['sid'] as string | undefined,
      cnf: cnf as AccessTokenClaims['cnf'],
    };
  }

  /**
   * Look up a refresh token record by its opaque value.
   */
  async getRefreshToken(tokenValue: string): Promise<RefreshTokenRecord | undefined> {
    const tokenHash = this.hashRefreshToken(tokenValue);
    const record = await this.refreshTokens.get(tokenHash);
    if (!record) return undefined;
    return {
      token: tokenValue,
      ...record,
    };
  }

  // -----------------------------------------------------------------------
  // Cleanup
  // -----------------------------------------------------------------------

  /** Stop background eviction (call during graceful shutdown). */
  destroy(): void {
    // No-op: stores manage their own lifecycle.
  }

  // -----------------------------------------------------------------------
  // Internal helpers
  // -----------------------------------------------------------------------

  private hashRefreshToken(tokenValue: string): string {
    // Keyed hash so tokens never appear (even hashed) in Redis keys/logs.
    return crypto
      .createHmac(this.hashAlgorithm, this.refreshTokenHashSecret)
      .update(tokenValue, 'utf8')
      .digest('hex');
  }

  private generateOpaqueToken(): string {
    return crypto.randomBytes(32).toString('base64url');
  }
}

// ---------------------------------------------------------------------------
// Token-specific error
// ---------------------------------------------------------------------------

export type TokenErrorCode =
  | 'TOKEN_NOT_FOUND'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_INVALID'
  | 'TOKEN_REVOKED'
  | 'TOKEN_REUSE'
  | 'TOKEN_BINDING_FAILED';

export class TokenError extends Error {
  public readonly code: TokenErrorCode;

  constructor(message: string, code: TokenErrorCode) {
    super(message);
    this.name = 'TokenError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
