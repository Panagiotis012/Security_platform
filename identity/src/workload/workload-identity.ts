/**
 * Workload Identity Service -- service-to-service authentication.
 *
 * Enables microservices in the Zero Trust platform to authenticate to each
 * other without long-lived shared secrets.  Each service registers a public
 * key; the identity plane issues short-lived JWTs that other services can
 * verify using the platform's JWKS.
 *
 * Security invariants:
 *  - No long-lived shared secrets between services.
 *  - Workload tokens are short-lived (max 15 min, default 5 min).
 *  - mTLS certificate validation helpers are provided.
 *  - Certificate fingerprint extraction for token binding.
 */

import * as jose from 'jose';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../../config/default';
import type { JWKSManager } from '../tokens/jwks';
import { createLogger } from '../logger';

const logger = createLogger('workload-identity');

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WorkloadRegistration {
  /** Unique service identifier (e.g. "gateway", "policy-engine"). */
  serviceId: string;
  /** The service's public key in JWK format (for verifying service-signed requests). */
  publicKey: jose.JWK;
  /** Scopes this service is allowed to request. */
  allowedScopes: string[];
  /** ISO-8601 registration timestamp. */
  registeredAt: string;
  /** Whether this service registration is active. */
  active: boolean;
  /** SHA-256 fingerprint of the service's mTLS certificate (optional). */
  certificateFingerprint?: string;
  /** Human-readable description of the service. */
  description?: string;
}

export interface WorkloadTokenClaims {
  /** JWT ID. */
  jti: string;
  /** Subject: the service ID. */
  sub: string;
  /** Issuer. */
  iss: string;
  /** Audience. */
  aud: string;
  /** Issued-at (Unix epoch). */
  iat: number;
  /** Expiration (Unix epoch). */
  exp: number;
  /** Scopes granted. */
  scopes: string[];
  /** Token type: always "workload". */
  token_type: 'workload';
  /** Certificate confirmation (mTLS binding). */
  cnf?: { 'x5t#S256': string };
}

// ---------------------------------------------------------------------------
// Workload Identity Service
// ---------------------------------------------------------------------------

export class WorkloadIdentityService {
  private readonly jwks: JWKSManager;

  /**
   * Registered services.  In production, persist to a database.
   */
  private readonly registrations = new Map<string, WorkloadRegistration>();

  constructor(jwks: JWKSManager) {
    this.jwks = jwks;
  }

  // -----------------------------------------------------------------------
  // Service registration
  // -----------------------------------------------------------------------

  /**
   * Register a service with its public key.
   *
   * @param serviceId           Unique identifier for the service.
   * @param publicKeyJWK        The service's public key in JWK format.
   * @param allowedScopes       Scopes the service may request.
   * @param certFingerprint     Optional mTLS certificate fingerprint.
   * @param description         Human-readable description.
   */
  async registerService(
    serviceId: string,
    publicKeyJWK: jose.JWK,
    allowedScopes: string[] = [],
    certFingerprint?: string,
    description?: string,
  ): Promise<WorkloadRegistration> {
    // Validate that the JWK is a public key (no private material).
    if (publicKeyJWK.d || publicKeyJWK.p || publicKeyJWK.q) {
      throw new WorkloadError(
        'Registration must use a public key, not a private key',
        'INVALID_KEY',
      );
    }

    // Validate that the key is usable.
    try {
      await jose.importJWK(publicKeyJWK);
    } catch (err) {
      throw new WorkloadError(
        `Invalid public key: ${(err as Error).message}`,
        'INVALID_KEY',
      );
    }

    const registration: WorkloadRegistration = {
      serviceId,
      publicKey: publicKeyJWK,
      allowedScopes,
      registeredAt: new Date().toISOString(),
      active: true,
      certificateFingerprint: certFingerprint,
      description,
    };

    this.registrations.set(serviceId, registration);

    logger.info('Workload service registered', {
      serviceId,
      allowedScopes,
      hasCertFingerprint: !!certFingerprint,
    });

    return registration;
  }

  /**
   * Deactivate a service registration without removing its record.
   */
  deactivateService(serviceId: string): void {
    const reg = this.registrations.get(serviceId);
    if (reg) {
      reg.active = false;
      this.registrations.set(serviceId, reg);
      logger.info('Workload service deactivated', { serviceId });
    }
  }

  /**
   * Look up a service registration.
   */
  getRegistration(serviceId: string): WorkloadRegistration | undefined {
    return this.registrations.get(serviceId);
  }

  // -----------------------------------------------------------------------
  // Token issuance
  // -----------------------------------------------------------------------

  /**
   * Issue a short-lived workload JWT for a registered service.
   *
   * @param serviceId        The requesting service's identifier.
   * @param requestedScopes  The scopes the service wants.
   * @param certFingerprint  Optional: the SHA-256 fingerprint of the
   *                         presenting mTLS certificate for token binding.
   */
  async issueWorkloadToken(
    serviceId: string,
    requestedScopes: string[],
    certFingerprint?: string,
  ): Promise<{ token: string; expiresIn: number }> {
    const registration = this.registrations.get(serviceId);

    if (!registration) {
      throw new WorkloadError(
        `Service '${serviceId}' is not registered`,
        'SERVICE_NOT_FOUND',
      );
    }

    if (!registration.active) {
      throw new WorkloadError(
        `Service '${serviceId}' is deactivated`,
        'SERVICE_INACTIVE',
      );
    }

    // Validate that the service has registered an mTLS cert if one is
    // presented, and that they match.
    if (registration.certificateFingerprint && certFingerprint) {
      if (registration.certificateFingerprint !== certFingerprint) {
        throw new WorkloadError(
          'Certificate fingerprint does not match registration',
          'CERT_MISMATCH',
        );
      }
    }

    // Filter requested scopes to only those the service is allowed.
    const grantedScopes = requestedScopes.filter((s) =>
      registration.allowedScopes.includes(s),
    );

    if (grantedScopes.length === 0 && requestedScopes.length > 0) {
      throw new WorkloadError(
        'None of the requested scopes are allowed for this service',
        'SCOPE_DENIED',
      );
    }

    const signingKey = this.jwks.getSigningKey();
    const jti = uuidv4();
    const ttl = config.tokens.workloadTokenTtlSeconds;
    const now = Math.floor(Date.now() / 1000);

    const payload: Record<string, unknown> = {
      jti,
      scopes: grantedScopes,
      token_type: 'workload',
    };

    // Token binding via certificate confirmation.
    if (certFingerprint) {
      payload['cnf'] = { 'x5t#S256': certFingerprint };
    }

    const token = await new jose.SignJWT(payload)
      .setProtectedHeader({
        alg: signingKey.algorithm,
        kid: signingKey.kid,
        typ: 'at+jwt',
      })
      .setIssuer(config.tokens.issuer)
      .setAudience(config.tokens.audience)
      .setSubject(serviceId)
      .setIssuedAt(now)
      .setExpirationTime(now + ttl)
      .setNotBefore(now)
      .sign(signingKey.privateKey);

    logger.info('Workload token issued', {
      serviceId,
      jti,
      grantedScopes,
      ttl,
    });

    return { token, expiresIn: ttl };
  }

  // -----------------------------------------------------------------------
  // Token validation
  // -----------------------------------------------------------------------

  /**
   * Validate a workload token.  Verifies signature, expiry, issuer,
   * audience, and that the token type is "workload".
   *
   * @param token            The raw JWT.
   * @param certFingerprint  If token has `cnf`, the presented cert must match.
   */
  async validateWorkloadToken(
    token: string,
    certFingerprint?: string,
  ): Promise<WorkloadTokenClaims> {
    const jwksData = await this.jwks.toJWKS();
    const localJWKS = jose.createLocalJWKSet(jwksData);

    let payload: jose.JWTPayload;
    try {
      const result = await jose.jwtVerify(token, localJWKS, {
        issuer: config.tokens.issuer,
        audience: config.tokens.audience,
        clockTolerance: 5,
      });
      payload = result.payload;
    } catch (err) {
      if (err instanceof jose.errors.JWTExpired) {
        throw new WorkloadError('Workload token expired', 'TOKEN_EXPIRED');
      }
      throw new WorkloadError(
        `Workload token validation failed: ${(err as Error).message}`,
        'TOKEN_INVALID',
      );
    }

    // Ensure this is a workload token.
    if (payload['token_type'] !== 'workload') {
      throw new WorkloadError(
        'Token is not a workload token',
        'TOKEN_INVALID',
      );
    }

    // Certificate binding check.
    const cnf = payload['cnf'] as { 'x5t#S256'?: string } | undefined;
    if (cnf?.['x5t#S256']) {
      if (!certFingerprint) {
        throw new WorkloadError(
          'Workload token requires certificate binding but no certificate presented',
          'CERT_REQUIRED',
        );
      }
      if (cnf['x5t#S256'] !== certFingerprint) {
        throw new WorkloadError(
          'Certificate fingerprint does not match token binding',
          'CERT_MISMATCH',
        );
      }
    }

    return {
      jti: payload['jti'] as string,
      sub: payload['sub'] as string,
      iss: payload['iss'] as string,
      aud: payload['aud'] as string,
      iat: payload['iat'] as number,
      exp: payload['exp'] as number,
      scopes: (payload['scopes'] as string[]) ?? [],
      token_type: 'workload',
      cnf: cnf as WorkloadTokenClaims['cnf'],
    };
  }

  // -----------------------------------------------------------------------
  // mTLS helpers
  // -----------------------------------------------------------------------

  /**
   * Extract the SHA-256 fingerprint from a DER-encoded X.509 certificate.
   * This is used for certificate-bound token binding (RFC 8705).
   */
  static extractCertificateFingerprint(derCert: Buffer): string {
    return crypto.createHash('sha256').update(derCert).digest('base64url');
  }

  /**
   * Extract certificate fingerprint from a PEM-encoded certificate string.
   */
  static extractFingerprintFromPEM(pem: string): string {
    // Strip PEM headers and decode base64 to get DER.
    const b64 = pem
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\s/g, '');
    const der = Buffer.from(b64, 'base64');
    return WorkloadIdentityService.extractCertificateFingerprint(der);
  }

  /**
   * Extract the certificate fingerprint from an Express request's TLS
   * socket (when mTLS is enabled).
   *
   * @param req  Express request object.
   * @returns    SHA-256 fingerprint, or undefined if no client cert.
   */
  static extractFingerprintFromRequest(
    req: { socket?: unknown },
  ): string | undefined {
    const socket = req.socket as {
      getPeerCertificate?: (detailed?: boolean) => { raw?: Buffer };
    } | undefined;

    if (!socket?.getPeerCertificate) {
      return undefined;
    }

    const cert = socket.getPeerCertificate(false);
    if (!cert?.raw) {
      return undefined;
    }

    return WorkloadIdentityService.extractCertificateFingerprint(cert.raw);
  }

  /**
   * Validate that the presented client certificate has a fingerprint
   * matching the expected value.
   */
  static validateCertificateFingerprint(
    presentedFingerprint: string,
    expectedFingerprint: string,
  ): boolean {
    // Constant-time comparison.
    if (presentedFingerprint.length !== expectedFingerprint.length) {
      return false;
    }
    return crypto.timingSafeEqual(
      Buffer.from(presentedFingerprint),
      Buffer.from(expectedFingerprint),
    );
  }
}

// ---------------------------------------------------------------------------
// Workload-specific error
// ---------------------------------------------------------------------------

export type WorkloadErrorCode =
  | 'SERVICE_NOT_FOUND'
  | 'SERVICE_INACTIVE'
  | 'INVALID_KEY'
  | 'SCOPE_DENIED'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_INVALID'
  | 'CERT_REQUIRED'
  | 'CERT_MISMATCH'
  | 'SHARED_SECRET_DENIED';

export class WorkloadError extends Error {
  public readonly code: WorkloadErrorCode;

  constructor(message: string, code: WorkloadErrorCode) {
    super(message);
    this.name = 'WorkloadError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
