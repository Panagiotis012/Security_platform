/**
 * OIDC Provider integration.
 *
 * Wraps the `openid-client` library to support multiple identity providers
 * (Google, Microsoft, Keycloak, or any spec-compliant OIDC issuer).
 *
 * Security invariants:
 *  - PKCE (S256) is mandatory for ALL flows, including confidential clients.
 *  - ID tokens are validated against the provider's JWKS (signature, iss,
 *    aud, exp, nonce).
 *  - Refresh token rotation is requested when supported by the provider.
 */

import type { Client, TokenSet, BaseClient } from 'openid-client';
import { Issuer, generators } from 'openid-client';
import * as jose from 'jose';
import type { OIDCProviderConfig } from '../../config/default';
import { createLogger } from '../logger';

const logger = createLogger('oidc-provider');

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface OIDCTokens {
  accessToken: string;
  idToken: string;
  refreshToken?: string;
  expiresAt?: number;
  tokenType: string;
}

export interface IDTokenClaims {
  sub: string;
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
  nonce?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
  roles?: string[];
  [key: string]: unknown;
}

export interface PKCEPair {
  codeVerifier: string;
  codeChallenge: string;
}

// ---------------------------------------------------------------------------
// OIDC Provider
// ---------------------------------------------------------------------------

export class OIDCProvider {
  private readonly providerConfig: OIDCProviderConfig;
  private issuer: Issuer | null = null;
  private client: Client | null = null;
  private jwksClient: ReturnType<typeof jose.createRemoteJWKSet> | null = null;

  constructor(providerConfig: OIDCProviderConfig) {
    this.providerConfig = providerConfig;
  }

  // -----------------------------------------------------------------------
  // Discovery & configuration
  // -----------------------------------------------------------------------

  /**
   * Discover the provider's OpenID configuration from
   * `.well-known/openid-configuration` and configure the client.
   */
  async discover(): Promise<void> {
    const { issuerUrl, clientId, clientSecret } = this.providerConfig;

    logger.info('Discovering OIDC provider', {
      name: this.providerConfig.name,
      issuerUrl,
    });

    this.issuer = await Issuer.discover(issuerUrl);

    logger.info('OIDC provider discovered', {
      name: this.providerConfig.name,
      issuer: this.issuer.metadata.issuer,
      authorizationEndpoint: this.issuer.metadata.authorization_endpoint,
      tokenEndpoint: this.issuer.metadata.token_endpoint,
    });

    // Determine if this is a public client (no secret) or confidential.
    const clientMetadata: Record<string, unknown> = {
      client_id: clientId,
      redirect_uris: [this.providerConfig.redirectUri],
      response_types: ['code'],
      token_endpoint_auth_method: clientSecret ? 'client_secret_basic' : 'none',
    };

    if (clientSecret) {
      clientMetadata['client_secret'] = clientSecret;
    }

    this.client = new this.issuer.Client(clientMetadata as ConstructorParameters<typeof BaseClient>[0]);

    // Prepare remote JWKS resolver for ID-token validation.
    const jwksUri = this.issuer.metadata.jwks_uri;
    if (jwksUri) {
      this.jwksClient = jose.createRemoteJWKSet(new URL(jwksUri));
    }
  }

  // -----------------------------------------------------------------------
  // PKCE helpers
  // -----------------------------------------------------------------------

  /**
   * Generate a PKCE code_verifier / code_challenge pair.
   * Uses S256 method exclusively.
   */
  static generatePKCE(): PKCEPair {
    const codeVerifier = generators.codeVerifier();
    const codeChallenge = generators.codeChallenge(codeVerifier);
    return { codeVerifier, codeChallenge };
  }

  // -----------------------------------------------------------------------
  // Authorization URL
  // -----------------------------------------------------------------------

  /**
   * Build the authorization URL that the user's browser should be
   * redirected to.
   *
   * @param state           Opaque CSRF / routing state.
   * @param nonce           Nonce for ID-token replay protection.
   * @param codeChallenge   PKCE code challenge (S256).
   */
  buildAuthorizationUrl(
    state: string,
    nonce: string,
    codeChallenge: string,
  ): string {
    this.ensureConfigured();

    const url = this.client!.authorizationUrl({
      scope: this.providerConfig.scopes.join(' '),
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      response_type: 'code',
      redirect_uri: this.providerConfig.redirectUri,
    });

    logger.debug('Authorization URL built', {
      provider: this.providerConfig.name,
    });

    return url;
  }

  // -----------------------------------------------------------------------
  // Token exchange
  // -----------------------------------------------------------------------

  /**
   * Exchange an authorization code for tokens at the provider's token
   * endpoint.
   *
   * @param code          The authorization code from the callback.
   * @param codeVerifier  The PKCE code verifier that matches the challenge.
   */
  async exchangeCode(
    code: string,
    codeVerifier: string,
  ): Promise<OIDCTokens> {
    this.ensureConfigured();

    const tokenSet: TokenSet = await this.client!.callback(
      this.providerConfig.redirectUri,
      { code },
      { code_verifier: codeVerifier },
    );

    if (!tokenSet.access_token || !tokenSet.id_token) {
      throw new OIDCError(
        'Token exchange did not return required tokens',
        'EXCHANGE_FAILED',
      );
    }

    logger.info('Authorization code exchanged', {
      provider: this.providerConfig.name,
      hasRefreshToken: !!tokenSet.refresh_token,
    });

    return {
      accessToken: tokenSet.access_token,
      idToken: tokenSet.id_token,
      refreshToken: tokenSet.refresh_token,
      expiresAt: tokenSet.expires_at,
      tokenType: tokenSet.token_type ?? 'Bearer',
    };
  }

  // -----------------------------------------------------------------------
  // ID Token validation
  // -----------------------------------------------------------------------

  /**
   * Validate an ID token:
   *  1. Verify the signature using the provider's JWKS.
   *  2. Check iss, aud, exp.
   *  3. Verify the nonce if provided.
   *
   * Returns the decoded claims.
   */
  async validateIdToken(
    idToken: string,
    expectedNonce?: string,
  ): Promise<IDTokenClaims> {
    this.ensureConfigured();

    if (!this.jwksClient) {
      throw new OIDCError(
        'No JWKS URI available for this provider',
        'JWKS_UNAVAILABLE',
      );
    }

    let payload: jose.JWTPayload;

    try {
      const result = await jose.jwtVerify(idToken, this.jwksClient, {
        issuer: this.issuer!.metadata.issuer,
        audience: this.providerConfig.clientId,
        clockTolerance: 30, // 30-second skew tolerance
      });
      payload = result.payload;
    } catch (err) {
      if (err instanceof jose.errors.JWTExpired) {
        throw new OIDCError('ID token has expired', 'ID_TOKEN_EXPIRED');
      }
      throw new OIDCError(
        `ID token validation failed: ${(err as Error).message}`,
        'ID_TOKEN_INVALID',
      );
    }

    // Nonce check (required when a nonce was sent in the auth request).
    if (expectedNonce) {
      if (payload['nonce'] !== expectedNonce) {
        throw new OIDCError(
          'ID token nonce does not match expected value',
          'NONCE_MISMATCH',
        );
      }
    }

    // Ensure required claims are present.
    if (!payload['sub']) {
      throw new OIDCError('ID token missing sub claim', 'ID_TOKEN_INVALID');
    }

    const claims: IDTokenClaims = {
      sub: payload['sub'] as string,
      iss: payload['iss'] as string,
      aud: payload['aud'] as string | string[],
      exp: payload['exp'] as number,
      iat: payload['iat'] as number,
      nonce: payload['nonce'] as string | undefined,
      email: payload['email'] as string | undefined,
      email_verified: payload['email_verified'] as boolean | undefined,
      name: payload['name'] as string | undefined,
      preferred_username: payload['preferred_username'] as string | undefined,
      roles: payload['roles'] as string[] | undefined,
    };

    logger.info('ID token validated', {
      provider: this.providerConfig.name,
      sub: claims.sub,
    });

    return claims;
  }

  // -----------------------------------------------------------------------
  // Token refresh
  // -----------------------------------------------------------------------

  /**
   * Refresh the token set using the provider's refresh token.
   * Requests rotation when supported.
   */
  async refreshTokens(refreshToken: string): Promise<OIDCTokens> {
    this.ensureConfigured();

    let tokenSet: TokenSet;
    try {
      tokenSet = await this.client!.refresh(refreshToken);
    } catch (err) {
      throw new OIDCError(
        `Token refresh failed: ${(err as Error).message}`,
        'REFRESH_FAILED',
      );
    }

    if (!tokenSet.access_token) {
      throw new OIDCError(
        'Token refresh did not return an access token',
        'REFRESH_FAILED',
      );
    }

    logger.info('Tokens refreshed', {
      provider: this.providerConfig.name,
      hasNewRefreshToken: !!tokenSet.refresh_token,
    });

    return {
      accessToken: tokenSet.access_token,
      idToken: tokenSet.id_token ?? '',
      refreshToken: tokenSet.refresh_token ?? refreshToken,
      expiresAt: tokenSet.expires_at,
      tokenType: tokenSet.token_type ?? 'Bearer',
    };
  }

  // -----------------------------------------------------------------------
  // Accessors
  // -----------------------------------------------------------------------

  /** Get the provider name. */
  get name(): string {
    return this.providerConfig.name;
  }

  /** Get the provider config (read-only). */
  get providerName(): string {
    return this.providerConfig.name;
  }

  get issuerUrl(): string {
    return this.providerConfig.issuerUrl;
  }

  // -----------------------------------------------------------------------
  // Internal
  // -----------------------------------------------------------------------

  private ensureConfigured(): void {
    if (!this.client || !this.issuer) {
      throw new OIDCError(
        'OIDC provider has not been discovered. Call discover() first.',
        'NOT_CONFIGURED',
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Multi-provider registry
// ---------------------------------------------------------------------------

/**
 * Manages multiple OIDC providers and provides lookup by name.
 */
export class OIDCProviderRegistry {
  private readonly providers = new Map<string, OIDCProvider>();

  /** Register and discover a provider. */
  async register(
    name: string,
    providerConfig: OIDCProviderConfig,
  ): Promise<void> {
    if (!providerConfig.enabled) {
      logger.info('OIDC provider disabled, skipping', { name });
      return;
    }

    const provider = new OIDCProvider(providerConfig);

    try {
      await provider.discover();
      this.providers.set(name, provider);
      logger.info('OIDC provider registered', { name });
    } catch (err) {
      logger.error('Failed to discover OIDC provider', {
        name,
        error: (err as Error).message,
      });
      // Do not throw -- allow the service to start even if one provider
      // is unavailable.  The provider simply won't be offered for login.
    }
  }

  /** Get a provider by name. */
  get(name: string): OIDCProvider | undefined {
    return this.providers.get(name);
  }

  /** List all registered (and discovered) provider names. */
  listProviders(): string[] {
    return Array.from(this.providers.keys());
  }

  /** Get the first available provider (default). */
  getDefault(): OIDCProvider | undefined {
    const first = this.providers.values().next();
    return first.done ? undefined : first.value;
  }

  /** Get a provider or throw if not found. */
  getOrThrow(name: string): OIDCProvider {
    const provider = this.providers.get(name);
    if (!provider) {
      throw new OIDCError(
        `OIDC provider '${name}' not found or not configured`,
        'PROVIDER_NOT_FOUND',
      );
    }
    return provider;
  }
}

// ---------------------------------------------------------------------------
// OIDC-specific error
// ---------------------------------------------------------------------------

export type OIDCErrorCode =
  | 'NOT_CONFIGURED'
  | 'EXCHANGE_FAILED'
  | 'ID_TOKEN_INVALID'
  | 'ID_TOKEN_EXPIRED'
  | 'NONCE_MISMATCH'
  | 'JWKS_UNAVAILABLE'
  | 'REFRESH_FAILED'
  | 'PROVIDER_NOT_FOUND';

export class OIDCError extends Error {
  public readonly code: OIDCErrorCode;

  constructor(message: string, code: OIDCErrorCode) {
    super(message);
    this.name = 'OIDCError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
