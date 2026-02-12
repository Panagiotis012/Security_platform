/**
 * Default configuration for the Identity & Authorization Plane.
 *
 * All durations are in seconds unless otherwise noted.
 * Sensitive values (client secrets, signing keys) MUST be provided via
 * environment variables and are never committed to source control.
 */

import { readSecret } from '@zerotrust/shared';

// ---------------------------------------------------------------------------
// OIDC provider templates
// ---------------------------------------------------------------------------

export interface OIDCProviderConfig {
  /** Human-readable name shown in login selectors. */
  name: string;
  /** OpenID Connect issuer URL (used for .well-known discovery). */
  issuerUrl: string;
  /** OAuth 2.0 client ID. */
  clientId: string;
  /** OAuth 2.0 client secret (empty string for public clients using PKCE only). */
  clientSecret: string;
  /** URI the provider redirects to after authentication. */
  redirectUri: string;
  /** Scopes to request. */
  scopes: string[];
  /** Whether this provider is enabled. */
  enabled: boolean;
}

export interface IdentityConfig {
  server: {
    port: number;
    host: string;
    /** Base URL for constructing absolute redirect URIs. */
    externalBaseUrl: string;
  };

  oidcProviders: Record<string, OIDCProviderConfig>;

  tokens: {
    /** Access token lifetime in seconds. Hard cap at 900 (15 min). */
    accessTokenTtlSeconds: number;
    /** Refresh token lifetime in seconds. Hard cap at 86400 (24 h). */
    refreshTokenTtlSeconds: number;
    /** Step-up authentication window in seconds. */
    stepUpTtlSeconds: number;
    /** Workload token lifetime in seconds. */
    workloadTokenTtlSeconds: number;
    /** Issuer claim written into JWTs. */
    issuer: string;
    /** Audience claim written into JWTs. */
    audience: string;
    /** Algorithm for signing JWTs. */
    algorithm: 'RS256' | 'ES256';
  };

  sessions: {
    /** Idle timeout in seconds. Session expires after this period of inactivity. */
    idleTimeoutSeconds: number;
    /** Absolute timeout in seconds. Session expires regardless of activity. */
    absoluteTimeoutSeconds: number;
    /** Cookie name for the session identifier. */
    cookieName: string;
    /** Cookie domain (empty = most restrictive, no Domain attribute). */
    cookieDomain: string;
    /** Cookie path. */
    cookiePath: string;
    /** SameSite attribute: 'strict' or 'lax'. */
    cookieSameSite: 'strict' | 'lax';
    /** Whether the Secure flag is set. Must be true in production. */
    cookieSecure: boolean;
  };

  cors: {
    /** Allowed origins for auth endpoints. */
    allowedOrigins: string[];
    /** Allowed HTTP methods. */
    allowedMethods: string[];
    /** Allowed request headers. */
    allowedHeaders: string[];
    /** Whether credentials (cookies) are allowed. */
    credentials: boolean;
    /** Max age for preflight cache (seconds). */
    maxAgeSeconds: number;
  };

  csrf: {
    /** Header name used for double-submit cookie CSRF protection. */
    headerName: string;
    /** Cookie name for the CSRF token. */
    cookieName: string;
  };

  redis: {
    host: string;
    port: number;
    password: string;
    /** Key prefix to isolate identity data in a shared Redis instance. */
    keyPrefix: string;
    tls: boolean;
  };

  logging: {
    level: string;
  };
}

// ---------------------------------------------------------------------------
// Enforce hard caps on token lifetimes
// ---------------------------------------------------------------------------

const MAX_ACCESS_TOKEN_TTL = 900;   // 15 minutes
const MAX_REFRESH_TOKEN_TTL = 86400; // 24 hours
const MAX_STEP_UP_TTL = 300;         // 5 minutes

function clamp(value: number, max: number): number {
  return Math.min(Math.max(value, 1), max);
}

// ---------------------------------------------------------------------------
// Build config from environment with safe defaults
// ---------------------------------------------------------------------------

function env(key: string, fallback: string): string {
  return process.env[key] ?? fallback;
}

function envInt(key: string, fallback: number): number {
  const raw = process.env[key];
  if (raw === undefined) return fallback;
  const parsed = parseInt(raw, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

function envBool(key: string, fallback: boolean): boolean {
  const raw = process.env[key];
  if (raw === undefined) return fallback;
  return raw === 'true' || raw === '1';
}

const externalBaseUrl = env('IDENTITY_EXTERNAL_BASE_URL', 'https://localhost:8182');

export const config: IdentityConfig = {
  server: {
    port: envInt('IDENTITY_PORT', envInt('PORT', 8182)),
    host: env('IDENTITY_HOST', env('HOST', '0.0.0.0')),
    externalBaseUrl,
  },

  oidcProviders: {
    google: {
      name: 'Google',
      issuerUrl: 'https://accounts.google.com',
      clientId: env('OIDC_GOOGLE_CLIENT_ID', ''),
      clientSecret: readSecret('OIDC_GOOGLE_CLIENT_SECRET', { defaultValue: '' }),
      redirectUri: `${externalBaseUrl}/auth/callback`,
      scopes: ['openid', 'profile', 'email'],
      enabled: envBool('OIDC_GOOGLE_ENABLED', false),
    },
    microsoft: {
      name: 'Microsoft',
      issuerUrl: env(
        'OIDC_MICROSOFT_ISSUER',
        'https://login.microsoftonline.com/common/v2.0',
      ),
      clientId: env('OIDC_MICROSOFT_CLIENT_ID', ''),
      clientSecret: readSecret('OIDC_MICROSOFT_CLIENT_SECRET', { defaultValue: '' }),
      redirectUri: `${externalBaseUrl}/auth/callback`,
      scopes: ['openid', 'profile', 'email'],
      enabled: envBool('OIDC_MICROSOFT_ENABLED', false),
    },
    keycloak: {
      name: 'Keycloak',
      issuerUrl: env(
        'OIDC_KEYCLOAK_ISSUER',
        'https://keycloak.local/realms/zerotrust',
      ),
      clientId: env('OIDC_KEYCLOAK_CLIENT_ID', ''),
      clientSecret: readSecret('OIDC_KEYCLOAK_CLIENT_SECRET', { defaultValue: '' }),
      redirectUri: `${externalBaseUrl}/auth/callback`,
      scopes: ['openid', 'profile', 'email', 'roles'],
      enabled: envBool('OIDC_KEYCLOAK_ENABLED', false),
    },
  },

  tokens: {
    accessTokenTtlSeconds: clamp(
      envInt('TOKEN_ACCESS_TTL', 900),
      MAX_ACCESS_TOKEN_TTL,
    ),
    refreshTokenTtlSeconds: clamp(
      envInt('TOKEN_REFRESH_TTL', 86400),
      MAX_REFRESH_TOKEN_TTL,
    ),
    stepUpTtlSeconds: clamp(
      envInt('TOKEN_STEPUP_TTL', 300),
      MAX_STEP_UP_TTL,
    ),
    workloadTokenTtlSeconds: clamp(
      envInt('TOKEN_WORKLOAD_TTL', 300),
      MAX_ACCESS_TOKEN_TTL,
    ),
    issuer: env('TOKEN_ISSUER', 'https://identity.zerotrust.local'),
    audience: env('TOKEN_AUDIENCE', 'https://api.zerotrust.local'),
    algorithm: (env('TOKEN_ALGORITHM', 'ES256') as 'RS256' | 'ES256'),
  },

  sessions: {
    idleTimeoutSeconds: envInt('SESSION_IDLE_TIMEOUT', 1800),   // 30 min
    absoluteTimeoutSeconds: envInt('SESSION_ABSOLUTE_TIMEOUT', 43200), // 12 h
    // Use __Host- by default for host-only + secure + Path=/ cookies (strongest default).
    cookieName: env('SESSION_COOKIE_NAME', '__Host-zt_sid'),
    cookieDomain: env('SESSION_COOKIE_DOMAIN', ''),              // most restrictive
    cookiePath: '/',
    cookieSameSite: env('SESSION_COOKIE_SAMESITE', 'strict') as 'strict' | 'lax',
    cookieSecure: envBool('SESSION_COOKIE_SECURE', true),
  },

  cors: {
    allowedOrigins: env('CORS_ORIGINS', '').split(',').filter(Boolean),
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: [
      'Authorization',
      'Content-Type',
      'X-CSRF-Token',
      'X-Request-ID',
    ],
    credentials: true,
    maxAgeSeconds: 600,
  },

  csrf: {
    headerName: 'x-csrf-token',
    cookieName: '__Host-zt_csrf',
  },

  redis: {
    host: env('REDIS_HOST', '127.0.0.1'),
    port: envInt('REDIS_PORT', 6379),
    password: readSecret('REDIS_PASSWORD', { defaultValue: '' }),
    keyPrefix: 'zt:identity:',
    tls: envBool('REDIS_TLS', false),
  },

  logging: {
    level: env('LOG_LEVEL', 'info'),
  },
};

export default config;
