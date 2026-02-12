/**
 * Identity models for the Zero Trust security platform.
 *
 * Covers:
 *  - UserIdentity / WorkloadIdentity: the principal making a request.
 *  - Session: server-side session with idle & absolute timeouts, rotation
 *    tracking, and device binding.
 *  - TokenClaims: JWT claim set used across the platform.
 */

import { z } from 'zod';

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export const IdentityType = {
  User: 'user',
  Workload: 'workload',
} as const;
export type IdentityType = (typeof IdentityType)[keyof typeof IdentityType];

export const PrivilegeLevel = {
  /** Standard access – no step-up. */
  Standard: 'standard',
  /** Elevated after MFA / step-up auth. */
  Elevated: 'elevated',
  /** Admin-level (break-glass). */
  Admin: 'admin',
} as const;
export type PrivilegeLevel =
  (typeof PrivilegeLevel)[keyof typeof PrivilegeLevel];

export const SessionStatus = {
  Active: 'active',
  Expired: 'expired',
  Revoked: 'revoked',
  Locked: 'locked',
} as const;
export type SessionStatus =
  (typeof SessionStatus)[keyof typeof SessionStatus];

// ---------------------------------------------------------------------------
// UserIdentity
// ---------------------------------------------------------------------------

export const UserIdentitySchema = z.object({
  type: z.literal('user'),
  /** Globally unique user identifier (e.g. UUID). */
  id: z.string().min(1).max(256),
  /** Username / login handle. */
  username: z.string().min(1).max(256),
  /** User's email address. */
  email: z.string().email().max(320).optional(),
  /** Display name. */
  displayName: z.string().max(256).optional(),
  /** Roles assigned via RBAC. */
  roles: z.array(z.string().min(1).max(128)).default([]),
  /** Groups the user belongs to. */
  groups: z.array(z.string().min(1).max(256)).default([]),
  /** Arbitrary attributes for ABAC evaluation. */
  attributes: z.record(z.string(), z.unknown()).default({}),
  /** Whether the identity is currently enabled. */
  enabled: z.boolean().default(true),
  /** MFA enrollment status. */
  mfaEnabled: z.boolean().default(false),
  /** ISO 8601 timestamp of last successful authentication. */
  lastAuthenticated: z.string().datetime({ offset: true }).optional(),
  /** Identity provider that vouches for this user. */
  identityProvider: z.string().max(256).optional(),
  createdAt: z.string().datetime({ offset: true }),
  updatedAt: z.string().datetime({ offset: true }),
});

export type UserIdentity = z.infer<typeof UserIdentitySchema>;

// ---------------------------------------------------------------------------
// WorkloadIdentity (service / machine)
// ---------------------------------------------------------------------------

export const WorkloadIdentitySchema = z.object({
  type: z.literal('workload'),
  /** Unique workload identifier (e.g. SPIFFE ID, service account). */
  id: z.string().min(1).max(512),
  /** Service name. */
  serviceName: z.string().min(1).max(256),
  /** Namespace or environment (e.g. "production", "staging"). */
  namespace: z.string().max(256).optional(),
  /** Roles assigned to the workload. */
  roles: z.array(z.string().min(1).max(128)).default([]),
  /** Arbitrary attributes for ABAC evaluation. */
  attributes: z.record(z.string(), z.unknown()).default({}),
  /** Whether the workload identity is active. */
  enabled: z.boolean().default(true),
  /** SPIFFE ID (if available). */
  spiffeId: z.string().max(512).optional(),
  /** Certificate thumbprint for mTLS binding. */
  certificateThumbprint: z.string().max(128).optional(),
  createdAt: z.string().datetime({ offset: true }),
  updatedAt: z.string().datetime({ offset: true }),
});

export type WorkloadIdentity = z.infer<typeof WorkloadIdentitySchema>;

// ---------------------------------------------------------------------------
// Union identity
// ---------------------------------------------------------------------------

export const IdentitySchema = z.discriminatedUnion('type', [
  UserIdentitySchema,
  WorkloadIdentitySchema,
]);

export type Identity = z.infer<typeof IdentitySchema>;

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

export const SessionSchema = z.object({
  /** Unique session identifier (opaque, high-entropy). */
  id: z.string().min(32).max(256),
  /** The user this session belongs to. */
  userId: z.string().min(1).max(256),
  /** When the session was created (ISO 8601). */
  createdAt: z.string().datetime({ offset: true }),
  /** Last activity timestamp – used for idle timeout enforcement. */
  lastActivity: z.string().datetime({ offset: true }),
  /**
   * Idle timeout in seconds.  If the session is inactive for longer than
   * this, it must be re-authenticated.
   */
  idleTimeoutSeconds: z.number().int().positive().max(86400),
  /**
   * Absolute timeout in seconds from createdAt.  The session expires
   * regardless of activity after this duration.
   */
  absoluteTimeoutSeconds: z.number().int().positive().max(604800), // max 7 days
  /** Current privilege level (may change via step-up auth). */
  privilegeLevel: z.enum(['standard', 'elevated', 'admin']).default('standard'),
  /** When the session token was last rotated. */
  rotatedAt: z.string().datetime({ offset: true }).optional(),
  /** Number of times the session token has been rotated. */
  rotationCount: z.number().int().nonnegative().default(0),
  /** Originating IP address. */
  ipAddress: z.string().max(45).optional(),
  /** Device fingerprint for session binding. */
  deviceFingerprint: z.string().max(512).optional(),
  /** Device identifier for cross-referencing with device trust. */
  deviceId: z.string().max(256).optional(),
  /** User agent string at session creation. */
  userAgent: z.string().max(1024).optional(),
  /** Current session status. */
  status: z.enum(['active', 'expired', 'revoked', 'locked']).default('active'),
  /** Reason the session was terminated (if applicable). */
  terminationReason: z.string().max(512).optional(),
  /** Arbitrary metadata. */
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export type Session = z.infer<typeof SessionSchema>;

// ---------------------------------------------------------------------------
// TokenClaims (JWT payload)
// ---------------------------------------------------------------------------

export const TokenClaimsSchema = z.object({
  /** Subject – the principal the token represents. */
  sub: z.string().min(1).max(256),
  /** Issuer – the authority that issued the token. */
  iss: z.string().min(1).max(256),
  /** Audience – intended recipient(s). */
  aud: z.union([
    z.string().min(1).max(256),
    z.array(z.string().min(1).max(256)),
  ]),
  /** Expiration time (Unix epoch seconds). */
  exp: z.number().int().positive(),
  /** Issued at (Unix epoch seconds). */
  iat: z.number().int().positive(),
  /** JWT ID – unique token identifier for revocation tracking. */
  jti: z.string().min(1).max(256),
  /** OAuth 2.0 scopes. */
  scope: z.union([
    z.string().max(2048),
    z.array(z.string().max(256)),
  ]).optional(),
  /** RBAC roles embedded in the token. */
  roles: z.array(z.string().min(1).max(128)).optional(),
  /** Step-up authentication level (0 = none, 1 = MFA, 2 = hardware key, etc.). */
  stepUpLevel: z.number().int().min(0).max(10).optional(),
  /** Session ID this token is bound to. */
  sid: z.string().max(256).optional(),
  /** Device ID the token is bound to. */
  did: z.string().max(256).optional(),
  /** Identity provider that authenticated the subject. */
  idp: z.string().max(256).optional(),
  /** Arbitrary custom claims. */
  custom: z.record(z.string(), z.unknown()).optional(),
});

export type TokenClaims = z.infer<typeof TokenClaimsSchema>;

// ---------------------------------------------------------------------------
// Session helpers
// ---------------------------------------------------------------------------

/**
 * Check whether a session has exceeded its idle timeout.
 */
export function isSessionIdle(session: Session, now: Date = new Date()): boolean {
  const lastActivity = new Date(session.lastActivity).getTime();
  const elapsed = (now.getTime() - lastActivity) / 1000;
  return elapsed > session.idleTimeoutSeconds;
}

/**
 * Check whether a session has exceeded its absolute timeout.
 */
export function isSessionExpired(session: Session, now: Date = new Date()): boolean {
  const created = new Date(session.createdAt).getTime();
  const elapsed = (now.getTime() - created) / 1000;
  return elapsed > session.absoluteTimeoutSeconds;
}

/**
 * Determine if a session is currently valid (active, not idle, not expired).
 */
export function isSessionValid(session: Session, now: Date = new Date()): boolean {
  if (session.status !== 'active') return false;
  if (isSessionIdle(session, now)) return false;
  if (isSessionExpired(session, now)) return false;
  return true;
}

/**
 * Parse and validate a TokenClaims payload from an untrusted source.
 */
export function parseTokenClaims(
  data: unknown,
): { success: true; claims: TokenClaims } | { success: false; errors: z.ZodError } {
  const result = TokenClaimsSchema.safeParse(data);
  if (result.success) {
    return { success: true, claims: result.data };
  }
  return { success: false, errors: result.error };
}

/**
 * Check whether a token is expired based on its `exp` claim.
 */
export function isTokenExpired(
  claims: TokenClaims,
  clockSkewSeconds: number = 30,
): boolean {
  const now = Math.floor(Date.now() / 1000);
  return claims.exp < now - clockSkewSeconds;
}

/**
 * Get the scopes from a TokenClaims as a normalised string array.
 */
export function getScopes(claims: TokenClaims): string[] {
  if (!claims.scope) return [];
  if (Array.isArray(claims.scope)) return claims.scope;
  return claims.scope.split(/\s+/).filter(Boolean);
}

/**
 * Check whether a token has all of the required scopes.
 */
export function hasScopes(
  claims: TokenClaims,
  required: string[],
): boolean {
  const tokenScopes = new Set(getScopes(claims));
  return required.every((s) => tokenScopes.has(s));
}
