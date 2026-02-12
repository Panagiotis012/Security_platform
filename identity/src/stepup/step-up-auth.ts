/**
 * Step-Up Authentication Service.
 *
 * Handles elevating a user's authentication level for high-risk operations
 * such as email changes, payments, admin actions, and API key creation.
 *
 * Step-up levels:
 *   0 = basic (password or OIDC only)
 *   1 = MFA verified
 *   2 = recent MFA (within step-up TTL window)
 *
 * Security invariants:
 *  - Step-up challenges have a short TTL (default 5 minutes).
 *  - Challenges can only be verified once (single-use).
 *  - TOTP implementation uses otplib with recommended settings.
 *  - Failed attempts are tracked; excessive failures lock the challenge.
 */

import crypto from 'crypto';
import { authenticator } from 'otplib';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../../config/default';
import type { SessionData } from '../sessions/session-store';
import { createLogger } from '../logger';

const logger = createLogger('step-up-auth');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Maximum number of failed verification attempts before a challenge is locked. */
const MAX_FAILED_ATTEMPTS = 5;

/** TOTP configuration. */
authenticator.options = {
  digits: 6,
  step: 30,     // 30-second time window
  window: 1,    // Allow 1 step before and after (handles clock skew)
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type StepUpMethod = 'totp' | 'email' | 'push';

export interface StepUpChallenge {
  /** Unique challenge identifier. */
  challengeId: string;
  /** User this challenge belongs to. */
  userId: string;
  /** Method used for this challenge. */
  method: StepUpMethod;
  /** ISO-8601 timestamp when the challenge was created. */
  createdAt: string;
  /** ISO-8601 timestamp when the challenge expires. */
  expiresAt: string;
  /** Whether the challenge has been successfully verified. */
  verified: boolean;
  /** Number of failed verification attempts. */
  failedAttempts: number;
  /** Whether the challenge is locked due to too many failures. */
  locked: boolean;
  /**
   * Internal data used for verification.
   * For email: the OTP code sent.
   * For TOTP: the user's secret (looked up from registration).
   * For push: a nonce to match against the push response.
   * NEVER exposed to the client.
   */
  internalSecret: string;
}

export interface StepUpInitiateResult {
  challengeId: string;
  method: StepUpMethod;
  expiresAt: string;
  /** For email method: a hint like "sent to j***@example.com". */
  hint?: string;
}

export interface StepUpVerifyResult {
  success: boolean;
  newLevel: number;
  reason?: string;
}

export interface UserMFARegistration {
  userId: string;
  totpSecret?: string;
  email?: string;
  pushDeviceId?: string;
}

// ---------------------------------------------------------------------------
// Step-Up Auth Service
// ---------------------------------------------------------------------------

export class StepUpAuthService {
  /**
   * Active challenges, keyed by challengeId.
   * In production, back this with Redis with TTL-based expiry.
   */
  private readonly challenges = new Map<string, StepUpChallenge>();

  /**
   * User MFA registrations, keyed by userId.
   * In production this would be a database query.
   */
  private readonly userRegistrations = new Map<string, UserMFARegistration>();

  /** Eviction timer for expired challenges. */
  private evictionTimer: ReturnType<typeof setInterval> | null = null;

  constructor() {
    this.evictionTimer = setInterval(() => this.evictExpired(), 30_000);
    if (this.evictionTimer.unref) {
      this.evictionTimer.unref();
    }
  }

  // -----------------------------------------------------------------------
  // Level checks
  // -----------------------------------------------------------------------

  /**
   * Determine whether a step-up is required.
   *
   * @param currentLevel   The user's current authentication level.
   * @param requiredLevel  The level required for the action.
   * @returns true if step-up is needed.
   */
  requireStepUp(currentLevel: number, requiredLevel: number): boolean {
    return currentLevel < requiredLevel;
  }

  /**
   * Determine the current step-up level from a session.
   *
   * Level 2 (recent MFA) decays to level 1 after the step-up TTL window
   * expires.  Level 1 persists for the session lifetime.
   */
  getStepUpLevel(session: SessionData): number {
    const baseLevel = session.privilegeLevel;

    if (baseLevel < 2) {
      return baseLevel;
    }

    // Level 2 is time-bound: check whether the step-up window is still active.
    const stepUpTimestamp = session.metadata['stepUpAt'] as string | undefined;
    if (!stepUpTimestamp) {
      // If there's no step-up timestamp, decay to level 1.
      return 1;
    }

    const elapsed = Date.now() - new Date(stepUpTimestamp).getTime();
    const ttlMs = config.tokens.stepUpTtlSeconds * 1000;

    if (elapsed > ttlMs) {
      // Step-up window expired, decay to level 1.
      return 1;
    }

    return 2;
  }

  // -----------------------------------------------------------------------
  // Challenge initiation
  // -----------------------------------------------------------------------

  /**
   * Initiate a step-up challenge for a user.
   *
   * @param userId  The user requesting step-up.
   * @param method  The MFA method to use.
   * @returns       Challenge metadata (never includes the secret).
   */
  async initiateStepUp(
    userId: string,
    method: StepUpMethod,
  ): Promise<StepUpInitiateResult> {
    const registration = this.userRegistrations.get(userId);

    // Validate that the user has the requested method registered.
    this.validateMethodAvailable(userId, method, registration);

    const challengeId = uuidv4();
    const now = new Date();
    const expiresAt = new Date(
      now.getTime() + config.tokens.stepUpTtlSeconds * 1000,
    );

    let internalSecret: string;
    let hint: string | undefined;

    switch (method) {
      case 'totp': {
        // For TOTP, the internal secret is the user's registered TOTP secret.
        internalSecret = registration!.totpSecret!;
        break;
      }
      case 'email': {
        // Generate a 6-digit OTP and (in production) send it via email.
        internalSecret = this.generateEmailOTP();
        const email = registration?.email ?? 'unknown';
        hint = `Sent to ${this.maskEmail(email)}`;
        logger.info('Email OTP generated for step-up', {
          userId,
          challengeId,
          // In production: trigger email send here.
        });
        break;
      }
      case 'push': {
        // Generate a nonce that the push notification response must echo.
        internalSecret = crypto.randomBytes(16).toString('hex');
        hint = 'Push notification sent to your registered device';
        logger.info('Push challenge created', {
          userId,
          challengeId,
          // In production: send push notification here.
        });
        break;
      }
    }

    const challenge: StepUpChallenge = {
      challengeId,
      userId,
      method,
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      verified: false,
      failedAttempts: 0,
      locked: false,
      internalSecret,
    };

    this.challenges.set(challengeId, challenge);

    logger.info('Step-up challenge initiated', {
      challengeId,
      userId,
      method,
      expiresAt: expiresAt.toISOString(),
    });

    return {
      challengeId,
      method,
      expiresAt: expiresAt.toISOString(),
      hint,
    };
  }

  // -----------------------------------------------------------------------
  // Challenge verification
  // -----------------------------------------------------------------------

  /**
   * Verify a step-up challenge response.
   *
   * @param userId       The user verifying.
   * @param challengeId  The challenge to verify.
   * @param response     The user's response (TOTP code, email OTP, push nonce).
   * @returns            Verification result with the new level.
   */
  async verifyStepUp(
    userId: string,
    challengeId: string,
    response: string,
  ): Promise<StepUpVerifyResult> {
    const challenge = this.challenges.get(challengeId);

    // Basic existence and ownership checks.
    if (!challenge) {
      return { success: false, newLevel: 0, reason: 'Challenge not found' };
    }

    if (challenge.userId !== userId) {
      logger.warn('Step-up challenge ownership mismatch', {
        challengeId,
        expectedUserId: challenge.userId,
        actualUserId: userId,
      });
      return { success: false, newLevel: 0, reason: 'Challenge not found' };
    }

    if (challenge.locked) {
      return {
        success: false,
        newLevel: 0,
        reason: 'Challenge locked due to too many failed attempts',
      };
    }

    if (challenge.verified) {
      return {
        success: false,
        newLevel: 0,
        reason: 'Challenge already verified',
      };
    }

    // Check expiry.
    if (new Date(challenge.expiresAt).getTime() <= Date.now()) {
      this.challenges.delete(challengeId);
      return { success: false, newLevel: 0, reason: 'Challenge expired' };
    }

    // Method-specific verification.
    let valid = false;

    switch (challenge.method) {
      case 'totp': {
        valid = authenticator.check(response, challenge.internalSecret);
        break;
      }
      case 'email': {
        // Constant-time comparison for the email OTP.
        valid = this.constantTimeEquals(response, challenge.internalSecret);
        break;
      }
      case 'push': {
        // The push response must echo the challenge nonce.
        valid = this.constantTimeEquals(response, challenge.internalSecret);
        break;
      }
    }

    if (!valid) {
      challenge.failedAttempts += 1;

      if (challenge.failedAttempts >= MAX_FAILED_ATTEMPTS) {
        challenge.locked = true;
        logger.warn('Step-up challenge locked (max attempts)', {
          challengeId,
          userId,
        });
      }

      this.challenges.set(challengeId, challenge);

      logger.info('Step-up verification failed', {
        challengeId,
        userId,
        attempt: challenge.failedAttempts,
      });

      return {
        success: false,
        newLevel: 0,
        reason: 'Invalid response',
      };
    }

    // Mark challenge as verified (single-use).
    challenge.verified = true;
    this.challenges.set(challengeId, challenge);

    logger.info('Step-up verification succeeded', {
      challengeId,
      userId,
      method: challenge.method,
    });

    return {
      success: true,
      newLevel: 2, // Recent MFA
    };
  }

  // -----------------------------------------------------------------------
  // TOTP registration
  // -----------------------------------------------------------------------

  /**
   * Generate a new TOTP secret for a user.  Returns the secret and a
   * provisioning URI for QR code generation.
   */
  generateTOTPSecret(
    userId: string,
    accountName: string,
    issuerName = 'ZeroTrust',
  ): { secret: string; uri: string } {
    // Keep userId in the API for callers; we don't currently include it in the URI.
    void userId;
    const secret = authenticator.generateSecret();
    const uri = authenticator.keyuri(accountName, issuerName, secret);
    return { secret, uri };
  }

  /**
   * Register (or update) a user's MFA methods.
   */
  registerUserMFA(registration: UserMFARegistration): void {
    this.userRegistrations.set(registration.userId, registration);
    logger.info('User MFA registration updated', {
      userId: registration.userId,
      hasTotp: !!registration.totpSecret,
      hasEmail: !!registration.email,
      hasPush: !!registration.pushDeviceId,
    });
  }

  /**
   * Verify a TOTP code against a secret (used during initial TOTP setup
   * to confirm the user has correctly configured their authenticator app).
   */
  verifyTOTPSetup(secret: string, code: string): boolean {
    return authenticator.check(code, secret);
  }

  // -----------------------------------------------------------------------
  // High-risk action definitions
  // -----------------------------------------------------------------------

  /**
   * Determine the required step-up level for a given action.
   * Returns 0 if no step-up is needed.
   */
  static getRequiredLevel(action: string): number {
    const highRiskActions: Record<string, number> = {
      'email_change': 2,
      'password_change': 2,
      'payment': 2,
      'admin_action': 2,
      'api_key_create': 2,
      'api_key_delete': 2,
      'mfa_disable': 2,
      'role_change': 2,
      'account_delete': 2,
      'export_data': 1,
      'view_audit_log': 1,
    };

    return highRiskActions[action] ?? 0;
  }

  // -----------------------------------------------------------------------
  // Cleanup
  // -----------------------------------------------------------------------

  /** Stop the eviction timer (graceful shutdown). */
  destroy(): void {
    if (this.evictionTimer) {
      clearInterval(this.evictionTimer);
      this.evictionTimer = null;
    }
  }

  // -----------------------------------------------------------------------
  // Internal helpers
  // -----------------------------------------------------------------------

  private validateMethodAvailable(
    userId: string,
    method: StepUpMethod,
    registration: UserMFARegistration | undefined,
  ): void {
    if (!registration) {
      throw new StepUpError(
        `User ${userId} has no MFA methods registered`,
        'NO_MFA_REGISTERED',
      );
    }

    switch (method) {
      case 'totp':
        if (!registration.totpSecret) {
          throw new StepUpError(
            'TOTP not registered for this user',
            'METHOD_NOT_AVAILABLE',
          );
        }
        break;
      case 'email':
        if (!registration.email) {
          throw new StepUpError(
            'Email not registered for step-up',
            'METHOD_NOT_AVAILABLE',
          );
        }
        break;
      case 'push':
        if (!registration.pushDeviceId) {
          throw new StepUpError(
            'Push device not registered',
            'METHOD_NOT_AVAILABLE',
          );
        }
        break;
    }
  }

  private generateEmailOTP(): string {
    // Generate a cryptographically random 6-digit numeric code.
    const buffer = crypto.randomBytes(4);
    const num = buffer.readUInt32BE(0) % 1_000_000;
    return num.toString().padStart(6, '0');
  }

  private maskEmail(email: string): string {
    const [local, domain] = email.split('@');
    if (!local || !domain) return '***';
    const masked = local.charAt(0) + '***';
    return `${masked}@${domain}`;
  }

  private constantTimeEquals(a: string, b: string): boolean {
    if (a.length !== b.length) {
      // Still perform a comparison to avoid timing side-channels on length.
      const dummy = Buffer.alloc(a.length);
      crypto.timingSafeEqual(dummy, Buffer.from(a));
      return false;
    }
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  }

  private evictExpired(): void {
    const now = Date.now();
    for (const [id, challenge] of this.challenges) {
      if (new Date(challenge.expiresAt).getTime() <= now) {
        this.challenges.delete(id);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Step-up error
// ---------------------------------------------------------------------------

export type StepUpErrorCode =
  | 'NO_MFA_REGISTERED'
  | 'METHOD_NOT_AVAILABLE'
  | 'CHALLENGE_NOT_FOUND'
  | 'CHALLENGE_EXPIRED'
  | 'CHALLENGE_LOCKED'
  | 'VERIFICATION_FAILED';

export class StepUpError extends Error {
  public readonly code: StepUpErrorCode;

  constructor(message: string, code: StepUpErrorCode) {
    super(message);
    this.name = 'StepUpError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
