/**
 * Break-Glass Emergency Access System
 *
 * Provides a controlled, auditable emergency access mechanism for security
 * teams to bypass normal policy-based access controls during critical incidents.
 *
 * Key features:
 * - Time-limited tokens with configurable TTL
 * - Mandatory justification and eligibility checks
 * - Complete action audit trail for all break-glass sessions
 * - Mandatory review workflow (pending → approved/flagged)
 * - Auto-revocation of expired sessions
 * - Event emission for real-time alerting
 *
 * Every action taken under break-glass is logged to a separate audit trail
 * that includes the break-glass session context. This enables forensic analysis
 * and compliance validation of emergency access usage.
 *
 * Security considerations:
 * - Break-glass tokens are validated on every request
 * - Sessions respect TTL and cannot be extended
 * - All activities are logged regardless of policy decisions
 * - Review workflow ensures human oversight
 * - Supports optional pre-approval workflow for trusted requesters
 */

import { v4 as uuidv4 } from 'uuid';
import { EventEmitter } from 'events';

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

export enum BreakGlassErrorCode {
  INVALID_TOKEN = 'BREAK_GLASS_1001',
  SESSION_EXPIRED = 'BREAK_GLASS_1002',
  SESSION_REVOKED = 'BREAK_GLASS_1003',
  INSUFFICIENT_ELIGIBILITY = 'BREAK_GLASS_1004',
  INVALID_JUSTIFICATION = 'BREAK_GLASS_1005',
  SESSION_PENDING_REVIEW = 'BREAK_GLASS_1006',
  SESSION_FLAGGED = 'BREAK_GLASS_1007',
  MISSING_REVIEWER = 'BREAK_GLASS_1008',
  INTERNAL_ERROR = 'BREAK_GLASS_9001',
}

// ---------------------------------------------------------------------------
// Types and Interfaces
// ---------------------------------------------------------------------------

/**
 * Represents a single action taken during a break-glass session.
 * Used to build the complete audit trail of activities.
 */
export interface BreakGlassAction {
  /** Unique identifier for this action */
  id: string;
  /** HTTP method (GET, POST, etc.) */
  method: string;
  /** URI path of the request */
  path: string;
  /** ISO 8601 timestamp when action occurred */
  timestamp: string;
  /** Result of the action (allowed/denied by downstream policy) */
  result: 'allowed' | 'denied';
  /** Reason for denial if denied */
  denialReason?: string;
  /** HTTP status code returned */
  statusCode: number;
  /** Optional metadata about the action */
  metadata?: Record<string, unknown>;
}

/**
 * Review status of a break-glass session.
 * Sessions must transition through these states:
 * - pending_review: Initial state, waiting for reviewer
 * - reviewed_approved: Reviewer approved the emergency access
 * - reviewed_flagged: Reviewer flagged suspicious activity
 */
export type BreakGlassReviewStatus =
  | 'pending_review'
  | 'reviewed_approved'
  | 'reviewed_flagged';

/**
 * Represents an active or historical break-glass session.
 *
 * A break-glass session grants temporary elevated access with full auditability.
 * The session must be reviewed by a designated reviewer before it expires.
 */
export interface BreakGlassSession {
  /** Unique session identifier */
  id: string;
  /** User ID of the person requesting emergency access */
  requesterId: string;
  /** Mandatory justification for the emergency access request */
  justification: string;
  /** User ID of the person who approved the request (null if auto-approved) */
  approvedBy: string | null;
  /** ISO 8601 timestamp when the session was granted */
  grantedAt: string;
  /** ISO 8601 timestamp when the session expires */
  expiresAt: string;
  /** ISO 8601 timestamp when session was revoked (null if not revoked) */
  revokedAt: string | null;
  /** Complete audit trail of actions taken during this session */
  actions: BreakGlassAction[];
  /** Current review status of the session */
  reviewStatus: BreakGlassReviewStatus;
  /** User ID of the reviewer who reviewed this session (null if pending) */
  reviewedBy: string | null;
  /** Additional notes from the reviewer */
  reviewNotes: string | null;
}

/**
 * An entry in the break-glass audit trail.
 * Separate from regular audit events to enable focused forensic analysis
 * of emergency access usage.
 */
export interface BreakGlassAuditEntry {
  /** Unique audit entry identifier */
  id: string;
  /** Break-glass session ID this entry belongs to */
  sessionId: string;
  /** User requesting emergency access */
  requesterId: string;
  /** Action taken during the break-glass session */
  action: BreakGlassAction;
  /** ISO 8601 timestamp of the audit entry */
  timestamp: string;
  /** Additional context about the action */
  context: {
    /** Request IP address if available */
    sourceIp?: string;
    /** User agent if available */
    userAgent?: string;
    /** Correlation ID for tracing */
    correlationId?: string;
    /** Resource accessed */
    resource?: string;
    /** Arbitrary metadata */
    metadata?: Record<string, unknown>;
  };
}

/**
 * Configuration for eligibility checking.
 * Determines which users/roles can request break-glass access.
 */
export interface BreakGlassEligibility {
  /** Allowed user IDs that can request break-glass */
  allowedUserIds?: string[];
  /** Allowed group IDs whose members can request break-glass */
  allowedGroupIds?: string[];
  /** Allowed roles that can request break-glass */
  allowedRoles?: string[];
  /** Custom eligibility check function */
  customCheck?: (userId: string, context?: unknown) => boolean | Promise<boolean>;
}

/**
 * Approval workflow configuration.
 */
export interface BreakGlassApprovalConfig {
  /** If true, requests from eligible users are auto-approved */
  autoApproveEligible?: boolean;
  /** User IDs who can approve break-glass requests */
  approverUserIds?: string[];
  /** Group IDs whose members can approve requests */
  approverGroupIds?: string[];
  /** Custom approval check function */
  customApprover?: (userId: string, context?: unknown) => boolean | Promise<boolean>;
}

/**
 * Review workflow configuration.
 * Mandatory for all sessions to ensure human oversight.
 */
export interface BreakGlassReviewConfig {
  /** User IDs who can review break-glass sessions */
  reviewerUserIds?: string[];
  /** Group IDs whose members can review sessions */
  reviewerGroupIds?: string[];
  /** Maximum hours before a pending review times out (alert SOC) */
  reviewTimeoutHours?: number;
  /** Custom review eligibility check */
  customReviewer?: (userId: string, context?: unknown) => boolean | Promise<boolean>;
}

/**
 * Complete configuration for the break-glass system.
 */
export interface BreakGlassManagerConfig {
  /** Time-to-live for break-glass tokens in minutes (default: 30) */
  tokenTTLMinutes?: number;
  /** Minimum length for justification text (default: 10 characters) */
  minJustificationLength?: number;
  /** Maximum length for justification text (default: 2000 characters) */
  maxJustificationLength?: number;
  /** Eligibility rules for requesters */
  eligibility: BreakGlassEligibility;
  /** Approval workflow rules */
  approval?: BreakGlassApprovalConfig;
  /** Review workflow rules */
  review: BreakGlassReviewConfig;
  /** Custom audit store (in-memory if not provided) */
  auditStore?: BreakGlassAuditStore;
  /** Custom session store (in-memory if not provided) */
  sessionStore?: BreakGlassSessionStore;
  /** Event emitter for break-glass lifecycle events */
  eventEmitter?: EventEmitter;
}

/**
 * Interface for persisting and retrieving break-glass audit entries.
 */
export interface BreakGlassAuditStore {
  /**
   * Save an audit entry to the store.
   */
  save(entry: BreakGlassAuditEntry): Promise<void>;

  /**
   * Retrieve audit entries for a session.
   */
  getBySessionId(sessionId: string): Promise<BreakGlassAuditEntry[]>;

  /**
   * Retrieve audit entries for a requester.
   */
  getByRequesterId(
    requesterId: string,
    limit?: number,
  ): Promise<BreakGlassAuditEntry[]>;

  /**
   * Retrieve all audit entries within a time range.
   */
  getByTimeRange(
    startTime: string,
    endTime: string,
  ): Promise<BreakGlassAuditEntry[]>;
}

/**
 * Interface for persisting and retrieving break-glass sessions.
 */
export interface BreakGlassSessionStore {
  /**
   * Save or update a session.
   */
  save(session: BreakGlassSession): Promise<void>;

  /**
   * Retrieve a session by ID.
   */
  getById(sessionId: string): Promise<BreakGlassSession | null>;

  /**
   * Retrieve sessions for a requester.
   */
  getByRequesterId(
    requesterId: string,
    limit?: number,
  ): Promise<BreakGlassSession[]>;

  /**
   * Retrieve all pending review sessions.
   */
  getPendingReview(limit?: number): Promise<BreakGlassSession[]>;

  /**
   * Retrieve all active (non-expired, non-revoked) sessions.
   */
  getActive(): Promise<BreakGlassSession[]>;
}

/**
 * In-memory implementation of BreakGlassAuditStore.
 * Suitable for development and testing; production should use persistent storage.
 */
class InMemoryBreakGlassAuditStore implements BreakGlassAuditStore {
  private entries: BreakGlassAuditEntry[] = [];

  async save(entry: BreakGlassAuditEntry): Promise<void> {
    this.entries.push(entry);
  }

  async getBySessionId(sessionId: string): Promise<BreakGlassAuditEntry[]> {
    return this.entries.filter((e) => e.sessionId === sessionId);
  }

  async getByRequesterId(
    requesterId: string,
    limit?: number,
  ): Promise<BreakGlassAuditEntry[]> {
    const results = this.entries.filter((e) => e.requesterId === requesterId);
    return limit ? results.slice(-limit) : results;
  }

  async getByTimeRange(
    startTime: string,
    endTime: string,
  ): Promise<BreakGlassAuditEntry[]> {
    const start = new Date(startTime).getTime();
    const end = new Date(endTime).getTime();
    return this.entries.filter((e) => {
      const ts = new Date(e.timestamp).getTime();
      return ts >= start && ts <= end;
    });
  }
}

/**
 * In-memory implementation of BreakGlassSessionStore.
 * Suitable for development and testing; production should use persistent storage.
 */
class InMemoryBreakGlassSessionStore implements BreakGlassSessionStore {
  private sessions = new Map<string, BreakGlassSession>();

  async save(session: BreakGlassSession): Promise<void> {
    this.sessions.set(session.id, JSON.parse(JSON.stringify(session)));
  }

  async getById(sessionId: string): Promise<BreakGlassSession | null> {
    const session = this.sessions.get(sessionId);
    return session ? JSON.parse(JSON.stringify(session)) : null;
  }

  async getByRequesterId(
    requesterId: string,
    limit?: number,
  ): Promise<BreakGlassSession[]> {
    const results = Array.from(this.sessions.values()).filter(
      (s) => s.requesterId === requesterId,
    );
    return (limit ? results.slice(-limit) : results).map((s) =>
      JSON.parse(JSON.stringify(s)),
    );
  }

  async getPendingReview(limit?: number): Promise<BreakGlassSession[]> {
    const results = Array.from(this.sessions.values()).filter(
      (s) => s.reviewStatus === 'pending_review',
    );
    return (limit ? results.slice(-limit) : results).map((s) =>
      JSON.parse(JSON.stringify(s)),
    );
  }

  async getActive(): Promise<BreakGlassSession[]> {
    const now = new Date();
    const results = Array.from(this.sessions.values()).filter(
      (s) => new Date(s.expiresAt) > now && !s.revokedAt,
    );
    return results.map((s) => JSON.parse(JSON.stringify(s)));
  }
}

// ---------------------------------------------------------------------------
// BreakGlassManager
// ---------------------------------------------------------------------------

/**
 * Manager for break-glass emergency access sessions.
 *
 * Responsibilities:
 * - Validate emergency access requests
 * - Issue time-limited break-glass tokens
 * - Track all actions taken during break-glass sessions
 * - Manage review workflow
 * - Auto-revoke expired sessions
 * - Emit events for alerting
 *
 * All break-glass sessions are logged to a separate audit trail and must
 * pass mandatory review before expiration.
 */
export class BreakGlassManager {
  private config: Required<BreakGlassManagerConfig>;
  private sessions: BreakGlassSessionStore;
  private auditStore: BreakGlassAuditStore;
  private eventEmitter: EventEmitter;

  /**
   * Create a new BreakGlassManager instance.
   *
   * @param config - Configuration for the break-glass system
   * @throws Error if required configuration is missing
   */
  constructor(config: BreakGlassManagerConfig) {
    if (!config.eligibility) {
      throw new Error('BreakGlassManager requires eligibility configuration');
    }
    if (!config.review) {
      throw new Error('BreakGlassManager requires review configuration');
    }

    this.config = {
      tokenTTLMinutes: config.tokenTTLMinutes ?? 30,
      minJustificationLength: config.minJustificationLength ?? 10,
      maxJustificationLength: config.maxJustificationLength ?? 2000,
      eligibility: config.eligibility,
      approval: config.approval ?? {},
      review: config.review,
      auditStore: config.auditStore ?? new InMemoryBreakGlassAuditStore(),
      sessionStore: config.sessionStore ?? new InMemoryBreakGlassSessionStore(),
      eventEmitter: config.eventEmitter ?? new EventEmitter(),
    };

    this.sessions = this.config.sessionStore;
    this.auditStore = this.config.auditStore;
    this.eventEmitter = this.config.eventEmitter;

    // Start cleanup interval for expired sessions
    this.startCleanupInterval();
  }

  /**
   * Request break-glass emergency access.
   *
   * Validates the requester's eligibility, justification, and approval rules,
   * then creates a new break-glass session if all checks pass.
   *
   * @param requesterId - User ID requesting emergency access
   * @param justification - Reason for requesting emergency access
   * @param context - Optional context for eligibility/approval checks
   * @returns The created break-glass session with a valid token
   * @throws SecurityError if eligibility or justification checks fail
   */
  async requestBreakGlass(
    requesterId: string,
    justification: string,
    context?: unknown,
  ): Promise<BreakGlassSession> {
    // Validate justification
    if (
      justification.length < this.config.minJustificationLength ||
      justification.length > this.config.maxJustificationLength
    ) {
      this.eventEmitter.emit('break-glass:request-failed', {
        requesterId,
        reason: 'invalid_justification',
        timestamp: new Date().toISOString(),
      });

      throw new Error(
        `Justification must be between ${this.config.minJustificationLength} ` +
          `and ${this.config.maxJustificationLength} characters`,
      );
    }

    // Check eligibility
    const isEligible = await this.checkEligibility(requesterId, context);
    if (!isEligible) {
      this.eventEmitter.emit('break-glass:request-failed', {
        requesterId,
        reason: 'insufficient_eligibility',
        timestamp: new Date().toISOString(),
      });

      throw new Error(
        'User is not eligible to request break-glass emergency access',
      );
    }

    // Check approval rules
    const approvedBy = await this.checkApproval(requesterId, context);

    // Create the session
    const now = new Date();
    const expiresAt = new Date(
      now.getTime() + this.config.tokenTTLMinutes * 60 * 1000,
    );

    const session: BreakGlassSession = {
      id: uuidv4(),
      requesterId,
      justification,
      approvedBy: approvedBy ?? null,
      grantedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      revokedAt: null,
      actions: [],
      reviewStatus: 'pending_review',
      reviewedBy: null,
      reviewNotes: null,
    };

    await this.sessions.save(session);

    this.eventEmitter.emit('break-glass:activated', {
      sessionId: session.id,
      requesterId,
      expiresAt: session.expiresAt,
      timestamp: session.grantedAt,
    });

    return session;
  }

  /**
   * Validate a break-glass token and retrieve its session.
   *
   * Performs several checks:
   * - Session exists
   * - Token not expired
   * - Token not revoked
   * - Session not pending review (optional strict mode)
   *
   * @param sessionId - The session ID to validate
   * @param strictReview - If true, reject sessions pending review
   * @returns The validated break-glass session
   * @throws Error if validation fails
   */
  async validateSession(
    sessionId: string,
    strictReview: boolean = false,
  ): Promise<BreakGlassSession> {
    const session = await this.sessions.getById(sessionId);

    if (!session) {
      throw new Error('Break-glass session not found');
    }

    const now = new Date();

    if (session.revokedAt) {
      throw new Error('Break-glass session has been revoked');
    }

    if (new Date(session.expiresAt) <= now) {
      throw new Error('Break-glass session has expired');
    }

    if (strictReview && session.reviewStatus === 'pending_review') {
      throw new Error(
        'Break-glass session is pending review and cannot be used',
      );
    }

    if (session.reviewStatus === 'reviewed_flagged') {
      throw new Error(
        'Break-glass session was flagged during review and cannot be used',
      );
    }

    return session;
  }

  /**
   * Record an action taken during a break-glass session.
   *
   * All actions are logged to the separate break-glass audit trail.
   *
   * @param sessionId - The session ID
   * @param action - The action that was taken
   * @param context - Optional context for the audit entry
   */
  async recordAction(
    sessionId: string,
    action: Omit<BreakGlassAction, 'id' | 'timestamp'>,
    context?: BreakGlassAuditEntry['context'],
  ): Promise<void> {
    const session = await this.sessions.getById(sessionId);
    if (!session) {
      throw new Error('Session not found for audit logging');
    }

    const actionWithId: BreakGlassAction = {
      ...action,
      id: uuidv4(),
      timestamp: new Date().toISOString(),
    };

    // Add to session's action list
    session.actions.push(actionWithId);
    await this.sessions.save(session);

    // Create audit entry
    const auditEntry: BreakGlassAuditEntry = {
      id: uuidv4(),
      sessionId,
      requesterId: session.requesterId,
      action: actionWithId,
      timestamp: actionWithId.timestamp,
      context: context ?? {},
    };

    await this.auditStore.save(auditEntry);

    this.eventEmitter.emit('break-glass:action-recorded', {
      sessionId,
      action: actionWithId,
    });
  }

  /**
   * Revoke an active break-glass session immediately.
   *
   * @param sessionId - The session to revoke
   * @param reason - Optional reason for revocation
   */
  async revokeSession(sessionId: string, reason?: string): Promise<void> {
    const session = await this.sessions.getById(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    session.revokedAt = new Date().toISOString();
    await this.sessions.save(session);

    this.eventEmitter.emit('break-glass:revoked', {
      sessionId,
      reason,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Submit a review of a break-glass session.
   *
   * Only users with review eligibility can submit reviews.
   *
   * @param sessionId - The session to review
   * @param reviewerId - User ID of the reviewer
   * @param approved - Whether the session is approved or flagged
   * @param notes - Optional review notes
   * @param context - Optional context for review eligibility
   * @throws Error if reviewer is not eligible
   */
  async reviewSession(
    sessionId: string,
    reviewerId: string,
    approved: boolean,
    notes?: string,
    context?: unknown,
  ): Promise<BreakGlassSession> {
    const isReviewer = await this.checkReviewer(reviewerId, context);
    if (!isReviewer) {
      throw new Error('User is not eligible to review break-glass sessions');
    }

    const session = await this.sessions.getById(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    session.reviewStatus = approved ? 'reviewed_approved' : 'reviewed_flagged';
    session.reviewedBy = reviewerId;
    session.reviewNotes = notes ?? null;

    await this.sessions.save(session);

    this.eventEmitter.emit('break-glass:reviewed', {
      sessionId,
      reviewerId,
      approved,
      notes,
      timestamp: new Date().toISOString(),
    });

    return session;
  }

  /**
   * Get all sessions pending review.
   */
  async getPendingReview(limit?: number): Promise<BreakGlassSession[]> {
    return this.sessions.getPendingReview(limit);
  }

  /**
   * Get audit trail for a session.
   */
  async getAuditTrail(sessionId: string): Promise<BreakGlassAuditEntry[]> {
    return this.auditStore.getBySessionId(sessionId);
  }

  /**
   * Get all sessions for a requester.
   */
  async getRequesterSessions(
    requesterId: string,
    limit?: number,
  ): Promise<BreakGlassSession[]> {
    return this.sessions.getByRequesterId(requesterId, limit);
  }

  /**
   * Register an event listener for break-glass lifecycle events.
   * Common events: 'break-glass:activated', 'break-glass:reviewed', 'break-glass:revoked'
   */
  onBreakGlassEvent(
    eventName: string,
    handler: (...args: unknown[]) => void,
  ): void {
    this.eventEmitter.on(eventName, handler);
  }

  /**
   * Remove an event listener.
   */
  offBreakGlassEvent(
    eventName: string,
    handler: (...args: unknown[]) => void,
  ): void {
    this.eventEmitter.off(eventName, handler);
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private async checkEligibility(
    userId: string,
    context?: unknown,
  ): Promise<boolean> {
    const { eligibility } = this.config;

    if (eligibility.customCheck) {
      return eligibility.customCheck(userId, context);
    }

    if (eligibility.allowedUserIds?.includes(userId)) {
      return true;
    }

    // Note: In a real system, this would check group membership
    if (eligibility.allowedGroupIds?.length ?? 0 > 0) {
      // Placeholder for group check
      return true;
    }

    if (eligibility.allowedRoles?.length ?? 0 > 0) {
      // Placeholder for role check
      return true;
    }

    return false;
  }

  private async checkApproval(
    userId: string,
    context?: unknown,
  ): Promise<string | null> {
    const { approval } = this.config;

    if (!approval) {
      return null;
    }

    if (approval.autoApproveEligible) {
      return 'system';
    }

    if (approval.customApprover) {
      const approved = await approval.customApprover(userId, context);
      return approved ? 'system' : null;
    }

    if (approval.approverUserIds?.length ?? 0 > 0) {
      return null; // Requires manual approval
    }

    return null;
  }

  private async checkReviewer(
    userId: string,
    context?: unknown,
  ): Promise<boolean> {
    const { review } = this.config;

    if (review.customReviewer) {
      return review.customReviewer(userId, context);
    }

    if (review.reviewerUserIds?.includes(userId)) {
      return true;
    }

    // Note: In a real system, this would check group membership
    if (review.reviewerGroupIds?.length ?? 0 > 0) {
      return true;
    }

    return false;
  }

  private startCleanupInterval(): void {
    // Clean up expired sessions every 5 minutes
    setInterval(async () => {
      try {
        const activeSessions = await this.sessions.getActive();
        const now = new Date();

        for (const session of activeSessions) {
          if (
            new Date(session.expiresAt) < now &&
            !session.revokedAt &&
            session.reviewStatus === 'pending_review'
          ) {
            // Auto-revoke expired sessions that were never reviewed
            await this.revokeSession(
              session.id,
              'auto-revoked: session expired without review',
            );

            this.eventEmitter.emit('break-glass:expired-unreviewed', {
              sessionId: session.id,
              requesterId: session.requesterId,
              timestamp: new Date().toISOString(),
            });
          }
        }
      } catch (err) {
        // Log but don't throw - don't break the cleanup loop
        console.error('Error during break-glass cleanup:', err);
      }
    }, 5 * 60 * 1000);
  }
}

// ---------------------------------------------------------------------------
// Express Middleware
// ---------------------------------------------------------------------------

/**
 * Minimal Express types to avoid hard dependency.
 */
export interface BreakGlassRequest {
  headers: Record<string, string | string[] | undefined>;
  method: string;
  path: string;
  ip?: string;
  get(header: string): string | undefined;
  breakGlassSession?: BreakGlassSession;
  breakGlassToken?: string;
}

export interface BreakGlassResponse {
  status(code: number): this;
  json(data: unknown): void;
}

export type BreakGlassNextFunction = (err?: unknown) => void;

export interface BreakGlassMiddlewareOptions {
  /** Header name for break-glass token. Defaults to X-Break-Glass-Token */
  tokenHeader?: string;
  /** Break-glass manager instance */
  manager: BreakGlassManager;
  /** If true, pending-review sessions are rejected. Defaults to false (allows) */
  strictReview?: boolean;
  /** Paths that don't require break-glass token even if header is present */
  exemptPaths?: string[];
}

/**
 * Express middleware for validating break-glass tokens.
 *
 * Checks the X-Break-Glass-Token header, validates the session, and logs
 * all actions taken during the break-glass session to the audit trail.
 * Allows the request to proceed even if normal authorization would deny it,
 * but logs everything for forensic analysis.
 *
 * Usage:
 *   const manager = new BreakGlassManager(config);
 *   app.use(breakGlassMiddleware({ manager }));
 *   app.get('/sensitive', (req, res) => {
 *     if (req.breakGlassSession) {
 *       // Request is using break-glass access
 *       logger.info('Break-glass access', {
 *         sessionId: req.breakGlassSession.id,
 *       });
 *     }
 *   });
 */
export function breakGlassMiddleware(
  options: BreakGlassMiddlewareOptions,
): (req: BreakGlassRequest, res: BreakGlassResponse, next: BreakGlassNextFunction) => void {
  const {
    tokenHeader = 'X-Break-Glass-Token',
    manager,
    strictReview = false,
    exemptPaths = [],
  } = options;

  return async (
    req: BreakGlassRequest,
    res: BreakGlassResponse,
    next: BreakGlassNextFunction,
  ) => {
    try {
      // Check for break-glass token header
      const tokenHeaderLower = tokenHeader.toLowerCase();
      const raw =
        req.headers[tokenHeaderLower] ?? req.headers[tokenHeader];
      const token = Array.isArray(raw) ? raw[0] : raw;

      if (!token) {
        // No token provided, continue normally
        return next();
      }

      // Check if this path is exempt from break-glass
      const pathOnly = req.path.split('?')[0] ?? req.path;
      if (exemptPaths.includes(pathOnly)) {
        return next();
      }

      // Validate the session
      let session: BreakGlassSession;
      try {
        session = await manager.validateSession(token, strictReview);
      } catch (err) {
        return res.status(401).json({
          error: {
            code: 'BREAK_GLASS_INVALID_TOKEN',
            message: String(err),
            timestamp: new Date().toISOString(),
          },
        });
      }

      // Attach session to request for downstream handlers
      req.breakGlassSession = session;
      req.breakGlassToken = token;

      // Record this request in the break-glass audit trail
      const action: Omit<BreakGlassAction, 'id' | 'timestamp'> = {
        method: req.method,
        path: req.path,
        result: 'allowed', // Will be updated by downstream if denied
        statusCode: 200, // Will be updated by downstream
      };

      await manager.recordAction(session.id, action, {
        sourceIp: req.ip,
        userAgent: req.get('user-agent'),
        correlationId: req.get('x-correlation-id'),
        resource: req.path,
      });

      next();
    } catch (err) {
      // Internal error in middleware
      console.error('Error in break-glass middleware:', err);
      res.status(500).json({
        error: {
          code: 'BREAK_GLASS_INTERNAL_ERROR',
          message: 'Internal error processing break-glass token',
          timestamp: new Date().toISOString(),
        },
      });
    }
  };
}

/**
 * Helper to extract break-glass session from request (if present).
 */
export function getBreakGlassSession(
  req: BreakGlassRequest,
): BreakGlassSession | undefined {
  return req.breakGlassSession;
}

/**
 * Helper to check if a request is using break-glass access.
 */
export function isBreakGlassRequest(req: BreakGlassRequest): boolean {
  return !!req.breakGlassSession;
}
