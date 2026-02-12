/**
 * Standardized error types for the Zero Trust security platform.
 *
 * All errors carry a machine-readable code, a correlation ID for tracing,
 * and a safe public message that can be returned to external callers without
 * leaking implementation details.
 */

// ---------------------------------------------------------------------------
// Error codes – every error in the platform maps to exactly one code.
// ---------------------------------------------------------------------------

export enum SecurityErrorCode {
  // Authentication 1xxx
  AUTHENTICATION_FAILED = 'AUTH_1001',
  TOKEN_EXPIRED = 'AUTH_1002',
  TOKEN_INVALID = 'AUTH_1003',
  SESSION_EXPIRED = 'AUTH_1004',
  CREDENTIALS_INVALID = 'AUTH_1005',
  MFA_REQUIRED = 'AUTH_1006',
  STEP_UP_REQUIRED = 'AUTH_1007',

  // Authorization 2xxx
  ACCESS_DENIED = 'AUTHZ_2001',
  INSUFFICIENT_PRIVILEGES = 'AUTHZ_2002',
  POLICY_VIOLATION = 'AUTHZ_2003',
  SCOPE_INSUFFICIENT = 'AUTHZ_2004',

  // Rate limiting 3xxx
  RATE_LIMIT_EXCEEDED = 'RATE_3001',
  GREYLISTED = 'RATE_3002',

  // Validation 4xxx
  VALIDATION_FAILED = 'VAL_4001',
  INVALID_INPUT = 'VAL_4002',
  AMBIGUOUS_ENCODING = 'VAL_4003',
  PATH_TRAVERSAL_DETECTED = 'VAL_4004',

  // Integrity 5xxx
  INTEGRITY_VIOLATION = 'INT_5001',
  HASH_CHAIN_BROKEN = 'INT_5002',
  SIGNATURE_INVALID = 'INT_5003',

  // Internal 9xxx
  INTERNAL_ERROR = 'INT_9001',
  CONFIGURATION_ERROR = 'INT_9002',
  DEPENDENCY_ERROR = 'INT_9003',
}

// ---------------------------------------------------------------------------
// Base error
// ---------------------------------------------------------------------------

export interface SecurityErrorOptions {
  /** Machine-readable error code. */
  code: SecurityErrorCode;
  /** Internal message (may contain sensitive details – never expose to clients). */
  message: string;
  /** Correlation ID for cross-service tracing. */
  correlationId?: string;
  /** Safe message that can be returned to external callers. */
  publicMessage?: string;
  /** HTTP status code to use when this error surfaces in an API response. */
  httpStatus?: number;
  /** Upstream cause, if any. */
  cause?: Error;
  /** Arbitrary metadata to attach to structured logs. */
  metadata?: Record<string, unknown>;
}

export class SecurityError extends Error {
  public readonly code: SecurityErrorCode;
  public readonly correlationId: string | undefined;
  public readonly publicMessage: string;
  public readonly httpStatus: number;
  public readonly metadata: Record<string, unknown>;
  public readonly timestamp: string;
  public override readonly cause: Error | undefined;

  constructor(options: SecurityErrorOptions) {
    super(options.message);

    // Preserve the correct prototype chain so instanceof works.
    Object.setPrototypeOf(this, new.target.prototype);

    this.name = this.constructor.name;
    this.code = options.code;
    this.correlationId = options.correlationId;
    this.publicMessage =
      options.publicMessage ?? 'An unexpected error occurred.';
    this.httpStatus = options.httpStatus ?? 500;
    this.cause = options.cause;
    this.metadata = options.metadata ?? {};
    this.timestamp = new Date().toISOString();

    // Capture a clean stack trace (skip the constructor frame).
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  /**
   * Return a JSON-safe representation suitable for structured logging.
   * Internal `message` is included; callers exposing this externally should
   * use `toPublicJSON` instead.
   */
  public toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      publicMessage: this.publicMessage,
      httpStatus: this.httpStatus,
      correlationId: this.correlationId,
      timestamp: this.timestamp,
      metadata: this.metadata,
      cause: this.cause
        ? { name: this.cause.name, message: this.cause.message }
        : undefined,
    };
  }

  /**
   * Return a representation safe for external API responses.
   * Never includes internal error messages or stack traces.
   */
  public toPublicJSON(): Record<string, unknown> {
    return {
      error: {
        code: this.code,
        message: this.publicMessage,
        correlationId: this.correlationId,
        timestamp: this.timestamp,
      },
    };
  }
}

// ---------------------------------------------------------------------------
// Concrete error types
// ---------------------------------------------------------------------------

export class AuthenticationError extends SecurityError {
  constructor(
    message: string,
    options: Partial<Omit<SecurityErrorOptions, 'message'>> = {},
  ) {
    super({
      code: options.code ?? SecurityErrorCode.AUTHENTICATION_FAILED,
      message,
      publicMessage:
        options.publicMessage ?? 'Authentication failed. Please try again.',
      httpStatus: options.httpStatus ?? 401,
      ...options,
    });
  }
}

export class AuthorizationError extends SecurityError {
  constructor(
    message: string,
    options: Partial<Omit<SecurityErrorOptions, 'message'>> = {},
  ) {
    super({
      code: options.code ?? SecurityErrorCode.ACCESS_DENIED,
      message,
      publicMessage:
        options.publicMessage ??
        'You do not have permission to perform this action.',
      httpStatus: options.httpStatus ?? 403,
      ...options,
    });
  }
}

export class RateLimitError extends SecurityError {
  public readonly retryAfterMs: number;

  constructor(
    message: string,
    retryAfterMs: number = 60_000,
    options: Partial<Omit<SecurityErrorOptions, 'message'>> = {},
  ) {
    super({
      code: options.code ?? SecurityErrorCode.RATE_LIMIT_EXCEEDED,
      message,
      publicMessage:
        options.publicMessage ??
        'Too many requests. Please wait before trying again.',
      httpStatus: options.httpStatus ?? 429,
      ...options,
    });
    this.retryAfterMs = retryAfterMs;
  }

  public override toPublicJSON(): Record<string, unknown> {
    const base = super.toPublicJSON() as {
      error: Record<string, unknown>;
    };
    base.error['retryAfterMs'] = this.retryAfterMs;
    return base;
  }
}

export class ValidationError extends SecurityError {
  public readonly fieldErrors: ReadonlyArray<{
    field: string;
    message: string;
  }>;

  constructor(
    message: string,
    fieldErrors: Array<{ field: string; message: string }> = [],
    options: Partial<Omit<SecurityErrorOptions, 'message'>> = {},
  ) {
    super({
      code: options.code ?? SecurityErrorCode.VALIDATION_FAILED,
      message,
      publicMessage:
        options.publicMessage ?? 'The request contains invalid data.',
      httpStatus: options.httpStatus ?? 400,
      ...options,
    });
    this.fieldErrors = Object.freeze([...fieldErrors]);
  }

  public override toPublicJSON(): Record<string, unknown> {
    const base = super.toPublicJSON() as {
      error: Record<string, unknown>;
    };
    base.error['fields'] = this.fieldErrors;
    return base;
  }
}

export class PolicyViolationError extends SecurityError {
  public readonly policyId: string;
  public readonly decision: 'deny' | 'error';

  constructor(
    message: string,
    policyId: string,
    decision: 'deny' | 'error' = 'deny',
    options: Partial<Omit<SecurityErrorOptions, 'message'>> = {},
  ) {
    super({
      code: options.code ?? SecurityErrorCode.POLICY_VIOLATION,
      message,
      publicMessage:
        options.publicMessage ??
        'Request denied by security policy.',
      httpStatus: options.httpStatus ?? 403,
      ...options,
    });
    this.policyId = policyId;
    this.decision = decision;
  }
}

export class IntegrityError extends SecurityError {
  constructor(
    message: string,
    options: Partial<Omit<SecurityErrorOptions, 'message'>> = {},
  ) {
    super({
      code: options.code ?? SecurityErrorCode.INTEGRITY_VIOLATION,
      message,
      publicMessage:
        options.publicMessage ?? 'Data integrity check failed.',
      httpStatus: options.httpStatus ?? 500,
      ...options,
    });
  }
}

// ---------------------------------------------------------------------------
// Utility: wrap unknown thrown values into a SecurityError
// ---------------------------------------------------------------------------

export function toSecurityError(
  err: unknown,
  correlationId?: string,
): SecurityError {
  if (err instanceof SecurityError) {
    return err;
  }

  if (err instanceof Error) {
    return new SecurityError({
      code: SecurityErrorCode.INTERNAL_ERROR,
      message: err.message,
      publicMessage: 'An internal error occurred.',
      correlationId,
      cause: err,
    });
  }

  return new SecurityError({
    code: SecurityErrorCode.INTERNAL_ERROR,
    message: String(err),
    publicMessage: 'An internal error occurred.',
    correlationId,
  });
}
