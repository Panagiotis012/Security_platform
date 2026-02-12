/**
 * Schema-first input validation utilities.
 *
 * All external input (request bodies, query parameters, headers) MUST pass
 * through these validators before being used in business logic or authz
 * decisions.
 *
 * Built on Zod with additional security-hardened defaults:
 *  - String length limits to prevent resource exhaustion.
 *  - Strict numeric parsing (no NaN, no Infinity).
 *  - Date validation (ISO 8601 only).
 *  - Ambiguous encoding detection (defers to canonicalize module).
 */

import type { ZodType, ZodError } from 'zod';
import { z } from 'zod';
import { detectAmbiguousEncoding } from './canonicalize';
import { ValidationError, SecurityErrorCode } from './errors';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ValidationResult<T> {
  success: true;
  data: T;
}

export interface ValidationFailure {
  success: false;
  error: ValidationError;
}

// ---------------------------------------------------------------------------
// Core validation function
// ---------------------------------------------------------------------------

/**
 * Validate arbitrary data against a Zod schema.
 *
 * Returns a discriminated union so callers can handle success / failure
 * without try/catch.
 */
export function validate<T>(
  schema: ZodType<T>,
  data: unknown,
  label: string = 'input',
): ValidationResult<T> | ValidationFailure {
  const result = schema.safeParse(data);

  if (result.success) {
    return { success: true, data: result.data };
  }

  const fieldErrors = result.error.issues.map((issue) => ({
    field: issue.path.join('.') || label,
    message: issue.message,
  }));

  return {
    success: false,
    error: new ValidationError(
      `Validation failed for ${label}: ${summarizeZodError(result.error)}`,
      fieldErrors,
    ),
  };
}

/**
 * Validate and throw on failure.  Convenience wrapper for contexts where
 * a result union is cumbersome.
 */
export function validateOrThrow<T>(
  schema: ZodType<T>,
  data: unknown,
  label: string = 'input',
): T {
  const result = validate(schema, data, label);
  if (!result.success) {
    throw result.error;
  }
  return result.data;
}

// ---------------------------------------------------------------------------
// Request-specific validators
// ---------------------------------------------------------------------------

/**
 * Validate an Express-style request body.
 *
 * Additionally checks for ambiguous encodings in string values at the top
 * level (deeper checks rely on the canonicalization layer).
 */
export function validateRequestBody<T>(
  schema: ZodType<T>,
  body: unknown,
): ValidationResult<T> | ValidationFailure {
  // Pre-check: reject bodies that are not objects or arrays.
  if (body !== null && body !== undefined && typeof body !== 'object') {
    return {
      success: false,
      error: new ValidationError('Request body must be an object or array.', [
        { field: 'body', message: 'Expected object or array.' },
      ]),
    };
  }

  // Check top-level string values for ambiguous encoding.
  if (body && typeof body === 'object' && !Array.isArray(body)) {
    const record = body as Record<string, unknown>;
    for (const [key, value] of Object.entries(record)) {
      if (typeof value === 'string') {
        const encoding = detectAmbiguousEncoding(value);
        if (encoding.suspicious) {
          return {
            success: false,
            error: new ValidationError(
              `Ambiguous encoding in field "${key}": ${encoding.issues.join('; ')}`,
              [{ field: key, message: encoding.issues.join('; ') }],
              { code: SecurityErrorCode.AMBIGUOUS_ENCODING },
            ),
          };
        }
      }
    }
  }

  return validate(schema, body, 'request body');
}

/**
 * Validate Express-style query parameters.
 *
 * Query params arrive as `Record<string, string | string[]>`.  This function
 * applies Zod coercion so numeric / boolean query params are parsed correctly.
 */
export function validateQueryParams<T>(
  schema: ZodType<T>,
  query: Record<string, string | string[] | undefined>,
): ValidationResult<T> | ValidationFailure {
  // Check for ambiguous encoding in every value.
  for (const [key, value] of Object.entries(query)) {
    const values = value === undefined ? [] : Array.isArray(value) ? value : [value];
    for (const v of values) {
      const encoding = detectAmbiguousEncoding(v);
      if (encoding.suspicious) {
        return {
          success: false,
          error: new ValidationError(
            `Ambiguous encoding in query param "${key}": ${encoding.issues.join('; ')}`,
            [{ field: key, message: encoding.issues.join('; ') }],
            { code: SecurityErrorCode.AMBIGUOUS_ENCODING },
          ),
        };
      }
    }
  }

  return validate(schema, query, 'query params');
}

/**
 * Validate HTTP headers.
 *
 * Headers should already be canonicalized (lowercased, trimmed) by the
 * canonicalization middleware before reaching this point.
 */
export function validateHeaders<T>(
  schema: ZodType<T>,
  headers: Record<string, string | string[] | undefined>,
): ValidationResult<T> | ValidationFailure {
  return validate(schema, headers, 'headers');
}

// ---------------------------------------------------------------------------
// Pre-built Zod schemas for common types
// ---------------------------------------------------------------------------

/** A non-empty string with a sensible max length. */
export const SafeString = (maxLength: number = 1024) =>
  z.string().min(1).max(maxLength);

/** A trimmed, non-empty string. */
export const TrimmedString = (maxLength: number = 1024) =>
  z
    .string()
    .min(1)
    .max(maxLength)
    .transform((s) => s.trim());

/** A string that must be a valid UUID. */
export const UUIDString = z.string().uuid();

/** A string that must be a valid ISO 8601 datetime. */
export const ISODateString = z.string().datetime({ offset: true });

/** A strictly-parsed integer (rejects NaN, Infinity, floats). */
export const StrictInt = z
  .union([z.number(), z.string()])
  .pipe(
    z.coerce
      .number()
      .int()
      .refine((n) => Number.isFinite(n), {
        message: 'Must be a finite integer.',
      }),
  );

/** A strictly-parsed positive integer. */
export const PositiveInt = StrictInt.pipe(z.number().positive());

/** A strictly-parsed non-negative integer. */
export const NonNegativeInt = StrictInt.pipe(z.number().nonnegative());

/** A strictly-parsed float (rejects NaN, Infinity). */
export const StrictFloat = z
  .union([z.number(), z.string()])
  .pipe(
    z.coerce
      .number()
      .refine((n) => Number.isFinite(n), {
        message: 'Must be a finite number.',
      }),
  );

/**
 * An email address.
 * Uses Zod's built-in email validation + length limit.
 */
export const EmailString = z.string().email().max(320);

/**
 * A URL string (https only in production use).
 */
export const HttpsUrl = z.string().url().max(2048).refine(
  (u) => u.startsWith('https://'),
  { message: 'URL must use HTTPS.' },
);

/**
 * IP address (v4 or v6).
 */
export const IPAddress = z.string().ip();

/**
 * Pagination parameters – commonly needed across APIs.
 */
export const PaginationSchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  pageSize: z.coerce.number().int().positive().max(200).default(20),
  sortBy: z.string().max(64).optional(),
  sortOrder: z.enum(['asc', 'desc']).default('asc'),
});

export type PaginationParams = z.infer<typeof PaginationSchema>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Produce a human-readable one-line summary of a ZodError.
 */
function summarizeZodError(error: ZodError): string {
  return error.issues
    .slice(0, 5) // cap to avoid enormous messages
    .map((i) => {
      const path = i.path.length > 0 ? `${i.path.join('.')}: ` : '';
      return `${path}${i.message}`;
    })
    .join('; ');
}
