/**
 * Input canonicalization utilities.
 *
 * CRITICAL: All inputs MUST be canonicalized BEFORE any authorization
 * decision is made. Failure to do so creates request-smuggling
 * vulnerabilities where attackers bypass policy checks with
 * non-canonical representations (double encoding, unicode tricks,
 * path traversal, etc.).
 *
 * The functions here normalise paths, headers, and other inputs into a
 * single canonical form so that policy evaluation is deterministic.
 */

import {
  SecurityError,
  SecurityErrorCode,
  ValidationError,
} from './errors';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CanonicalizationResult {
  /** The canonicalized value. */
  value: string;
  /** Whether any transformation was applied. */
  transformed: boolean;
  /** Warnings about suspicious patterns detected (but not blocked). */
  warnings: string[];
}

export interface AmbiguousEncodingResult {
  /** Whether ambiguous / suspicious encoding was detected. */
  suspicious: boolean;
  /** Description of each detected issue. */
  issues: string[];
}

// ---------------------------------------------------------------------------
// Path canonicalization
// ---------------------------------------------------------------------------

/**
 * Canonicalize a URL path.
 *
 * Steps (in order):
 *  1. Percent-decode exactly once.
 *  2. Normalise unicode (NFC).
 *  3. Replace backslashes with forward slashes.
 *  4. Collapse consecutive slashes to a single slash.
 *  5. Resolve `.` and `..` segments.
 *  6. Ensure leading slash.
 *  7. Remove trailing slash (except for root "/").
 *  8. Lowercase (paths are treated case-insensitively for authz).
 *
 * Throws if a null byte or path traversal above root is detected.
 */
export function canonicalizePath(rawPath: string): CanonicalizationResult {
  const warnings: string[] = [];
  let path = rawPath;

  // ---- Step 0: Block null bytes immediately ----
  if (path.includes('\0') || path.includes('%00')) {
    throw new ValidationError(
      'Null byte detected in path',
      [{ field: 'path', message: 'Path contains null byte.' }],
      { code: SecurityErrorCode.PATH_TRAVERSAL_DETECTED },
    );
  }

  // ---- Step 1: Percent-decode exactly once ----
  // Detect double-encoding first (e.g. %252F → %2F after one decode).
  const doubleEncodingCheck = detectDoubleEncoding(path);
  if (doubleEncodingCheck.suspicious) {
    warnings.push(...doubleEncodingCheck.issues);
  }

  try {
    path = decodeURIComponent(path);
  } catch {
    // If decoding fails the input contained malformed percent sequences.
    // Use it as-is but warn.
    warnings.push('Path contains malformed percent-encoding; used as-is.');
  }

  // ---- Step 2: Unicode NFC normalisation ----
  path = path.normalize('NFC');

  // ---- Step 3: Backslash → forward slash ----
  if (path.includes('\\')) {
    warnings.push('Backslashes replaced with forward slashes.');
    path = path.replace(/\\/g, '/');
  }

  // ---- Step 4: Collapse consecutive slashes ----
  path = path.replace(/\/\/+/g, '/');

  // ---- Step 5: Resolve . and .. ----
  path = resolvePathSegments(path);

  // ---- Step 6: Ensure leading slash ----
  if (!path.startsWith('/')) {
    path = '/' + path;
  }

  // ---- Step 7: Remove trailing slash (except root) ----
  if (path.length > 1 && path.endsWith('/')) {
    path = path.slice(0, -1);
  }

  // ---- Step 8: Lowercase ----
  path = path.toLowerCase();

  const transformed = path !== rawPath;
  return { value: path, transformed, warnings };
}

/**
 * Detect and block explicit path-traversal attempts.
 *
 * Call this AFTER canonicalization.  If the canonical path still contains
 * suspicious sequences something is very wrong.
 *
 * Throws SecurityError on detection.
 */
export function blockTraversalAttempts(canonicalPath: string): void {
  // After proper canonicalization there should never be `..` segments.
  if (canonicalPath.includes('..')) {
    throw new SecurityError({
      code: SecurityErrorCode.PATH_TRAVERSAL_DETECTED,
      message: `Path traversal detected in canonical path: ${canonicalPath}`,
      publicMessage: 'Invalid request path.',
      httpStatus: 400,
    });
  }

  // Null bytes (paranoia check – should have been caught earlier).
  if (canonicalPath.includes('\0')) {
    throw new SecurityError({
      code: SecurityErrorCode.PATH_TRAVERSAL_DETECTED,
      message: 'Null byte in canonical path.',
      publicMessage: 'Invalid request path.',
      httpStatus: 400,
    });
  }
}

// ---------------------------------------------------------------------------
// Header canonicalization
// ---------------------------------------------------------------------------

/**
 * Canonicalize HTTP headers.
 *
 *  - Lowercase all header names.
 *  - Trim leading / trailing whitespace from values.
 *  - Collapse interior whitespace in values to a single space.
 *  - Remove headers with empty values.
 */
export function canonicalizeHeaders(
  headers: Record<string, string | string[] | undefined>,
): Record<string, string> {
  const result: Record<string, string> = {};

  for (const [rawName, rawValue] of Object.entries(headers)) {
    if (rawValue === undefined) continue;

    const name = rawName.toLowerCase().trim();
    if (name.length === 0) continue;

    const values = Array.isArray(rawValue) ? rawValue : [rawValue];
    const joined = values.join(', ');
    const normalised = joined.trim().replace(/\s+/g, ' ');

    if (normalised.length > 0) {
      result[name] = normalised;
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Ambiguous encoding detection
// ---------------------------------------------------------------------------

/**
 * Detect suspicious double-encoding, unicode tricks, and null bytes.
 *
 * This is an advisory check – it does not modify the input.  Callers
 * should decide whether to block, warn, or log.
 */
export function detectAmbiguousEncoding(
  input: string,
): AmbiguousEncodingResult {
  const issues: string[] = [];

  // Null bytes.
  if (input.includes('\0') || /%00/i.test(input)) {
    issues.push('Null byte detected.');
  }

  // Double percent-encoding (e.g. %252F = double-encoded "/").
  const doubleResult = detectDoubleEncoding(input);
  if (doubleResult.suspicious) {
    issues.push(...doubleResult.issues);
  }

  // Overlong UTF-8 (if somehow present in a JS string, it's suspicious).
  // In practice this catches the %C0%AF pattern for "/" and similar.
  if (/%c0%af/i.test(input) || /%c1%9c/i.test(input)) {
    issues.push('Overlong UTF-8 encoding detected.');
  }

  // Unicode confusables: right-to-left override, zero-width chars.
  if (/[\u200B\u200C\u200D\u200E\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/.test(input)) {
    issues.push('Unicode bidirectional override or zero-width character detected.');
  }

  // Backslash (often used to evade path checks on Windows).
  if (input.includes('\\')) {
    issues.push('Backslash in input (potential path separator confusion).');
  }

  return {
    suspicious: issues.length > 0,
    issues,
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Detect double percent-encoding sequences.
 *
 * Looks for patterns like %25XX which, when decoded once, yield %XX.
 */
function detectDoubleEncoding(input: string): AmbiguousEncodingResult {
  const issues: string[] = [];

  // %25 followed by two hex chars = double-encoded percent sequence.
  const doubleEncoded = input.match(/%25[0-9a-fA-F]{2}/g);
  if (doubleEncoded && doubleEncoded.length > 0) {
    issues.push(
      `Double percent-encoding detected: ${doubleEncoded.slice(0, 5).join(', ')}${doubleEncoded.length > 5 ? '...' : ''}`
    );
  }

  return { suspicious: issues.length > 0, issues };
}

/**
 * Resolve `.` and `..` path segments.
 *
 * Refuses to traverse above the root (i.e. more `..` than depth) by
 * throwing instead of silently clamping.
 */
function resolvePathSegments(path: string): string {
  const segments = path.split('/');
  const resolved: string[] = [];

  for (const segment of segments) {
    if (segment === '.' || segment === '') {
      continue;
    }

    if (segment === '..') {
      if (resolved.length === 0) {
        throw new SecurityError({
          code: SecurityErrorCode.PATH_TRAVERSAL_DETECTED,
          message: `Path traversal above root: ${path}`,
          publicMessage: 'Invalid request path.',
          httpStatus: 400,
        });
      }
      resolved.pop();
    } else {
      resolved.push(segment);
    }
  }

  return '/' + resolved.join('/');
}
