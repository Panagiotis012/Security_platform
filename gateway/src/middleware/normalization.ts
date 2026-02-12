import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { GatewayConfig } from '../../config/default';
import { globalMetrics } from '@zerotrust/shared';
import { createSecurityLogger } from './request-logger';

/**
 * Request normalization middleware.
 *
 * CRITICAL: This runs BEFORE any auth/routing decisions to prevent
 * path confusion, header smuggling, and encoding bypasses.
 *
 * Threat model:
 * - Double-encoding to bypass WAF/auth rules
 * - Path traversal via ../ sequences
 * - Null byte injection
 * - HTTP method override attacks
 * - Header size overflow / smuggling
 * - Non-printable character injection
 */

const NULL_BYTE_REGEX = /%00|\x00/;
const NON_PRINTABLE_REGEX = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
const DOUBLE_ENCODE_REGEX = /%25[0-9a-fA-F]{2}/;
const PATH_TRAVERSAL_REGEX = /(?:^|[\\/])\.\.(?:[\\/]|$)/;
const DOUBLE_SLASH_REGEX = /\/{2,}/g;
const BACKSLASH_REGEX = /\\/g;

// Characters that must not appear in decoded paths beyond standard printables
const DANGEROUS_PATH_CHARS = /[\x00-\x1F\x7F<>{}|\\^`]/;

interface NormalizationOptions {
  maxHeaderSize: number;
  maxTotalHeaderSize: number;
  allowedMethods: string[];
}

export function createNormalizationMiddleware(config: GatewayConfig): RequestHandler {
  const securityLog = createSecurityLogger(config);
  const options: NormalizationOptions = {
    maxHeaderSize: config.server.maxHeaderFieldSize,
    maxTotalHeaderSize: config.server.maxHeaderSize,
    allowedMethods: config.allowedHttpMethods,
  };

  const recordBlock = (rule: string): void => {
    try {
      globalMetrics.recordCounter('normalization_blocks_total', 1, {
        service: 'gateway',
        rule,
      });
    } catch {
      // Metrics must never affect request handling.
    }
  };

  return (req: Request, res: Response, next: NextFunction): void => {
    const correlationId = (req.headers['x-correlation-id'] as string) || 'unknown';

    // ── Step 1: Block non-standard HTTP methods ───────────────────────
    if (!options.allowedMethods.includes(req.method.toUpperCase())) {
      recordBlock('blocked_method');
      securityLog.warn({
        event: 'normalization_blocked_method',
        correlationId,
        method: req.method,
        ip: req.ip,
        reason: 'Disallowed HTTP method',
      });
      res.status(405).json({ error: 'Method Not Allowed' });
      return;
    }

    // ── Step 2: Block method override headers ─────────────────────────
    // Prevent X-HTTP-Method-Override style attacks
    const methodOverrideHeaders = [
      'x-http-method-override',
      'x-http-method',
      'x-method-override',
    ];
    for (const header of methodOverrideHeaders) {
      if (req.headers[header]) {
        recordBlock('method_override_header');
        securityLog.warn({
          event: 'normalization_blocked_method_override',
          correlationId,
          header,
          ip: req.ip,
          reason: 'Method override header detected',
        });
        res.status(400).json({ error: 'Bad Request' });
        return;
      }
    }

    // ── Step 3: Validate and enforce header size limits ───────────────
    let totalHeaderSize = 0;
    const contentLengthValues: string[] = [];
    const transferEncodingValues: string[] = [];
    const rawHeaders = req.rawHeaders;
    for (let i = 0; i < rawHeaders.length; i += 2) {
      const name = rawHeaders[i];
      const value = rawHeaders[i + 1];
      if (name === undefined || value === undefined) continue;

      const fieldSize = Buffer.byteLength(name, 'utf8') + Buffer.byteLength(value, 'utf8');
      const lowerName = name.toLowerCase();

      if (lowerName === 'content-length') {
        contentLengthValues.push(value);
      }
      if (lowerName === 'transfer-encoding') {
        transferEncodingValues.push(value);
      }

      if (fieldSize > options.maxHeaderSize) {
        recordBlock('header_field_too_large');
        securityLog.warn({
          event: 'normalization_header_too_large',
          correlationId,
          headerName: lowerName,
          size: fieldSize,
          limit: options.maxHeaderSize,
          ip: req.ip,
        });
        res.status(431).json({ error: 'Request Header Fields Too Large' });
        return;
      }

      totalHeaderSize += fieldSize;
    }

    if (totalHeaderSize > options.maxTotalHeaderSize) {
      recordBlock('total_headers_too_large');
      securityLog.warn({
        event: 'normalization_total_headers_too_large',
        correlationId,
        totalSize: totalHeaderSize,
        limit: options.maxTotalHeaderSize,
        ip: req.ip,
      });
      res.status(431).json({ error: 'Request Header Fields Too Large' });
      return;
    }

    // ── Step 3b: Header smuggling / ambiguity checks ──────────────────
    // Reject CL+TE ambiguity and duplicate CL headers.
    if (contentLengthValues.length > 0 && transferEncodingValues.length > 0) {
      recordBlock('header_smuggling_cl_te');
      securityLog.warn({
        event: 'normalization_header_smuggling_cl_te',
        correlationId,
        ip: req.ip,
        reason: 'Both Content-Length and Transfer-Encoding present',
      });
      res.status(400).json({ error: 'Bad Request' });
      return;
    }

    if (contentLengthValues.length > 1) {
      recordBlock('duplicate_content_length');
      securityLog.warn({
        event: 'normalization_duplicate_content_length',
        correlationId,
        ip: req.ip,
        count: contentLengthValues.length,
      });
      res.status(400).json({ error: 'Bad Request' });
      return;
    }

    if (transferEncodingValues.length > 1) {
      recordBlock('duplicate_transfer_encoding');
      securityLog.warn({
        event: 'normalization_duplicate_transfer_encoding',
        correlationId,
        ip: req.ip,
        count: transferEncodingValues.length,
      });
      res.status(400).json({ error: 'Bad Request' });
      return;
    }

    // ── Step 4: Normalize header values (trim whitespace) ─────────────
    // Express already lowercases header names for req.headers,
    // but we trim values to prevent smuggling via leading/trailing whitespace
    for (const [key, value] of Object.entries(req.headers)) {
      if (typeof value === 'string') {
        req.headers[key] = value.trim();
      } else if (Array.isArray(value)) {
        req.headers[key] = value.map(v => v.trim());
      }
    }

    // ── Step 5: Check for non-printable characters in headers ─────────
    for (const [key, value] of Object.entries(req.headers)) {
      const values = Array.isArray(value) ? value : [value];
      for (const v of values) {
        if (typeof v === 'string' && NON_PRINTABLE_REGEX.test(v)) {
          recordBlock('nonprintable_header');
          securityLog.warn({
            event: 'normalization_nonprintable_header',
            correlationId,
            headerName: key,
            ip: req.ip,
            reason: 'Non-printable characters in header value',
          });
          res.status(400).json({ error: 'Bad Request' });
          return;
        }

        // Explicitly reject CR/LF to prevent header injection / request smuggling.
        if (typeof v === 'string' && /[\r\n]/.test(v)) {
          recordBlock('crlf_in_header');
          securityLog.warn({
            event: 'normalization_crlf_in_header',
            correlationId,
            headerName: key,
            ip: req.ip,
            reason: 'CR/LF detected in header value',
          });
          res.status(400).json({ error: 'Bad Request' });
          return;
        }
      }
    }

    // ── Step 6: URL path normalization ────────────────────────────────
    const originalUrl = req.url;
    let normalizedPath: string;

    try {
      normalizedPath = normalizePath(originalUrl);
    } catch (err) {
      recordBlock('path_error');
      securityLog.warn({
        event: 'normalization_path_error',
        correlationId,
        originalUrl,
        ip: req.ip,
        reason: err instanceof Error ? err.message : 'Path normalization failed',
      });
      res.status(400).json({ error: 'Bad Request' });
      return;
    }

    // Apply the normalized URL
    req.url = normalizedPath;

    // ── Step 7: Block path traversal in the normalized path ──────────
    // Parse just the path portion (before query string)
    const pathOnly = normalizedPath.split('?')[0] ?? normalizedPath;
    if (PATH_TRAVERSAL_REGEX.test(pathOnly)) {
      recordBlock('path_traversal');
      securityLog.warn({
        event: 'normalization_path_traversal',
        correlationId,
        originalUrl,
        normalizedUrl: normalizedPath,
        ip: req.ip,
        reason: 'Path traversal detected after normalization',
      });
      res.status(400).json({ error: 'Bad Request' });
      return;
    }

    next();
  };
}

/**
 * Canonicalize a URL path.
 *
 * Steps:
 * 1. Separate path from query string
 * 2. Replace backslashes with forward slashes
 * 3. Decode percent-encoded characters ONCE
 * 4. Detect double-encoding — reject if found
 * 5. Block null bytes and dangerous characters
 * 6. Resolve relative path segments (../, ./)
 * 7. Collapse double slashes
 * 8. Lowercase the path
 * 9. Ensure path starts with /
 */
function normalizePath(url: string): string {
  // Separate path and query string
  const qIndex = url.indexOf('?');
  let path = qIndex >= 0 ? url.substring(0, qIndex) : url;
  const query = qIndex >= 0 ? url.substring(qIndex) : '';

  // Replace backslashes (Windows-style path confusion)
  path = path.replace(BACKSLASH_REGEX, '/');

  // Check for double encoding BEFORE decoding
  if (DOUBLE_ENCODE_REGEX.test(path)) {
    throw new Error('Double-encoded characters detected');
  }

  // Decode percent-encoded characters ONCE
  try {
    path = decodeURIComponent(path);
  } catch {
    // If decoding fails, the encoding is malformed — reject
    throw new Error('Malformed URL encoding');
  }

  // After decoding, check again for percent-encoding (double-encoding evasion)
  if (/%[0-9a-fA-F]{2}/.test(path)) {
    throw new Error('Double-encoded characters detected after decode');
  }

  // Block null bytes
  if (NULL_BYTE_REGEX.test(path)) {
    throw new Error('Null byte detected in path');
  }

  // Block dangerous characters in decoded path
  if (DANGEROUS_PATH_CHARS.test(path)) {
    throw new Error('Dangerous characters detected in path');
  }

  // Resolve relative segments (../, ./)
  path = resolvePathSegments(path);

  // Collapse double slashes
  path = path.replace(DOUBLE_SLASH_REGEX, '/');

  // Lowercase the path for case-insensitive matching
  path = path.toLowerCase();

  // Ensure leading slash
  if (!path.startsWith('/')) {
    path = '/' + path;
  }

  // Remove trailing slash (except for root)
  if (path.length > 1 && path.endsWith('/')) {
    path = path.slice(0, -1);
  }

  return path + query;
}

/**
 * Resolve ../ and ./ segments in a path, preventing traversal above root.
 */
function resolvePathSegments(path: string): string {
  const segments = path.split('/');
  const resolved: string[] = [];

  for (const segment of segments) {
    if (segment === '.' || segment === '') {
      // Skip current-dir references and empty segments (from double slashes)
      // But preserve a single empty segment for root /
      if (resolved.length === 0) {
        resolved.push('');
      }
      continue;
    }

    if (segment === '..') {
      // Go up one level, but never above root
      if (resolved.length > 1) {
        resolved.pop();
      }
      continue;
    }

    resolved.push(segment);
  }

  const result = resolved.join('/');
  return result || '/';
}
