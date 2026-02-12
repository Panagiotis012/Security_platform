/**
 * Correlation ID middleware for Express.
 *
 * Extracts `X-Correlation-ID` from incoming requests (or generates a fresh
 * UUID v4 if absent), attaches it to the request object for downstream
 * handlers, and propagates it back on the response headers.
 *
 * This enables cross-service trace correlation when used together with the
 * StructuredLogger (which stamps every log entry with the correlation ID).
 *
 * Usage:
 *   import { correlationIdMiddleware, getCorrelationId } from '@zerotrust/shared';
 *   app.use(correlationIdMiddleware());
 *   app.get('/', (req, res) => {
 *     const cid = getCorrelationId(req);
 *     // ...
 *   });
 */

import { v4 as uuidv4, validate as uuidValidate } from 'uuid';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Minimal subset of Express types so we don't force a hard dependency on
 * @types/express at runtime. The real Express types are a superset of these.
 */
export interface CorrelationRequest {
  headers: Record<string, string | string[] | undefined>;
  correlationId?: string;
}

export interface CorrelationResponse {
  setHeader(name: string, value: string): void;
}

export type NextFunction = (err?: unknown) => void;

export interface CorrelationIdMiddlewareOptions {
  /**
   * Header name to read / write. Defaults to `X-Correlation-ID`.
   */
  headerName?: string;
  /**
   * If `true`, a correlation ID supplied by the client is accepted as-is
   * (after validation). If `false`, a new one is always generated.
   * Defaults to `true`.
   */
  trustIncoming?: boolean;
  /**
   * If `true`, the correlation ID is written to the response headers.
   * Defaults to `true`.
   */
  emitOnResponse?: boolean;
  /**
   * Custom generator function. Defaults to UUID v4.
   */
  generator?: () => string;
}

// ---------------------------------------------------------------------------
// Middleware factory
// ---------------------------------------------------------------------------

/**
 * Create Express middleware that manages correlation IDs.
 */
export function correlationIdMiddleware(
  options: CorrelationIdMiddlewareOptions = {},
): (req: CorrelationRequest, res: CorrelationResponse, next: NextFunction) => void {
  const headerName = options.headerName ?? 'X-Correlation-ID';
  const headerNameLower = headerName.toLowerCase();
  const trustIncoming = options.trustIncoming ?? true;
  const emitOnResponse = options.emitOnResponse ?? true;
  const generate = options.generator ?? uuidv4;

  return (
    req: CorrelationRequest,
    res: CorrelationResponse,
    next: NextFunction,
  ): void => {
    let correlationId: string | undefined;

    if (trustIncoming) {
      const raw = req.headers[headerNameLower] ?? req.headers[headerName];
      const candidate = Array.isArray(raw) ? raw[0] : raw;

      if (candidate && isValidCorrelationId(candidate)) {
        correlationId = candidate;
      }
    }

    if (!correlationId) {
      correlationId = generate();
    }

    // Attach to the request object so downstream handlers can access it.
    req.correlationId = correlationId;

    if (emitOnResponse) {
      res.setHeader(headerName, correlationId);
    }

    next();
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Retrieve the correlation ID from a request object.
 * Returns the attached ID or generates a new one as a fallback.
 */
export function getCorrelationId(req: CorrelationRequest): string {
  return req.correlationId ?? uuidv4();
}

/**
 * Validate that a candidate correlation ID is safe to accept.
 *
 * Accepts:
 *  - UUID v4 strings
 *  - Alphanumeric + dash strings up to 128 chars (for systems that use
 *    custom trace IDs like OpenTelemetry trace-id).
 *
 * Rejects anything that could be used for header injection or log injection.
 */
function isValidCorrelationId(value: string): boolean {
  if (value.length === 0 || value.length > 128) return false;

  // Fast path: if it's a valid UUID we're done.
  if (uuidValidate(value)) return true;

  // Allow alphanumeric, dash, underscore (covers W3C trace IDs, etc.).
  return /^[a-zA-Z0-9_-]+$/.test(value);
}
