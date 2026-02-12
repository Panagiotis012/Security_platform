import type { Request, Response, NextFunction, RequestHandler } from 'express';
import express from 'express';
import type { GatewayConfig} from '../../config/default';
import { getRouteConfig } from '../../config/default';
import { createSecurityLogger } from './request-logger';

/**
 * Body limits middleware.
 *
 * - Default 1MB body limit
 * - Per-route configurable limits
 * - Content-type validation and enforcement
 * - Strict JSON parsing (no comments, no trailing commas, no BOM)
 * - Block content-type sniffing attacks
 * - File upload size constraints
 */

// ─── Strict JSON Parser ──────────────────────────────────────────────────────

/**
 * Validates JSON is strict: no BOM, no non-standard syntax.
 * Express's built-in JSON parser handles most of this, but we add
 * extra validation for edge cases.
 */
function strictJsonVerifier(body: string): boolean {
  // Check for BOM (Byte Order Mark)
  if (body.charCodeAt(0) === 0xFEFF) {
    return false;
  }

  // Check for JavaScript-style comments
  if (/\/\/.*$/m.test(body) || /\/\*[\s\S]*?\*\//.test(body)) {
    return false;
  }

  // Check for trailing commas before } or ]
  if (/,\s*[}\]]/.test(body)) {
    return false;
  }

  // Check for single-quoted strings
  if (/'[^']*'/.test(body)) {
    return false;
  }

  // Check for unquoted keys (basic heuristic)
  if (/{\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*:/.test(body)) {
    // This is actually valid JSON if the key is quoted — but we need to verify
    // the raw string doesn't have unquoted keys. We'll rely on JSON.parse for this.
  }

  return true;
}

// ─── Content Type Validation ─────────────────────────────────────────────────

function isAllowedContentType(contentType: string | undefined, allowed: string[]): boolean {
  if (!contentType) return true; // No body or no content-type is handled elsewhere

  // Extract the media type (before any parameters like charset)
  const mediaType = contentType.split(';')[0]?.trim().toLowerCase();
  if (!mediaType) return false;

  return allowed.some(a => {
    const allowedLower = a.toLowerCase();
    // Support wildcard matching (e.g., "application/*")
    if (allowedLower.endsWith('/*')) {
      const prefix = allowedLower.slice(0, -2);
      return mediaType.startsWith(prefix);
    }
    return mediaType === allowedLower;
  });
}

// ─── Body Limits Middleware ──────────────────────────────────────────────────

export function createBodyLimitsMiddleware(config: GatewayConfig): RequestHandler[] {
  const securityLog = createSecurityLogger(config);

  // ── Content-type validation middleware ──────────────────────────────
  const contentTypeValidator: RequestHandler = (req: Request, res: Response, next: NextFunction): void => {
    const correlationId = (req.headers['x-correlation-id'] as string) || 'unknown';

    // Only validate content-type for requests that have a body
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      const contentType = req.headers['content-type'];

      if (contentType) {
        if (!isAllowedContentType(contentType, config.bodyLimits.allowedContentTypes)) {
          securityLog.warn({
            event: 'body_invalid_content_type',
            correlationId,
            ip: req.ip,
            path: req.path,
            method: req.method,
            contentType,
            allowedContentTypes: config.bodyLimits.allowedContentTypes,
          });
          res.status(415).json({ error: 'Unsupported Media Type' });
          return;
        }
      } else {
        // POST/PUT/PATCH without content-type is suspicious
        const contentLength = req.headers['content-length'];
        if (contentLength && parseInt(contentLength, 10) > 0) {
          securityLog.warn({
            event: 'body_missing_content_type',
            correlationId,
            ip: req.ip,
            path: req.path,
            method: req.method,
          });
          res.status(400).json({ error: 'Content-Type header required' });
          return;
        }
      }
    }

    next();
  };

  // ── Dynamic body size limit middleware ──────────────────────────────
  const dynamicSizeLimit: RequestHandler = (req: Request, res: Response, next: NextFunction): void => {
    const correlationId = (req.headers['x-correlation-id'] as string) || 'unknown';
    const routeConfig = getRouteConfig(config, req.path, req.method);

    // Determine the limit for this route
    const limit = routeConfig?.bodyLimitBytes ?? config.bodyLimits.defaultMaxBytes;

    // Check Content-Length header upfront to reject obviously too-large requests
    const contentLength = req.headers['content-length'];
    if (contentLength) {
      const declaredLength = parseInt(contentLength, 10);
      if (!isNaN(declaredLength) && declaredLength > limit) {
        securityLog.warn({
          event: 'body_too_large',
          correlationId,
          ip: req.ip,
          path: req.path,
          method: req.method,
          declaredSize: declaredLength,
          limit,
        });
        res.status(413).json({ error: 'Payload Too Large' });
        return;
      }
    }

    next();
  };

  // ── JSON body parser with strict options ───────────────────────────
  const jsonParser = express.json({
    limit: config.bodyLimits.defaultMaxBytes,
    strict: true, // Only parse arrays and objects (not primitives)
    type: 'application/json',
    verify: (req: express.Request, _res: express.Response, buf: Buffer) => {
      // Capture raw body so the proxy can forward bodies safely (body-parser consumes the stream).
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (req as any).rawBody = buf;

      if (!config.bodyLimits.strictJsonParsing) return;

      const correlationId = (req.headers['x-correlation-id'] as string) || 'unknown';
      const raw = buf.toString('utf8');

      if (!strictJsonVerifier(raw)) {
        securityLog.warn({
          event: 'body_strict_json_violation',
          correlationId,
          ip: req.ip,
          path: req.path,
          method: req.method,
          reason: 'Non-standard JSON syntax detected',
        });
        throw new Error('Strict JSON validation failed');
      }
    },
  });

  // ── URL-encoded body parser ────────────────────────────────────────
  const urlencodedParser = express.urlencoded({
    limit: config.bodyLimits.defaultMaxBytes,
    extended: false, // Use querystring library (simpler, safer)
    parameterLimit: 1000,
    type: 'application/x-www-form-urlencoded',
    verify: (req: express.Request, _res: express.Response, buf: Buffer) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (req as any).rawBody = buf;
    },
  });

  // ── Raw/text body parser for other allowed content types ───────────
  const textParser = express.text({
    limit: config.bodyLimits.defaultMaxBytes,
    type: 'text/plain',
    verify: (req: express.Request, _res: express.Response, buf: Buffer) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (req as any).rawBody = buf;
    },
  });

  // ── Error handler for body parsing errors ──────────────────────────
  const bodyParsingErrorHandler = (err: Error, req: Request, res: Response, next: NextFunction): void => {
    if (err) {
      const correlationId = (req.headers['x-correlation-id'] as string) || 'unknown';

      // Express body parser errors have a 'type' property
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const errType = (err as any).type as string | undefined;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const errStatus = (err as any).status as number | undefined;

      if (errType === 'entity.too.large' || errStatus === 413) {
        securityLog.warn({
          event: 'body_too_large',
          correlationId,
          ip: req.ip,
          path: req.path,
          method: req.method,
          error: err.message,
        });
        res.status(413).json({ error: 'Payload Too Large' });
        return;
      }

      if (errType === 'entity.parse.failed' || errStatus === 400) {
        securityLog.warn({
          event: 'body_parse_error',
          correlationId,
          ip: req.ip,
          path: req.path,
          method: req.method,
          error: err.message,
        });
        res.status(400).json({ error: 'Bad Request' });
        return;
      }

      securityLog.warn({
        event: 'body_error',
        correlationId,
        ip: req.ip,
        path: req.path,
        method: req.method,
        error: err.message,
      });
      res.status(400).json({ error: 'Bad Request' });
      return;
    }

    next();
  };

  // Return middleware array in correct order
  return [
    contentTypeValidator,
    dynamicSizeLimit,
    jsonParser,
    urlencodedParser,
    textParser,
    bodyParsingErrorHandler as unknown as RequestHandler,
  ];
}
