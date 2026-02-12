/**
 * Auth middleware for the Identity Plane's own API endpoints.
 *
 * Provides:
 *  - Session extraction from cookies.
 *  - Access token extraction from Authorization header.
 *  - CSRF protection for state-changing (non-GET/HEAD/OPTIONS) requests.
 *  - Request body validation via Zod schemas.
 *  - Request-ID propagation for tracing.
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { v4 as uuidv4 } from 'uuid';
import type { ZodSchema } from 'zod';
import { config } from '../../config/default';
import { SessionManager } from '../sessions/session-manager';
import type { TokenService, AccessTokenClaims} from '../tokens/token-service';
import { TokenError } from '../tokens/token-service';
import type { SessionData } from '../sessions/session-store';
import { createLogger } from '../logger';

const logger = createLogger('middleware');

// ---------------------------------------------------------------------------
// Augment Express Request with identity context
// ---------------------------------------------------------------------------

declare module 'express-serve-static-core' {
  interface Request {
    /** The authenticated session, if present. */
    session?: SessionData;
    /** The validated access token claims, if an Authorization header was provided. */
    tokenClaims?: AccessTokenClaims;
    /** Request correlation ID. */
    requestId?: string;
  }
}

// ---------------------------------------------------------------------------
// Request ID middleware
// ---------------------------------------------------------------------------

/**
 * Assign a unique request ID to every request.  If the upstream (e.g. API
 * gateway) already set X-Request-ID, reuse it.
 */
export function requestIdMiddleware(): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction): void => {
    req.requestId = (req.headers['x-request-id'] as string) ?? uuidv4();
    next();
  };
}

// ---------------------------------------------------------------------------
// Session extraction middleware
// ---------------------------------------------------------------------------

/**
 * Extract and validate the session from the session cookie.
 *
 * Populates `req.session` if a valid session is found.
 * Does NOT reject the request if no session is present -- downstream
 * handlers decide whether a session is required.
 */
export function sessionExtraction(sessionManager: SessionManager): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const sessionId = req.cookies?.[config.sessions.cookieName] as string | undefined;
      if (!sessionId) {
        next();
        return;
      }

      const result = await sessionManager.validateSession(sessionId);
      if (result.valid) {
        req.session = result.session;
        // Touch activity on every request.
        await sessionManager.updateActivity(sessionId);
      } else {
        logger.debug('Session invalid', {
          sessionId,
          reason: result.reason,
          requestId: req.requestId,
        });
      }

      next();
    } catch (err) {
      logger.error('Session extraction error', {
        error: (err as Error).message,
        requestId: req.requestId,
      });
      next();
    }
  };
}

// ---------------------------------------------------------------------------
// Token extraction middleware
// ---------------------------------------------------------------------------

/**
 * Extract and validate a Bearer token from the Authorization header.
 *
 * Populates `req.tokenClaims` if a valid token is found.
 * Does NOT reject the request if no token is present.
 */
export function tokenExtraction(tokenService: TokenService): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const authHeader = req.headers['authorization'];
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        next();
        return;
      }

      const token = authHeader.slice(7);
      if (!token) {
        next();
        return;
      }

      const claims = await tokenService.validateAccessToken(token);
      req.tokenClaims = claims;

      next();
    } catch (err) {
      if (err instanceof TokenError) {
        logger.debug('Token validation failed', {
          code: err.code,
          message: err.message,
          requestId: req.requestId,
        });
      } else {
        logger.error('Token extraction error', {
          error: (err as Error).message,
          requestId: req.requestId,
        });
      }
      // Do not populate tokenClaims; let downstream decide how to handle.
      next();
    }
  };
}

// ---------------------------------------------------------------------------
// Authentication gate (requires either valid session or valid token)
// ---------------------------------------------------------------------------

/**
 * Reject requests that have neither a valid session nor a valid token.
 */
export function requireAuth(): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (req.session || req.tokenClaims) {
      next();
      return;
    }

    res.status(401).json({
      error: {
        code: 'AUTH_1001',
        message: 'Authentication required',
      },
    });
  };
}

// ---------------------------------------------------------------------------
// CSRF protection
// ---------------------------------------------------------------------------

/**
 * CSRF protection using the double-submit cookie pattern.
 *
 * For state-changing methods (POST, PUT, DELETE, PATCH), the client must
 * include the CSRF token in a custom header that matches the value in the
 * CSRF cookie.
 *
 * Safe methods (GET, HEAD, OPTIONS) are exempt.
 */
export function csrfProtection(): RequestHandler {
  const safeMethods = new Set(['GET', 'HEAD', 'OPTIONS']);

  return (req: Request, res: Response, next: NextFunction): void => {
    // Skip CSRF for safe methods.
    if (safeMethods.has(req.method)) {
      next();
      return;
    }

    // Skip CSRF for API clients using Bearer tokens (they already prove
    // possession of a credential that CSRF attacks cannot obtain).
    if (req.headers['authorization']?.startsWith('Bearer ')) {
      next();
      return;
    }

    const sessionId = req.cookies?.[config.sessions.cookieName] as string | undefined;
    if (!sessionId) {
      // No session cookie -- CSRF does not apply.
      next();
      return;
    }

    const csrfHeader = req.headers[config.csrf.headerName] as string | undefined;
    if (!csrfHeader) {
      logger.warn('CSRF token missing', {
        requestId: req.requestId,
        path: req.path,
        method: req.method,
      });
      res.status(403).json({
        error: {
          code: 'CSRF_MISSING',
          message: 'CSRF token required for state-changing requests',
        },
      });
      return;
    }

    // Verify the CSRF token against the session.
    try {
      const valid = SessionManager.verifyCsrfToken(sessionId, csrfHeader);
      if (!valid) {
        logger.warn('CSRF token invalid', {
          requestId: req.requestId,
          path: req.path,
        });
        res.status(403).json({
          error: {
            code: 'CSRF_INVALID',
            message: 'CSRF token validation failed',
          },
        });
        return;
      }
    } catch (_err) {
      logger.warn('CSRF token validation error', {
        requestId: req.requestId,
        path: req.path,
      });
      res.status(403).json({
        error: {
          code: 'CSRF_INVALID',
          message: 'CSRF token validation failed',
        },
      });
      return;
    }

    next();
  };
}

// ---------------------------------------------------------------------------
// Request validation
// ---------------------------------------------------------------------------

/**
 * Validate the request body against a Zod schema.
 * Returns 400 with detailed field errors on validation failure.
 */
export function validateBody<T>(schema: ZodSchema<T>): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.body);

    if (!result.success) {
      const fieldErrors = result.error.issues.map((issue) => ({
        field: issue.path.join('.'),
        message: issue.message,
        code: issue.code,
      }));

      logger.debug('Request body validation failed', {
        requestId: req.requestId,
        path: req.path,
        errors: fieldErrors,
      });

      res.status(400).json({
        error: {
          code: 'VAL_4001',
          message: 'Request validation failed',
          fields: fieldErrors,
        },
      });
      return;
    }

    // Replace req.body with the parsed (and coerced) value.
    req.body = result.data;
    next();
  };
}

/**
 * Validate query parameters against a Zod schema.
 */
export function validateQuery<T>(schema: ZodSchema<T>): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.query);

    if (!result.success) {
      const fieldErrors = result.error.issues.map((issue) => ({
        field: issue.path.join('.'),
        message: issue.message,
        code: issue.code,
      }));

      res.status(400).json({
        error: {
          code: 'VAL_4001',
          message: 'Query parameter validation failed',
          fields: fieldErrors,
        },
      });
      return;
    }

    next();
  };
}

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

/**
 * Set security-related response headers on all responses.
 */
export function securityHeaders(): RequestHandler {
  return (_req: Request, res: Response, next: NextFunction): void => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '0'); // Modern browsers: use CSP instead
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    next();
  };
}

// ---------------------------------------------------------------------------
// CORS middleware
// ---------------------------------------------------------------------------

/**
 * CORS middleware configured from the identity config.
 */
export function corsMiddleware(): RequestHandler {
  const { allowedOrigins, allowedMethods, allowedHeaders, credentials, maxAgeSeconds } =
    config.cors;

  return (req: Request, res: Response, next: NextFunction): void => {
    const origin = req.headers['origin'];

    if (origin && allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }

    if (credentials) {
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }

    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Methods', allowedMethods.join(', '));
      res.setHeader('Access-Control-Allow-Headers', allowedHeaders.join(', '));
      res.setHeader('Access-Control-Max-Age', String(maxAgeSeconds));
      res.status(204).end();
      return;
    }

    next();
  };
}
