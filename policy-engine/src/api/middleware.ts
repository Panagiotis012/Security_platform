import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import type { ZodError, ZodSchema } from 'zod';
import config from '../../config/default';
import { createLogger } from '../utils/logger';

const logger = createLogger('middleware');

// ─── Extend Express Request with custom properties ──────────────────────────
declare module 'express-serve-static-core' {
  interface Request {
    correlationId: string;
    adminUser?: {
      sub: string;
      roles: string[];
    };
  }
}

// ─── Correlation ID middleware ──────────────────────────────────────────────

/**
 * Attach a correlation ID to every request.
 * Uses the X-Correlation-ID header if provided, otherwise generates one.
 */
export function correlationId(req: Request, _res: Response, next: NextFunction): void {
  req.correlationId =
    (req.headers['x-correlation-id'] as string) ||
    (req.headers['x-request-id'] as string) ||
    uuidv4();
  next();
}

// ─── Request logging middleware ─────────────────────────────────────────────

/**
 * Log every incoming request with correlation ID and timing.
 */
export function requestLogger(req: Request, res: Response, next: NextFunction): void {
  const startTime = Date.now();

  // Log when response finishes
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    logger.info('Request completed', {
      correlationId: req.correlationId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      durationMs: duration,
      ip: req.ip || req.socket.remoteAddress,
    });
  });

  next();
}

// ─── Admin authentication middleware ────────────────────────────────────────

/**
 * Authenticate admin users via JWT for policy management endpoints.
 * Verifies the token and checks for the required admin role.
 */
export function adminAuth(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    res.status(401).json({
      error: 'Authentication required',
      message: 'Missing Authorization header',
      correlationId: req.correlationId,
    });
    return;
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    res.status(401).json({
      error: 'Authentication required',
      message: 'Invalid Authorization header format. Expected: Bearer <token>',
      correlationId: req.correlationId,
    });
    return;
  }

  const token = parts[1];

  try {
    const decoded = jwt.verify(token, config.admin.jwtSecret, {
      issuer: config.admin.tokenIssuer,
    }) as jwt.JwtPayload;

    const roles: string[] = Array.isArray(decoded.roles) ? decoded.roles : [];
    const sub = typeof decoded.sub === 'string' ? decoded.sub : '';

    // Check for required admin role
    const hasAdminRole = roles.some(
      (role) =>
        role === config.admin.requiredRole ||
        role === 'admin' ||
        role === 'super-admin'
    );

    if (!hasAdminRole) {
      logger.warn('Admin authorization failed - insufficient role', {
        correlationId: req.correlationId,
        sub,
        roles,
        requiredRole: config.admin.requiredRole,
      });

      res.status(403).json({
        error: 'Forbidden',
        message: 'Insufficient privileges for policy management',
        correlationId: req.correlationId,
      });
      return;
    }

    req.adminUser = { sub, roles };

    logger.debug('Admin authenticated', {
      correlationId: req.correlationId,
      sub,
      roles,
    });

    next();
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      res.status(401).json({
        error: 'Token expired',
        message: 'Authentication token has expired',
        correlationId: req.correlationId,
      });
      return;
    }

    if (err instanceof jwt.JsonWebTokenError) {
      res.status(401).json({
        error: 'Invalid token',
        message: 'Authentication token is invalid',
        correlationId: req.correlationId,
      });
      return;
    }

    logger.error('Authentication error', {
      correlationId: req.correlationId,
      error: err instanceof Error ? err.message : 'Unknown error',
    });

    res.status(401).json({
      error: 'Authentication failed',
      message: 'Unable to verify authentication token',
      correlationId: req.correlationId,
    });
  }
}

// ─── Request validation middleware ──────────────────────────────────────────

/**
 * Create a middleware that validates the request body against a Zod schema.
 * Returns 400 with validation errors if the body doesn't match.
 */
export function validateBody(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.body);

    if (!result.success) {
      const errors = formatZodErrors(result.error);

      logger.debug('Request validation failed', {
        correlationId: req.correlationId,
        path: req.path,
        errors,
      });

      res.status(400).json({
        error: 'Validation failed',
        message: 'Request body validation failed',
        details: errors,
        correlationId: req.correlationId,
      });
      return;
    }

    // Replace body with parsed (and sanitized) data
    req.body = result.data;
    next();
  };
}

/**
 * Create a middleware that validates query parameters against a Zod schema.
 */
export function validateQuery(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.query);

    if (!result.success) {
      const errors = formatZodErrors(result.error);

      res.status(400).json({
        error: 'Validation failed',
        message: 'Query parameter validation failed',
        details: errors,
        correlationId: req.correlationId,
      });
      return;
    }

    req.query = result.data;
    next();
  };
}

// ─── Error handling middleware ───────────────────────────────────────────────

/**
 * Global error handler. Never leaks internal details to the client.
 * All unhandled errors result in a generic 500 response.
 */
export function errorHandler(
  err: Error,
  req: Request,
  res: Response,
  _next: NextFunction
): void {
  void _next; // preserve 4-arg signature for Express error middleware
  // Log the full error internally
  logger.error('Unhandled error', {
    correlationId: req.correlationId,
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
  });

  // Never leak internal error details
  res.status(500).json({
    error: 'Internal server error',
    message: 'An unexpected error occurred. Please try again later.',
    correlationId: req.correlationId,
  });
}

/**
 * 404 handler for unmatched routes.
 */
export function notFoundHandler(req: Request, res: Response): void {
  res.status(404).json({
    error: 'Not found',
    message: `Route ${req.method} ${req.path} not found`,
    correlationId: req.correlationId,
  });
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Format Zod validation errors into a clean, client-safe format.
 */
function formatZodErrors(error: ZodError): Array<{ path: string; message: string }> {
  return error.issues.map((issue) => ({
    path: issue.path.join('.'),
    message: issue.message,
  }));
}
