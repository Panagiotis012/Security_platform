import winston from 'winston';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { GatewayConfig } from '../../config/default';

/**
 * Structured request logger with PII redaction and security event separation.
 *
 * Every request is logged with: method, path, status, duration, correlationId, actor, policyDecisionId.
 * Sensitive fields (tokens, passwords, etc.) are redacted from all log output.
 * Security events (auth failures, blocks, anomalies) go to a separate log stream.
 */

// PII/Sensitive field patterns to redact from log values
const REDACT_PATTERNS = [
  /bearer\s+[a-zA-Z0-9\-._~+/]+=*/gi,
  /eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_.+/=]*/g,
  /password["']?\s*[:=]\s*["'][^"']+["']/gi,
  /secret["']?\s*[:=]\s*["'][^"']+["']/gi,
  /token["']?\s*[:=]\s*["'][^"']+["']/gi,
  /apikey["']?\s*[:=]\s*["'][^"']+["']/gi,
  /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,        // credit card
  /\b\d{3}-\d{2}-\d{4}\b/g,                                // SSN
];

let _accessLogger: winston.Logger | null = null;
let _securityLogger: winston.Logger | null = null;

/**
 * Create or return the singleton access logger.
 */
export function createAccessLogger(config: GatewayConfig): winston.Logger {
  if (_accessLogger) return _accessLogger;

  const transports: winston.transport[] = [
    new winston.transports.Console({
      level: config.logging.level,
    }),
  ];

  // File transport for production
  if (config.logging.accessLogPath && process.env['NODE_ENV'] === 'production') {
    transports.push(
      new winston.transports.File({
        filename: config.logging.accessLogPath,
        level: config.logging.level,
        maxsize: 100_000_000, // 100MB
        maxFiles: 10,
        tailable: true,
      })
    );
  }

  _accessLogger = winston.createLogger({
    level: config.logging.level,
    format: config.logging.format === 'json'
      ? winston.format.combine(
          winston.format.timestamp({ format: 'ISO' }),
          winston.format.json()
        )
      : winston.format.combine(
          winston.format.timestamp({ format: 'ISO' }),
          winston.format.simple()
        ),
    defaultMeta: { service: 'gateway', component: 'access' },
    transports,
  });

  return _accessLogger;
}

/**
 * Create or return the singleton security event logger.
 */
export function createSecurityLogger(config: GatewayConfig): winston.Logger {
  if (_securityLogger) return _securityLogger;

  const transports: winston.transport[] = [
    new winston.transports.Console({
      level: 'warn',
    }),
  ];

  if (config.logging.securityLogSeparate && config.logging.securityLogPath && process.env['NODE_ENV'] === 'production') {
    transports.push(
      new winston.transports.File({
        filename: config.logging.securityLogPath,
        level: 'warn',
        maxsize: 100_000_000,
        maxFiles: 20,
        tailable: true,
      })
    );
  }

  _securityLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
      winston.format.timestamp({ format: 'ISO' }),
      winston.format.json()
    ),
    defaultMeta: { service: 'gateway', component: 'security' },
    transports,
  });

  return _securityLogger;
}

/**
 * Redact sensitive values from a string.
 */
function redactSensitive(value: string): string {
  let redacted = value;
  for (const pattern of REDACT_PATTERNS) {
    redacted = redacted.replace(pattern, '[REDACTED]');
  }
  return redacted;
}

/**
 * Redact sensitive fields from an object, returning a safe copy.
 */
function redactObject(obj: Record<string, unknown>, redactFields: string[]): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase();
    if (redactFields.some(f => lowerKey.includes(f.toLowerCase()))) {
      result[key] = '[REDACTED]';
    } else if (typeof value === 'string') {
      result[key] = redactSensitive(value);
    } else if (Array.isArray(value)) {
      result[key] = value.map((v) => {
        if (typeof v === 'string') return redactSensitive(v);
        if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
          return redactObject(v as Record<string, unknown>, redactFields);
        }
        return v;
      });
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      result[key] = redactObject(value as Record<string, unknown>, redactFields);
    } else {
      result[key] = value;
    }
  }
  return result;
}

/**
 * Extract safe headers for logging (redacted).
 */
function safeHeaders(req: Request, redactFields: string[]): Record<string, unknown> {
  const headers: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(req.headers)) {
    const lowerKey = key.toLowerCase();
    if (redactFields.some(f => lowerKey.includes(f.toLowerCase()))) {
      headers[key] = '[REDACTED]';
    } else if (typeof value === 'string') {
      headers[key] = redactSensitive(value);
    } else if (Array.isArray(value)) {
      headers[key] = value.map((v) => (typeof v === 'string' ? redactSensitive(v) : v));
    } else {
      headers[key] = value;
    }
  }
  return headers;
}

/**
 * Request logging middleware.
 *
 * Logs every request with structured JSON, including timing, identity, and policy decision.
 * Sensitive data is redacted. Security events go to a separate logger.
 */
export function createRequestLoggerMiddleware(config: GatewayConfig): RequestHandler {
  const accessLog = createAccessLogger(config);
  const redactFields = config.logging.redactFields;

  return (req: Request, res: Response, next: NextFunction): void => {
    const startTime = process.hrtime.bigint();
    const correlationId = (req.headers['x-correlation-id'] as string) || 'unknown';

    // Capture the original end to log on response completion
    const originalEnd = res.end;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    res.end = function (this: Response, ...args: any[]): Response {
      const durationNs = process.hrtime.bigint() - startTime;
      const durationMs = Number(durationNs) / 1_000_000;

      // Extract identity from request context (set by jwt-validation middleware)
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const identity = (req as any).identity;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const policyDecisionId = (req as any).policyDecisionId;

      const logEntry = {
        event: 'http_request',
        correlationId,
        method: req.method,
        path: req.path,
        query: redactObject(req.query as Record<string, unknown>, redactFields),
        status: res.statusCode,
        durationMs: Math.round(durationMs * 100) / 100,
        ip: req.ip,
        userAgent: req.headers['user-agent'] || 'unknown',
        actor: identity ? {
          sub: identity.sub,
          roles: identity.roles,
        } : undefined,
        policyDecisionId: policyDecisionId || undefined,
        contentLength: res.getHeader('content-length') || 0,
        headers: safeHeaders(req, redactFields),
      };

      if (res.statusCode >= 500) {
        accessLog.error(logEntry);
      } else if (res.statusCode >= 400) {
        accessLog.warn(logEntry);
      } else {
        accessLog.info(logEntry);
      }

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return originalEnd.apply(this, args as any);
    };

    next();
  };
}

/**
 * Log a security event to the dedicated security logger.
 * Callable from any middleware.
 */
export function logSecurityEvent(
  config: GatewayConfig,
  level: 'info' | 'warn' | 'error',
  event: Record<string, unknown>
): void {
  const securityLog = createSecurityLogger(config);
  securityLog.log(level, {
    ...redactObject(event, config.logging.redactFields),
    timestamp: new Date().toISOString(),
  });
}
