/**
 * Structured logging with correlation-ID propagation and PII redaction.
 *
 * Wraps winston to produce JSON-structured log lines.  Every log entry
 * includes at minimum: correlationId, timestamp, service, level.
 *
 * A custom "security" level is injected between "warn" and "error" so
 * security-relevant events can be filtered in log aggregation pipelines.
 *
 * PII redaction is applied automatically to every log payload before it
 * reaches the transport.
 */

import winston from 'winston';
import { v4 as uuidv4 } from 'uuid';
import type { PIIRedactorConfig } from './pii-redactor';
import { PIIRedactor } from './pii-redactor';

// ---------------------------------------------------------------------------
// Custom log levels (npm defaults + "security")
// ---------------------------------------------------------------------------

const CUSTOM_LEVELS: Record<string, number> = {
  error: 0,
  security: 1, // custom – security-specific events
  warn: 2,
  info: 3,
  http: 4,
  verbose: 5,
  debug: 6,
};

const CUSTOM_COLORS: Record<string, string> = {
  error: 'red',
  security: 'magenta bold',
  warn: 'yellow',
  info: 'green',
  http: 'cyan',
  verbose: 'blue',
  debug: 'gray',
};

winston.addColors(CUSTOM_COLORS);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StructuredLoggerConfig {
  /** Name of the service emitting logs. */
  service: string;
  /** Minimum level to emit. Defaults to "info". */
  level?: string;
  /** Static correlation ID to attach to every log (e.g. from request context). */
  correlationId?: string;
  /** PII redaction configuration. */
  piiConfig?: PIIRedactorConfig;
  /** Set to `true` to output pretty-printed logs (development). */
  pretty?: boolean;
  /** Additional static metadata merged into every log entry. */
  defaultMeta?: Record<string, unknown>;
  /** Extra winston transports (e.g. file, syslog). */
  transports?: winston.transport[];
}

export interface LogPayload {
  message: string;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// StructuredLogger
// ---------------------------------------------------------------------------

export class StructuredLogger {
  private readonly logger: winston.Logger;
  private readonly service: string;
  private correlationId: string | undefined;
  private readonly redactor: PIIRedactor;

  constructor(config: StructuredLoggerConfig) {
    this.service = config.service;
    this.correlationId = config.correlationId;
    this.redactor = new PIIRedactor(config.piiConfig);

    const formats = [
      winston.format.timestamp({ format: 'ISO' }),
      winston.format.errors({ stack: true }),
      // Inject service + correlationId into every entry.
      winston.format((info) => {
        info['service'] = this.service;
        if (this.correlationId) {
          info['correlationId'] = this.correlationId;
        }
        return info;
      })(),
      // PII redaction format – applied before serialization.
      winston.format((info) => {
        // Redact the "message" field itself if it contains PII.
        const redacted = this.redactor.redact(info);
        // Preserve internal Symbol-keyed properties winston relies on.
        for (const sym of Object.getOwnPropertySymbols(info)) {
          (redacted as Record<symbol, unknown>)[sym] = (
            info as Record<symbol, unknown>
          )[sym];
        }
        return redacted as winston.Logform.TransformableInfo;
      })(),
    ];

    if (config.pretty) {
      formats.push(
        winston.format.colorize(),
        winston.format.printf(
          ({ timestamp, level, message, service: _svc, correlationId: _cid, ...rest }) => {
            const meta =
              Object.keys(rest).length > 0
                ? ` ${JSON.stringify(rest)}`
                : '';
            return `${String(timestamp)} [${String(level)}] [${String(_svc)}] [${String(_cid ?? '-')}] ${String(message)}${meta}`;
          },
        ),
      );
    } else {
      formats.push(winston.format.json());
    }

    const transports: winston.transport[] = config.transports ?? [
      new winston.transports.Console(),
    ];

    this.logger = winston.createLogger({
      levels: CUSTOM_LEVELS,
      level: config.level ?? 'info',
      format: winston.format.combine(...formats),
      defaultMeta: config.defaultMeta,
      transports,
      // Never crash the process on a logging failure.
      exitOnError: false,
    });
  }

  // -----------------------------------------------------------------------
  // Correlation ID management
  // -----------------------------------------------------------------------

  /** Set or override the current correlation ID. */
  public setCorrelationId(id: string): void {
    this.correlationId = id;
  }

  /** Get the current correlation ID (creates one if absent). */
  public getCorrelationId(): string {
    if (!this.correlationId) {
      this.correlationId = uuidv4();
    }
    return this.correlationId;
  }

  /**
   * Return a child logger that inherits all config but uses a different
   * correlation ID.  Useful for spawning per-request loggers.
   */
  public child(overrides: {
    correlationId?: string;
    defaultMeta?: Record<string, unknown>;
  }): StructuredLogger {
    const child = Object.create(this) as StructuredLogger;
    // Copy mutable state so child and parent are independent.
    Object.defineProperty(child, 'correlationId', {
      value: overrides.correlationId ?? this.correlationId,
      writable: true,
      configurable: true,
    });
    if (overrides.defaultMeta) {
      Object.defineProperty(child, 'logger', {
        value: this.logger.child(overrides.defaultMeta),
        writable: false,
        configurable: true,
      });
    }
    return child;
  }

  // -----------------------------------------------------------------------
  // Logging methods
  // -----------------------------------------------------------------------

  public debug(message: string, meta?: Record<string, unknown>): void {
    this.logger.log('debug', message, meta);
  }

  public info(message: string, meta?: Record<string, unknown>): void {
    this.logger.log('info', message, meta);
  }

  public warn(message: string, meta?: Record<string, unknown>): void {
    this.logger.log('warn', message, meta);
  }

  public error(
    message: string,
    meta?: Record<string, unknown> & { error?: Error },
  ): void {
    const payload: Record<string, unknown> = { ...meta };
    if (meta?.error instanceof Error) {
      payload['errorName'] = meta.error.name;
      payload['errorMessage'] = meta.error.message;
      payload['stack'] = meta.error.stack;
      delete payload['error'];
    }
    this.logger.log('error', message, payload);
  }

  /**
   * Log a security-specific event.  These events should always be
   * forwarded to the SIEM / audit pipeline.
   */
  public security(
    message: string,
    meta?: Record<string, unknown>,
  ): void {
    this.logger.log('security', message, {
      ...meta,
      securityEvent: true,
    });
  }

  /**
   * Log an HTTP-level message (request/response logging).
   */
  public http(message: string, meta?: Record<string, unknown>): void {
    this.logger.log('http', message, meta);
  }

  // -----------------------------------------------------------------------
  // Utilities
  // -----------------------------------------------------------------------

  /**
   * Flush all transports.  Call during graceful shutdown.
   */
  public async flush(): Promise<void> {
    return new Promise<void>((resolve) => {
      this.logger.on('finish', resolve);
      this.logger.end();
    });
  }
}

// ---------------------------------------------------------------------------
// Factory / singleton
// ---------------------------------------------------------------------------

let defaultLogger: StructuredLogger | null = null;

/**
 * Initialise (or reinitialise) the default global logger.
 */
export function initLogger(
  config: StructuredLoggerConfig,
): StructuredLogger {
  defaultLogger = new StructuredLogger(config);
  return defaultLogger;
}

/**
 * Retrieve the global logger.  Throws if `initLogger` was not called.
 */
export function getLogger(): StructuredLogger {
  if (!defaultLogger) {
    // Provide a minimal fallback rather than crashing.
    defaultLogger = new StructuredLogger({
      service: 'uninitialized',
      level: 'debug',
    });
  }
  return defaultLogger;
}
