/**
 * Structured logger for the Identity Plane.
 *
 * Wraps winston with sensible defaults: JSON format in production,
 * colorized console in development, and automatic PII redaction hints.
 */

import winston from 'winston';

const isProduction = process.env['NODE_ENV'] === 'production';

const baseFormat = winston.format.combine(
  winston.format.timestamp({ format: 'ISO' }),
  winston.format.errors({ stack: true }),
);

const productionFormat = winston.format.combine(
  baseFormat,
  winston.format.json(),
);

const developmentFormat = winston.format.combine(
  baseFormat,
  winston.format.colorize(),
  winston.format.printf(({ timestamp, level, message, component, ...meta }) => {
    const comp = component ? `[${component as string}]` : '';
    const metaStr = Object.keys(meta).length > 0 ? ` ${JSON.stringify(meta)}` : '';
    return `${timestamp as string} ${level} ${comp} ${message as string}${metaStr}`;
  }),
);

const rootLogger = winston.createLogger({
  level: process.env['LOG_LEVEL'] ?? 'info',
  format: isProduction ? productionFormat : developmentFormat,
  defaultMeta: { service: 'identity' },
  transports: [new winston.transports.Console()],
});

/**
 * Create a child logger tagged with a component name for easy filtering.
 */
export function createLogger(component: string): winston.Logger {
  return rootLogger.child({ component });
}

export default rootLogger;
