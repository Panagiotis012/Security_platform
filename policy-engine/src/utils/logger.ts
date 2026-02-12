import winston from 'winston';
import config from '../../config/default';

const logFormat =
  config.logging.format === 'json'
    ? winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      )
    : winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.colorize(),
        winston.format.printf(({ timestamp, level, message, service, ...meta }) => {
          const metaStr = Object.keys(meta).length > 0 ? ` ${JSON.stringify(meta)}` : '';
          return `${timestamp} [${service}] ${level}: ${message}${metaStr}`;
        })
      );

/**
 * Create a named logger instance.
 */
export function createLogger(service: string): winston.Logger {
  return winston.createLogger({
    level: config.logging.level,
    format: logFormat,
    defaultMeta: { service },
    transports: [new winston.transports.Console()],
  });
}

/**
 * Root logger for the application.
 */
export const rootLogger = createLogger('policy-engine');
