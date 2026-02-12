import type { Request, Response, NextFunction } from 'express';
import { globalMetrics } from './prometheus';

// ─── Type Definitions ───────────────────────────────────────────────────────

/**
 * Configuration options for the request metrics middleware.
 */
interface RequestMetricsOptions {
  /**
   * The name of the service reporting metrics.
   * Used as a label on all metrics.
   * Default: 'unknown'
   */
  serviceName?: string;

  /**
   * Whether to skip recording metrics for certain paths.
   * Can be a function that returns true to skip, or an array of path prefixes.
   * Useful to exclude /metrics, /health, etc. from metrics collection.
   * Default: undefined
   */
  skipPaths?: ((path: string) => boolean) | string[];

  /**
   * Whether to normalize paths by removing variable parts (IDs, etc).
   * If true, paths like /api/users/123 will be recorded as /api/users/{id}
   * Default: true
   */
  normalizePath?: boolean;

  /**
   * Custom path normalizer function.
   * Called when normalizePath is true to allow custom normalization logic.
   * Default: undefined
   */
  pathNormalizer?: (path: string) => string;

  /**
   * Maximum number of unique label combinations per metric to track.
   * Prevents unbounded cardinality from high-variance labels.
   * When exceeded, a metric called 'too_many_labels' is incremented.
   * Default: 1000
   */
  maxLabelCardinality?: number;
}

// ─── Module-Level State ─────────────────────────────────────────────────────

/**
 * Track the number of active connections.
 */
let activeConnections = 0;

/**
 * Track unique label combinations to prevent cardinality explosion.
 */
const labelCombinations = new Set<string>();

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Normalize a path by replacing numeric IDs with placeholders.
 * For example: /api/users/123/posts/456 becomes /api/users/{id}/posts/{id}
 *
 * @param path - The request path
 * @returns Normalized path
 */
function defaultPathNormalizer(path: string): string {
  return path.replace(/\/\d+/g, '/{id}');
}

/**
 * Check if a path should be skipped from metrics collection.
 *
 * @param path - The request path
 * @param skipPaths - Skip configuration
 * @returns True if the path should be skipped
 */
function shouldSkipPath(
  path: string,
  skipPaths?: ((path: string) => boolean) | string[]
): boolean {
  if (!skipPaths) {
    return false;
  }

  if (typeof skipPaths === 'function') {
    return skipPaths(path);
  }

  return skipPaths.some((prefix) => path.startsWith(prefix));
}

/**
 * Track label cardinality and return true if limit exceeded.
 *
 * @param labels - The labels being recorded
 * @param maxCardinality - Maximum allowed unique combinations
 * @returns True if cardinality limit exceeded
 */
function checkLabelCardinality(
  labels: Record<string, string>,
  maxCardinality: number
): boolean {
  const key = Object.entries(labels)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join(',');

  labelCombinations.add(key);

  if (labelCombinations.size > maxCardinality) {
    return true;
  }

  return false;
}

/**
 * Get the HTTP method from a request, normalized.
 * Returns uppercase method name.
 *
 * @param method - The HTTP method
 * @returns Normalized method
 */
function normalizeMethod(method: string): string {
  return method.toUpperCase();
}

// ─── Request Size Tracking ──────────────────────────────────────────────────

/**
 * Extend the Express request to track request size.
 * Monitors the 'data' event on request stream to accumulate bytes.
 *
 * @param req - Express request object
 * @returns Callback to call when request is complete
 */
function trackRequestSize(req: Request): () => number {
  let requestSize = 0;

  // Calculate headers size
  const headersSize = JSON.stringify(req.headers).length;
  requestSize += headersSize;

  // Monitor request body if present by tracking the 'data' event
  req.on('data', (chunk: Buffer) => {
    if (Buffer.isBuffer(chunk)) {
      requestSize += chunk.length;
    } else if (typeof chunk === 'string') {
      requestSize += Buffer.byteLength(chunk);
    }
  });

  return () => requestSize;
}

/**
 * Extend the Express response to track response size.
 * Monitors sent data to accumulate bytes.
 *
 * @param res - Express response object
 * @returns Callback to call when response is complete
 */
function trackResponseSize(res: Response): () => number {
  let responseSize = 0;

  // Track Content-Length header
  const originalSend = res.send.bind(res);
  res.send = ((data?: unknown) => {
    if (data) {
      if (typeof data === 'string') {
        responseSize += Buffer.byteLength(data);
      } else if (Buffer.isBuffer(data)) {
        responseSize += data.length;
      } else if (typeof data === 'object') {
        responseSize += Buffer.byteLength(JSON.stringify(data));
      }
    }

    // Include headers size
    responseSize += JSON.stringify(res.getHeaders()).length;

    return originalSend(data as never);
  }) as typeof res.send;

  return () => responseSize;
}

// ─── Main Middleware ────────────────────────────────────────────────────────

/**
 * Create an Express middleware that automatically captures HTTP metrics.
 *
 * This middleware wraps around Express requests to capture:
 * - HTTP request counts (http_requests_total)
 * - Request/response duration (http_request_duration_seconds)
 * - Request and response sizes (http_request_size_bytes, http_response_size_bytes)
 * - Active connection count (active_connections)
 *
 * Should be inserted early in the middleware chain (before route handlers).
 *
 * Usage:
 * ```typescript
 * import express from 'express';
 * import { createRequestMetricsMiddleware } from './request-metrics';
 *
 * const app = express();
 * app.use(createRequestMetricsMiddleware({ serviceName: 'api-gateway' }));
 * // ... other middleware and routes
 * ```
 *
 * @param options - Configuration options
 * @returns Express middleware function
 */
export function createRequestMetricsMiddleware(
  options: RequestMetricsOptions = {}
) {
  const {
    serviceName = 'unknown',
    skipPaths = undefined,
    normalizePath = true,
    pathNormalizer = defaultPathNormalizer,
    maxLabelCardinality = 1000,
  } = options;

  return (req: Request, res: Response, next: NextFunction): void => {
    // Skip metrics for excluded paths
    if (shouldSkipPath(req.path, skipPaths)) {
      return next();
    }

    // Track active connections
    activeConnections++;
    globalMetrics.recordGauge('active_connections', activeConnections, {
      service: serviceName,
    });

    // Record start time
    const startTimeHighRes = process.hrtime();

    // Track request size
    const getRequestSize = trackRequestSize(req);

    // Track response size
    const getResponseSize = trackResponseSize(res);

    // Normalize path
    let path = req.path;
    if (normalizePath && pathNormalizer) {
      path = pathNormalizer(path);
    }

    // Normalize method
    const method = normalizeMethod(req.method);

    // Setup response finish handler
    res.on('finish', () => {
      try {
        // Calculate duration in seconds
        const [seconds, nanoseconds] = process.hrtime(startTimeHighRes);
        const durationSeconds = seconds + nanoseconds / 1_000_000_000;

        // Get final values
        const statusCode = res.statusCode;
        const requestSize = getRequestSize();
        const responseSize = getResponseSize();

        // Prepare labels
        const baseLabels = {
          method,
          path,
          status_code: String(statusCode),
          service: serviceName,
        };

        const sizeLabels = {
          method,
          service: serviceName,
        };

        // Check cardinality before recording
        const cardinalityExceeded = checkLabelCardinality(
          baseLabels,
          maxLabelCardinality
        );

        if (!cardinalityExceeded) {
          // Record HTTP request counter
          globalMetrics.recordCounter('http_requests_total', 1, baseLabels);

          // Record request duration histogram
          globalMetrics.recordHistogram('http_request_duration_seconds', durationSeconds, {
            method,
            path,
            service: serviceName,
          });

          // Record request size histogram
          globalMetrics.recordHistogram('http_request_size_bytes', requestSize, sizeLabels);

          // Record response size histogram
          globalMetrics.recordHistogram('http_response_size_bytes', responseSize, sizeLabels);
        }

        // Decrement active connections
        activeConnections = Math.max(0, activeConnections - 1);
        globalMetrics.recordGauge('active_connections', activeConnections, {
          service: serviceName,
        });
      } catch (err) {
        // Silently ignore errors in metrics collection to avoid breaking request handling
        // In a real app, you might log this to a separate logger
        console.error('Error recording metrics:', err);
      }
    });

    next();
  };
}

/**
 * Create an Express middleware for request metrics with default options.
 * This is a convenience wrapper that uses sensible defaults.
 *
 * Usage:
 * ```typescript
 * const app = express();
 * app.use(requestMetricsMiddleware());
 * ```
 *
 * @param serviceName - The name of the service (optional)
 * @returns Express middleware function
 */
export function requestMetricsMiddleware(serviceName: string = 'unknown') {
  return createRequestMetricsMiddleware({
    serviceName,
    skipPaths: ['/metrics', '/health', '/readiness', '/liveness'],
    normalizePath: true,
  });
}

// ─── Specialized Metric Recording Functions ─────────────────────────────────

/**
 * Record a rate limit hit.
 *
 * @param tier - The rate limit tier (e.g., 'free', 'premium', 'enterprise')
 * @param serviceName - The service recording the hit
 */
export function recordRateLimitHit(tier: string, serviceName: string): void {
  try {
    globalMetrics.recordCounter('rate_limit_hits_total', 1, {
      tier,
      service: serviceName,
    });
  } catch {
    // Metrics must never affect request handling.
  }
}

/**
 * Record an authentication attempt.
 *
 * @param result - The result of the authentication attempt ('success', 'failure', 'error')
 * @param method - The authentication method used (e.g., 'basic', 'bearer', 'oauth')
 * @param serviceName - The service recording the attempt
 */
export function recordAuthAttempt(
  result: 'success' | 'failure' | 'error',
  method: string,
  serviceName: string
): void {
  try {
    globalMetrics.recordCounter('auth_attempts_total', 1, {
      result,
      method,
      service: serviceName,
    });
  } catch {
    // Metrics must never affect request handling.
  }
}

/**
 * Record a policy decision.
 *
 * @param decision - The decision made ('allow', 'deny', 'challenge')
 * @param serviceName - The service recording the decision
 */
export function recordPolicyDecision(decision: string, serviceName: string): void {
  try {
    globalMetrics.recordCounter('policy_decisions_total', 1, {
      decision,
      service: serviceName,
    });
  } catch {
    // Metrics must never affect request handling.
  }
}

/**
 * Record a detection alert.
 *
 * @param detectionId - The ID of the detection rule that triggered
 * @param severity - Alert severity ('low', 'medium', 'high', 'critical')
 * @param serviceName - The service recording the alert
 */
export function recordDetectionAlert(
  detectionId: string,
  severity: 'low' | 'medium' | 'high' | 'critical',
  serviceName: string
): void {
  try {
    globalMetrics.recordCounter('detection_alerts_total', 1, {
      detection_id: detectionId,
      severity,
      service: serviceName,
    });
  } catch {
    // Metrics must never affect request handling.
  }
}

/**
 * Update the circuit breaker state.
 *
 * @param upstream - The upstream service name
 * @param state - The circuit breaker state (0=closed, 1=open, 2=half_open)
 * @param serviceName - The service recording the state
 */
export function setCircuitBreakerState(
  upstream: string,
  state: 0 | 1 | 2,
  serviceName: string
): void {
  try {
    globalMetrics.recordGauge('circuit_breaker_state', state, {
      upstream,
      service: serviceName,
    });
  } catch {
    // Metrics must never affect request handling.
  }
}

/**
 * Record an audit event ingestion.
 *
 * @param count - Number of events ingested (default: 1)
 * @param serviceName - The service recording the events
 */
export function recordAuditEventsIngested(count: number = 1, serviceName: string = 'unknown'): void {
  try {
    globalMetrics.recordCounter('audit_events_ingested_total', count, {
      service: serviceName,
    });
  } catch {
    // Metrics must never affect request handling.
  }
}

/**
 * Update the active session count.
 *
 * @param count - The current number of active sessions
 * @param serviceName - The service recording the count
 */
export function setActiveSessionCount(count: number, serviceName: string): void {
  try {
    globalMetrics.recordGauge('session_active', count, {
      service: serviceName,
    });
  } catch {
    // Metrics must never affect request handling.
  }
}

/**
 * Update the Redis connection status.
 *
 * @param serviceName - The service recording the status
 * @param connected - Whether Redis is connected (true=1, false=0)
 */
export function setRedisConnectionStatus(serviceName: string, connected: boolean): void {
  try {
    globalMetrics.recordGauge('redis_connection_status', connected ? 1 : 0, {
      service: serviceName,
    });
  } catch {
    // Metrics must never affect request handling.
  }
}

// ─── Connection Tracking ────────────────────────────────────────────────────

/**
 * Get the current number of active connections.
 * Useful for monitoring or health checks.
 *
 * @returns Current active connection count
 */
export function getActiveConnectionCount(): number {
  return activeConnections;
}

/**
 * Reset the active connection counter.
 * Useful for testing or resetting metrics.
 */
export function resetActiveConnectionCount(): void {
  activeConnections = 0;
}

/**
 * Get the number of unique label combinations being tracked.
 * Useful for monitoring label cardinality.
 *
 * @returns Number of unique label combinations
 */
export function getLabelCombinationCount(): number {
  return labelCombinations.size;
}

/**
 * Clear the label combination tracking.
 * Useful for testing or resetting metrics.
 */
export function clearLabelCombinations(): void {
  labelCombinations.clear();
}
