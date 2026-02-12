/**
 * Production-grade Kubernetes health probes module for the Security Platform.
 *
 * Implements three probe types following Kubernetes best practices:
 * - Liveness probe (/healthz): Is the process alive and responsive?
 * - Readiness probe (/readyz): Can the service accept traffic?
 * - Startup probe (/startupz): Has the service completed initialization?
 *
 * Each probe integrates with optional Prometheus metrics and supports
 * dependency checks with individual health status per dependency.
 *
 * Usage:
 * ```typescript
 * import { HealthProbeManager } from '@zerotrust/shared/middleware/health-probes';
 *
 * const probeManager = new HealthProbeManager({
 *   serviceName: 'policy-engine',
 *   version: '1.0.0',
 * });
 *
 * probeManager.addDependencyCheck('redis', createRedisCheck(redisClient));
 * probeManager.addDependencyCheck('api', createHttpCheck('http://upstream.svc'));
 *
 * const app = express();
 * app.use(probeManager.createHealthRouter());
 * ```
 */

import type { Request, Response } from 'express';
import { Router } from 'express';
import { EventEmitter } from 'events';
import v8 from 'v8';

// ─────────────────────────────────────────────────────────────────────────────
// Type Definitions
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Result of a single dependency health check.
 */
export interface DependencyCheckResult {
  /** Unique identifier for this dependency. */
  name: string;
  /** Health status of the dependency. */
  status: 'up' | 'down' | 'degraded';
  /** Time in milliseconds to complete the health check. */
  latencyMs: number;
  /** Optional error message if the check failed. */
  error?: string;
}

/**
 * Function that performs a health check for a dependency.
 * Should resolve with a DependencyCheckResult.
 */
export type DependencyCheckFunction = () => Promise<DependencyCheckResult>;

/**
 * Response format for all health probe endpoints.
 */
export interface HealthProbeResponse {
  /** Overall status: 'ok' (all checks passed), 'degraded' (some checks failed), 'unhealthy' (critical failure). */
  status: 'ok' | 'degraded' | 'unhealthy';
  /** ISO-8601 timestamp when this check was performed. */
  timestamp: string;
  /** Process uptime in milliseconds. */
  uptime: number;
  /** Service name. */
  service: string;
  /** Service version. */
  version: string;
  /** Individual dependency check results. */
  checks: Record<string, DependencyCheckResult>;
}

/**
 * Configuration for the HealthProbeManager.
 */
export interface HealthProbeManagerOptions {
  /** Name of the service using these probes. */
  serviceName: string;
  /** Semantic version of the service. */
  version: string;
  /** Maximum time (ms) a readiness check can take before timing out. Default: 3000. */
  readinessTimeoutMs?: number;
  /** Event loop stall detection threshold in milliseconds. Default: 5000. */
  eventLoopStallThresholdMs?: number;
  /** Heap memory pressure threshold as percentage (0-100). Default: 90. */
  heapThresholdPercent?: number;
  /** Optional metrics registry for recording probe metrics. */
  metricsRegistry?: MetricsRegistry;
}

/**
 * Minimal metrics registry interface to allow optional integration.
 */
export interface MetricsRegistry {
  recordHistogram?(metricName: string, value: number, labels?: Record<string, string | number>): void;
  recordCounter?(metricName: string, value: number, labels?: Record<string, string | number>): void;
  recordGauge?(metricName: string, value: number, labels?: Record<string, string | number>): void;
}

// ─────────────────────────────────────────────────────────────────────────────
// Pre-built Dependency Check Factories
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Create a health check for Redis connectivity.
 * Sends a PING command and measures response time.
 *
 * @param redisClient - Redis client with a ping() method
 * @returns Dependency check function
 *
 * @example
 * ```typescript
 * const redisClient = redis.createClient();
 * probeManager.addDependencyCheck('redis', createRedisCheck(redisClient));
 * ```
 */
export function createRedisCheck(redisClient: { ping: () => Promise<string> }): DependencyCheckFunction {
  return async (): Promise<DependencyCheckResult> => {
    const startTime = Date.now();
    try {
      await redisClient.ping();
      const latencyMs = Date.now() - startTime;
      return {
        name: 'redis',
        status: 'up',
        latencyMs,
      };
    } catch (err) {
      const latencyMs = Date.now() - startTime;
      return {
        name: 'redis',
        status: 'down',
        latencyMs,
        error: err instanceof Error ? err.message : 'Unknown error',
      };
    }
  };
}

/**
 * Create a health check for an HTTP upstream service.
 * Sends a HEAD or GET request to the specified URL.
 *
 * @param url - The URL to check (e.g., 'http://policy-engine.svc:8080/healthz')
 * @param timeoutMs - Request timeout in milliseconds. Default: 5000.
 * @param method - HTTP method to use ('HEAD' or 'GET'). Default: 'HEAD'.
 * @returns Dependency check function
 *
 * @example
 * ```typescript
 * probeManager.addDependencyCheck('policy-engine', createHttpCheck('http://policy-engine.svc:8080/healthz'));
 * ```
 */
export function createHttpCheck(
  url: string,
  timeoutMs: number = 5000,
  method: 'HEAD' | 'GET' = 'HEAD',
): DependencyCheckFunction {
  return async (): Promise<DependencyCheckResult> => {
    const startTime = Date.now();
    const serviceName = new URL(url).hostname || url;

    try {
      const controller = new AbortController();
      const timeoutHandle = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const response = await fetch(url, {
          method,
          signal: controller.signal,
        });

        clearTimeout(timeoutHandle);
        const latencyMs = Date.now() - startTime;

        // Consider 2xx and 3xx status codes as healthy.
        const isHealthy = response.status >= 200 && response.status < 400;

        return {
          name: serviceName,
          status: isHealthy ? 'up' : 'degraded',
          latencyMs,
          error: isHealthy ? undefined : `HTTP ${response.status}`,
        };
      } catch (err) {
        clearTimeout(timeoutHandle);
        throw err;
      }
    } catch (err) {
      const latencyMs = Date.now() - startTime;

      if (err instanceof Error && err.name === 'AbortError') {
        return {
          name: serviceName,
          status: 'down',
          latencyMs,
          error: `Timeout after ${timeoutMs}ms`,
        };
      }

      return {
        name: serviceName,
        status: 'down',
        latencyMs,
        error: err instanceof Error ? err.message : 'Unknown error',
      };
    }
  };
}

/**
 * Create a custom health check with arbitrary async logic.
 * Useful for database connections, cache checks, or other custom validations.
 *
 * @param name - The name of this dependency
 * @param checkFn - Async function that returns true if healthy, false if unhealthy, or throws on error
 * @returns Dependency check function
 *
 * @example
 * ```typescript
 * probeManager.addDependencyCheck('database', createCustomCheck('postgres', async () => {
 *   const result = await db.query('SELECT 1');
 *   return result.rows.length > 0;
 * }));
 * ```
 */
export function createCustomCheck(
  name: string,
  checkFn: () => Promise<boolean>,
): DependencyCheckFunction {
  return async (): Promise<DependencyCheckResult> => {
    const startTime = Date.now();
    try {
      const isHealthy = await checkFn();
      const latencyMs = Date.now() - startTime;

      return {
        name,
        status: isHealthy ? 'up' : 'degraded',
        latencyMs,
      };
    } catch (err) {
      const latencyMs = Date.now() - startTime;
      return {
        name,
        status: 'down',
        latencyMs,
        error: err instanceof Error ? err.message : 'Unknown error',
      };
    }
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Main HealthProbeManager Class
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Manages all health probes for a service with support for liveness, readiness,
 * and startup checks. Integrates with Prometheus metrics and supports custom
 * dependency checks.
 *
 * Kubernetes will use these endpoints as follows:
 * - livenessProbe: /healthz (kill and restart if returns non-200)
 * - readinessProbe: /readyz (remove from load balancer if returns non-200)
 * - startupProbe: /startupz (keep trying until it succeeds)
 */
export class HealthProbeManager {
  private serviceName: string;
  private version: string;
  private startTime = Date.now();
  private isReady = false;
  private lastEventLoopCheck = Date.now();
  private eventLoopStallThresholdMs: number;
  private heapThresholdPercent: number;
  private readinessTimeoutMs: number;
  private metricsRegistry?: MetricsRegistry;
  private dependencyChecks = new Map<string, DependencyCheckFunction>();
  private eventEmitter = new EventEmitter();

  constructor(options: HealthProbeManagerOptions) {
    this.serviceName = options.serviceName;
    this.version = options.version;
    this.eventLoopStallThresholdMs = options.eventLoopStallThresholdMs ?? 5000;
    this.heapThresholdPercent = Math.min(100, Math.max(0, options.heapThresholdPercent ?? 90));
    this.readinessTimeoutMs = options.readinessTimeoutMs ?? 3000;
    this.metricsRegistry = options.metricsRegistry;

    // Start periodic event loop monitoring.
    this.startEventLoopMonitoring();
  }

  /**
   * Register a dependency health check with a given name.
   * The check will be executed by the readiness probe.
   *
   * @param name - Unique identifier for this dependency
   * @param checkFn - Async function that returns DependencyCheckResult
   */
  public addDependencyCheck(name: string, checkFn: DependencyCheckFunction): void {
    this.dependencyChecks.set(name, checkFn);
  }

  /**
   * Remove a previously registered dependency check.
   *
   * @param name - Name of the dependency to remove
   */
  public removeDependencyCheck(name: string): void {
    this.dependencyChecks.delete(name);
  }

  /**
   * Signal that the service has completed initialization and is ready to serve traffic.
   * This is called after all critical setup is done (e.g., database migrations, cache warming).
   */
  public markReady(): void {
    this.isReady = true;
    this.eventEmitter.emit('ready');
  }

  /**
   * Mark the service as no longer ready. Useful for graceful shutdown procedures.
   */
  public markNotReady(): void {
    this.isReady = false;
  }

  /**
   * Get the current readiness state.
   *
   * @returns true if markReady() has been called, false otherwise
   */
  public isServiceReady(): boolean {
    return this.isReady;
  }

  /**
   * Create an Express Router with all three probe endpoints.
   * The router should be mounted before authentication middleware so probes are always accessible.
   *
   * Endpoints:
   * - GET /healthz - Liveness probe (is the process alive?)
   * - GET /readyz - Readiness probe (can we accept traffic?)
   * - GET /startupz - Startup probe (have we finished initialization?)
   *
   * @returns Express Router instance
   */
  public createHealthRouter(): Router {
    const router = Router();

    router.get('/healthz', (req, res) => {
      this.handleLivenessProbe(req, res);
    });

    router.get('/readyz', (req, res) => {
      this.handleReadinessProbe(req, res);
    });

    router.get('/startupz', (req, res) => {
      this.handleStartupProbe(req, res);
    });

    return router;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Liveness Probe Handler
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Handle the liveness probe (/healthz).
   * Lightweight check to ensure the process is alive and not deadlocked.
   */
  private handleLivenessProbe(_req: Request, res: Response): void {
    const startTime = Date.now();

    // Check for event loop stalls (indicates deadlock or heavy processing).
    const eventLoopHealth = this.checkEventLoopHealth();

    // Check heap memory pressure.
    const memoryHealth = this.checkMemoryHealth();

    const isHealthy = eventLoopHealth.ok && memoryHealth.ok;
    const checks: Record<string, DependencyCheckResult> = {};

    if (!eventLoopHealth.ok) {
      checks['event_loop'] = {
        name: 'event_loop',
        status: 'degraded',
        latencyMs: eventLoopHealth.latencyMs,
        error: eventLoopHealth.error,
      };
    }

    if (!memoryHealth.ok) {
      checks['memory'] = {
        name: 'memory',
        status: 'degraded',
        latencyMs: memoryHealth.latencyMs,
        error: memoryHealth.error,
      };
    }

    const response: HealthProbeResponse = {
      status: isHealthy ? 'ok' : 'degraded',
      timestamp: new Date().toISOString(),
      uptime: Date.now() - this.startTime,
      service: this.serviceName,
      version: this.version,
      checks,
    };

    const statusCode = isHealthy ? 200 : 503;

    this.recordProbeMetric('liveness', statusCode, Date.now() - startTime);

    res.status(statusCode).json(response);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Readiness Probe Handler
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Handle the readiness probe (/readyz).
   * Checks if the service is ready to accept traffic by verifying all dependencies.
   */
  private async handleReadinessProbe(_req: Request, res: Response): Promise<void> {
    const startTime = Date.now();
    const checks: Record<string, DependencyCheckResult> = {};

    // Service must be marked as ready before checking dependencies.
    if (!this.isReady) {
      const response: HealthProbeResponse = {
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        uptime: Date.now() - this.startTime,
        service: this.serviceName,
        version: this.version,
        checks,
      };

      this.recordProbeMetric('readiness', 503, Date.now() - startTime);
      res.status(503).json(response);
      return;
    }

    // Execute all dependency checks in parallel with timeout protection.
    const checkPromises = Array.from(this.dependencyChecks.entries()).map(
      async ([name, checkFn]) => {
        try {
          const result = await Promise.race([
            checkFn(),
            this.createTimeoutPromise<DependencyCheckResult>(
              this.readinessTimeoutMs,
              name,
            ),
          ]);

          checks[name] = result;
        } catch (err) {
          // Catch any uncaught errors and record them.
          checks[name] = {
            name,
            status: 'down',
            latencyMs: Date.now() - startTime,
            error: err instanceof Error ? err.message : 'Unknown error',
          };
        }
      },
    );

    // Wait for all checks with a global timeout.
    await Promise.race([
      Promise.all(checkPromises),
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error(`Readiness check timeout after ${this.readinessTimeoutMs}ms`)),
          this.readinessTimeoutMs,
        ),
      ),
    ]).catch(() => {
      // If global timeout or other error, we still have partial results.
      // Mark this as degraded if we have some results, unhealthy if we have none.
    });

    // Determine overall status.
    const hasAllUp = Object.values(checks).every((c) => c.status === 'up');
    const hasAnyDown = Object.values(checks).some((c) => c.status === 'down');

    let status: 'ok' | 'degraded' | 'unhealthy' = 'ok';
    if (hasAnyDown) {
      status = 'unhealthy';
    } else if (!hasAllUp) {
      status = 'degraded';
    }

    const response: HealthProbeResponse = {
      status,
      timestamp: new Date().toISOString(),
      uptime: Date.now() - this.startTime,
      service: this.serviceName,
      version: this.version,
      checks,
    };

    const statusCode = status === 'ok' ? 200 : 503;

    this.recordProbeMetric('readiness', statusCode, Date.now() - startTime);

    res.status(statusCode).json(response);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Startup Probe Handler
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Handle the startup probe (/startupz).
   * Checks if the service has completed initialization (markReady() has been called).
   */
  private handleStartupProbe(_req: Request, res: Response): void {
    const startTime = Date.now();

    const isHealthy = this.isReady;

    const response: HealthProbeResponse = {
      status: isHealthy ? 'ok' : 'unhealthy',
      timestamp: new Date().toISOString(),
      uptime: Date.now() - this.startTime,
      service: this.serviceName,
      version: this.version,
      checks: {},
    };

    const statusCode = isHealthy ? 200 : 503;

    this.recordProbeMetric('startup', statusCode, Date.now() - startTime);

    res.status(statusCode).json(response);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Health Check Helpers
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Check if the event loop is responsive (not stalled/deadlocked).
   * Uses an async check to detect if the event loop can process new tasks.
   */
  private checkEventLoopHealth(): { ok: boolean; latencyMs: number; error?: string } {
    const startTime = Date.now();

    // Record the current time; if too much time passes before the next check,
    // we know the event loop is stalled.
    const now = Date.now();
    const timeSinceLastCheck = now - this.lastEventLoopCheck;

    this.lastEventLoopCheck = now;

    if (timeSinceLastCheck > this.eventLoopStallThresholdMs) {
      return {
        ok: false,
        latencyMs: Date.now() - startTime,
        error: `Event loop stall detected: ${timeSinceLastCheck}ms since last check (threshold: ${this.eventLoopStallThresholdMs}ms)`,
      };
    }

    return {
      ok: true,
      latencyMs: Date.now() - startTime,
    };
  }

  /**
   * Check if heap memory usage is within acceptable limits.
   */
  private checkMemoryHealth(): { ok: boolean; latencyMs: number; error?: string } {
    const startTime = Date.now();

    try {
      // Get memory usage from Node.js.
      const usage = process.memoryUsage();
      // NOTE: `heapTotal` is just the currently-allocated V8 heap and tends to
      // track `heapUsed` closely under normal operation, which makes
      // `heapUsed/heapTotal` look like "high pressure" even when the heap can
      // still grow. Use the V8 heap limit to reflect real headroom.
      const stats = v8.getHeapStatistics();
      const heapLimit = stats.heap_size_limit > 0 ? stats.heap_size_limit : usage.heapTotal;
      const heapUsedPercent = heapLimit > 0 ? (usage.heapUsed / heapLimit) * 100 : 0;

      const isHealthy = heapUsedPercent <= this.heapThresholdPercent;

      return {
        ok: isHealthy,
        latencyMs: Date.now() - startTime,
        error: isHealthy
          ? undefined
          : `Heap memory pressure at ${heapUsedPercent.toFixed(1)}% (threshold: ${this.heapThresholdPercent}%)`,
      };
    } catch (err) {
      return {
        ok: false,
        latencyMs: Date.now() - startTime,
        error: err instanceof Error ? err.message : 'Memory check failed',
      };
    }
  }

  /**
   * Create a timeout promise that rejects after a specified duration.
   */
  private createTimeoutPromise<T>(
    timeoutMs: number,
    name: string,
  ): Promise<T> {
    return new Promise((_, reject) => {
      setTimeout(() => {
        reject(
          new Error(`Dependency check '${name}' timed out after ${timeoutMs}ms`),
        );
      }, timeoutMs);
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Metrics Recording
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Record probe metrics to the metrics registry if available.
   */
  private recordProbeMetric(probeType: string, statusCode: number, durationMs: number): void {
    if (!this.metricsRegistry) return;

    // Record probe latency histogram.
    if (this.metricsRegistry.recordHistogram) {
      this.metricsRegistry.recordHistogram(
        'health_probe_duration_ms',
        durationMs,
        {
          probe: probeType,
          status: statusCode >= 200 && statusCode < 300 ? 'success' : 'failure',
        },
      );
    }

    // Record probe status counter.
    if (this.metricsRegistry.recordCounter) {
      this.metricsRegistry.recordCounter(
        'health_probe_requests_total',
        1,
        {
          probe: probeType,
          status_code: statusCode,
        },
      );
    }
  }

  /**
   * Start periodic event loop monitoring to detect stalls.
   * This runs in the background and doesn't block the event loop.
   */
  private startEventLoopMonitoring(): void {
    // Use setImmediate to check event loop responsiveness periodically.
    const monitor = () => {
      // Update the last check time so checkEventLoopHealth() can detect stalls.
      this.lastEventLoopCheck = Date.now();

      // Schedule the next check.
      setImmediate(monitor);
    };

    // Start the monitoring loop.
    setImmediate(monitor);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Exports
// ─────────────────────────────────────────────────────────────────────────────
