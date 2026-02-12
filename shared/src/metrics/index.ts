/**
 * Prometheus Metrics Module
 *
 * This module provides a comprehensive metrics collection system for the Security Platform.
 * It implements Prometheus exposition format without external dependencies.
 *
 * Core Components:
 * - MetricsRegistry: Main class for registering and recording metrics
 * - globalMetrics: Singleton instance for application-wide metrics
 * - Request Metrics Middleware: Automatic HTTP metrics collection
 * - Specialized Metric Recorders: Domain-specific metrics helpers
 *
 * Supported Metric Types:
 * - Counter: Monotonically increasing values
 * - Gauge: Values that can increase and decrease
 * - Histogram: Distribution of values with configurable buckets
 * - Summary: Distribution with percentiles
 *
 * Usage Example:
 * ```typescript
 * import express from 'express';
 * import {
 *   initializeDefaultMetrics,
 *   createRequestMetricsMiddleware,
 *   createExpressMiddleware,
 *   recordAuthAttempt,
 *   recordPolicyDecision,
 * } from '@shared/metrics';
 *
 * const app = express();
 *
 * // Initialize metrics
 * initializeDefaultMetrics();
 *
 * // Add metrics middleware
 * app.use(createRequestMetricsMiddleware({ serviceName: 'api-gateway' }));
 *
 * // Expose metrics endpoint
 * app.get('/metrics', createExpressMiddleware());
 *
 * // Record domain-specific metrics
 * app.post('/login', (req, res) => {
 *   try {
 *     // ... authentication logic ...
 *     recordAuthAttempt('success', 'bearer', 'api-gateway');
 *   } catch (err) {
 *     recordAuthAttempt('failure', 'bearer', 'api-gateway');
 *   }
 * });
 *
 * app.listen(3000);
 * ```
 */

// ─── Core Exports from prometheus.ts ─────────────────────────────────────────

export {
  MetricsRegistry,
  globalMetrics,
  initializeDefaultMetrics,
  createExpressMiddleware,
  metricsMiddleware,
} from './prometheus';

export type { Labels, MetricValue } from './prometheus';

// ─── Exports from request-metrics.ts ────────────────────────────────────────

export {
  createRequestMetricsMiddleware,
  requestMetricsMiddleware,
  recordRateLimitHit,
  recordAuthAttempt,
  recordPolicyDecision,
  recordDetectionAlert,
  setCircuitBreakerState,
  recordAuditEventsIngested,
  setActiveSessionCount,
  setRedisConnectionStatus,
  getActiveConnectionCount,
  resetActiveConnectionCount,
  getLabelCombinationCount,
  clearLabelCombinations,
} from './request-metrics';

export type { } from './request-metrics';
