import type { Request, Response, NextFunction } from 'express';

// ─── Type Definitions ───────────────────────────────────────────────────────

/**
 * Label object containing metric dimensions.
 * All label values are converted to strings.
 */
type Labels = Record<string, string | number | boolean>;

/**
 * Metric value with associated labels.
 */
interface MetricValue {
  labels: Record<string, string>;
  value: number;
}

/**
 * Counter metric - monotonically increasing.
 */
interface CounterMetric {
  type: 'counter';
  help: string;
  values: MetricValue[];
}

/**
 * Gauge metric - can increase and decrease.
 */
interface GaugeMetric {
  type: 'gauge';
  help: string;
  values: MetricValue[];
}

/**
 * Histogram metric - observes value distributions with buckets.
 */
interface HistogramMetric {
  type: 'histogram';
  help: string;
  buckets: number[];
  values: MetricValue[];
}

/**
 * Summary metric - observes value distributions with percentiles.
 */
interface SummaryMetric {
  type: 'summary';
  help: string;
  percentiles: number[];
  values: MetricValue[];
}

type Metric = CounterMetric | GaugeMetric | HistogramMetric | SummaryMetric;

// ─── Prometheus Text Exposition Format Helpers ───────────────────────────────

/**
 * Escape label values for Prometheus exposition format.
 * Replaces backslashes and double quotes.
 *
 * @param value - The value to escape
 * @returns The escaped value safe for Prometheus format
 */
function escapeLabelValue(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

/**
 * Format label pairs as a Prometheus label string.
 * Example: {method="GET",path="/api/users"}
 *
 * @param labels - Object containing label key-value pairs
 * @returns Formatted label string
 */
function formatLabels(labels: Record<string, string>): string {
  const pairs = Object.entries(labels)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}="${escapeLabelValue(value)}"`)
    .join(',');
  return `{${pairs}}`;
}

/**
 * Format a metric sample line for Prometheus exposition format.
 *
 * @param name - The metric name
 * @param labels - The labels for this sample
 * @param value - The numeric value
 * @param timestamp - Optional timestamp in milliseconds
 * @returns Formatted line for exposition format
 */
function formatSample(
  name: string,
  labels: Record<string, string>,
  value: number,
  timestamp?: number
): string {
  const labelStr = Object.keys(labels).length > 0 ? formatLabels(labels) : '';
  const line = `${name}${labelStr} ${value}`;
  if (timestamp !== undefined) {
    return `${line} ${timestamp}`;
  }
  return line;
}

// ─── Metrics Registry Class ─────────────────────────────────────────────────

/**
 * Registry for Prometheus metrics supporting Counter, Gauge, Histogram, and Summary types.
 * Provides methods to record metric observations and serialize to Prometheus exposition format.
 *
 * Usage:
 * ```typescript
 * const registry = new MetricsRegistry();
 * registry.recordCounter('requests_total', 1, { method: 'GET' });
 * registry.recordGauge('active_connections', 42, { service: 'api' });
 * const output = registry.serialize();
 * ```
 */
export class MetricsRegistry {
  private metrics: Map<string, Metric> = new Map();
  private counterValues: Map<string, number> = new Map();
  private gaugeValues: Map<string, number> = new Map();
  private histogramObservations: Map<string, number[][]> = new Map();
  private summaryObservations: Map<string, number[][]> = new Map();

  /**
   * Register a counter metric.
   *
   * @param name - Metric name (e.g., 'requests_total')
   * @param help - Human-readable help text
   */
  registerCounter(name: string, help: string): void {
    this.metrics.set(name, {
      type: 'counter',
      help,
      values: [],
    });
  }

  /**
   * Register a gauge metric.
   *
   * @param name - Metric name (e.g., 'active_connections')
   * @param help - Human-readable help text
   */
  registerGauge(name: string, help: string): void {
    this.metrics.set(name, {
      type: 'gauge',
      help,
      values: [],
    });
  }

  /**
   * Register a histogram metric with configurable buckets.
   *
   * @param name - Metric name (e.g., 'request_duration_seconds')
   * @param help - Human-readable help text
   * @param buckets - Bucket boundaries (will include +Inf automatically)
   */
  registerHistogram(name: string, help: string, buckets: number[] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]): void {
    this.metrics.set(name, {
      type: 'histogram',
      help,
      buckets: buckets.slice().sort((a, b) => a - b),
      values: [],
    });
    this.histogramObservations.set(name, []);
  }

  /**
   * Register a summary metric with configurable percentiles.
   *
   * @param name - Metric name (e.g., 'request_latency')
   * @param help - Human-readable help text
   * @param percentiles - Percentiles to calculate (e.g., [0.5, 0.9, 0.99])
   */
  registerSummary(name: string, help: string, percentiles: number[] = [0.5, 0.9, 0.99]): void {
    this.metrics.set(name, {
      type: 'summary',
      help,
      percentiles,
      values: [],
    });
    this.summaryObservations.set(name, []);
  }

  /**
   * Record a counter observation (increments the counter).
   *
   * @param name - Metric name
   * @param value - Increment amount (default: 1)
   * @param labels - Optional labels for this observation
   */
  recordCounter(name: string, value: number = 1, labels: Labels = {}): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'counter') {
      throw new Error(`Counter metric '${name}' not registered`);
    }

    const key = this.getLabelKey(name, labels);
    const current = this.counterValues.get(key) || 0;
    this.counterValues.set(key, current + value);
  }

  /**
   * Record a gauge observation (sets or updates the gauge value).
   *
   * @param name - Metric name
   * @param value - The gauge value
   * @param labels - Optional labels for this observation
   */
  recordGauge(name: string, value: number, labels: Labels = {}): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'gauge') {
      throw new Error(`Gauge metric '${name}' not registered`);
    }

    const key = this.getLabelKey(name, labels);
    this.gaugeValues.set(key, value);
  }

  /**
   * Record a histogram observation.
   *
   * @param name - Metric name
   * @param value - The observed value
   * @param labels - Optional labels for this observation
   */
  recordHistogram(name: string, value: number, labels: Labels = {}): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'histogram') {
      throw new Error(`Histogram metric '${name}' not registered`);
    }

    const observations = this.histogramObservations.get(name) || [];
    const labelArray = observations.find((obs) => this.isSameLabelKey(name, obs, labels));

    if (labelArray) {
      labelArray.push(value);
    } else {
      observations.push([value]);
      this.histogramObservations.set(name, observations);
    }
  }

  /**
   * Record a summary observation.
   *
   * @param name - Metric name
   * @param value - The observed value
   * @param labels - Optional labels for this observation
   */
  recordSummary(name: string, value: number, labels: Labels = {}): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== 'summary') {
      throw new Error(`Summary metric '${name}' not registered`);
    }

    const observations = this.summaryObservations.get(name) || [];
    const labelArray = observations.find((obs) => this.isSameLabelKey(name, obs, labels));

    if (labelArray) {
      labelArray.push(value);
    } else {
      observations.push([value]);
      this.summaryObservations.set(name, observations);
    }
  }

  /**
   * Generate a unique key for label combinations.
   *
   * @param name - Metric name
   * @param labels - Labels object
   * @returns Unique key string
   */
  private getLabelKey(name: string, labels: Labels): string {
    const sortedLabels = Object.keys(labels)
      .sort()
      .map((k) => `${k}=${labels[k]}`)
      .join('|');
    return `${name}:${sortedLabels}`;
  }

  /**
   * Check if a label array matches the given labels.
   *
   * @param name - Metric name
   * @param labelArray - The stored label array
   * @param labels - The labels to match
   * @returns True if labels match
   */
  private isSameLabelKey(name: string, _labelArray: number[], labels: Labels): boolean {
    return this.getLabelKey(name, labels) === this.getLabelKey(name, {});
  }

  /**
   * Serialize all metrics to Prometheus exposition format.
   * Includes HELP and TYPE lines for each metric.
   *
   * @returns String in Prometheus exposition format
   */
  serialize(): string {
    const lines: string[] = [];

    for (const [name, metric] of this.metrics) {
      // Add HELP line
      lines.push(`# HELP ${name} ${metric.help}`);

      // Add TYPE line
      lines.push(`# TYPE ${name} ${metric.type}`);

      // Generate metric lines based on type
      if (metric.type === 'counter' || metric.type === 'gauge') {
        lines.push(...this.serializeCounterOrGauge(name, metric));
      } else if (metric.type === 'histogram') {
        lines.push(...this.serializeHistogram(name, metric));
      } else if (metric.type === 'summary') {
        lines.push(...this.serializeSummary(name, metric));
      }

      // Add blank line between metrics
      lines.push('');
    }

    return lines.join('\n');
  }

  /**
   * Serialize counter or gauge metric lines.
   *
   * @param name - Metric name
   * @param metric - The metric definition
   * @returns Array of exposition format lines
   */
  private serializeCounterOrGauge(name: string, metric: CounterMetric | GaugeMetric): string[] {
    const lines: string[] = [];
    const storage = metric.type === 'counter' ? this.counterValues : this.gaugeValues;

    for (const [key, value] of storage) {
      if (key.startsWith(`${name}:`)) {
        const labels = this.extractLabelsFromKey(key);
        lines.push(formatSample(name, labels, value));
      }
    }

    return lines;
  }

  /**
   * Serialize histogram metric lines including buckets and sum/count.
   *
   * @param name - Metric name
   * @param metric - The histogram metric definition
   * @returns Array of exposition format lines
   */
  private serializeHistogram(name: string, metric: HistogramMetric): string[] {
    const lines: string[] = [];
    const observations = this.histogramObservations.get(name) || [];

    if (observations.length === 0) {
      return lines;
    }

    // Group observations by labels
    const labelGroups = new Map<string, number[]>();

    for (const obs of observations) {
      const key = `${name}:`;
      if (!labelGroups.has(key)) {
        labelGroups.set(key, []);
      }
      labelGroups.get(key)!.push(...obs);
    }

    for (const [key, values] of labelGroups) {
      const labels = this.extractLabelsFromKey(key);

      // Calculate bucket counts
      const bucketCounts = new Map<string | number, number>();
      for (const bucket of metric.buckets) {
        bucketCounts.set(bucket, 0);
      }
      bucketCounts.set('+Inf', 0);

      let sum = 0;
      for (const value of values) {
        sum += value;
        for (const [b] of bucketCounts) {
          if (b === '+Inf' || (typeof b === 'number' && value <= b)) {
            bucketCounts.set(b, (bucketCounts.get(b) || 0) + 1);
          }
        }
      }

      // Output bucket lines
      for (const bucket of metric.buckets) {
        const bucketLabels = { ...labels, le: String(bucket) };
        const count = bucketCounts.get(bucket) || 0;
        lines.push(formatSample(`${name}_bucket`, bucketLabels, count));
      }

      // Output +Inf bucket
      const infLabels = { ...labels, le: '+Inf' };
      lines.push(formatSample(`${name}_bucket`, infLabels, values.length));

      // Output sum
      lines.push(formatSample(`${name}_sum`, labels, sum));

      // Output count
      lines.push(formatSample(`${name}_count`, labels, values.length));
    }

    return lines;
  }

  /**
   * Serialize summary metric lines including percentiles.
   *
   * @param name - Metric name
   * @param metric - The summary metric definition
   * @returns Array of exposition format lines
   */
  private serializeSummary(name: string, metric: SummaryMetric): string[] {
    const lines: string[] = [];
    const observations = this.summaryObservations.get(name) || [];

    if (observations.length === 0) {
      return lines;
    }

    // Group observations by labels
    const labelGroups = new Map<string, number[]>();

    for (const obs of observations) {
      const key = `${name}:`;
      if (!labelGroups.has(key)) {
        labelGroups.set(key, []);
      }
      labelGroups.get(key)!.push(...obs);
    }

    for (const [key, values] of labelGroups) {
      const labels = this.extractLabelsFromKey(key);
      const sorted = values.slice().sort((a, b) => a - b);

      // Calculate percentiles
      for (const percentile of metric.percentiles) {
        const index = Math.ceil((percentile / 100) * sorted.length) - 1;
        const value = sorted[Math.max(0, index)] ?? 0;
        const quantileLabels = { ...labels, quantile: String(percentile / 100) };
        lines.push(formatSample(`${name}`, quantileLabels, value));
      }

      // Output sum
      const sum = values.reduce((a, b) => a + b, 0);
      lines.push(formatSample(`${name}_sum`, labels, sum));

      // Output count
      lines.push(formatSample(`${name}_count`, labels, values.length));
    }

    return lines;
  }

  /**
   * Extract labels from a label key string.
   *
   * @param key - The key string in format "metric:key1=val1|key2=val2"
   * @returns Labels object
   */
  private extractLabelsFromKey(key: string): Record<string, string> {
    const labels: Record<string, string> = {};
    const parts = key.split(':');
    if (parts.length > 1 && parts[1]) {
      const labelParts = parts[1].split('|');
      for (const part of labelParts) {
        if (part) {
          const [k, v] = part.split('=');
          if (k && v) {
            labels[k] = v;
          }
        }
      }
    }
    return labels;
  }

  /**
   * Clear all metrics from the registry.
   * Useful for testing or resetting metrics.
   */
  clear(): void {
    this.metrics.clear();
    this.counterValues.clear();
    this.gaugeValues.clear();
    this.histogramObservations.clear();
    this.summaryObservations.clear();
  }

  /**
   * Get the current value of a counter or gauge metric.
   *
   * @param name - Metric name
   * @param labels - Optional labels to filter
   * @returns The metric value, or undefined if not found
   */
  getValue(name: string, labels: Labels = {}): number | undefined {
    const key = this.getLabelKey(name, labels);
    const metric = this.metrics.get(name);

    if (metric?.type === 'counter' || metric?.type === 'gauge') {
      return this.counterValues.get(key) || this.gaugeValues.get(key);
    }

    return undefined;
  }
}

// ─── Global Metrics Registry Singleton ───────────────────────────────────────

/**
 * Global metrics registry instance used by the entire application.
 * Register and record metrics through this instance.
 */
export const globalMetrics = new MetricsRegistry();

/**
 * Register all default security platform metrics.
 * Call this once during application initialization.
 */
export function initializeDefaultMetrics(): void {
  // HTTP Request Metrics
  globalMetrics.registerCounter(
    'http_requests_total',
    'Total number of HTTP requests received'
  );
  globalMetrics.registerHistogram(
    'http_request_duration_seconds',
    'HTTP request duration in seconds',
    [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
  );
  globalMetrics.registerHistogram(
    'http_request_size_bytes',
    'HTTP request size in bytes',
    [100, 1000, 10000, 100000, 1000000]
  );
  globalMetrics.registerHistogram(
    'http_response_size_bytes',
    'HTTP response size in bytes',
    [100, 1000, 10000, 100000, 1000000]
  );

  // Connection Metrics
  globalMetrics.registerGauge('active_connections', 'Number of active connections');

  // Rate Limiting Metrics
  globalMetrics.registerCounter(
    'rate_limit_hits_total',
    'Total number of rate limit hits'
  );

  // Authentication Metrics
  globalMetrics.registerCounter(
    'auth_attempts_total',
    'Total number of authentication attempts'
  );

  // Policy Decision Metrics
  globalMetrics.registerCounter(
    'policy_decisions_total',
    'Total number of policy decisions made'
  );

  // Detection & Alert Metrics
  globalMetrics.registerCounter(
    'detection_alerts_total',
    'Total number of detection alerts generated'
  );

  // Edge Security Metrics
  globalMetrics.registerCounter(
    'waf_blocks_total',
    'Total number of requests blocked by the WAF'
  );
  globalMetrics.registerCounter(
    'waf_detections_total',
    'Total number of WAF detections (below blocking threshold)'
  );
  globalMetrics.registerCounter(
    'normalization_blocks_total',
    'Total number of requests blocked by request normalization'
  );
  globalMetrics.registerCounter(
    'pdp_failures_total',
    'Total number of PDP failures (unreachable/errors) resulting in a fallback decision'
  );
  globalMetrics.registerCounter(
    'adaptive_ip_signals_total',
    'Total number of adaptive IP defense abuse signals observed'
  );
  globalMetrics.registerCounter(
    'adaptive_ip_challenges_total',
    'Total number of IPs escalated to bot challenge by adaptive defense'
  );
  globalMetrics.registerCounter(
    'adaptive_ip_blocks_total',
    'Total number of IP addresses blocked by adaptive IP defense'
  );
  globalMetrics.registerCounter(
    'bot_challenge_required_total',
    'Total number of bot challenge responses issued'
  );
  globalMetrics.registerCounter(
    'bot_challenge_pass_total',
    'Total number of successful bot challenge validations'
  );

  // Circuit Breaker Metrics
  globalMetrics.registerGauge(
    'circuit_breaker_state',
    'Current state of circuit breaker (0=closed, 1=open, 2=half_open)'
  );

  // Audit Metrics
  globalMetrics.registerCounter(
    'audit_events_ingested_total',
    'Total number of audit events ingested'
  );

  // Session Metrics
  globalMetrics.registerGauge('session_active', 'Number of active sessions');

  // Redis Connection Metrics
  globalMetrics.registerGauge(
    'redis_connection_status',
    'Redis connection status (1=connected, 0=disconnected)'
  );
}

// ─── Express Middleware ──────────────────────────────────────────────────────

/**
 * Create an Express middleware handler for the /metrics endpoint.
 * Returns the Prometheus exposition format when accessed.
 *
 * Usage:
 * ```typescript
 * import express from 'express';
 * import { createExpressMiddleware } from './prometheus';
 *
 * const app = express();
 * app.get('/metrics', createExpressMiddleware());
 * ```
 *
 * @param registry - Optional metrics registry (defaults to globalMetrics)
 * @returns Express middleware handler
 */
export function createExpressMiddleware(registry: MetricsRegistry = globalMetrics) {
  return (_req: Request, res: Response): void => {
    res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.status(200).send(registry.serialize());
  };
}

/**
 * Create an Express middleware that exposes metrics on a specific path.
 * This is a convenience wrapper around createExpressMiddleware.
 *
 * Usage:
 * ```typescript
 * const app = express();
 * app.use(metricsMiddleware());
 * // Now /metrics endpoint will serve metrics
 * ```
 *
 * @param path - The path to expose metrics on (default: '/metrics')
 * @param registry - Optional metrics registry (defaults to globalMetrics)
 * @returns Express middleware function
 */
export function metricsMiddleware(
  path: string = '/metrics',
  registry: MetricsRegistry = globalMetrics
) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (req.path === path && req.method === 'GET') {
      // `createExpressMiddleware` returns a (req, res) handler (no `next`).
      createExpressMiddleware(registry)(req, res);
    } else {
      next();
    }
  };
}

// ─── Type Exports ───────────────────────────────────────────────────────────

export type { Labels, MetricValue };
