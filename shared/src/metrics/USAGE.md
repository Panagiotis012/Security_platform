# Prometheus Metrics Module

A comprehensive, dependency-free Prometheus metrics collection library for the Security Platform. Implements the Prometheus exposition format directly without requiring the `prom-client` library.

## Features

- **No External Dependencies**: Implements Prometheus text format exposition format directly
- **Multiple Metric Types**: Counter, Gauge, Histogram, and Summary metrics
- **Label Support**: All metrics support flexible labeling for dimensions
- **Express Integration**: Built-in middleware for automatic HTTP metrics and `/metrics` endpoint
- **Pre-configured Metrics**: Common security platform metrics ready to use
- **Cardinality Protection**: Guards against unbounded label combinations
- **Type-Safe**: Full TypeScript support with comprehensive JSDoc documentation

## Metric Types

### Counter
Monotonically increasing metrics. Can only go up.

```typescript
globalMetrics.registerCounter('http_requests_total', 'Total HTTP requests');
globalMetrics.recordCounter('http_requests_total', 1, { method: 'GET', path: '/api' });
```

### Gauge
Metrics that can increase or decrease.

```typescript
globalMetrics.registerGauge('active_connections', 'Current connections');
globalMetrics.recordGauge('active_connections', 42, { service: 'api' });
```

### Histogram
Distribution metrics with configurable buckets. Automatically generates `_bucket`, `_count`, and `_sum` suffixes.

```typescript
const buckets = [0.1, 0.5, 1.0, 2.5, 5.0, 10.0];
globalMetrics.registerHistogram('request_duration_seconds', 'Request duration', buckets);
globalMetrics.recordHistogram('request_duration_seconds', 0.234, { method: 'GET' });
```

### Summary
Distribution metrics with percentiles. Generates `_count` and `_sum` suffixes plus percentile lines.

```typescript
const percentiles = [0.5, 0.9, 0.99];
globalMetrics.registerSummary('api_latency', 'API latency', percentiles);
globalMetrics.recordSummary('api_latency', 0.156, { endpoint: '/users' });
```

## Pre-configured Metrics

The module includes these pre-configured security platform metrics:

### HTTP Metrics
- `http_requests_total` (counter) - Total requests received
- `http_request_duration_seconds` (histogram) - Request duration in seconds
- `http_request_size_bytes` (histogram) - Request payload size
- `http_response_size_bytes` (histogram) - Response payload size

### Connection Metrics
- `active_connections` (gauge) - Current active connections

### Rate Limiting
- `rate_limit_hits_total` (counter) - Rate limit violations

### Authentication
- `auth_attempts_total` (counter) - Authentication attempts with result labels

### Policy Engine
- `policy_decisions_total` (counter) - Policy decisions made

### Detection & Alerts
- `detection_alerts_total` (counter) - Alerts generated with severity labels

### Circuit Breaker
- `circuit_breaker_state` (gauge) - State of circuit breakers (0=closed, 1=open, 2=half-open)

### Audit
- `audit_events_ingested_total` (counter) - Audit events processed

### Sessions
- `session_active` (gauge) - Active session count

### Redis
- `redis_connection_status` (gauge) - Redis connection status (1=connected, 0=disconnected)

## Usage

### Basic Setup

```typescript
import express from 'express';
import {
  initializeDefaultMetrics,
  createRequestMetricsMiddleware,
  createExpressMiddleware,
} from '@shared/metrics';

const app = express();

// Initialize default metrics
initializeDefaultMetrics();

// Add request metrics middleware (captures HTTP metrics automatically)
app.use(createRequestMetricsMiddleware({
  serviceName: 'api-gateway',
  skipPaths: ['/health', '/metrics'],
  normalizePath: true,
  maxLabelCardinality: 1000,
}));

// Expose metrics endpoint
app.get('/metrics', createExpressMiddleware());

app.listen(3000);
```

### Recording Custom Metrics

```typescript
import {
  globalMetrics,
  recordAuthAttempt,
  recordPolicyDecision,
  recordDetectionAlert,
  setCircuitBreakerState,
} from '@shared/metrics';

// Use helper functions for domain metrics
recordAuthAttempt('success', 'bearer', 'api-gateway');
recordPolicyDecision('allow', 'policy-engine');
recordDetectionAlert('SQL_INJECTION_001', 'high', 'threat-detector');
setCircuitBreakerState('upstream-service', 0, 'api-gateway');

// Or use registry directly for custom metrics
globalMetrics.recordCounter('custom_metric', 5, {
  label1: 'value1',
  label2: 'value2'
});
```

### Creating Custom Metrics

```typescript
// Register custom metrics
globalMetrics.registerCounter('login_attempts', 'Total login attempts');
globalMetrics.registerGauge('cache_size_bytes', 'Cache size in bytes');
globalMetrics.registerHistogram(
  'db_query_duration_ms',
  'Database query duration',
  [10, 50, 100, 500, 1000]
);

// Record observations
globalMetrics.recordCounter('login_attempts', 1, { user: 'alice' });
globalMetrics.recordGauge('cache_size_bytes', 1024000, { cache: 'memory' });
globalMetrics.recordHistogram('db_query_duration_ms', 123, { query: 'users' });
```

## Middleware Options

### RequestMetricsOptions

```typescript
interface RequestMetricsOptions {
  // Name of the service (used in all metric labels)
  serviceName?: string;  // default: 'unknown'

  // Paths to exclude from metrics collection
  skipPaths?: ((path: string) => boolean) | string[];

  // Whether to normalize paths (e.g., /users/123 → /users/{id})
  normalizePath?: boolean;  // default: true

  // Custom path normalization function
  pathNormalizer?: (path: string) => string;

  // Maximum unique label combinations per metric
  maxLabelCardinality?: number;  // default: 1000
}
```

## Prometheus Output Format

The metrics are serialized in Prometheus text exposition format:

```
# HELP http_requests_total Total number of HTTP requests received
# TYPE http_requests_total counter
http_requests_total{method="GET",path="/api/users",status_code="200",service="api-gateway"} 42
http_requests_total{method="POST",path="/api/users",status_code="201",service="api-gateway"} 5

# HELP http_request_duration_seconds HTTP request duration in seconds
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{le="0.005",method="GET",service="api-gateway"} 10
http_request_duration_seconds_bucket{le="0.01",method="GET",service="api-gateway"} 25
...
http_request_duration_seconds_bucket{le="+Inf",method="GET",service="api-gateway"} 100
http_request_duration_seconds_sum{method="GET",service="api-gateway"} 123.45
http_request_duration_seconds_count{method="GET",service="api-gateway"} 100

# HELP active_connections Number of active connections
# TYPE active_connections gauge
active_connections{service="api-gateway"} 23
```

## Default Histogram Buckets

### Request Duration (seconds)
`[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]`

### Request/Response Size (bytes)
`[100, 1000, 10000, 100000, 1000000]`

## Best Practices

### 1. Label Cardinality
Avoid high-cardinality labels (e.g., user IDs, request IDs). The middleware protects against this with `maxLabelCardinality` option.

```typescript
// BAD: User ID as label (unbounded cardinality)
globalMetrics.recordCounter('user_actions', 1, { user_id: userId });

// GOOD: User tier as label (bounded cardinality)
globalMetrics.recordCounter('user_actions', 1, { tier: userTier });
```

### 2. Path Normalization
Enable path normalization to reduce cardinality:

```typescript
// Without normalization: /users/123, /users/456, /users/789 → 3 unique paths
// With normalization: all become /users/{id} → 1 unique path
app.use(createRequestMetricsMiddleware({
  normalizePath: true
}));
```

### 3. Exclude Internal Routes
Skip metrics for internal routes:

```typescript
app.use(createRequestMetricsMiddleware({
  skipPaths: ['/metrics', '/health', '/readiness', '/liveness'],
}));
```

### 4. Service Naming
Always specify a service name for multi-service environments:

```typescript
app.use(createRequestMetricsMiddleware({
  serviceName: 'api-gateway',  // Used in all metrics
}));
```

### 5. Custom Metrics
Register custom metrics at application startup:

```typescript
function initializeAppMetrics() {
  globalMetrics.registerCounter('feature_flag_evaluations', 'Feature flag evaluations');
  globalMetrics.registerGauge('database_pool_size', 'Database connection pool size');
  globalMetrics.registerHistogram('cache_hit_latency_ms', 'Cache hit latency', [1, 5, 10, 50]);
}

initializeAppMetrics();
```

## Example: Full Service Setup

```typescript
import express from 'express';
import {
  initializeDefaultMetrics,
  createRequestMetricsMiddleware,
  createExpressMiddleware,
  recordAuthAttempt,
  recordPolicyDecision,
  setRedisConnectionStatus,
} from '@shared/metrics';

const app = express();

// Initialize metrics
initializeDefaultMetrics();

// Add request metrics before route handlers
app.use(createRequestMetricsMiddleware({
  serviceName: 'policy-engine',
  skipPaths: ['/health', '/metrics'],
  normalizePath: true,
}));

// Your routes
app.post('/evaluate', (req, res) => {
  try {
    const decision = evaluatePolicy(req.body);
    recordPolicyDecision(decision, 'policy-engine');
    res.json({ decision });
  } catch (err) {
    res.status(500).json({ error: 'Evaluation failed' });
  }
});

// Redis health check
async function checkRedisHealth() {
  try {
    await redis.ping();
    setRedisConnectionStatus('policy-engine', true);
  } catch {
    setRedisConnectionStatus('policy-engine', false);
  }
}

// Expose metrics
app.get('/metrics', createExpressMiddleware());

app.listen(3000, () => {
  console.log('Server running on port 3000');
  setInterval(checkRedisHealth, 10000);
});
```

## Testing

```typescript
import { MetricsRegistry, initializeDefaultMetrics } from '@shared/metrics';

describe('Metrics', () => {
  let registry: MetricsRegistry;

  beforeEach(() => {
    registry = new MetricsRegistry();
    initializeDefaultMetrics();
  });

  it('should record counter metrics', () => {
    registry.registerCounter('test_counter', 'Test counter');
    registry.recordCounter('test_counter', 5, { label: 'value' });

    const value = registry.getValue('test_counter', { label: 'value' });
    expect(value).toBe(5);
  });

  it('should serialize metrics in Prometheus format', () => {
    registry.registerCounter('test', 'Test metric');
    registry.recordCounter('test', 1, { method: 'GET' });

    const output = registry.serialize();
    expect(output).toContain('# HELP test Test metric');
    expect(output).toContain('# TYPE test counter');
    expect(output).toContain('test{method="GET"} 1');
  });
});
```

## Architecture

The module consists of three main components:

### 1. prometheus.ts
- `MetricsRegistry` class: Core metric storage and serialization
- Prometheus exposition format implementation
- Express middleware helpers
- Global singleton for application metrics

### 2. request-metrics.ts
- Automatic HTTP metrics collection middleware
- Helper functions for domain-specific metrics
- Active connection tracking
- Label cardinality protection

### 3. index.ts
- Central export point for the entire module
- Aggregates exports from both files

## Performance Considerations

- **Memory**: Each unique label combination creates a separate stored value. Use bounded labels.
- **Serialization**: `serialize()` rebuilds output on each call. Cache if needed for high-traffic `/metrics` endpoints.
- **Recording**: Metric recording is O(1) for counters/gauges, O(n) for histograms/summaries where n is observation count.
- **No GC Pressure**: All allocations are predictable and long-lived.

## Prometheus Scrape Configuration

Example Prometheus `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'security-platform'
    static_configs:
      - targets: ['localhost:3000']
    metrics_path: '/metrics'
    scrape_interval: 10s
```

## Troubleshooting

### Metrics Not Appearing
1. Ensure `initializeDefaultMetrics()` was called
2. Check that middleware is registered before route handlers
3. Verify service name is specified correctly

### High Cardinality Warnings
1. Check for unbounded labels (user IDs, request IDs, etc.)
2. Enable path normalization
3. Reduce `maxLabelCardinality` to catch issues earlier
4. Use category labels instead (e.g., 'tier' instead of 'user_id')

### Missing Request Metrics
1. Ensure `createRequestMetricsMiddleware()` is the first middleware
2. Check that paths aren't in `skipPaths`
3. Verify no earlier middleware is catching the request

## License & Notes

- No external dependencies - pure TypeScript
- Prometheus exposition format v0.0.4 compatible
- Full metric type support (counter, gauge, histogram, summary)
- Production-ready with comprehensive error handling
