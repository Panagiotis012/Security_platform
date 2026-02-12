# Prometheus Metrics Module

A production-ready, zero-dependency Prometheus metrics implementation for the Security Platform. Provides comprehensive metrics collection without requiring external dependencies like `prom-client`.

## Overview

This module delivers a complete metrics solution for the Security Platform with:

- **MetricsRegistry**: Core class supporting Counter, Gauge, Histogram, and Summary metrics
- **Express Integration**: Automatic HTTP request/response metrics via middleware
- **Pre-configured Metrics**: 13 security-focused metrics ready to use
- **Prometheus Compliance**: Full text exposition format support (v0.0.4)
- **Production Ready**: Type-safe, well-documented, thoroughly tested patterns

## Files

### Core Implementation

- **`prometheus.ts` (684 lines)**
  - `MetricsRegistry` class: Register and record metrics
  - Metric types: Counter, Gauge, Histogram, Summary
  - Prometheus text format serialization
  - Express middleware helpers
  - Global metrics singleton

- **`request-metrics.ts` (518 lines)**
  - Express middleware for automatic HTTP metrics
  - Request/response timing and sizing
  - Active connection tracking
  - Domain-specific metric helpers
  - Cardinality protection

- **`index.ts` (86 lines)**
  - Central exports for the metrics module
  - Clean public API

### Documentation & Examples

- **`USAGE.md`** - Complete usage guide with examples
- **`EXAMPLE.ts`** - 7 runnable example scenarios
- **`README.md`** - This file

## Quick Start

```typescript
import express from 'express';
import {
  initializeDefaultMetrics,
  createRequestMetricsMiddleware,
  createExpressMiddleware,
  recordAuthAttempt,
} from '@shared/metrics';

const app = express();

// 1. Initialize default metrics
initializeDefaultMetrics();

// 2. Add request metrics middleware (early in chain)
app.use(createRequestMetricsMiddleware({
  serviceName: 'api-gateway',
  skipPaths: ['/health', '/metrics'],
  normalizePath: true,
}));

// 3. Your routes
app.post('/login', (req, res) => {
  try {
    authenticate(req.body);
    recordAuthAttempt('success', 'bearer', 'api-gateway');
    res.json({ token: 'xxx' });
  } catch (err) {
    recordAuthAttempt('failure', 'bearer', 'api-gateway');
    res.status(401).json({ error: 'Invalid' });
  }
});

// 4. Expose metrics endpoint
app.get('/metrics', createExpressMiddleware());

app.listen(3000);
```

Then access metrics at: `http://localhost:3000/metrics`

## Supported Metric Types

### Counter
Monotonically increasing values. Can only go up or reset.

```typescript
globalMetrics.registerCounter('requests_total', 'Total requests');
globalMetrics.recordCounter('requests_total', 1, { method: 'GET' });
```

Output:
```
requests_total{method="GET"} 42
```

### Gauge
Values that can increase and decrease.

```typescript
globalMetrics.registerGauge('active_connections', 'Active connections');
globalMetrics.recordGauge('active_connections', 150, { service: 'api' });
```

Output:
```
active_connections{service="api"} 150
```

### Histogram
Distribution of values with configurable buckets. Generates `_bucket`, `_sum`, and `_count` suffixes.

```typescript
const buckets = [0.1, 0.5, 1, 5];
globalMetrics.registerHistogram('request_duration', 'Request duration', buckets);
globalMetrics.recordHistogram('request_duration', 0.234, { endpoint: '/api' });
```

Output:
```
request_duration_bucket{le="0.1",endpoint="/api"} 0
request_duration_bucket{le="0.5",endpoint="/api"} 1
request_duration_bucket{le="1",endpoint="/api"} 1
request_duration_bucket{le="5",endpoint="/api"} 1
request_duration_bucket{le="+Inf",endpoint="/api"} 1
request_duration_sum{endpoint="/api"} 0.234
request_duration_count{endpoint="/api"} 1
```

### Summary
Distribution with percentiles. Generates `_sum` and `_count` suffixes plus percentile lines.

```typescript
const percentiles = [50, 90, 99];
globalMetrics.registerSummary('latency', 'Latency', percentiles);
globalMetrics.recordSummary('latency', 0.156);
```

Output:
```
latency{quantile="0.5"} 0.156
latency{quantile="0.9"} 0.234
latency{quantile="0.99"} 0.512
latency_sum 12.456
latency_count 100
```

## Pre-configured Metrics

### HTTP Metrics (Automatic)
- `http_requests_total` - Counter of all requests
- `http_request_duration_seconds` - Histogram of request durations
- `http_request_size_bytes` - Histogram of request sizes
- `http_response_size_bytes` - Histogram of response sizes

Default buckets:
- Duration: `[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]` seconds
- Size: `[100, 1000, 10000, 100000, 1000000]` bytes

### Connection Metrics
- `active_connections` - Gauge of active connections

### Security Metrics (Manual)
- `rate_limit_hits_total` - Counter of rate limit violations
- `auth_attempts_total` - Counter of authentication attempts
- `policy_decisions_total` - Counter of policy evaluations
- `detection_alerts_total` - Counter of detected threats

### Operational Metrics
- `circuit_breaker_state` - Gauge: 0=closed, 1=open, 2=half-open
- `audit_events_ingested_total` - Counter of audit events
- `session_active` - Gauge of active sessions
- `redis_connection_status` - Gauge: 1=connected, 0=disconnected

## Request Metrics Middleware

The `createRequestMetricsMiddleware()` function automatically captures:

1. **Request Count** - Increments `http_requests_total`
2. **Request Duration** - Records in `http_request_duration_seconds`
3. **Request Size** - Records in `http_request_size_bytes`
4. **Response Size** - Records in `http_response_size_bytes`
5. **Active Connections** - Maintains `active_connections` gauge

### Options

```typescript
interface RequestMetricsOptions {
  serviceName?: string;           // Label value for all metrics
  skipPaths?: string[] | Function; // Exclude paths from metrics
  normalizePath?: boolean;         // Replace IDs with {id}
  pathNormalizer?: Function;       // Custom path normalization
  maxLabelCardinality?: number;   // Prevent label explosion
}
```

### Example Configuration

```typescript
app.use(createRequestMetricsMiddleware({
  serviceName: 'api-gateway',
  skipPaths: ['/health', '/metrics', '/readiness'],
  normalizePath: true,
  maxLabelCardinality: 1000,
}));
```

## Domain-Specific Helpers

Helper functions for common security platform metrics:

```typescript
import {
  recordRateLimitHit,
  recordAuthAttempt,
  recordPolicyDecision,
  recordDetectionAlert,
  setCircuitBreakerState,
  recordAuditEventsIngested,
  setActiveSessionCount,
  setRedisConnectionStatus,
} from '@shared/metrics';

// Rate limiting
recordRateLimitHit('free-tier', 'api-gateway');
recordRateLimitHit('premium-tier', 'api-gateway');

// Authentication
recordAuthAttempt('success', 'bearer', 'auth-service');
recordAuthAttempt('failure', 'basic', 'auth-service');
recordAuthAttempt('error', 'oauth', 'auth-service');

// Policy decisions
recordPolicyDecision('allow', 'policy-engine');
recordPolicyDecision('deny', 'policy-engine');
recordPolicyDecision('challenge', 'policy-engine');

// Detection alerts
recordDetectionAlert('SQL_INJECTION_001', 'critical', 'threat-detector');
recordDetectionAlert('XSS_DETECTED_002', 'high', 'threat-detector');
recordDetectionAlert('ANOMALY_003', 'medium', 'threat-detector');

// Circuit breaker
setCircuitBreakerState('auth-service', 0, 'api-gateway');  // closed
setCircuitBreakerState('policy-engine', 1, 'api-gateway'); // open
setCircuitBreakerState('detector', 2, 'api-gateway');      // half-open

// Audit
recordAuditEventsIngested(42, 'audit-service');

// Sessions
setActiveSessionCount(150, 'session-manager');

// Redis
setRedisConnectionStatus('api-gateway', true);  // connected
setRedisConnectionStatus('cache', false);       // disconnected
```

## Prometheus Integration

### Scrape Configuration

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'security-platform'
    static_configs:
      - targets: ['localhost:3000']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

### PromQL Examples

```promql
# Total requests per second
rate(http_requests_total[5m])

# P95 request latency
histogram_quantile(0.95, http_request_duration_seconds)

# Active connections
active_connections

# Authentication success rate
rate(auth_attempts_total{result="success"}[5m]) / rate(auth_attempts_total[5m])

# Detection alert rate by severity
rate(detection_alerts_total[5m]) by (severity)

# Circuit breaker state
circuit_breaker_state
```

## Best Practices

### 1. Label Cardinality
Avoid unbounded labels. Use categories instead of identifiers:

```typescript
// BAD: User ID (unbounded)
recordAuthAttempt('success', 'bearer', 'api-gateway');
globalMetrics.recordCounter('auth_attempts', 1, { user_id: userId });

// GOOD: User tier (bounded)
globalMetrics.recordCounter('auth_attempts', 1, { tier: userTier });
```

### 2. Path Normalization
Enable normalization to reduce unique paths:

```typescript
// Without: /users/123, /users/456, /users/789 → 3 unique
// With: all become /users/{id} → 1 unique
app.use(createRequestMetricsMiddleware({ normalizePath: true }));
```

### 3. Middleware Placement
Insert metrics middleware early in the chain:

```typescript
app.use(createRequestMetricsMiddleware(...));  // First
app.use(errorHandler);                         // After metrics
app.use(router);                               // Routes
```

### 4. Service Naming
Use consistent service names across the platform:

```typescript
const serviceName = process.env.SERVICE_NAME || 'api-gateway';
app.use(createRequestMetricsMiddleware({ serviceName }));
```

### 5. Testing
Create isolated registries for testing:

```typescript
const testRegistry = new MetricsRegistry();
testRegistry.registerCounter('test', 'Test');
testRegistry.recordCounter('test', 1);
expect(testRegistry.serialize()).toContain('test{} 1');
```

## Performance

### Memory
- Counters/Gauges: ~100 bytes per unique label combination
- Histograms: ~100 bytes + 8 bytes per observation
- Summaries: ~100 bytes + 8 bytes per observation

### CPU
- Recording metrics: O(1) for counters/gauges
- Recording metrics: O(1) for histogram/summary (append to array)
- Serialization: O(n) where n = total observations

### Cardinality Protection
The middleware tracks label combinations and warns at `maxLabelCardinality`:

```typescript
app.use(createRequestMetricsMiddleware({
  maxLabelCardinality: 1000,  // Warn if exceeded
}));
```

## Examples

See `EXAMPLE.ts` for 7 comprehensive examples:

1. Basic metrics registration and recording
2. Using global metrics registry
3. Express application integration
4. Domain-specific metrics
5. Custom registries for testing
6. Cardinality protection
7. Histogram bucket distribution

Run examples:

```bash
npx ts-node shared/src/metrics/EXAMPLE.ts
```

## Troubleshooting

### Metrics Not Appearing
1. Call `initializeDefaultMetrics()` before recording
2. Ensure middleware is registered before routes
3. Check service name matches metric labels

### High Label Cardinality
1. Reduce unique path values (enable normalization)
2. Remove high-cardinality labels
3. Lower `maxLabelCardinality` threshold

### Missing Request Metrics
1. Verify middleware is the first in chain
2. Check paths aren't in `skipPaths`
3. Confirm no earlier middleware catches requests

### Performance Issues
1. Reduce histogram bucket count
2. Increase `maxLabelCardinality`
3. Cache serialization if scraping frequently

## API Reference

### MetricsRegistry

```typescript
// Registration
registerCounter(name: string, help: string): void
registerGauge(name: string, help: string): void
registerHistogram(name: string, help: string, buckets?: number[]): void
registerSummary(name: string, help: string, percentiles?: number[]): void

// Recording
recordCounter(name: string, value?: number, labels?: Labels): void
recordGauge(name: string, value: number, labels?: Labels): void
recordHistogram(name: string, value: number, labels?: Labels): void
recordSummary(name: string, value: number, labels?: Labels): void

// Retrieval
getValue(name: string, labels?: Labels): number | undefined
serialize(): string

// Maintenance
clear(): void
```

### Request Metrics

```typescript
createRequestMetricsMiddleware(options?: RequestMetricsOptions): Middleware
requestMetricsMiddleware(serviceName?: string): Middleware

recordRateLimitHit(tier: string, serviceName: string): void
recordAuthAttempt(result: string, method: string, serviceName: string): void
recordPolicyDecision(decision: string, serviceName: string): void
recordDetectionAlert(detectionId: string, severity: string, serviceName: string): void
setCircuitBreakerState(upstream: string, state: 0|1|2, serviceName: string): void
recordAuditEventsIngested(count?: number, serviceName?: string): void
setActiveSessionCount(count: number, serviceName: string): void
setRedisConnectionStatus(serviceName: string, connected: boolean): void
```

### Express Middleware

```typescript
createExpressMiddleware(registry?: MetricsRegistry): Handler
metricsMiddleware(path?: string, registry?: MetricsRegistry): Middleware
```

## License

This module is part of the Security Platform and follows the same license terms.

---

For detailed usage information, see `USAGE.md`
For runnable examples, see `EXAMPLE.ts`
