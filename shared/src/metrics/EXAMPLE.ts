/**
 * Example usage of the Prometheus metrics module
 * This file demonstrates all major features and patterns
 */

import express from 'express';
import {
  MetricsRegistry,
  globalMetrics,
  initializeDefaultMetrics,
  createRequestMetricsMiddleware,
  createExpressMiddleware,
  recordRateLimitHit,
  recordAuthAttempt,
  recordPolicyDecision,
  recordDetectionAlert,
  setCircuitBreakerState,
  recordAuditEventsIngested,
  setActiveSessionCount,
  setRedisConnectionStatus,
} from './index';

// ─── Example 1: Basic Metrics Registration and Recording ────────────────────

export function exampleBasicMetrics(): void {
  const registry = new MetricsRegistry();

  // Register different metric types
  registry.registerCounter('purchases_total', 'Total purchases made');
  registry.registerGauge('inventory_level', 'Current inventory level');
  registry.registerHistogram(
    'order_processing_time_seconds',
    'Time to process an order',
    [0.1, 0.5, 1, 5, 10]
  );
  registry.registerSummary('payment_latency_ms', 'Payment processing latency', [0.5, 0.9, 0.99]);

  // Record observations
  registry.recordCounter('purchases_total', 1, { region: 'US', tier: 'premium' });
  registry.recordCounter('purchases_total', 1, { region: 'EU', tier: 'basic' });
  registry.recordGauge('inventory_level', 500, { warehouse: 'central' });
  registry.recordGauge('inventory_level', 250, { warehouse: 'regional' });
  registry.recordHistogram('order_processing_time_seconds', 2.34, { region: 'US' });
  registry.recordHistogram('order_processing_time_seconds', 1.12, { region: 'EU' });
  registry.recordSummary('payment_latency_ms', 45, { provider: 'stripe' });
  registry.recordSummary('payment_latency_ms', 123, { provider: 'paypal' });

  // Serialize to Prometheus format
  const output = registry.serialize();
  console.log('=== Example 1: Basic Metrics ===');
  console.log(output);
}

// ─── Example 2: Using Global Metrics Registry ──────────────────────────────

export function exampleGlobalMetrics(): void {
  initializeDefaultMetrics();

  // Record some metrics using the global registry
  globalMetrics.recordCounter('http_requests_total', 1, {
    method: 'GET',
    path: '/api/users',
    status_code: '200',
    service: 'api-gateway',
  });

  globalMetrics.recordCounter('http_requests_total', 1, {
    method: 'POST',
    path: '/api/users',
    status_code: '201',
    service: 'api-gateway',
  });

  globalMetrics.recordHistogram('http_request_duration_seconds', 0.123, {
    method: 'GET',
    path: '/api/users',
    service: 'api-gateway',
  });

  globalMetrics.recordGauge('active_connections', 42, { service: 'api-gateway' });

  console.log('\n=== Example 2: Global Metrics ===');
  console.log(globalMetrics.serialize());
}

// ─── Example 3: Express Application Integration ────────────────────────────

export function exampleExpressApp(): void {
  const app = express();

  // Initialize default metrics
  initializeDefaultMetrics();

  // Add request metrics middleware early in the chain
  app.use(
    createRequestMetricsMiddleware({
      serviceName: 'example-service',
      skipPaths: ['/health', '/metrics'],
      normalizePath: true,
      maxLabelCardinality: 1000,
    })
  );

  // Define some routes
  app.get('/health', (_req, res) => {
    res.json({ status: 'healthy' });
  });

  app.post('/login', (_req, res) => {
    try {
      // Simulate authentication
      const authenticated = Math.random() > 0.1; // 90% success rate

      if (authenticated) {
        recordAuthAttempt('success', 'bearer', 'example-service');
        res.json({ token: 'fake-jwt-token' });
      } else {
        recordAuthAttempt('failure', 'bearer', 'example-service');
        res.status(401).json({ error: 'Invalid credentials' });
      }
    } catch (err) {
      recordAuthAttempt('error', 'bearer', 'example-service');
      res.status(500).json({ error: 'Authentication error' });
    }
  });

  app.post('/policy/evaluate', (_req, res) => {
    // Simulate policy decision
    const decision = Math.random() > 0.3 ? 'allow' : 'deny';
    recordPolicyDecision(decision, 'example-service');
    res.json({ decision });
  });

  app.get('/detect/status', (_req, res) => {
    // Simulate detection alerts
    if (Math.random() > 0.8) {
      recordDetectionAlert('BRUTE_FORCE_001', 'high', 'example-service');
    }
    res.json({ alerts: 0 });
  });

  // Expose metrics endpoint
  app.get('/metrics', createExpressMiddleware());

  // Example of periodic health checks that update metrics
  setInterval(() => {
    setRedisConnectionStatus('example-service', Math.random() > 0.1); // 90% uptime
    setCircuitBreakerState('upstream-api', 0, 'example-service'); // 0=closed (normal)
    recordAuditEventsIngested(5, 'example-service');
    setActiveSessionCount(Math.floor(Math.random() * 100), 'example-service');
  }, 5000);

  console.log('\n=== Example 3: Express App ===');
  console.log('App configured with metrics. Routes:');
  console.log('  GET  /health          - Health check');
  console.log('  POST /login           - Authentication (records auth_attempts_total)');
  console.log('  POST /policy/evaluate - Policy decision (records policy_decisions_total)');
  console.log('  GET  /detect/status   - Detection alerts (records detection_alerts_total)');
  console.log('  GET  /metrics         - Prometheus metrics endpoint');
  console.log('\nAll HTTP requests are automatically tracked with request metrics.');
}

// ─── Example 4: Domain-Specific Metrics Helpers ───────────────────────────

export function exampleDomainMetrics(): void {
  initializeDefaultMetrics();

  // Simulate various security platform operations
  console.log('\n=== Example 4: Domain-Specific Metrics ===');

  // Rate limiting
  recordRateLimitHit('free', 'api-gateway');
  recordRateLimitHit('free', 'api-gateway');
  recordRateLimitHit('premium', 'api-gateway');
  console.log('Recorded rate limit hits');

  // Authentication attempts
  recordAuthAttempt('success', 'bearer', 'auth-service');
  recordAuthAttempt('success', 'bearer', 'auth-service');
  recordAuthAttempt('failure', 'basic', 'auth-service');
  recordAuthAttempt('error', 'oauth', 'auth-service');
  console.log('Recorded authentication attempts');

  // Policy decisions
  recordPolicyDecision('allow', 'policy-engine');
  recordPolicyDecision('allow', 'policy-engine');
  recordPolicyDecision('deny', 'policy-engine');
  recordPolicyDecision('challenge', 'policy-engine');
  console.log('Recorded policy decisions');

  // Detection alerts
  recordDetectionAlert('SQL_INJECTION_001', 'critical', 'threat-detector');
  recordDetectionAlert('XSS_DETECTED_002', 'high', 'threat-detector');
  recordDetectionAlert('BRUTE_FORCE_003', 'medium', 'threat-detector');
  recordDetectionAlert('ANOMALY_004', 'low', 'threat-detector');
  console.log('Recorded detection alerts');

  // Circuit breaker states
  setCircuitBreakerState('auth-service', 0, 'api-gateway'); // closed
  setCircuitBreakerState('policy-engine', 0, 'api-gateway'); // closed
  setCircuitBreakerState('threat-detector', 1, 'api-gateway'); // open
  setCircuitBreakerState('external-api', 2, 'api-gateway'); // half-open
  console.log('Set circuit breaker states');

  // Audit events
  recordAuditEventsIngested(42, 'audit-service');
  recordAuditEventsIngested(18, 'audit-service');
  console.log('Recorded audit events');

  // Session management
  setActiveSessionCount(150, 'session-manager');
  setActiveSessionCount(200, 'session-manager'); // updated
  console.log('Set active session count');

  // Redis connectivity
  setRedisConnectionStatus('cache-layer', true);
  setRedisConnectionStatus('session-store', false); // temporarily disconnected
  console.log('Set Redis connection status');

  console.log('\nMetrics snapshot:');
  const metrics = globalMetrics.serialize();
  const lines = metrics.split('\n').filter((line) => !line.startsWith('#') && line.trim());
  console.log(`Total metric samples: ${lines.length}`);
  lines.slice(0, 10).forEach((line) => console.log(`  ${line}`));
  console.log('  ...');
}

// ─── Example 5: Custom Registry for Testing ──────────────────────────────

export function exampleCustomRegistry(): void {
  // Create isolated registry for testing
  const testRegistry = new MetricsRegistry();

  testRegistry.registerCounter('test_requests', 'Test requests');
  testRegistry.registerGauge('test_gauge', 'Test gauge');

  // Record multiple observations
  for (let i = 0; i < 10; i++) {
    testRegistry.recordCounter('test_requests', 1, {
      endpoint: `/api/endpoint-${i % 3}`,
    });
  }

  testRegistry.recordGauge('test_gauge', 42, { instance: 'test' });

  console.log('\n=== Example 5: Custom Registry for Testing ===');
  const output = testRegistry.serialize();
  const sampleCount = output.split('\n').filter((line) => !line.startsWith('#') && line.trim()).length;
  console.log(`Custom registry has ${sampleCount} metric samples`);
}

// ─── Example 6: High-Cardinality Protection ────────────────────────────────

export function exampleCardinalityProtection(): void {
  initializeDefaultMetrics();

  console.log('\n=== Example 6: Cardinality Protection ===');

  // Simulate recording many different paths
  const paths = ['/api/users', '/api/posts', '/api/comments', '/api/likes'];
  const methods = ['GET', 'POST', 'PUT', 'DELETE'];
  const statusCodes = ['200', '201', '400', '401', '404', '500'];

  let count = 0;
  for (const path of paths) {
    for (const method of methods) {
      for (const status of statusCodes) {
        globalMetrics.recordCounter('http_requests_total', 1, {
          method,
          path,
          status_code: status,
          service: 'api-gateway',
        });
        count++;
      }
    }
  }

  console.log(`Recorded ${count} unique metric combinations`);
  console.log(`Total unique path/method/status combinations: ${paths.length * methods.length * statusCodes.length}`);

  // Show first few metrics
  const output = globalMetrics.serialize();
  const samples = output.split('\n').filter((line) => !line.startsWith('#') && line.includes('http_requests_total'));
  console.log(`\nFirst 5 recorded combinations:`);
  samples.slice(0, 5).forEach((line) => console.log(`  ${line}`));
}

// ─── Example 7: Histogram Bucket Distribution ──────────────────────────────

export function exampleHistogramBuckets(): void {
  const registry = new MetricsRegistry();

  // Register histogram with buckets in seconds
  registry.registerHistogram('request_duration_seconds', 'Request duration', [0.01, 0.05, 0.1, 0.5, 1]);

  // Record various latencies
  const latencies = [
    0.001, // very fast
    0.008, // < 0.01
    0.015, // 0.01-0.05
    0.075, // 0.05-0.1
    0.25, // 0.1-0.5
    0.8, // 0.5-1
    2.0, // > 1
  ];

  for (const latency of latencies) {
    registry.recordHistogram('request_duration_seconds', latency, { endpoint: 'api' });
  }

  console.log('\n=== Example 7: Histogram Buckets ===');
  const output = registry.serialize();
  const bucketLines = output.split('\n').filter((line) => line.includes('_bucket'));

  console.log('Histogram bucket distribution:');
  bucketLines.forEach((line) => {
    console.log(`  ${line}`);
  });
}

// ─── Run All Examples ────────────────────────────────────────────────────────

export function runAllExamples(): void {
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║  Prometheus Metrics Module - Examples                      ║');
  console.log('╚════════════════════════════════════════════════════════════╝');

  exampleBasicMetrics();
  exampleGlobalMetrics();
  exampleDomainMetrics();
  exampleCustomRegistry();
  exampleCardinalityProtection();
  exampleHistogramBuckets();

  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('All examples completed!');
  console.log('═══════════════════════════════════════════════════════════════\n');
}

// Run examples if this file is executed directly
if (require.main === module) {
  runAllExamples();
}
