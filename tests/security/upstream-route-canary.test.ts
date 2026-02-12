import type { RouteConfig } from '../../gateway/config/default';
import {
  buildRouteCanaryKey,
  CanaryRouteMonitor,
  computeCanaryRolloutBucket,
  resolveRouteUpstream,
} from '../../gateway/src/proxy/upstream-router';

function makeRoute(overrides: Partial<RouteConfig> = {}): RouteConfig {
  return {
    path: '/api',
    upstream: 'primary',
    methods: ['GET'],
    authRequired: true,
    bodyLimitBytes: 1_048_576,
    timeoutMs: 30_000,
    wafRuleSets: ['xss'],
    stripRequestHeaders: [],
    requiredScopes: [],
    stepUpRequired: false,
    ...overrides,
  };
}

describe('Upstream Route Canary', () => {
  test('computes deterministic canary rollout buckets', () => {
    const a = computeCanaryRolloutBucket('route:/api|ip:1.2.3.4');
    const b = computeCanaryRolloutBucket('route:/api|ip:1.2.3.4');
    const c = computeCanaryRolloutBucket('route:/api|ip:1.2.3.5');
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(a).toBeGreaterThanOrEqual(0);
    expect(a).toBeLessThanOrEqual(100);
  });

  test('selects canary upstream for 100% rollout', () => {
    const route = makeRoute({
      canary: {
        enabled: true,
        upstream: 'canary',
        rolloutPercent: 100,
        stickiness: 'ip',
        headerName: 'x-canary-key',
      },
    });
    const resolved = resolveRouteUpstream(route, {
      headers: {},
      ip: '203.0.113.10',
    });
    expect(resolved.upstreamName).toBe('canary');
    expect(resolved.usedCanary).toBe(true);
  });

  test('sticks to primary for 0% rollout', () => {
    const route = makeRoute({
      canary: {
        enabled: true,
        upstream: 'canary',
        rolloutPercent: 0,
        stickiness: 'ip',
        headerName: 'x-canary-key',
      },
    });
    const resolved = resolveRouteUpstream(route, {
      headers: {},
      ip: '203.0.113.10',
    });
    expect(resolved.upstreamName).toBe('primary');
    expect(resolved.usedCanary).toBe(false);
  });

  test('uses header stickiness key when configured', () => {
    const route = makeRoute({
      canary: {
        enabled: true,
        upstream: 'canary',
        rolloutPercent: 50,
        stickiness: 'header',
        headerName: 'x-canary-key',
      },
    });
    const first = resolveRouteUpstream(route, {
      headers: { 'x-canary-key': 'tenant-a' },
      ip: '203.0.113.10',
    });
    const second = resolveRouteUpstream(route, {
      headers: { 'x-canary-key': 'tenant-a' },
      ip: '198.51.100.20',
    });
    expect(first.bucket).toBe(second.bucket);
    expect(first.upstreamName).toBe(second.upstreamName);
  });

  test('suppresses canary when rollback is active', () => {
    const route = makeRoute({
      canary: {
        enabled: true,
        upstream: 'canary',
        rolloutPercent: 100,
        stickiness: 'ip',
        headerName: 'x-canary-key',
      },
    });
    const resolved = resolveRouteUpstream(
      route,
      {
        headers: {},
        ip: '203.0.113.10',
      },
      { rollbackActive: true },
    );
    expect(resolved.upstreamName).toBe('primary');
    expect(resolved.usedCanary).toBe(false);
    expect(resolved.rollbackSuppressed).toBe(true);
  });

  test('activates automatic rollback when canary error rate exceeds threshold', () => {
    const route = makeRoute({
      canary: {
        enabled: true,
        upstream: 'canary',
        rolloutPercent: 50,
        stickiness: 'ip',
        headerName: 'x-canary-key',
      },
    });
    const routeKey = buildRouteCanaryKey(route);
    const monitor = new CanaryRouteMonitor({
      enabled: true,
      windowMs: 60_000,
      minRequests: 3,
      errorRateThreshold: 0.5,
      latencyThresholdMs: 10_000,
      cooldownMs: 120_000,
      maxRoutes: 100,
    });

    const now = Date.parse('2026-02-11T12:00:00.000Z');
    for (let i = 0; i < 3; i += 1) {
      monitor.recordDecision(routeKey, {
        atMs: now + i * 1_000,
        routePath: route.path,
        primaryUpstream: route.upstream,
        canaryUpstream: route.canary?.upstream ?? 'canary',
        selectedUpstream: 'canary',
        usedCanary: true,
        rolloutPercent: 50,
        bucket: 10,
        rollbackSuppressed: false,
      }, now + i * 1_000);
    }

    monitor.recordOutcome(routeKey, { success: true, latencyMs: 120, nowMs: now + 1_000 });
    monitor.recordOutcome(routeKey, { success: false, latencyMs: 300, nowMs: now + 2_000 });
    const trigger = monitor.recordOutcome(routeKey, { success: false, latencyMs: 350, nowMs: now + 3_000 });
    expect(trigger.rollbackActivated).toBe(true);
    expect(monitor.isRollbackActive(routeKey, now + 4_000)).toBe(true);

    const snapshot = monitor.getSnapshot(route.path, now + 4_000);
    expect(snapshot.routeCount).toBe(1);
    expect(snapshot.routes[0]?.window.requests).toBe(3);
    expect(snapshot.routes[0]?.window.failures).toBe(2);
    expect(snapshot.routes[0]?.rollback.active).toBe(true);
  });
});
