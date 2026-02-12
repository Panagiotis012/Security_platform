import { UpstreamEndpointPool } from '../../gateway/src/proxy/upstream-pool';

describe('UpstreamEndpointPool', () => {
  test('prefers higher-weight endpoint during selection', () => {
    const pool = new UpstreamEndpointPool(
      'identity',
      'https://identity-a.local',
      [
        { url: 'https://identity-a.local', weight: 1 },
        { url: 'https://identity-b.local', weight: 3 },
      ],
      {
        enabled: true,
        consecutiveFailuresThreshold: 3,
        ejectionDurationMs: 30_000,
        maxEjectionPercent: 50,
      },
    );

    const picks: Record<string, number> = {
      'https://identity-a.local': 0,
      'https://identity-b.local': 0,
    };

    for (let i = 0; i < 1000; i += 1) {
      const selected = pool.selectEndpoint(Date.now(), Math.random());
      picks[selected.url] += 1;
    }

    expect(picks['https://identity-b.local']).toBeGreaterThan(picks['https://identity-a.local']);
  });

  test('uses deterministic affinity key selection independent of random input', () => {
    const pool = new UpstreamEndpointPool(
      'identity',
      'https://identity-a.local',
      [
        { url: 'https://identity-a.local', weight: 1 },
        { url: 'https://identity-b.local', weight: 1 },
      ],
      {
        enabled: true,
        consecutiveFailuresThreshold: 3,
        ejectionDurationMs: 30_000,
        maxEjectionPercent: 50,
      },
    );

    const first = pool.selectEndpoint(Date.now(), 0.01, 'tenant:user-123').url;
    for (let i = 0; i < 100; i += 1) {
      const selected = pool.selectEndpoint(Date.now(), Math.random(), 'tenant:user-123').url;
      expect(selected).toBe(first);
    }
  });

  test('latency-aware steering shifts traffic toward lower-latency endpoint', () => {
    const pool = new UpstreamEndpointPool(
      'identity',
      'https://identity-a.local',
      [
        { url: 'https://identity-a.local', weight: 1 },
        { url: 'https://identity-b.local', weight: 1 },
      ],
      {
        enabled: true,
        consecutiveFailuresThreshold: 3,
        ejectionDurationMs: 30_000,
        maxEjectionPercent: 50,
      },
      {
        policy: 'latency_aware',
        latencyEwmaAlpha: 0.4,
        defaultLatencyMs: 100,
      },
    );

    for (let i = 0; i < 20; i += 1) {
      pool.recordSuccess('https://identity-a.local', 20);
      pool.recordSuccess('https://identity-b.local', 400);
    }

    const picks: Record<string, number> = {
      'https://identity-a.local': 0,
      'https://identity-b.local': 0,
    };
    for (let i = 0; i < 1000; i += 1) {
      const selected = pool.selectEndpoint(Date.now(), Math.random());
      picks[selected.url] += 1;
    }

    expect(picks['https://identity-a.local']).toBeGreaterThan(picks['https://identity-b.local']);
  });

  test('ejects failing endpoint and recovers after ejection window', () => {
    const now = Date.now();
    const pool = new UpstreamEndpointPool(
      'telemetry',
      'https://telemetry-a.local',
      [
        { url: 'https://telemetry-a.local', weight: 1 },
        { url: 'https://telemetry-b.local', weight: 1 },
      ],
      {
        enabled: true,
        consecutiveFailuresThreshold: 2,
        ejectionDurationMs: 5_000,
        maxEjectionPercent: 50,
      },
    );

    expect(pool.recordFailure('https://telemetry-a.local', now)).toBe(false);
    expect(pool.recordFailure('https://telemetry-a.local', now + 1)).toBe(true);

    const stateDuringEjection = pool.getEndpointState('https://telemetry-a.local', now + 100);
    expect(stateDuringEjection?.ejected).toBe(true);

    // During ejection, random=0 would normally select first endpoint, but it should skip ejected one.
    const selectedDuringEjection = pool.selectEndpoint(now + 100, 0);
    expect(selectedDuringEjection.url).toBe('https://telemetry-b.local');

    // After ejection window, endpoint returns to candidate set.
    const stateAfterWindow = pool.getEndpointState('https://telemetry-a.local', now + 6_000);
    expect(stateAfterWindow?.ejected).toBe(false);
  });

  test('respects max ejection percent guardrail', () => {
    const now = Date.now();
    const pool = new UpstreamEndpointPool(
      'supply-chain',
      'https://sc-a.local',
      [
        { url: 'https://sc-a.local', weight: 1 },
        { url: 'https://sc-b.local', weight: 1 },
      ],
      {
        enabled: true,
        consecutiveFailuresThreshold: 1,
        ejectionDurationMs: 30_000,
        maxEjectionPercent: 50,
      },
    );

    // First ejection is allowed.
    expect(pool.recordFailure('https://sc-a.local', now)).toBe(true);
    // Second ejection would exceed 50% (would be 100%), so it must be rejected.
    expect(pool.recordFailure('https://sc-b.local', now + 1)).toBe(false);

    const b = pool.getEndpointState('https://sc-b.local', now + 2);
    expect(b?.ejected).toBe(false);
  });

  test('uses endpoint priority for active-passive failover', () => {
    const now = Date.now();
    const pool = new UpstreamEndpointPool(
      'identity',
      'https://identity-a.local',
      [
        { url: 'https://identity-a.local', weight: 1, priority: 0 },
        { url: 'https://identity-b.local', weight: 1, priority: 1 },
      ],
      {
        enabled: true,
        consecutiveFailuresThreshold: 1,
        ejectionDurationMs: 30_000,
        maxEjectionPercent: 50,
      },
    );

    // While healthy, only priority 0 endpoint should be selected.
    for (let i = 0; i < 20; i += 1) {
      expect(pool.selectEndpoint(now + i, Math.random()).url).toBe('https://identity-a.local');
    }

    // Eject primary and verify failover to priority 1 endpoint.
    expect(pool.recordFailure('https://identity-a.local', now + 50)).toBe(true);
    expect(pool.selectEndpoint(now + 100, 0).url).toBe('https://identity-b.local');
  });
});
