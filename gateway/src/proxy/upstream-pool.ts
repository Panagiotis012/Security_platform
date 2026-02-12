import { createHash } from 'crypto';

export interface UpstreamPoolEndpoint {
  url: string;
  weight: number;
  priority?: number;
}

export interface UpstreamOutlierEjectionConfig {
  enabled: boolean;
  consecutiveFailuresThreshold: number;
  ejectionDurationMs: number;
  maxEjectionPercent: number;
}

export interface UpstreamSteeringConfig {
  policy: 'weighted_random' | 'latency_aware';
  latencyEwmaAlpha: number;
  defaultLatencyMs: number;
}

interface EndpointState {
  consecutiveFailures: number;
  ejectedUntilMs: number;
  ewmaLatencyMs: number;
  latencySamples: number;
}

interface WeightedEndpoint {
  endpoint: UpstreamPoolEndpoint;
  weight: number;
}

function normalizeWeight(weight: number | undefined): number {
  const numeric = Number(weight);
  if (!Number.isFinite(numeric)) return 1;
  return Math.max(1, Math.floor(numeric));
}

function normalizePriority(priority: number | undefined): number {
  const numeric = Number(priority);
  if (!Number.isFinite(numeric)) return 0;
  return Math.max(0, Math.floor(numeric));
}

function normalizeAlpha(alpha: number | undefined): number {
  const numeric = Number(alpha);
  if (!Number.isFinite(numeric)) return 0.2;
  return Math.max(0.01, Math.min(1, numeric));
}

function normalizeLatencyMs(latencyMs: number | undefined): number {
  const numeric = Number(latencyMs);
  if (!Number.isFinite(numeric)) return 100;
  return Math.max(1, Math.floor(numeric));
}

function isEjected(state: EndpointState, nowMs: number): boolean {
  return state.ejectedUntilMs > nowMs;
}

function hashToUnitInterval(value: string): number {
  const digest = createHash('sha256').update(value).digest();
  const uint = digest.readUInt32BE(0);
  return (uint >>> 0) / 0x1_0000_0000;
}

export class UpstreamEndpointPool {
  private readonly endpoints: UpstreamPoolEndpoint[];
  private readonly states = new Map<string, EndpointState>();
  private readonly steering: UpstreamSteeringConfig;

  constructor(
    private readonly upstreamName: string,
    primaryUrl: string,
    endpoints: UpstreamPoolEndpoint[] | undefined,
    private readonly outlierConfig: UpstreamOutlierEjectionConfig,
    steeringConfig?: Partial<UpstreamSteeringConfig>,
  ) {
    const normalized = (endpoints && endpoints.length > 0)
      ? endpoints.map((endpoint) => ({
          url: endpoint.url,
          weight: normalizeWeight(endpoint.weight),
          priority: normalizePriority(endpoint.priority),
        }))
      : [{ url: primaryUrl, weight: 1, priority: 0 }];

    this.endpoints = normalized;
    this.steering = {
      policy: steeringConfig?.policy === 'latency_aware' ? 'latency_aware' : 'weighted_random',
      latencyEwmaAlpha: normalizeAlpha(steeringConfig?.latencyEwmaAlpha),
      defaultLatencyMs: normalizeLatencyMs(steeringConfig?.defaultLatencyMs),
    };

    for (const endpoint of this.endpoints) {
      this.states.set(endpoint.url, {
        consecutiveFailures: 0,
        ejectedUntilMs: 0,
        ewmaLatencyMs: this.steering.defaultLatencyMs,
        latencySamples: 0,
      });
    }
  }

  public selectEndpoint(
    nowMs: number = Date.now(),
    randomValue: number = Math.random(),
    affinityKey?: string,
  ): UpstreamPoolEndpoint {
    const candidates = this.endpoints.filter((endpoint) => {
      const state = this.states.get(endpoint.url);
      return !state || !isEjected(state, nowMs);
    });

    const active = candidates.length > 0 ? candidates : this.endpoints;
    const prioritized = candidates.length > 0
      ? this.selectLowestPriority(active)
      : active;
    if (prioritized.length === 1) {
      return prioritized[0]!;
    }

    const weighted = prioritized.map((endpoint) => ({
      endpoint,
      weight: this.effectiveWeight(endpoint),
    }));

    const selectionValue = affinityKey && affinityKey.length > 0
      ? hashToUnitInterval(affinityKey)
      : randomValue;
    return this.chooseWeighted(weighted, selectionValue);
  }

  public recordSuccess(url: string, observedLatencyMs?: number): void {
    const state = this.states.get(url);
    if (!state) return;
    state.consecutiveFailures = 0;

    if (!Number.isFinite(observedLatencyMs ?? 0) || (observedLatencyMs as number) <= 0) {
      return;
    }

    const latencyMs = Math.max(1, observedLatencyMs as number);
    if (state.latencySamples <= 0) {
      state.ewmaLatencyMs = latencyMs;
      state.latencySamples = 1;
      return;
    }

    const alpha = this.steering.latencyEwmaAlpha;
    state.ewmaLatencyMs = alpha * latencyMs + (1 - alpha) * state.ewmaLatencyMs;
    state.latencySamples += 1;
  }

  public recordFailure(url: string, nowMs: number = Date.now()): boolean {
    const state = this.states.get(url);
    if (!state) return false;

    state.consecutiveFailures += 1;

    if (!this.outlierConfig.enabled) {
      return false;
    }

    if (state.consecutiveFailures < this.outlierConfig.consecutiveFailuresThreshold) {
      return false;
    }

    const ejectedCount = this.currentEjectedCount(nowMs);
    const projectedEjectionPercent = ((ejectedCount + 1) / this.endpoints.length) * 100;
    if (projectedEjectionPercent > this.outlierConfig.maxEjectionPercent) {
      // Keep endpoint in rotation if ejecting it would exceed allowed blast radius.
      state.consecutiveFailures = this.outlierConfig.consecutiveFailuresThreshold;
      return false;
    }

    state.ejectedUntilMs = nowMs + this.outlierConfig.ejectionDurationMs;
    state.consecutiveFailures = 0;
    return true;
  }

  public getEndpointState(url: string, nowMs: number = Date.now()): {
    ejected: boolean;
    consecutiveFailures: number;
    ejectedUntilMs: number;
    ewmaLatencyMs: number;
    latencySamples: number;
  } | null {
    const state = this.states.get(url);
    if (!state) return null;
    return {
      ejected: isEjected(state, nowMs),
      consecutiveFailures: state.consecutiveFailures,
      ejectedUntilMs: state.ejectedUntilMs,
      ewmaLatencyMs: state.ewmaLatencyMs,
      latencySamples: state.latencySamples,
    };
  }

  public getSnapshot(nowMs: number = Date.now()): Array<{
    url: string;
    weight: number;
    priority: number;
    effectiveWeight: number;
    ejected: boolean;
    ejectedUntilMs: number;
    consecutiveFailures: number;
    ewmaLatencyMs: number;
    latencySamples: number;
  }> {
    return this.endpoints.map((endpoint) => {
      const state = this.states.get(endpoint.url) || {
        consecutiveFailures: 0,
        ejectedUntilMs: 0,
        ewmaLatencyMs: this.steering.defaultLatencyMs,
        latencySamples: 0,
      };
      return {
        url: endpoint.url,
        weight: endpoint.weight,
        priority: endpoint.priority ?? 0,
        effectiveWeight: this.effectiveWeight(endpoint),
        ejected: isEjected(state, nowMs),
        ejectedUntilMs: state.ejectedUntilMs,
        consecutiveFailures: state.consecutiveFailures,
        ewmaLatencyMs: state.ewmaLatencyMs,
        latencySamples: state.latencySamples,
      };
    });
  }

  private currentEjectedCount(nowMs: number): number {
    let count = 0;
    for (const endpoint of this.endpoints) {
      const state = this.states.get(endpoint.url);
      if (state && isEjected(state, nowMs)) {
        count += 1;
      }
    }
    return count;
  }

  private effectiveWeight(endpoint: UpstreamPoolEndpoint): number {
    if (this.steering.policy !== 'latency_aware') {
      return endpoint.weight;
    }

    const state = this.states.get(endpoint.url);
    const observedLatency = state?.ewmaLatencyMs ?? this.steering.defaultLatencyMs;
    const boundedLatency = Math.max(1, observedLatency);
    const latencyFactor = Math.max(
      0.05,
      Math.min(20, this.steering.defaultLatencyMs / boundedLatency),
    );
    return Math.max(0.0001, endpoint.weight * latencyFactor);
  }

  private chooseWeighted(weighted: WeightedEndpoint[], randomValue: number): UpstreamPoolEndpoint {
    const totalWeight = weighted.reduce((sum, item) => sum + item.weight, 0);
    if (totalWeight <= 0) {
      const clamped = Math.max(0, Math.min(0.999999999, randomValue));
      const idx = Math.floor(clamped * weighted.length);
      return weighted[Math.max(0, Math.min(weighted.length - 1, idx))]!.endpoint;
    }

    let needle = Math.max(0, Math.min(0.999999999, randomValue)) * totalWeight;
    for (const item of weighted) {
      needle -= item.weight;
      if (needle <= 0) {
        return item.endpoint;
      }
    }
    return weighted[weighted.length - 1]!.endpoint;
  }

  private selectLowestPriority(endpoints: UpstreamPoolEndpoint[]): UpstreamPoolEndpoint[] {
    let minPriority = Number.POSITIVE_INFINITY;
    for (const endpoint of endpoints) {
      const priority = endpoint.priority ?? 0;
      if (priority < minPriority) {
        minPriority = priority;
      }
    }
    return endpoints.filter((endpoint) => (endpoint.priority ?? 0) === minPriority);
  }

  public get size(): number {
    return this.endpoints.length;
  }

  public get name(): string {
    return this.upstreamName;
  }
}
