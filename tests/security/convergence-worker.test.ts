import {
  buildControlPlaneAuditEventInput,
  buildControlPlaneAuditExport,
  buildEdgeInvalidationEventInput,
  buildEdgeInvalidationExport,
  buildSecurityControlsAuditEntry,
  buildSecurityControlsHistoryExport,
  buildSecurityControlsRevision,
  buildSecurityControlsSnapshot,
  buildRoutePolicyExport,
  buildUpstreamRoutingPolicyExport,
} from '../../gateway/src/internal/internal-routes';
import {
  detectControlPlaneAuditCursorDrift,
  detectEdgeCacheVersionDrift,
  detectEdgeInvalidationCursorDrift,
  detectRoutePolicyDrift,
  detectSecurityControlsDrift,
  detectUpstreamRoutingDrift,
  runConvergenceOnce,
} from '../../gateway/src/internal/convergence-worker';
import { GatewayConfigSchema } from '../../gateway/config/default';
import { RoutePolicyManager } from '../../gateway/src/proxy/route-policy-manager';
import { UpstreamRoutingPolicyManager } from '../../gateway/src/proxy/upstream-policy-manager';
import { InMemoryEdgeCacheStore } from '../../gateway/src/state/inmemory-edge-cache-store';
import { InMemoryControlPlaneAuditStore } from '../../gateway/src/state/inmemory-control-plane-audit-store';
import { InMemoryEdgeInvalidationEventStore } from '../../gateway/src/state/inmemory-edge-invalidation-event-store';
import { InMemorySecurityControlsAuditStore } from '../../gateway/src/state/inmemory-security-controls-audit-store';

function makeConfig() {
  return GatewayConfigSchema.parse({
    jwt: {
      jwksUri: 'https://example.invalid/jwks.json',
      issuer: 'issuer',
      audience: 'aud',
    },
    pdp: { url: 'https://example.invalid' },
    waf: {
      enabled: true,
      riskScoreThreshold: 20,
    },
    botManagement: {
      enabled: true,
      challengeThreshold: 30,
      blockThreshold: 60,
      clearance: {
        enabled: true,
        secret: 'bot-clearance-secret-1234567890',
        previousSecrets: ['old-secret'],
      },
    },
    accessControl: {
      enabled: false,
      policy: {
        ipDenylist: [],
      },
    },
    routes: [
      { path: '/api', upstream: 'u', methods: ['GET'] },
    ],
    upstreams: {
      u: { name: 'u', url: 'http://example.invalid' },
      u2: { name: 'u2', url: 'http://example-2.invalid' },
    },
  });
}

describe('Convergence Worker', () => {
  test('detects revision and edge-version drifts', () => {
    expect(detectSecurityControlsDrift('r1:aaa', 'r2:bbb')).toBe(true);
    expect(detectSecurityControlsDrift('r1:aaa', 'r1:aaa')).toBe(false);
    expect(
      detectEdgeCacheVersionDrift(
        [{ routePath: '/public', version: '2' }],
        [{ routePath: '/public', version: '3' }],
      ),
    ).toBe(true);
    expect(
      detectEdgeCacheVersionDrift(
        [{ routePath: '/public', version: '3' }],
        [{ routePath: '/public', version: '3' }],
      ),
    ).toBe(false);
    expect(detectEdgeInvalidationCursorDrift('5', '9')).toBe(true);
    expect(detectEdgeInvalidationCursorDrift('9', '9')).toBe(false);
    expect(detectControlPlaneAuditCursorDrift('12', '15')).toBe(true);
    expect(detectControlPlaneAuditCursorDrift('15', '15')).toBe(false);
    expect(detectUpstreamRoutingDrift('ur:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'ur:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')).toBe(true);
    expect(detectUpstreamRoutingDrift('ur:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'ur:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe(false);
    expect(detectRoutePolicyDrift('rr:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'rr:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')).toBe(true);
    expect(detectRoutePolicyDrift('rr:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'rr:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe(false);
  });

  test('auto-heals local state from peer exports', async () => {
    const localAudit = new InMemorySecurityControlsAuditStore();
    const remoteAudit = new InMemorySecurityControlsAuditStore();
    const localEdge = new InMemoryEdgeCacheStore(1000);
    const remoteEdge = new InMemoryEdgeCacheStore(1000);
    const localControlPlaneAudit = new InMemoryControlPlaneAuditStore();
    const remoteControlPlaneAudit = new InMemoryControlPlaneAuditStore();
    const localInvalidation = new InMemoryEdgeInvalidationEventStore();
    const remoteInvalidation = new InMemoryEdgeInvalidationEventStore();
    const secret = 'audit-secret-0123456789abcdef';
    const localConfig = makeConfig();
    const remoteConfig = makeConfig();
    const localUpstreamRouting = new UpstreamRoutingPolicyManager(localConfig);
    const remoteUpstreamRouting = new UpstreamRoutingPolicyManager(remoteConfig);
    const config = localConfig;
    const snapshot = buildSecurityControlsSnapshot(config);
    const localRoutePolicy = new RoutePolicyManager(localConfig);
    const remoteRoutePolicy = new RoutePolicyManager(remoteConfig);

    const now = Date.now();
    await localEdge.set('cache:/public', '/public', 60, {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      bodyBase64: Buffer.from('{"ok":true}', 'utf8').toString('base64'),
      createdAtMs: now,
      expiresAtMs: now + 60_000,
    });

    const remoteEntry = buildSecurityControlsAuditEntry({
      patch: { waf: { riskScoreThreshold: 31 } },
      snapshot,
      previousEntryHash: null,
      actor: 'telemetry',
      correlationId: 'peer-1',
      signingSecret: secret,
    });
    await remoteAudit.append(remoteEntry, 100);
    await remoteEdge.setRouteVersion('/public', '9');
    await remoteInvalidation.append(buildEdgeInvalidationEventInput({
      source: 'gateway-remote',
      actor: 'ops',
      kind: 'purge',
      payload: { routePath: '/public', maxDelete: 500 },
    }), 1000);
    await remoteInvalidation.append(buildEdgeInvalidationEventInput({
      source: 'gateway-remote',
      actor: 'ops',
      kind: 'version_set',
      payload: { routePath: '/public', version: '11' },
    }), 1000);
    await remoteControlPlaneAudit.append(buildControlPlaneAuditEventInput({
      source: 'gateway-remote',
      actor: 'telemetry',
      correlationId: 'corr-audit-1',
      method: 'POST',
      path: '/internal/block-ip',
      statusCode: 200,
      outcome: 'success',
      requestBodyHash: 'a'.repeat(64),
      requestContentLength: 123,
      permissionScope: 'enforcement.write',
    }), 1000);
    const remoteRoutingPatch = remoteUpstreamRouting.applyPatch({
      u: {
        timeoutMs: 45_000,
        retries: 4,
      },
    });
    expect(remoteRoutingPatch.ok).toBe(true);
    const remoteRoutePolicyPatch = remoteRoutePolicy.applyPatch([
      {
        path: '/api',
        patch: {
          upstream: 'u2',
          methods: ['GET', 'POST'],
        },
      },
    ]);
    expect(remoteRoutePolicyPatch.ok).toBe(true);

    const remotePointers = await remoteAudit.getChainPointers();
    const remoteRevision = buildSecurityControlsRevision({
      total: remotePointers.total,
      latestEntryHash: remotePointers.latestEntryHash,
      anchorHash: remotePointers.anchorHash,
    });
    const remoteHistory = await buildSecurityControlsHistoryExport(remoteAudit, 100);
    const remoteEdgeExport = await remoteEdge.listRouteVersions(100);
    const remoteUpstreamPolicyExport = buildUpstreamRoutingPolicyExport(
      remoteUpstreamRouting,
      'gateway-remote',
    );
    const remoteRoutePolicyExport = buildRoutePolicyExport(
      remoteRoutePolicy,
      'gateway-remote',
    );

    const fetchFn = async (url: string) => {
      if (url.endsWith('/internal/security-controls')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ revision: remoteRevision }),
        };
      }
      if (url.includes('/internal/security-controls/history/export')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ signed: false, entries: remoteHistory.entries }),
        };
      }
      if (url.includes('/internal/edge-cache/version/export')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ signed: false, entries: remoteEdgeExport, strategy: 'max' }),
        };
      }
      if (url.includes('/internal/edge-cache/invalidation/export')) {
        const parsed = new URL(url);
        const afterCursor = parsed.searchParams.get('afterCursor') ?? '0';
        const payload = await buildEdgeInvalidationExport(
          remoteInvalidation,
          afterCursor,
          100,
          'gateway-remote',
        );
        return {
          ok: true,
          status: 200,
          json: async () => ({ signed: false, ...payload }),
        };
      }
      if (url.includes('/internal/control-plane/audit/export')) {
        const parsed = new URL(url);
        const afterCursor = parsed.searchParams.get('afterCursor') ?? '0';
        const payload = await buildControlPlaneAuditExport(
          remoteControlPlaneAudit,
          afterCursor,
          100,
          'gateway-remote',
        );
        return {
          ok: true,
          status: 200,
          json: async () => ({ signed: false, ...payload }),
        };
      }
      if (url.includes('/internal/upstreams/policy/export')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ signed: false, ...remoteUpstreamPolicyExport }),
        };
      }
      if (url.includes('/internal/routes/policy/export')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ signed: false, ...remoteRoutePolicyExport }),
        };
      }
      return {
        ok: false,
        status: 404,
        json: async () => ({}),
      };
    };

    const run = await runConvergenceOnce({
      peers: ['https://peer-a.example'],
      autoHeal: true,
      exportLimit: 100,
      fetchFn,
      securityControls: {
        auditStore: localAudit,
        signingSecret: secret,
        maxEntries: 1000,
        requireSignedImports: false,
        verification: {
          keyring: {},
          allowedSources: [],
          allowedKeyIds: [],
          maxSkewSeconds: 300,
          replayProtectionEnabled: false,
          replayCacheMaxEntries: 5000,
        },
      },
      edgeCache: {
        store: localEdge,
        requireSignedImports: false,
        verification: {
          keyring: {},
          allowedSources: [],
          allowedKeyIds: [],
          maxSkewSeconds: 300,
          replayProtectionEnabled: false,
          replayCacheMaxEntries: 5000,
        },
        invalidation: {
          eventStore: localInvalidation,
          maxEntries: 10_000,
          localSourceId: 'gateway-local',
          requireSignedImports: false,
          verification: {
            keyring: {},
            allowedSources: [],
            allowedKeyIds: [],
            maxSkewSeconds: 300,
            replayProtectionEnabled: false,
            replayCacheMaxEntries: 5000,
          },
        },
      },
      controlPlaneAudit: {
        store: localControlPlaneAudit,
        maxEntries: 10_000,
        localSourceId: 'gateway-local',
        requireSignedImports: false,
        verification: {
          keyring: {},
          allowedSources: [],
          allowedKeyIds: [],
          maxSkewSeconds: 300,
          replayProtectionEnabled: false,
          replayCacheMaxEntries: 5000,
        },
      },
      upstreamRouting: {
        manager: localUpstreamRouting,
        requireSignedImports: false,
        verification: {
          keyring: {},
          allowedSources: [],
          allowedKeyIds: [],
          maxSkewSeconds: 300,
          replayProtectionEnabled: false,
          replayCacheMaxEntries: 5000,
        },
      },
      routePolicy: {
        manager: localRoutePolicy,
        requireSignedImports: false,
        verification: {
          keyring: {},
          allowedSources: [],
          allowedKeyIds: [],
          maxSkewSeconds: 300,
          replayProtectionEnabled: false,
          replayCacheMaxEntries: 5000,
        },
      },
    });

    expect(run.errors).toBe(0);
    expect(run.results[0]?.securityControls.imported).toBe(1);
    expect(run.results[0]?.edgeInvalidation?.imported).toBe(2);
    expect(run.results[0]?.edgeInvalidation?.healed).toBe(true);
    expect(run.results[0]?.controlPlaneAudit?.imported).toBe(1);
    expect(run.results[0]?.controlPlaneAudit?.healed).toBe(true);
    expect(run.results[0]?.upstreamRouting?.driftDetected).toBe(true);
    expect(run.results[0]?.upstreamRouting?.healed).toBe(true);
    expect(run.results[0]?.routePolicy?.driftDetected).toBe(true);
    expect(run.results[0]?.routePolicy?.healed).toBe(true);
    expect(await localEdge.get('cache:/public')).toBeNull();
    expect(await localEdge.getRouteVersion('/public')).toBe('11');
    expect(localUpstreamRouting.getRevision()).toBe(remoteUpstreamRouting.getRevision());
    expect(localRoutePolicy.getRevision()).toBe(remoteRoutePolicy.getRevision());

    localControlPlaneAudit.destroy();
    remoteControlPlaneAudit.destroy();
    localEdge.destroy();
    remoteEdge.destroy();
    localInvalidation.destroy();
    remoteInvalidation.destroy();
  });

  test('enforces policy quorum and writes signed convergence audit telemetry', async () => {
    const localAudit = new InMemorySecurityControlsAuditStore();
    const localControlPlaneAudit = new InMemoryControlPlaneAuditStore();
    const localConfig = makeConfig();
    const localUpstreamRouting = new UpstreamRoutingPolicyManager(localConfig);
    const localRoutePolicy = new RoutePolicyManager(localConfig);

    const peerAConfig = makeConfig();
    const peerBConfig = makeConfig();
    const peerAUpstreamRouting = new UpstreamRoutingPolicyManager(peerAConfig);
    const peerBUpstreamRouting = new UpstreamRoutingPolicyManager(peerBConfig);
    const peerARoutePolicy = new RoutePolicyManager(peerAConfig);
    const peerBRoutePolicy = new RoutePolicyManager(peerBConfig);

    const peerAUpstreamPatch = peerAUpstreamRouting.applyPatch({
      u: { timeoutMs: 40_000, retries: 3 },
    });
    const peerBUpstreamPatch = peerBUpstreamRouting.applyPatch({
      u: { timeoutMs: 50_000, retries: 5 },
    });
    expect(peerAUpstreamPatch.ok).toBe(true);
    expect(peerBUpstreamPatch.ok).toBe(true);

    const peerARoutePatch = peerARoutePolicy.applyPatch([
      {
        path: '/api',
        patch: { upstream: 'u2', methods: ['GET', 'POST'] },
      },
    ]);
    const peerBRoutePatch = peerBRoutePolicy.applyPatch([
      {
        path: '/api',
        patch: { methods: ['GET', 'PUT'] },
      },
    ]);
    expect(peerARoutePatch.ok).toBe(true);
    expect(peerBRoutePatch.ok).toBe(true);

    const peerAUpstreamExport = buildUpstreamRoutingPolicyExport(peerAUpstreamRouting, 'peer-a');
    const peerBUpstreamExport = buildUpstreamRoutingPolicyExport(peerBUpstreamRouting, 'peer-b');
    const peerARouteExport = buildRoutePolicyExport(peerARoutePolicy, 'peer-a');
    const peerBRouteExport = buildRoutePolicyExport(peerBRoutePolicy, 'peer-b');

    const localPointers = await localAudit.getChainPointers();
    const localSecurityRevision = buildSecurityControlsRevision({
      total: localPointers.total,
      latestEntryHash: localPointers.latestEntryHash,
      anchorHash: localPointers.anchorHash,
    });

    const fetchFn = async (url: string) => {
      const peer = new URL(url).origin;
      if (url.endsWith('/internal/security-controls')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ revision: localSecurityRevision }),
        };
      }
      if (url.includes('/internal/upstreams/policy/export')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            signed: false,
            ...(peer === 'https://peer-a.example' ? peerAUpstreamExport : peerBUpstreamExport),
          }),
        };
      }
      if (url.includes('/internal/routes/policy/export')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            signed: false,
            ...(peer === 'https://peer-a.example' ? peerARouteExport : peerBRouteExport),
          }),
        };
      }
      return {
        ok: false,
        status: 404,
        json: async () => ({}),
      };
    };

    const run = await runConvergenceOnce({
      peers: ['https://peer-a.example', 'https://peer-b.example'],
      autoHeal: true,
      exportLimit: 100,
      fetchFn,
      policyQuorum: {
        enabled: true,
        minPeers: 2,
      },
      securityControls: {
        auditStore: localAudit,
        signingSecret: 'audit-secret-0123456789abcdef',
        maxEntries: 1000,
        requireSignedImports: false,
        verification: {
          keyring: {},
          allowedSources: [],
          allowedKeyIds: [],
          maxSkewSeconds: 300,
          replayProtectionEnabled: false,
          replayCacheMaxEntries: 5000,
        },
      },
      upstreamRouting: {
        manager: localUpstreamRouting,
        requireSignedImports: false,
        verification: {
          keyring: {},
          allowedSources: [],
          allowedKeyIds: [],
          maxSkewSeconds: 300,
          replayProtectionEnabled: false,
          replayCacheMaxEntries: 5000,
        },
      },
      routePolicy: {
        manager: localRoutePolicy,
        requireSignedImports: false,
        verification: {
          keyring: {},
          allowedSources: [],
          allowedKeyIds: [],
          maxSkewSeconds: 300,
          replayProtectionEnabled: false,
          replayCacheMaxEntries: 5000,
        },
      },
      auditTrail: {
        store: localControlPlaneAudit,
        maxEntries: 1000,
        localSourceId: 'gateway-local',
        actor: 'convergence-worker',
        signingKeyId: 'gateway-convergence-v1',
        signingSecret: '0123456789abcdef0123456789abcdef',
        path: '/internal/control-plane/convergence/peer',
        permissionScope: 'convergence.write',
      },
    });

    expect(run.results).toHaveLength(2);
    expect(run.results[0]?.upstreamRouting?.healed).toBe(false);
    expect(run.results[0]?.upstreamRouting?.error).toContain('quorum_not_met');
    expect(run.results[0]?.routePolicy?.healed).toBe(false);
    expect(run.results[0]?.routePolicy?.error).toContain('quorum_not_met');
    expect(run.results[0]?.telemetry?.signature).toMatch(/^[a-f0-9]{64}$/);
    expect(localUpstreamRouting.getRevision()).not.toBe(peerAUpstreamRouting.getRevision());
    expect(localUpstreamRouting.getRevision()).not.toBe(peerBUpstreamRouting.getRevision());
    expect(localRoutePolicy.getRevision()).not.toBe(peerARoutePolicy.getRevision());
    expect(localRoutePolicy.getRevision()).not.toBe(peerBRoutePolicy.getRevision());

    const auditEvents = await localControlPlaneAudit.listAfter('0', 100);
    expect(auditEvents.entries.length).toBe(2);
    expect(auditEvents.entries.every((entry) => entry.path === '/internal/control-plane/convergence/peer')).toBe(true);
    expect(auditEvents.entries.every((entry) => entry.permissionScope === 'convergence.write')).toBe(true);
    expect(auditEvents.entries.every((entry) => /^[a-f0-9]{64}$/.test(entry.requestBodyHash))).toBe(true);

    localControlPlaneAudit.destroy();
  });
});
