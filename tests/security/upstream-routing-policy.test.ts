import { InMemoryInternalAuthReplayStore } from '@zerotrust/shared';
import { GatewayConfigSchema } from '../../gateway/config/default';
import {
  applyUpstreamRoutingPolicyImport,
  buildSignedUpstreamRoutingPolicyExport,
  buildUpstreamRoutingPolicyExport,
} from '../../gateway/src/internal/internal-routes';
import { verifySignedUpstreamRoutingPolicyBundle } from '../../gateway/src/internal/upstream-policy-signing';
import { UpstreamRoutingPolicyManager } from '../../gateway/src/proxy/upstream-policy-manager';

function makeConfig() {
  return GatewayConfigSchema.parse({
    jwt: {
      jwksUri: 'https://example.invalid/jwks.json',
      issuer: 'issuer',
      audience: 'aud',
    },
    pdp: { url: 'https://example.invalid' },
    routes: [
      { path: '/api', upstream: 'u', methods: ['GET'] },
    ],
    upstreams: {
      u: {
        name: 'u',
        url: 'http://example.invalid',
        timeoutMs: 30_000,
        retries: 1,
      },
    },
  });
}

describe('Upstream Routing Policy', () => {
  test('exports/imports runtime policy snapshots by revision', () => {
    const local = new UpstreamRoutingPolicyManager(makeConfig());
    const remote = new UpstreamRoutingPolicyManager(makeConfig());
    const patch = remote.applyPatch({
      u: {
        retries: 4,
        timeoutMs: 45_000,
      },
    });
    expect(patch.ok).toBe(true);

    const exported = buildUpstreamRoutingPolicyExport(remote, 'gateway-remote');
    const imported = applyUpstreamRoutingPolicyImport(local, {
      revision: exported.revision,
      upstreams: exported.upstreams,
    });
    expect(imported.ok).toBe(true);
    if (!imported.ok) return;
    expect(imported.changed).toBe(true);
    expect(imported.revision).toBe(exported.revision);

    const importedAgain = applyUpstreamRoutingPolicyImport(local, {
      revision: exported.revision,
      upstreams: exported.upstreams,
    });
    expect(importedAgain.ok).toBe(true);
    if (!importedAgain.ok) return;
    expect(importedAgain.changed).toBe(false);
    expect(importedAgain.skipped).toBe(true);
  });

  test('builds signed policy exports and rejects replayed bundles', async () => {
    const manager = new UpstreamRoutingPolicyManager(makeConfig());

    const signed = await buildSignedUpstreamRoutingPolicyExport(
      manager,
      {
        sourceId: 'gateway-a',
        defaultBundleTtlSeconds: 300,
        signExports: true,
        requireSignedImports: true,
        signingKeyId: 'gateway-upstream-routing-v1',
        signingSecret: '0123456789abcdef0123456789abcdef',
        allowedSources: ['gateway-a'],
        allowedKeyIds: ['gateway-upstream-routing-v1'],
        keyring: { 'gateway-upstream-routing-v1': '0123456789abcdef0123456789abcdef' },
        replayProtectionEnabled: true,
        replayCacheMaxEntries: 5000,
        maxSkewSeconds: 300,
      },
    );

    const replayStore = new InMemoryInternalAuthReplayStore(5000);
    const first = await verifySignedUpstreamRoutingPolicyBundle(
      signed.bundle,
      {
        keyring: { 'gateway-upstream-routing-v1': '0123456789abcdef0123456789abcdef' },
        allowedSources: ['gateway-a'],
        allowedKeyIds: ['gateway-upstream-routing-v1'],
        maxSkewSeconds: 300,
        replayProtectionEnabled: true,
        replayCacheMaxEntries: 5000,
      },
      replayStore,
    );
    expect(first.ok).toBe(true);

    const second = await verifySignedUpstreamRoutingPolicyBundle(
      signed.bundle,
      {
        keyring: { 'gateway-upstream-routing-v1': '0123456789abcdef0123456789abcdef' },
        allowedSources: ['gateway-a'],
        allowedKeyIds: ['gateway-upstream-routing-v1'],
        maxSkewSeconds: 300,
        replayProtectionEnabled: true,
        replayCacheMaxEntries: 5000,
      },
      replayStore,
    );
    expect(second.ok).toBe(false);
    if (!second.ok) {
      expect(second.reason).toBe('bundle_replay_detected');
    }
  });
});

