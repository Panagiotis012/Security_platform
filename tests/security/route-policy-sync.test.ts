import { InMemoryInternalAuthReplayStore } from '@zerotrust/shared';
import { GatewayConfigSchema } from '../../gateway/config/default';
import {
  applyRoutePolicyImport,
  buildRoutePolicyExport,
  buildSignedRoutePolicyExport,
} from '../../gateway/src/internal/internal-routes';
import { verifySignedRoutePolicyBundle } from '../../gateway/src/internal/route-policy-signing';
import { RoutePolicyManager } from '../../gateway/src/proxy/route-policy-manager';

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
      },
      u2: {
        name: 'u2',
        url: 'http://example-2.invalid',
      },
    },
  });
}

describe('Route Policy Sync', () => {
  test('exports/imports runtime policy snapshots by revision', () => {
    const local = new RoutePolicyManager(makeConfig());
    const remote = new RoutePolicyManager(makeConfig());
    const patch = remote.applyPatch([
      {
        path: '/api',
        patch: {
          upstream: 'u2',
          methods: ['GET', 'POST'],
        },
      },
    ]);
    expect(patch.ok).toBe(true);

    const exported = buildRoutePolicyExport(remote, 'gateway-remote');
    const imported = applyRoutePolicyImport(local, {
      revision: exported.revision,
      routes: exported.routes,
    });
    expect(imported.ok).toBe(true);
    if (!imported.ok) return;
    expect(imported.changed).toBe(true);
    expect(imported.revision).toBe(exported.revision);

    const importedAgain = applyRoutePolicyImport(local, {
      revision: exported.revision,
      routes: exported.routes,
    });
    expect(importedAgain.ok).toBe(true);
    if (!importedAgain.ok) return;
    expect(importedAgain.changed).toBe(false);
    expect(importedAgain.skipped).toBe(true);
  });

  test('builds signed policy exports and rejects replayed bundles', async () => {
    const manager = new RoutePolicyManager(makeConfig());

    const signed = await buildSignedRoutePolicyExport(
      manager,
      {
        sourceId: 'gateway-a',
        defaultBundleTtlSeconds: 300,
        signExports: true,
        requireSignedImports: true,
        signingKeyId: 'gateway-route-policy-v1',
        signingSecret: '0123456789abcdef0123456789abcdef',
        allowedSources: ['gateway-a'],
        allowedKeyIds: ['gateway-route-policy-v1'],
        keyring: { 'gateway-route-policy-v1': '0123456789abcdef0123456789abcdef' },
        replayProtectionEnabled: true,
        replayCacheMaxEntries: 5000,
        maxSkewSeconds: 300,
      },
    );

    const replayStore = new InMemoryInternalAuthReplayStore(5000);
    const first = await verifySignedRoutePolicyBundle(
      signed.bundle,
      {
        keyring: { 'gateway-route-policy-v1': '0123456789abcdef0123456789abcdef' },
        allowedSources: ['gateway-a'],
        allowedKeyIds: ['gateway-route-policy-v1'],
        maxSkewSeconds: 300,
        replayProtectionEnabled: true,
        replayCacheMaxEntries: 5000,
      },
      replayStore,
    );
    expect(first.ok).toBe(true);

    const second = await verifySignedRoutePolicyBundle(
      signed.bundle,
      {
        keyring: { 'gateway-route-policy-v1': '0123456789abcdef0123456789abcdef' },
        allowedSources: ['gateway-a'],
        allowedKeyIds: ['gateway-route-policy-v1'],
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
