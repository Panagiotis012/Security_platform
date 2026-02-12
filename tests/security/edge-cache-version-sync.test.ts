import { InMemoryInternalAuthReplayStore } from '@zerotrust/shared';
import {
  applyEdgeCacheVersionImport,
  buildEdgeCacheVersionExport,
  buildSignedEdgeCacheVersionExport,
} from '../../gateway/src/internal/internal-routes';
import { verifySignedEdgeCacheVersionBundle } from '../../gateway/src/internal/edge-cache-version-signing';
import { InMemoryEdgeCacheStore } from '../../gateway/src/state/inmemory-edge-cache-store';

describe('Edge Cache Version Sync', () => {
  test('exports route versions with a limit', async () => {
    const store = new InMemoryEdgeCacheStore(1000);
    await store.setRouteVersion('/a', '3');
    await store.setRouteVersion('/b', '9');
    await store.setRouteVersion('/c', '1');

    const exportPayload = await buildEdgeCacheVersionExport(store, 2);
    expect(exportPayload.entryCount).toBe(2);
    expect(exportPayload.entries).toHaveLength(2);
    expect(exportPayload.entries[0]?.routePath).toBe('/a');

    store.destroy();
  });

  test('builds signed bundles and rejects replay', async () => {
    const store = new InMemoryEdgeCacheStore(1000);
    await store.setRouteVersion('/public', '7');

    const signed = await buildSignedEdgeCacheVersionExport(store, 100, {
      sourceId: 'gateway-us-east',
      exportMaxEntries: 1000,
      defaultBundleTtlSeconds: 300,
      signExports: true,
      requireSignedImports: true,
      signingKeyId: 'gateway-edge-cache-v1',
      signingSecret: '0123456789abcdef0123456789abcdef',
      allowedSources: ['gateway-us-east'],
      allowedKeyIds: ['gateway-edge-cache-v1'],
      keyring: { 'gateway-edge-cache-v1': '0123456789abcdef0123456789abcdef' },
      replayProtectionEnabled: true,
      replayCacheMaxEntries: 5000,
      maxSkewSeconds: 300,
    });

    const replayStore = new InMemoryInternalAuthReplayStore(5000);
    const first = await verifySignedEdgeCacheVersionBundle(
      signed.bundle,
      {
        keyring: { 'gateway-edge-cache-v1': '0123456789abcdef0123456789abcdef' },
        allowedSources: ['gateway-us-east'],
        allowedKeyIds: ['gateway-edge-cache-v1'],
        maxSkewSeconds: 300,
        replayProtectionEnabled: true,
        replayCacheMaxEntries: 5000,
      },
      replayStore,
    );
    expect(first.ok).toBe(true);

    const second = await verifySignedEdgeCacheVersionBundle(
      signed.bundle,
      {
        keyring: { 'gateway-edge-cache-v1': '0123456789abcdef0123456789abcdef' },
        allowedSources: ['gateway-us-east'],
        allowedKeyIds: ['gateway-edge-cache-v1'],
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

    store.destroy();
  });

  test('imports with max strategy and skips lower/equal versions', async () => {
    const store = new InMemoryEdgeCacheStore(1000);
    await store.setRouteVersion('/public', '5');
    await store.setRouteVersion('/admin', '8');

    const imported = await applyEdgeCacheVersionImport(store, {
      source: 'gateway-us-west',
      strategy: 'max',
      entries: [
        { routePath: '/public', version: '9' },
        { routePath: '/admin', version: '8' },
        { routePath: '/public', version: '10' },
      ],
    });

    expect(imported.imported).toBe(1);
    expect(imported.updated).toBe(1);
    expect(imported.skipped).toBe(2);
    expect((await store.getRouteVersion('/public'))).toBe('9');
    expect((await store.getRouteVersion('/admin'))).toBe('8');

    store.destroy();
  });

  test('imports with overwrite strategy', async () => {
    const store = new InMemoryEdgeCacheStore(1000);
    await store.setRouteVersion('/public', '20');

    const imported = await applyEdgeCacheVersionImport(store, {
      source: 'gateway-eu',
      strategy: 'overwrite',
      entries: [
        { routePath: '/public', version: '3' },
      ],
    });

    expect(imported.imported).toBe(1);
    expect(imported.updated).toBe(1);
    expect(imported.skipped).toBe(0);
    expect((await store.getRouteVersion('/public'))).toBe('3');

    store.destroy();
  });
});
