import { InMemoryInternalAuthReplayStore } from '@zerotrust/shared';
import {
  applyEdgeInvalidationImport,
  buildEdgeInvalidationEventInput,
  buildEdgeInvalidationExport,
  buildSignedEdgeInvalidationExport,
} from '../../gateway/src/internal/internal-routes';
import { verifySignedEdgeInvalidationBundle } from '../../gateway/src/internal/edge-invalidation-signing';
import { InMemoryEdgeInvalidationEventStore } from '../../gateway/src/state/inmemory-edge-invalidation-event-store';
import { InMemoryEdgeCacheStore } from '../../gateway/src/state/inmemory-edge-cache-store';

function cachedResponse(body: string) {
  const now = Date.now();
  return {
    statusCode: 200,
    headers: {
      'content-type': 'application/json',
    },
    bodyBase64: Buffer.from(body, 'utf8').toString('base64'),
    createdAtMs: now,
    expiresAtMs: now + 60_000,
  };
}

describe('Edge Invalidation Log', () => {
  test('stores cursored events and supports after-cursor pagination', async () => {
    const store = new InMemoryEdgeInvalidationEventStore();

    await store.append(buildEdgeInvalidationEventInput({
      source: 'gateway-a',
      actor: 'telemetry',
      kind: 'purge',
      payload: { routePath: '/a', maxDelete: 100 },
    }), 2);
    await store.append(buildEdgeInvalidationEventInput({
      source: 'gateway-a',
      actor: 'telemetry',
      kind: 'version_set',
      payload: { routePath: '/a', version: '2' },
    }), 2);
    const third = await store.append(buildEdgeInvalidationEventInput({
      source: 'gateway-a',
      actor: 'telemetry',
      kind: 'version_set',
      payload: { routePath: '/b', version: '3' },
    }), 2);

    const exportPayload = await buildEdgeInvalidationExport(store, '0', 100);
    expect(exportPayload.entryCount).toBe(2);
    expect(exportPayload.entries[0]?.cursor).toBe('2');
    expect(exportPayload.toCursor).toBe(third.cursor);

    const page2 = await buildEdgeInvalidationExport(store, '2', 100);
    expect(page2.entryCount).toBe(1);
    expect(page2.entries[0]?.cursor).toBe('3');
  });

  test('builds signed invalidation export and rejects replayed bundles', async () => {
    const store = new InMemoryEdgeInvalidationEventStore();
    await store.append(buildEdgeInvalidationEventInput({
      source: 'gateway-a',
      actor: 'telemetry',
      kind: 'version_set',
      payload: { routePath: '/public', version: '9' },
    }), 100);

    const signed = await buildSignedEdgeInvalidationExport(
      store,
      '0',
      100,
      {
        sourceId: 'gateway-a',
        exportMaxEntries: 1000,
        defaultBundleTtlSeconds: 300,
        signExports: true,
        requireSignedImports: true,
        signingKeyId: 'gateway-edge-invalidation-v1',
        signingSecret: '0123456789abcdef0123456789abcdef',
        allowedSources: ['gateway-a'],
        allowedKeyIds: ['gateway-edge-invalidation-v1'],
        keyring: { 'gateway-edge-invalidation-v1': '0123456789abcdef0123456789abcdef' },
        replayProtectionEnabled: true,
        replayCacheMaxEntries: 5000,
        maxSkewSeconds: 300,
      },
    );

    const replayStore = new InMemoryInternalAuthReplayStore(5000);
    const first = await verifySignedEdgeInvalidationBundle(
      signed.bundle,
      {
        keyring: { 'gateway-edge-invalidation-v1': '0123456789abcdef0123456789abcdef' },
        allowedSources: ['gateway-a'],
        allowedKeyIds: ['gateway-edge-invalidation-v1'],
        maxSkewSeconds: 300,
        replayProtectionEnabled: true,
        replayCacheMaxEntries: 5000,
      },
      replayStore,
    );
    expect(first.ok).toBe(true);

    const second = await verifySignedEdgeInvalidationBundle(
      signed.bundle,
      {
        keyring: { 'gateway-edge-invalidation-v1': '0123456789abcdef0123456789abcdef' },
        allowedSources: ['gateway-a'],
        allowedKeyIds: ['gateway-edge-invalidation-v1'],
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

  test('imports cursored events and replays purge/version-set effects', async () => {
    const remoteLog = new InMemoryEdgeInvalidationEventStore();
    const localLog = new InMemoryEdgeInvalidationEventStore();
    const localCache = new InMemoryEdgeCacheStore(1000);

    await localCache.set('k1', '/public', 60, cachedResponse('{"ok":true}'));

    await remoteLog.append(buildEdgeInvalidationEventInput({
      source: 'gateway-remote',
      actor: 'ops',
      kind: 'purge',
      payload: { routePath: '/public', maxDelete: 100 },
    }), 1000);
    await remoteLog.append(buildEdgeInvalidationEventInput({
      source: 'gateway-remote',
      actor: 'ops',
      kind: 'version_set',
      payload: { routePath: '/public', version: '7' },
    }), 1000);

    const exported = await buildEdgeInvalidationExport(remoteLog, '0', 1000);
    const imported = await applyEdgeInvalidationImport(
      localLog,
      localCache,
      {
        source: 'gateway-remote',
        fromCursor: exported.fromCursor,
        toCursor: exported.toCursor,
        entries: exported.entries,
      },
      {
        maxEntries: 1000,
        localSourceId: 'gateway-local',
      },
    );

    expect(imported.imported).toBe(2);
    expect(imported.applied).toBe(2);
    expect(imported.appended).toBe(2);
    expect(imported.latestImportedCursor).toBe(exported.toCursor);
    expect(await localCache.get('k1')).toBeNull();
    expect(await localCache.getRouteVersion('/public')).toBe('7');

    const importedAgain = await applyEdgeInvalidationImport(
      localLog,
      localCache,
      {
        source: 'gateway-remote',
        fromCursor: exported.fromCursor,
        toCursor: exported.toCursor,
        entries: exported.entries,
      },
      {
        maxEntries: 1000,
        localSourceId: 'gateway-local',
      },
    );
    expect(importedAgain.imported).toBe(0);
    expect(importedAgain.skipped).toBe(2);

    localCache.destroy();
    remoteLog.destroy();
    localLog.destroy();
  });
});
