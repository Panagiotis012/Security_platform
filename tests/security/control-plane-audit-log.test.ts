import { InMemoryInternalAuthReplayStore } from '@zerotrust/shared';
import {
  applyControlPlaneAuditImport,
  buildControlPlaneAuditEventInput,
  buildControlPlaneAuditExport,
  buildSignedControlPlaneAuditExport,
} from '../../gateway/src/internal/internal-routes';
import { verifySignedControlPlaneAuditBundle } from '../../gateway/src/internal/control-plane-audit-signing';
import { InMemoryControlPlaneAuditStore } from '../../gateway/src/state/inmemory-control-plane-audit-store';

describe('Control Plane Audit Log', () => {
  test('stores cursored events and supports after-cursor pagination', async () => {
    const store = new InMemoryControlPlaneAuditStore();

    await store.append(buildControlPlaneAuditEventInput({
      source: 'gateway-a',
      actor: 'telemetry',
      correlationId: 'c1',
      method: 'POST',
      path: '/internal/block-ip',
      statusCode: 200,
      outcome: 'success',
      requestBodyHash: 'a'.repeat(64),
      requestContentLength: 32,
      permissionScope: 'enforcement.write',
    }), 2);
    await store.append(buildControlPlaneAuditEventInput({
      source: 'gateway-a',
      actor: 'telemetry',
      correlationId: 'c2',
      method: 'PATCH',
      path: '/internal/security-controls',
      statusCode: 200,
      outcome: 'success',
      requestBodyHash: 'b'.repeat(64),
      requestContentLength: 44,
      permissionScope: 'security_controls.write',
    }), 2);
    const third = await store.append(buildControlPlaneAuditEventInput({
      source: 'gateway-a',
      actor: 'telemetry',
      correlationId: 'c3',
      method: 'POST',
      path: '/internal/edge-cache/version/import',
      statusCode: 200,
      outcome: 'success',
      requestBodyHash: 'c'.repeat(64),
      requestContentLength: 58,
      permissionScope: 'edge_cache.write',
    }), 2);

    const exportPayload = await buildControlPlaneAuditExport(store, '0', 100, 'gateway-a');
    expect(exportPayload.entryCount).toBe(2);
    expect(exportPayload.entries[0]?.cursor).toBe('2');
    expect(exportPayload.toCursor).toBe(third.cursor);

    const page2 = await buildControlPlaneAuditExport(store, '2', 100, 'gateway-a');
    expect(page2.entryCount).toBe(1);
    expect(page2.entries[0]?.cursor).toBe('3');
  });

  test('builds signed audit export and rejects replayed bundles', async () => {
    const store = new InMemoryControlPlaneAuditStore();
    await store.append(buildControlPlaneAuditEventInput({
      source: 'gateway-a',
      actor: 'telemetry',
      correlationId: 'c4',
      method: 'POST',
      path: '/internal/block-ip',
      statusCode: 200,
      outcome: 'success',
      requestBodyHash: 'd'.repeat(64),
      requestContentLength: 91,
      permissionScope: 'enforcement.write',
    }), 100);

    const signed = await buildSignedControlPlaneAuditExport(
      store,
      '0',
      100,
      {
        sourceId: 'gateway-a',
        exportMaxEntries: 1000,
        defaultBundleTtlSeconds: 300,
        signExports: true,
        requireSignedImports: true,
        signingKeyId: 'gateway-control-plane-audit-v1',
        signingSecret: '0123456789abcdef0123456789abcdef',
        allowedSources: ['gateway-a'],
        allowedKeyIds: ['gateway-control-plane-audit-v1'],
        keyring: { 'gateway-control-plane-audit-v1': '0123456789abcdef0123456789abcdef' },
        replayProtectionEnabled: true,
        replayCacheMaxEntries: 5000,
        maxSkewSeconds: 300,
      },
    );

    const replayStore = new InMemoryInternalAuthReplayStore(5000);
    const first = await verifySignedControlPlaneAuditBundle(
      signed.bundle,
      {
        keyring: { 'gateway-control-plane-audit-v1': '0123456789abcdef0123456789abcdef' },
        allowedSources: ['gateway-a'],
        allowedKeyIds: ['gateway-control-plane-audit-v1'],
        maxSkewSeconds: 300,
        replayProtectionEnabled: true,
        replayCacheMaxEntries: 5000,
      },
      replayStore,
    );
    expect(first.ok).toBe(true);

    const second = await verifySignedControlPlaneAuditBundle(
      signed.bundle,
      {
        keyring: { 'gateway-control-plane-audit-v1': '0123456789abcdef0123456789abcdef' },
        allowedSources: ['gateway-a'],
        allowedKeyIds: ['gateway-control-plane-audit-v1'],
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

  test('imports cursored audit events and dedupes by imported cursor', async () => {
    const remote = new InMemoryControlPlaneAuditStore();
    const local = new InMemoryControlPlaneAuditStore();

    await remote.append(buildControlPlaneAuditEventInput({
      source: 'gateway-remote',
      actor: 'telemetry',
      correlationId: 'c5',
      method: 'POST',
      path: '/internal/block-ip',
      statusCode: 200,
      outcome: 'success',
      requestBodyHash: 'e'.repeat(64),
      requestContentLength: 21,
      permissionScope: 'enforcement.write',
    }), 1000);
    await remote.append(buildControlPlaneAuditEventInput({
      source: 'gateway-remote',
      actor: 'telemetry',
      correlationId: 'c6',
      method: 'PATCH',
      path: '/internal/security-controls',
      statusCode: 200,
      outcome: 'success',
      requestBodyHash: 'f'.repeat(64),
      requestContentLength: 52,
      permissionScope: 'security_controls.write',
    }), 1000);

    const exported = await buildControlPlaneAuditExport(remote, '0', 1000, 'gateway-remote');
    const imported = await applyControlPlaneAuditImport(
      local,
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
    expect(imported.appended).toBe(2);
    expect(imported.latestImportedCursor).toBe(exported.toCursor);

    const importedAgain = await applyControlPlaneAuditImport(
      local,
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

    remote.destroy();
    local.destroy();
  });
});
