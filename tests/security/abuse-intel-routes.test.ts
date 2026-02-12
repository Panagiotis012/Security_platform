import { InMemoryInternalAuthReplayStore } from '@zerotrust/shared';
import {
  buildAbuseIntelExport,
  buildSignedAbuseIntelExport,
  applyAbuseIntelImport,
} from '../../gateway/src/internal/internal-routes';
import { verifySignedAbuseIntelBundle } from '../../gateway/src/internal/abuse-intel-signing';
import { InMemorySecurityStateStore } from '../../gateway/src/state/inmemory-security-state-store';

describe('Abuse Intel Export/Import', () => {
  test('exports active blocked IP entries', async () => {
    const store = new InMemorySecurityStateStore();
    await store.blockIps(['203.0.113.10', '198.51.100.22'], 300, { reason: 'test' });

    const payload = await buildAbuseIntelExport(store, 100);
    expect(payload.entryCount).toBeGreaterThanOrEqual(2);
    expect(payload.entries.some((e) => e.ip === '203.0.113.10')).toBe(true);

    store.destroy();
  });

  test('imports peer intelligence with ttl filtering and dedupe', async () => {
    const store = new InMemorySecurityStateStore();
    const result = await applyAbuseIntelImport(store, {
      source: 'region-b',
      minTtlSeconds: 60,
      entries: [
        { ip: '203.0.113.11', ttlSeconds: 300, reason: 'waf' },
        { ip: '203.0.113.11', ttlSeconds: 300, reason: 'waf_duplicate' },
        { ip: '203.0.113.12', ttlSeconds: 30, reason: 'short' },
      ],
    });

    expect(result.imported).toBe(1);
    expect(result.skipped).toBe(2);
    expect(result.importedIps).toEqual(['203.0.113.11']);

    const blocked = await store.isIpBlocked('203.0.113.11');
    expect(blocked).not.toBeNull();
    expect(blocked?.reason).toContain('abuse_intel:region-b');

    store.destroy();
  });

  test('builds signed bundles and rejects replayed bundles', async () => {
    const store = new InMemorySecurityStateStore();
    await store.blockIps(['203.0.113.50'], 300, { reason: 'test' });

    const signed = await buildSignedAbuseIntelExport(store, 100, {
      enabled: true,
      sourceId: 'gateway-us-east',
      exportMaxEntries: 1000,
      defaultBundleTtlSeconds: 300,
      signExports: true,
      requireSignedImports: true,
      signingKeyId: 'gateway-abuse-v1',
      signingSecret: '0123456789abcdef0123456789abcdef',
      allowedSources: ['gateway-us-east'],
      allowedKeyIds: ['gateway-abuse-v1'],
      keyring: { 'gateway-abuse-v1': '0123456789abcdef0123456789abcdef' },
      replayProtectionEnabled: true,
      replayCacheMaxEntries: 5000,
      maxSkewSeconds: 300,
    });

    const replayStore = new InMemoryInternalAuthReplayStore(5000);
    const first = await verifySignedAbuseIntelBundle(
      signed.bundle,
      {
        keyring: { 'gateway-abuse-v1': '0123456789abcdef0123456789abcdef' },
        allowedSources: ['gateway-us-east'],
        allowedKeyIds: ['gateway-abuse-v1'],
        maxSkewSeconds: 300,
        replayProtectionEnabled: true,
        replayCacheMaxEntries: 5000,
      },
      replayStore,
    );
    expect(first.ok).toBe(true);

    const second = await verifySignedAbuseIntelBundle(
      signed.bundle,
      {
        keyring: { 'gateway-abuse-v1': '0123456789abcdef0123456789abcdef' },
        allowedSources: ['gateway-us-east'],
        allowedKeyIds: ['gateway-abuse-v1'],
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

  test('rejects tampered signed bundles', async () => {
    const store = new InMemorySecurityStateStore();
    await store.blockIps(['203.0.113.77'], 300, { reason: 'test' });

    const signed = await buildSignedAbuseIntelExport(store, 100, {
      enabled: true,
      sourceId: 'gateway-us-west',
      exportMaxEntries: 1000,
      defaultBundleTtlSeconds: 300,
      signExports: true,
      requireSignedImports: true,
      signingKeyId: 'gateway-abuse-v1',
      signingSecret: '0123456789abcdef0123456789abcdef',
      allowedSources: ['gateway-us-west'],
      allowedKeyIds: ['gateway-abuse-v1'],
      keyring: { 'gateway-abuse-v1': '0123456789abcdef0123456789abcdef' },
      replayProtectionEnabled: true,
      replayCacheMaxEntries: 5000,
      maxSkewSeconds: 300,
    });

    signed.bundle.entries.push({ ip: '198.51.100.200', ttlSeconds: 600 });

    const verification = await verifySignedAbuseIntelBundle(signed.bundle, {
      keyring: { 'gateway-abuse-v1': '0123456789abcdef0123456789abcdef' },
      allowedSources: ['gateway-us-west'],
      allowedKeyIds: ['gateway-abuse-v1'],
      maxSkewSeconds: 300,
      replayProtectionEnabled: false,
      replayCacheMaxEntries: 5000,
    });

    expect(verification.ok).toBe(false);
    if (!verification.ok) {
      expect(verification.reason).toBe('signature_invalid');
    }

    store.destroy();
  });
});
