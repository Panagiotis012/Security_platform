import {
  signEdgeCacheVersionBundle,
  verifySignedEdgeCacheVersionBundle,
} from '../../gateway/src/internal/edge-cache-version-signing';

describe('Edge Cache Version Bundle Signing', () => {
  test('verifies signed bundle and rejects tampering', async () => {
    const secret = '0123456789abcdef0123456789abcdef';
    const now = Date.now();
    const bundle = signEdgeCacheVersionBundle({
      source: 'gateway-us-east',
      bundleId: 'bundle-1',
      keyId: 'gateway-edge-cache-v1',
      generatedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 120_000).toISOString(),
      strategy: 'max',
      entries: [
        { routePath: '/public', version: '12' },
      ],
    }, secret);

    const ok = await verifySignedEdgeCacheVersionBundle(bundle, {
      keyring: { 'gateway-edge-cache-v1': secret },
      allowedSources: ['gateway-us-east'],
      allowedKeyIds: ['gateway-edge-cache-v1'],
      maxSkewSeconds: 300,
      replayProtectionEnabled: false,
      replayCacheMaxEntries: 5000,
    });
    expect(ok.ok).toBe(true);

    bundle.entries.push({ routePath: '/admin', version: '3' });
    const tampered = await verifySignedEdgeCacheVersionBundle(bundle, {
      keyring: { 'gateway-edge-cache-v1': secret },
      allowedSources: ['gateway-us-east'],
      allowedKeyIds: ['gateway-edge-cache-v1'],
      maxSkewSeconds: 300,
      replayProtectionEnabled: false,
      replayCacheMaxEntries: 5000,
    });
    expect(tampered.ok).toBe(false);
    if (!tampered.ok) {
      expect(tampered.reason).toBe('signature_invalid');
    }
  });
});
