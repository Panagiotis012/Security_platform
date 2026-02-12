import { InMemoryInternalAuthReplayStore } from '@zerotrust/shared';
import {
  signSecurityControlsHistoryBundle,
  verifySignedSecurityControlsHistoryBundle,
} from '../../gateway/src/internal/security-controls-history-signing';

describe('Security Controls History Bundle Signing', () => {
  test('signs and verifies a valid bundle', async () => {
    const unsigned = {
      source: 'gateway-us-east',
      bundleId: 'bundle-1',
      keyId: 'controls-v1',
      generatedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      entries: [
        {
          changedAt: new Date().toISOString(),
          actor: 'telemetry',
          correlationId: 'corr-1',
          patch: { waf: { riskScoreThreshold: 30 } },
          snapshotHash: 'a'.repeat(64),
        },
      ],
    };
    const signed = signSecurityControlsHistoryBundle(unsigned, 'secret-1234567890');

    const verified = await verifySignedSecurityControlsHistoryBundle(signed, {
      keyring: { 'controls-v1': 'secret-1234567890' },
      allowedSources: ['gateway-us-east'],
      allowedKeyIds: ['controls-v1'],
      maxSkewSeconds: 300,
      replayProtectionEnabled: false,
      replayCacheMaxEntries: 5000,
    });
    expect(verified.ok).toBe(true);
  });

  test('rejects replayed bundles when replay protection is enabled', async () => {
    const unsigned = {
      source: 'gateway-us-east',
      bundleId: 'bundle-2',
      keyId: 'controls-v1',
      generatedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      entries: [
        {
          changedAt: new Date().toISOString(),
          actor: 'telemetry',
          patch: { waf: { riskScoreThreshold: 30 } },
        },
      ],
    };
    const signed = signSecurityControlsHistoryBundle(unsigned, 'secret-1234567890');
    const replayStore = new InMemoryInternalAuthReplayStore(5000);

    const first = await verifySignedSecurityControlsHistoryBundle(
      signed,
      {
        keyring: { 'controls-v1': 'secret-1234567890' },
        allowedSources: ['gateway-us-east'],
        allowedKeyIds: ['controls-v1'],
        maxSkewSeconds: 300,
        replayProtectionEnabled: true,
        replayCacheMaxEntries: 5000,
      },
      replayStore,
    );
    expect(first.ok).toBe(true);

    const second = await verifySignedSecurityControlsHistoryBundle(
      signed,
      {
        keyring: { 'controls-v1': 'secret-1234567890' },
        allowedSources: ['gateway-us-east'],
        allowedKeyIds: ['controls-v1'],
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

  test('rejects tampered bundle payload', async () => {
    const unsigned = {
      source: 'gateway-us-east',
      bundleId: 'bundle-3',
      keyId: 'controls-v1',
      generatedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      entries: [
        {
          changedAt: new Date().toISOString(),
          actor: 'telemetry',
          patch: { waf: { riskScoreThreshold: 30 } },
        },
      ],
    };
    const signed = signSecurityControlsHistoryBundle(unsigned, 'secret-1234567890');
    signed.entries.push({
      changedAt: new Date().toISOString(),
      actor: 'tampered',
      patch: { accessControl: { enabled: true } },
    });

    const verified = await verifySignedSecurityControlsHistoryBundle(signed, {
      keyring: { 'controls-v1': 'secret-1234567890' },
      allowedSources: ['gateway-us-east'],
      allowedKeyIds: ['controls-v1'],
      maxSkewSeconds: 300,
      replayProtectionEnabled: false,
      replayCacheMaxEntries: 5000,
    });
    expect(verified.ok).toBe(false);
    if (!verified.ok) {
      expect(verified.reason).toBe('signature_invalid');
    }
  });
});
