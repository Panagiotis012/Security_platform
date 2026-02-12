import { GatewayConfigSchema } from '../../gateway/config/default';
import {
  buildSecurityControlsAuditEntry,
  buildSecurityControlsSnapshot,
  sanitizeSecurityControlsPatchForHistory,
  verifySecurityControlsAuditChain,
} from '../../gateway/src/internal/internal-routes';

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
    },
  });
}

describe('Security Controls Audit History', () => {
  test('builds and verifies signed hash-chain entries', () => {
    const config = makeConfig();
    const snapshot1 = buildSecurityControlsSnapshot(config);
    const secret = 'audit-secret-0123456789abcdef';

    const entry1 = buildSecurityControlsAuditEntry({
      patch: {
        waf: {
          riskScoreThreshold: 30,
        },
      },
      snapshot: snapshot1,
      previousEntryHash: null,
      actor: 'telemetry',
      correlationId: 'corr-1',
      signingSecret: secret,
      nowMs: Date.parse('2026-02-11T10:00:00.000Z'),
    });

    const snapshot2 = buildSecurityControlsSnapshot(config);
    const entry2 = buildSecurityControlsAuditEntry({
      patch: {
        accessControl: {
          enabled: true,
        },
      },
      snapshot: snapshot2,
      previousEntryHash: entry1.entryHash,
      actor: 'telemetry',
      correlationId: 'corr-2',
      signingSecret: secret,
      nowMs: Date.parse('2026-02-11T10:05:00.000Z'),
    });

    const verification = verifySecurityControlsAuditChain({
      entries: [entry1, entry2],
      signingSecret: secret,
    });

    expect(verification.ok).toBe(true);
    if (verification.ok) {
      expect(verification.latestEntryHash).toBe(entry2.entryHash);
      expect(verification.checked).toBe(2);
    }
  });

  test('detects tampered entries in chain verification', () => {
    const config = makeConfig();
    const snapshot = buildSecurityControlsSnapshot(config);
    const secret = 'audit-secret-0123456789abcdef';

    const entry = buildSecurityControlsAuditEntry({
      patch: {
        waf: {
          riskScoreThreshold: 30,
        },
      },
      snapshot,
      previousEntryHash: null,
      actor: 'telemetry',
      correlationId: 'corr-1',
      signingSecret: secret,
    });

    entry.patch = {
      waf: {
        riskScoreThreshold: 999,
      },
    };

    const verification = verifySecurityControlsAuditChain({
      entries: [entry],
      signingSecret: secret,
    });
    expect(verification.ok).toBe(false);
    if (!verification.ok) {
      expect(verification.reason).toBe('entry_hash_invalid');
      expect(verification.failedIndex).toBe(0);
    }
  });

  test('verifies truncated history when chain anchor hash is provided', () => {
    const config = makeConfig();
    const snapshot = buildSecurityControlsSnapshot(config);
    const secret = 'audit-secret-0123456789abcdef';

    const entry1 = buildSecurityControlsAuditEntry({
      patch: { waf: { riskScoreThreshold: 30 } },
      snapshot,
      previousEntryHash: null,
      actor: 'telemetry',
      correlationId: 'corr-1',
      signingSecret: secret,
    });

    const entry2 = buildSecurityControlsAuditEntry({
      patch: { waf: { riskScoreThreshold: 35 } },
      snapshot,
      previousEntryHash: entry1.entryHash,
      actor: 'telemetry',
      correlationId: 'corr-2',
      signingSecret: secret,
    });

    const verification = verifySecurityControlsAuditChain({
      entries: [entry2],
      signingSecret: secret,
      initialPreviousEntryHash: entry1.entryHash,
    });
    expect(verification.ok).toBe(true);
  });

  test('redacts secrets from history patch payloads', () => {
    const sanitized = sanitizeSecurityControlsPatchForHistory({
      botManagement: {
        clearance: {
          secret: 'new-secret',
          previousSecrets: ['old-1', 'old-2'],
        },
      },
    });

    const botManagement = sanitized['botManagement'] as {
      clearance?: Record<string, unknown>;
    };
    const clearance = botManagement.clearance || {};

    expect(clearance['secret']).toBeUndefined();
    expect(clearance['secretConfigured']).toBe(true);
    expect(clearance['previousSecrets']).toBeUndefined();
    expect(clearance['previousSecretsConfigured']).toBe(2);
  });
});
