import { GatewayConfigSchema } from '../../gateway/config/default';
import {
  applySecurityControlsHistoryImport,
  applySecurityControlsPatch,
  buildSecurityControlsHistoryExport,
  buildSecurityControlsRevision,
  buildSecurityControlsAuditEntry,
  buildSecurityControlsSnapshot,
  extractIfMatchRevisionHeader,
  parseSecurityControlsPatchRequestBody,
  previewSecurityControlsPatch,
} from '../../gateway/src/internal/internal-routes';
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
    },
  });
}

describe('Security Controls Audit Store', () => {
  test('trims old entries and maintains anchor hash', async () => {
    const store = new InMemorySecurityControlsAuditStore();
    const config = makeConfig();
    const snapshot = buildSecurityControlsSnapshot(config);
    const secret = 'audit-secret-0123456789abcdef';

    const entry1 = buildSecurityControlsAuditEntry({
      patch: { waf: { riskScoreThreshold: 21 } },
      snapshot,
      previousEntryHash: null,
      actor: 'telemetry',
      correlationId: 'corr-1',
      signingSecret: secret,
    });
    await store.append(entry1, 2);

    const entry2 = buildSecurityControlsAuditEntry({
      patch: { waf: { riskScoreThreshold: 22 } },
      snapshot,
      previousEntryHash: entry1.entryHash,
      actor: 'telemetry',
      correlationId: 'corr-2',
      signingSecret: secret,
    });
    await store.append(entry2, 2);

    const entry3 = buildSecurityControlsAuditEntry({
      patch: { waf: { riskScoreThreshold: 23 } },
      snapshot,
      previousEntryHash: entry2.entryHash,
      actor: 'telemetry',
      correlationId: 'corr-3',
      signingSecret: secret,
    });
    const pointers = await store.append(entry3, 2);

    expect(pointers.total).toBe(2);
    expect(pointers.anchorHash).toBe(entry1.entryHash);
    expect(pointers.latestEntryHash).toBe(entry3.entryHash);

    const history = await store.listAll();
    expect(history.entries.map((entry) => entry.id)).toEqual([entry2.id, entry3.id]);
    expect(await store.getById(entry1.id)).toBeNull();
    expect(await store.getById(entry2.id)).not.toBeNull();
  });

  test('preview validates patch without mutating config; apply commits changes', () => {
    const config = makeConfig();
    const before = config.waf.riskScoreThreshold;

    const preview = previewSecurityControlsPatch(config, {
      waf: {
        riskScoreThreshold: 42,
      },
    });
    expect(preview.ok).toBe(true);
    expect(config.waf.riskScoreThreshold).toBe(before);

    const apply = applySecurityControlsPatch(config, {
      waf: {
        riskScoreThreshold: 42,
      },
    });
    expect(apply.ok).toBe(true);
    expect(config.waf.riskScoreThreshold).toBe(42);
  });

  test('parses direct and envelope security-controls patch requests', () => {
    const direct = parseSecurityControlsPatchRequestBody({
      waf: { riskScoreThreshold: 31 },
      dryRun: true,
      ifRevision: 'r1:abc',
    });
    expect(direct.ok).toBe(true);
    if (direct.ok) {
      expect(direct.patch.waf).toBeDefined();
      expect(direct.dryRun).toBe(true);
      expect(direct.ifRevision).toBe('r1:abc');
    }

    const envelope = parseSecurityControlsPatchRequestBody({
      patch: {
        accessControl: { enabled: true },
      },
      dryRun: true,
      ifRevision: 'r2:def',
    });
    expect(envelope.ok).toBe(true);
    if (envelope.ok) {
      expect(envelope.patch.accessControl).toBeDefined();
      expect(envelope.dryRun).toBe(true);
      expect(envelope.ifRevision).toBe('r2:def');
    }
  });

  test('extracts revision from If-Match header', () => {
    expect(extractIfMatchRevisionHeader('"r2:abcdef"')).toBe('r2:abcdef');
    expect(extractIfMatchRevisionHeader('W/"r3:abcdef"')).toBe('r3:abcdef');
    expect(extractIfMatchRevisionHeader('*')).toBeNull();
    expect(extractIfMatchRevisionHeader(undefined)).toBeNull();
  });

  test('builds stable revision tokens from chain pointers', () => {
    expect(buildSecurityControlsRevision({
      total: 0,
      latestEntryHash: null,
      anchorHash: null,
    })).toBe('r0:genesis');

    expect(buildSecurityControlsRevision({
      total: 3,
      latestEntryHash: 'hash3',
      anchorHash: 'hash1',
    })).toBe('r3:hash3');
  });

  test('exports and imports history entries into a local signed chain', async () => {
    const sourceStore = new InMemorySecurityControlsAuditStore();
    const destinationStore = new InMemorySecurityControlsAuditStore();
    const config = makeConfig();
    const snapshot = buildSecurityControlsSnapshot(config);
    const secret = 'audit-secret-0123456789abcdef';

    const entry = buildSecurityControlsAuditEntry({
      patch: { waf: { riskScoreThreshold: 31 } },
      snapshot,
      previousEntryHash: null,
      actor: 'telemetry',
      correlationId: 'corr-1',
      signingSecret: secret,
    });
    await sourceStore.append(entry, 100);

    const exported = await buildSecurityControlsHistoryExport(sourceStore, 100);
    expect(exported.entryCount).toBe(1);

    const imported = await applySecurityControlsHistoryImport(
      destinationStore,
      {
        source: 'gateway-us-west',
        entries: exported.entries,
      },
      {
        signingSecret: secret,
        maxEntries: 100,
        fallbackSnapshotHash: 'b'.repeat(64),
      },
    );
    expect(imported.imported).toBe(1);
    expect(imported.skipped).toBe(0);

    const history = await destinationStore.listAll();
    expect(history.entries).toHaveLength(1);
    expect(history.entries[0]?.actor).toContain('federated:gateway-us-west');
  });
});
