import {
  computeInternalAuthHeaders,
  verifyInternalAuth,
  verifyInternalAuthAsync,
  sha256Hex,
  hmacSha256Hex,
  buildInternalSignatureInput,
  type InternalAuthReplayStore,
} from '../../shared/src/middleware/internal-auth';

describe('Internal Auth (HMAC)', () => {
  test('computes headers that verify successfully (path includes query)', () => {
    const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const rawBody = Buffer.from(JSON.stringify({ hello: 'world' }), 'utf8');
    const now = 1_700_000_000; // stable test timestamp

    const path = '/v1/audit/events?limit=10&cursor=abc';
    const headers = computeInternalAuthHeaders({ method: 'POST', path, rawBody }, secret, now);

    const result = verifyInternalAuth(
      {
        method: 'POST',
        path,
        headers,
        rawBody,
      },
      {
        enabled: true,
        secret,
        allowedSkewSeconds: 60,
        exemptPaths: [],
      },
      now,
    );

    expect(result).toEqual({ ok: true });
  });

  test('rejects when body hash does not match', () => {
    const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const rawBody = Buffer.from('abc', 'utf8');
    const now = 1_700_000_000;
    const path = '/v1/pdp/decide';

    const headers = computeInternalAuthHeaders({ method: 'POST', path, rawBody }, secret, now);
    const tamperedBody = Buffer.from('abcd', 'utf8');

    const result = verifyInternalAuth(
      {
        method: 'POST',
        path,
        headers,
        rawBody: tamperedBody,
      },
      {
        enabled: true,
        secret,
        allowedSkewSeconds: 60,
        exemptPaths: [],
      },
      now,
    );

    expect(result).toEqual({ ok: false, reason: 'internal_body_sha_mismatch' });
  });

  test('rejects when timestamp is outside allowed skew window', () => {
    const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const rawBody = Buffer.alloc(0);
    const path = '/v1/alerts';

    const headers = computeInternalAuthHeaders({ method: 'GET', path, rawBody }, secret, 1_700_000_000);

    const result = verifyInternalAuth(
      {
        method: 'GET',
        path,
        headers,
        rawBody,
      },
      {
        enabled: true,
        secret,
        allowedSkewSeconds: 10,
        exemptPaths: [],
      },
      1_700_000_000 + 100,
    );

    expect(result).toEqual({ ok: false, reason: 'internal_timestamp_out_of_window' });
  });

  test('exemptPaths matches path only (ignores query string)', () => {
    const result = verifyInternalAuth(
      {
        method: 'GET',
        path: '/health?full=1',
        headers: {},
        rawBody: Buffer.alloc(0),
      },
      {
        enabled: true,
        secret: 'unused',
        allowedSkewSeconds: 60,
        exemptPaths: ['/health'],
      },
      1_700_000_000,
    );

    expect(result).toEqual({ ok: true });
  });

  test('sha256Hex matches known value for empty body', () => {
    expect(sha256Hex(Buffer.alloc(0))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  test('rejects replayed nonce+signature within the skew window', () => {
    const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const rawBody = Buffer.from(JSON.stringify({ event: 'test' }), 'utf8');
    const now = 1_700_000_000;
    const path = '/v1/audit/events';
    const nonce = 'replay-test-nonce-0001';
    const headers = computeInternalAuthHeaders({ method: 'POST', path, rawBody }, secret, now, nonce);

    const options = {
      enabled: true,
      secret,
      allowedSkewSeconds: 60,
      exemptPaths: [],
      requireNonce: true,
      replayProtectionEnabled: true,
      replayCacheMaxEntries: 10,
    };

    const first = verifyInternalAuth(
      {
        method: 'POST',
        path,
        headers,
        rawBody,
      },
      options,
      now,
    );

    const second = verifyInternalAuth(
      {
        method: 'POST',
        path,
        headers,
        rawBody,
      },
      options,
      now + 1,
    );

    expect(first).toEqual({ ok: true });
    expect(second).toEqual({ ok: false, reason: 'internal_replay_detected' });
  });

  test('strict mode rejects requests without nonce header', () => {
    const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const rawBody = Buffer.from('legacy', 'utf8');
    const now = 1_700_000_000;
    const ts = String(now);
    const path = '/v1/legacy';
    const bodySha = sha256Hex(rawBody);
    const sigInput = buildInternalSignatureInput(ts, 'POST', path, bodySha);
    const sig = hmacSha256Hex(secret, sigInput);

    const result = verifyInternalAuth(
      {
        method: 'POST',
        path,
        headers: {
          'x-internal-timestamp': ts,
          'x-internal-content-sha256': bodySha,
          'x-internal-signature': sig,
        },
        rawBody,
      },
      {
        enabled: true,
        secret,
        allowedSkewSeconds: 60,
        exemptPaths: [],
        requireNonce: true,
      },
      now,
    );

    expect(result).toEqual({ ok: false, reason: 'missing_internal_nonce' });
  });

  test('compat mode accepts legacy signatures without nonce', () => {
    const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const rawBody = Buffer.from('legacy-compat', 'utf8');
    const now = 1_700_000_000;
    const ts = String(now);
    const path = '/v1/legacy';
    const bodySha = sha256Hex(rawBody);
    const sigInput = buildInternalSignatureInput(ts, 'POST', path, bodySha);
    const sig = hmacSha256Hex(secret, sigInput);

    const result = verifyInternalAuth(
      {
        method: 'POST',
        path,
        headers: {
          'x-internal-timestamp': ts,
          'x-internal-content-sha256': bodySha,
          'x-internal-signature': sig,
        },
        rawBody,
      },
      {
        enabled: true,
        secret,
        allowedSkewSeconds: 60,
        exemptPaths: [],
        requireNonce: false,
      },
      now,
    );

    expect(result).toEqual({ ok: true });
  });

  test('validates caller + audience when required', () => {
    const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const rawBody = Buffer.from(JSON.stringify({ ok: true }), 'utf8');
    const now = 1_700_000_000;
    const path = '/v1/internal/action';

    const headers = computeInternalAuthHeaders(
      { method: 'POST', path, rawBody },
      secret,
      now,
      'caller-aud-test-0001',
      'gateway',
      'telemetry',
    );

    const result = verifyInternalAuth(
      {
        method: 'POST',
        path,
        headers,
        rawBody,
      },
      {
        enabled: true,
        secret,
        allowedSkewSeconds: 60,
        exemptPaths: [],
        requireNonce: true,
        requireCallerId: true,
        allowedCallerIds: ['gateway'],
        expectedAudience: 'telemetry',
      },
      now,
    );

    expect(result).toEqual({ ok: true });
  });

  test('rejects when caller is not allowlisted', () => {
    const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const rawBody = Buffer.from(JSON.stringify({ ok: true }), 'utf8');
    const now = 1_700_000_000;
    const path = '/v1/internal/action';

    const headers = computeInternalAuthHeaders(
      { method: 'POST', path, rawBody },
      secret,
      now,
      'caller-deny-test-0001',
      'telemetry',
      'identity',
    );

    const result = verifyInternalAuth(
      {
        method: 'POST',
        path,
        headers,
        rawBody,
      },
      {
        enabled: true,
        secret,
        allowedSkewSeconds: 60,
        exemptPaths: [],
        requireNonce: true,
        requireCallerId: true,
        allowedCallerIds: ['gateway'],
        expectedAudience: 'identity',
      },
      now,
    );

    expect(result).toEqual({ ok: false, reason: 'internal_caller_not_allowed' });
  });

  test('rejects when audience does not match expected service', () => {
    const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const rawBody = Buffer.from(JSON.stringify({ ok: true }), 'utf8');
    const now = 1_700_000_000;
    const path = '/v1/internal/action';

    const headers = computeInternalAuthHeaders(
      { method: 'POST', path, rawBody },
      secret,
      now,
      'aud-mismatch-test-0001',
      'gateway',
      'supply-chain',
    );

    const result = verifyInternalAuth(
      {
        method: 'POST',
        path,
        headers,
        rawBody,
      },
      {
        enabled: true,
        secret,
        allowedSkewSeconds: 60,
        exemptPaths: [],
        requireNonce: true,
        requireCallerId: true,
        allowedCallerIds: ['gateway'],
        expectedAudience: 'identity',
      },
      now,
    );

    expect(result).toEqual({ ok: false, reason: 'internal_audience_mismatch' });
  });

  test('async verifier enforces replay detection through shared store', async () => {
    const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const rawBody = Buffer.from(JSON.stringify({ ok: true }), 'utf8');
    const now = 1_700_000_000;
    const path = '/v1/internal/action';
    const headers = computeInternalAuthHeaders(
      { method: 'POST', path, rawBody },
      secret,
      now,
      'async-replay-test-0001',
      'gateway',
      'telemetry',
    );

    class TestReplayStore implements InternalAuthReplayStore {
      private readonly seen = new Set<string>();
      async consume(replayKey: string, _ttlSeconds: number): Promise<boolean> {
        void _ttlSeconds;
        if (this.seen.has(replayKey)) return false;
        this.seen.add(replayKey);
        return true;
      }
    }

    const store = new TestReplayStore();
    const options = {
      enabled: true,
      secret,
      allowedSkewSeconds: 60,
      exemptPaths: [],
      requireNonce: true,
      requireCallerId: true,
      allowedCallerIds: ['gateway'],
      expectedAudience: 'telemetry',
      replayProtectionEnabled: true,
      replayCacheMaxEntries: 10,
    };

    const first = await verifyInternalAuthAsync(
      {
        method: 'POST',
        path,
        headers,
        rawBody,
      },
      options,
      store,
      now,
    );

    const second = await verifyInternalAuthAsync(
      {
        method: 'POST',
        path,
        headers,
        rawBody,
      },
      options,
      store,
      now + 1,
    );

    expect(first).toEqual({ ok: true });
    expect(second).toEqual({ ok: false, reason: 'internal_replay_detected' });
  });

  test('async verifier fails closed when replay store errors', async () => {
    const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const rawBody = Buffer.from(JSON.stringify({ ok: true }), 'utf8');
    const now = 1_700_000_000;
    const path = '/v1/internal/action';
    const headers = computeInternalAuthHeaders(
      { method: 'POST', path, rawBody },
      secret,
      now,
      'async-replay-error-0001',
      'gateway',
      'telemetry',
    );

    const failingStore: InternalAuthReplayStore = {
      async consume(_replayKey: string, _ttlSeconds: number): Promise<boolean> {
        void _replayKey;
        void _ttlSeconds;
        throw new Error('redis down');
      },
    };

    const result = await verifyInternalAuthAsync(
      {
        method: 'POST',
        path,
        headers,
        rawBody,
      },
      {
        enabled: true,
        secret,
        allowedSkewSeconds: 60,
        exemptPaths: [],
        requireNonce: true,
        requireCallerId: true,
        allowedCallerIds: ['gateway'],
        expectedAudience: 'telemetry',
        replayProtectionEnabled: true,
      },
      failingStore,
      now,
    );

    expect(result).toEqual({ ok: false, reason: 'internal_replay_store_error' });
  });

  test('verifies signatures with key-id and keyring secret', () => {
    const legacySecret = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const rotatedSecret = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    const rawBody = Buffer.from(JSON.stringify({ rotate: true }), 'utf8');
    const now = 1_700_000_000;
    const path = '/v1/rotate';

    const headers = computeInternalAuthHeaders(
      { method: 'POST', path, rawBody },
      rotatedSecret,
      now,
      'keyring-test-nonce-0001',
      'gateway',
      'identity',
      'gateway-v2',
    );

    const result = verifyInternalAuth(
      { method: 'POST', path, headers, rawBody },
      {
        enabled: true,
        secret: legacySecret,
        allowedSkewSeconds: 60,
        exemptPaths: [],
        requireNonce: true,
        requireCallerId: true,
        requireKeyId: true,
        allowedCallerIds: ['gateway'],
        allowedKeyIds: ['gateway-v2'],
        expectedAudience: 'identity',
        keyring: {
          'gateway-v2': rotatedSecret,
        },
      },
      now,
    );

    expect(result).toEqual({ ok: true });
  });

  test('rejects unknown key-id when keyring is configured', () => {
    const secret = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    const rawBody = Buffer.from(JSON.stringify({ rotate: true }), 'utf8');
    const now = 1_700_000_000;
    const path = '/v1/rotate';

    const headers = computeInternalAuthHeaders(
      { method: 'POST', path, rawBody },
      secret,
      now,
      'keyring-unknown-nonce-0001',
      'gateway',
      'identity',
      'gateway-v3',
    );

    const result = verifyInternalAuth(
      { method: 'POST', path, headers, rawBody },
      {
        enabled: true,
        secret: secret,
        allowedSkewSeconds: 60,
        exemptPaths: [],
        requireNonce: true,
        requireCallerId: true,
        requireKeyId: true,
        allowedCallerIds: ['gateway'],
        allowedKeyIds: ['gateway-v3'],
        expectedAudience: 'identity',
        keyring: {
          'gateway-v2': secret,
        },
      },
      now,
    );

    expect(result).toEqual({ ok: false, reason: 'internal_key_id_unknown' });
  });
});
