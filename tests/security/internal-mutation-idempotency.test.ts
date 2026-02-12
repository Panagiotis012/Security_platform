import type { Request } from 'express';
import { InMemoryInternalAuthReplayStore } from '@zerotrust/shared';
import { enforceMutationIdempotency } from '../../gateway/src/internal/internal-routes';

function makeRequest(overrides: Partial<Request> = {}): Request {
  const req: Partial<Request> = {
    method: 'POST',
    path: '/internal/security-controls',
    headers: {},
    ...overrides,
  };
  return req as Request;
}

describe('Internal Mutation Idempotency', () => {
  test('rejects duplicate mutation requests for same key, route, and caller', async () => {
    const replayStore = new InMemoryInternalAuthReplayStore(5000);
    const config = {
      enabled: true,
      ttlSeconds: 300,
      replayCacheMaxEntries: 5000,
    };
    const req = makeRequest({
      headers: {
        'idempotency-key': 'req-12345678',
        'x-internal-caller': 'telemetry',
      },
    });

    const first = await enforceMutationIdempotency(req, replayStore, config);
    expect(first.ok).toBe(true);

    const second = await enforceMutationIdempotency(req, replayStore, config);
    expect(second.ok).toBe(false);
    if (!second.ok) {
      expect(second.status).toBe(409);
      expect(second.body.error).toBe('idempotency_conflict');
    }
  });

  test('allows same key on different mutation routes', async () => {
    const replayStore = new InMemoryInternalAuthReplayStore(5000);
    const config = {
      enabled: true,
      ttlSeconds: 300,
      replayCacheMaxEntries: 5000,
    };

    const first = await enforceMutationIdempotency(
      makeRequest({
        path: '/internal/security-controls',
        headers: { 'x-idempotency-key': 'req-abcdefgh', 'x-internal-caller': 'telemetry' },
      }),
      replayStore,
      config,
    );
    expect(first.ok).toBe(true);

    const second = await enforceMutationIdempotency(
      makeRequest({
        path: '/internal/edge-cache/purge',
        headers: { 'x-idempotency-key': 'req-abcdefgh', 'x-internal-caller': 'telemetry' },
      }),
      replayStore,
      config,
    );
    expect(second.ok).toBe(true);
  });

  test('returns validation error for malformed key', async () => {
    const replayStore = new InMemoryInternalAuthReplayStore(5000);
    const config = {
      enabled: true,
      ttlSeconds: 300,
      replayCacheMaxEntries: 5000,
    };
    const req = makeRequest({
      headers: {
        'idempotency-key': 'bad key with spaces',
      },
    });

    const result = await enforceMutationIdempotency(req, replayStore, config);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(400);
      expect(result.body.error).toBe('invalid_idempotency_key');
    }
  });

  test('skips checks for non-mutation methods', async () => {
    const replayStore = new InMemoryInternalAuthReplayStore(5000);
    const config = {
      enabled: true,
      ttlSeconds: 300,
      replayCacheMaxEntries: 5000,
    };
    const req = makeRequest({
      method: 'GET',
      headers: { 'idempotency-key': 'req-12345678' },
    });

    const result = await enforceMutationIdempotency(req, replayStore, config);
    expect(result.ok).toBe(true);
  });
});
