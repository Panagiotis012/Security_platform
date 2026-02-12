import type { Request } from 'express';
import {
  authorizeInternalMutationRequest,
  resolveInternalMutationPermission,
  type InternalControlPlaneConfig,
} from '../../gateway/src/internal/internal-routes';

function makeRequest(overrides: Partial<Request> = {}): Request {
  const req: Partial<Request> = {
    method: 'PATCH',
    path: '/internal/security-controls',
    headers: {},
    ...overrides,
  };
  return req as Request;
}

function baseConfig(): InternalControlPlaneConfig {
  return {
    enabled: true,
    requireApiKeyForMutations: true,
    callerRoles: {
      telemetry: ['security_controls_admin'],
    },
    apiKeys: {
      'ops-key': {
        secret: 'ops-secret-123456',
        scopes: ['security_controls.write'],
      },
    },
    apiKeyIdHeader: 'x-internal-api-key-id',
    apiKeySecretHeader: 'x-internal-api-key',
  };
}

describe('Internal Control Plane Access', () => {
  test('resolves route-specific required permission', () => {
    expect(resolveInternalMutationPermission('/internal/security-controls').scope).toBe('security_controls.write');
    expect(resolveInternalMutationPermission('/internal/edge-cache/purge').scope).toBe('edge_cache.write');
    expect(resolveInternalMutationPermission('/internal/control-plane/audit/import').scope).toBe('audit.write');
    expect(resolveInternalMutationPermission('/internal/routes/policy').scope).toBe('route.write');
    expect(resolveInternalMutationPermission('/internal/upstreams/policy').scope).toBe('upstream.write');
  });

  test('allows authorized mutation with role + scoped api key', () => {
    const result = authorizeInternalMutationRequest(
      makeRequest({
        headers: {
          'x-internal-caller': 'telemetry',
          'x-internal-api-key-id': 'ops-key',
          'x-internal-api-key': 'ops-secret-123456',
        },
      }),
      baseConfig(),
    );
    expect(result.ok).toBe(true);
  });

  test('denies mutation when caller role is missing', () => {
    const result = authorizeInternalMutationRequest(
      makeRequest({
        headers: {
          'x-internal-caller': 'unknown-service',
          'x-internal-api-key-id': 'ops-key',
          'x-internal-api-key': 'ops-secret-123456',
        },
      }),
      baseConfig(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(403);
      expect(result.body.error).toBe('insufficient_control_plane_role');
    }
  });

  test('denies mutation when api key scope is insufficient', () => {
    const cfg = baseConfig();
    cfg.apiKeys['ops-key'] = {
      secret: 'ops-secret-123456',
      scopes: ['edge_cache.write'],
    };

    const result = authorizeInternalMutationRequest(
      makeRequest({
        headers: {
          'x-internal-caller': 'telemetry',
          'x-internal-api-key-id': 'ops-key',
          'x-internal-api-key': 'ops-secret-123456',
        },
      }),
      cfg,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(403);
      expect(result.body.error).toBe('insufficient_control_plane_scope');
    }
  });

  test('skips checks for read-only methods and disabled mode', () => {
    const cfg = baseConfig();
    const readResult = authorizeInternalMutationRequest(
      makeRequest({ method: 'GET' }),
      cfg,
    );
    expect(readResult.ok).toBe(true);

    cfg.enabled = false;
    const disabledResult = authorizeInternalMutationRequest(makeRequest(), cfg);
    expect(disabledResult.ok).toBe(true);
  });
});
