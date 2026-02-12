import type { Request, Response } from 'express';
import { requireGatewayPrincipal, requireAnyRole } from '../../telemetry/src/api/routes';
import { createMockRes, createNext } from '../test-utils/mock-express';

describe('Telemetry local authz middleware', () => {
  test('rejects requests missing gateway principal header', () => {
    const mw = requireGatewayPrincipal();
    const req = { headers: {} } as unknown as Request;
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });

  test('rejects requests without required SOC role', () => {
    const mw = requireAnyRole(['security-admin', 'incident-responder']);
    const req = {
      headers: {
        'x-authenticated-roles': 'user,viewer',
      },
    } as unknown as Request;
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  test('allows requests with required SOC role', () => {
    const mw = requireAnyRole(['security-admin', 'incident-responder']);
    const req = {
      headers: {
        'x-authenticated-roles': 'user,Security-Admin',
      },
    } as unknown as Request;
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.statusCode).toBe(200);
  });
});
