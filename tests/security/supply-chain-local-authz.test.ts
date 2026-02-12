import type { Request, Response } from 'express';
import {
  requireGatewayPrincipal,
  requireAnyRole,
  requireStepUpLevel,
} from '../../supply-chain/src/api/routes';
import { createMockRes, createNext } from '../test-utils/mock-express';

describe('Supply-chain local authz middleware', () => {
  test('rejects requests missing gateway principal header', () => {
    const mw = requireGatewayPrincipal();
    const req = { headers: {} } as unknown as Request;
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });

  test('rejects admin route access for non-admin roles', () => {
    const mw = requireAnyRole(['admin', 'security-admin']);
    const req = {
      headers: {
        'x-authenticated-roles': 'user,developer',
      },
    } as unknown as Request;
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  test('rejects insufficient step-up level for high-risk actions', () => {
    const mw = requireStepUpLevel(2);
    const req = {
      headers: {
        'x-step-up-level': '1',
      },
    } as unknown as Request;
    const res = createMockRes() as unknown as Response;
    const next = createNext();

    mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
    expect(res.getHeader('x-zt-step-up-required')).toBe('true');
    expect(res.getHeader('x-zt-required-step-up-level')).toBe('2');
  });

  test('allows when role and step-up are sufficient', () => {
    const roleMw = requireAnyRole(['admin', 'security-admin']);
    const stepUpMw = requireStepUpLevel(2);
    const req = {
      headers: {
        'x-authenticated-roles': 'security-admin',
        'x-step-up-level': '2',
      },
    } as unknown as Request;
    const res = createMockRes() as unknown as Response;
    const nextRole = createNext();
    const nextStep = createNext();

    roleMw(req, res, nextRole);
    stepUpMw(req, res, nextStep);

    expect(nextRole).toHaveBeenCalledTimes(1);
    expect(nextStep).toHaveBeenCalledTimes(1);
    expect(res.statusCode).toBe(200);
  });
});
