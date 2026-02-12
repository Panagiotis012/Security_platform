import type { Request, Response } from 'express';
import { Router } from 'express';
import { z } from 'zod';
import { createLogger } from '../logger';
import type { TokenService } from '../tokens/token-service';
import type { SessionManager } from '../sessions/session-manager';

const logger = createLogger('internal-routes');

export interface InternalRoutesDeps {
  tokenService: TokenService;
  sessionManager: SessionManager;
}

const RevokeUserSchema = z.object({
  userId: z.string().min(1).max(256),
  revokeSessions: z.boolean().default(true),
  revokeTokens: z.boolean().default(true),
  reason: z.string().min(1).max(512).default('automated response'),
  alertId: z.string().min(1).max(128).optional(),
});

/**
 * Internal incident-response endpoints.
 *
 * NOTE: Authentication is enforced by the global internal-auth + mTLS middleware
 * in `identity/src/index.ts`. These endpoints are NOT intended for end-user access.
 */
export function createInternalRoutes(deps: InternalRoutesDeps): Router {
  const router = Router();

  // POST /internal/revoke-user
  // Compromise response: destroys sessions and bumps token version, causing the gateway
  // to reject any previously issued access tokens.
  router.post('/internal/revoke-user', async (req: Request, res: Response) => {
    const parsed = RevokeUserSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: { code: 'INVALID_REQUEST', details: parsed.error.issues } });
      return;
    }

    const { userId, revokeSessions, revokeTokens, reason, alertId } = parsed.data;

    try {
      const sessionsDestroyed = revokeSessions
        ? await deps.sessionManager.destroyAllUserSessions(userId)
        : 0;

      const newTokenVersion = revokeTokens
        ? await deps.tokenService.revokeUserTokens(userId)
        : undefined;

      logger.warn('Internal revoke-user executed', {
        userId,
        revokeSessions,
        revokeTokens,
        sessionsDestroyed,
        newTokenVersion,
        reason,
        alertId,
      });

      res.status(200).json({
        userId,
        revokeSessions,
        revokeTokens,
        sessionsDestroyed,
        tokenVersion: newTokenVersion,
      });
    } catch (err) {
      logger.error('Internal revoke-user failed', {
        userId,
        error: err instanceof Error ? err.message : String(err),
      });
      res.status(500).json({ error: { code: 'INTERNAL', message: 'Failed to revoke user' } });
    }
  });

  return router;
}

