/**
 * Auth API routes for the Identity Plane.
 *
 * All routes use Zod for input validation.  CSRF protection is applied
 * to state-changing endpoints via middleware.  Session-based endpoints use
 * cookies; API-based endpoints use Bearer tokens.
 */

import type { Request, Response } from 'express';
import { Router } from 'express';
import crypto from 'crypto';
import { z } from 'zod';
import type { OIDCProviderRegistry} from '../oidc/provider';
import { OIDCProvider, OIDCError } from '../oidc/provider';
import type { TokenService} from '../tokens/token-service';
import { TokenError } from '../tokens/token-service';
import type { JWKSManager } from '../tokens/jwks';
import { SessionManager } from '../sessions/session-manager';
import type { StepUpAuthService} from '../stepup/step-up-auth';
import { StepUpError } from '../stepup/step-up-auth';
import { WorkloadIdentityService, WorkloadError } from '../workload/workload-identity';
import {
  requireAuth,
  validateBody,
  csrfProtection,
} from './middleware';
import type { AuthFlowStore } from './auth-flow-store';
import { config } from '../../config/default';
import { createLogger } from '../logger';
import { readSecret } from '@zerotrust/shared';

const logger = createLogger('routes');

// ---------------------------------------------------------------------------
// Zod schemas for request validation
// ---------------------------------------------------------------------------

const LoginQuerySchema = z.object({
  provider: z.string().min(1).optional(),
  redirect_uri: z.string().url().optional(),
});

const TokenRefreshSchema = z.object({
  refresh_token: z.string().min(1, 'Refresh token is required'),
});

const StepUpInitiateSchema = z.object({
  method: z.enum(['totp', 'email', 'push']),
});

const StepUpVerifySchema = z.object({
  challenge_id: z.string().uuid('Invalid challenge ID'),
  response: z.string().min(1, 'Response is required').max(128),
});

const WorkloadTokenSchema = z.object({
  service_id: z.string().min(1, 'Service ID is required'),
  scopes: z.array(z.string()).default([]),
});

const DevIssueTokenSchema = z.object({
  sub: z.string().min(1).max(256).default('dev-user'),
  roles: z.array(z.string().min(1).max(64)).default(['user']),
  scopes: z.array(z.string().min(1).max(128)).default(['openid', 'profile', 'email']),
  step_up_level: z.number().int().min(0).max(2).default(0),
});

// ---------------------------------------------------------------------------
// Route factory
// ---------------------------------------------------------------------------

export interface RoutesDependencies {
  oidcRegistry: OIDCProviderRegistry;
  authFlowStore: AuthFlowStore;
  tokenService: TokenService;
  jwksManager: JWKSManager;
  sessionManager: SessionManager;
  stepUpService: StepUpAuthService;
  workloadService: WorkloadIdentityService;
}

export function createAuthRoutes(deps: RoutesDependencies): Router {
  const {
    oidcRegistry,
    authFlowStore,
    tokenService,
    jwksManager,
    sessionManager,
    stepUpService,
    workloadService,
  } = deps;

  const router = Router();

  // -----------------------------------------------------------------------
  // POST /auth/dev/issue-token -- issue a dev-only access token (local testing)
  // -----------------------------------------------------------------------

  router.post(
    '/auth/dev/issue-token',
    validateBody(DevIssueTokenSchema),
    async (req: Request, res: Response): Promise<void> => {
      const enabled = ['true', '1', 'yes'].includes((process.env['DEV_TOKEN_ISSUER_ENABLED'] ?? '').toLowerCase());
      if (!enabled) {
        res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Endpoint not found' } });
        return;
      }

      const secret = readSecret('DEV_TOKEN_ISSUER_SECRET');
      if (secret.length < 32) {
        logger.error('DEV_TOKEN_ISSUER_ENABLED is true but DEV_TOKEN_ISSUER_SECRET is missing/weak', {
          requestId: req.requestId,
        });
        res.status(503).json({
          error: {
            code: 'DEV_TOKEN_ISSUER_NOT_CONFIGURED',
            message: 'Dev token issuer is not configured',
          },
        });
        return;
      }

      const providedRaw = req.headers['x-dev-issuer-secret'];
      const provided =
        typeof providedRaw === 'string'
          ? providedRaw
          : Array.isArray(providedRaw) && typeof providedRaw[0] === 'string'
            ? providedRaw[0]
            : '';

      const secretBuf = Buffer.from(secret, 'utf8');
      const providedBuf = Buffer.from(provided, 'utf8');
      const ok =
        providedBuf.length === secretBuf.length &&
        providedBuf.length > 0 &&
        crypto.timingSafeEqual(providedBuf, secretBuf);

      if (!ok) {
        res.status(401).json({
          error: {
            code: 'UNAUTHORIZED',
            message: 'Invalid dev issuer secret',
          },
        });
        return;
      }

      try {
        const body = req.body as z.infer<typeof DevIssueTokenSchema>;
        const access = await tokenService.issueAccessToken(
          body.sub,
          Array.from(new Set(body.roles)),
          Array.from(new Set(body.scopes)),
          body.step_up_level,
        );

        res.status(200).json({
          access_token: access.token,
          token_type: 'Bearer',
          expires_in: access.expiresIn,
          claims: {
            sub: body.sub,
            roles: body.roles,
            scopes: body.scopes,
            step_up_level: body.step_up_level,
          },
        });
      } catch (err) {
        logger.error('Dev token issuance failed', {
          error: (err as Error).message,
          requestId: req.requestId,
        });
        res.status(500).json({
          error: { code: 'INTERNAL', message: 'Dev token issuance failed' },
        });
      }
    },
  );

  // -----------------------------------------------------------------------
  // GET /auth/login -- redirect to OIDC provider
  // -----------------------------------------------------------------------

  router.get('/auth/login', async (req: Request, res: Response): Promise<void> => {
    try {
      const query = LoginQuerySchema.safeParse(req.query);
      if (!query.success) {
        res.status(400).json({
          error: { code: 'VAL_4001', message: 'Invalid query parameters' },
        });
        return;
      }

      const providerName = query.data.provider ?? oidcRegistry.listProviders()[0];
      if (!providerName) {
        res.status(503).json({
          error: {
            code: 'NO_PROVIDER',
            message: 'No OIDC providers are configured',
          },
        });
        return;
      }

      let provider: OIDCProvider;
      try {
        provider = oidcRegistry.getOrThrow(providerName);
      } catch (_err) {
        res.status(400).json({
          error: {
            code: 'PROVIDER_NOT_FOUND',
            message: `Provider '${providerName}' is not available`,
          },
        });
        return;
      }

      // Generate PKCE pair.
      const pkce = OIDCProvider.generatePKCE();

      // Generate state (CSRF for the OIDC flow) and nonce.
      const state = crypto.randomBytes(32).toString('base64url');
      const nonce = crypto.randomBytes(32).toString('base64url');

      // Store flow state for the callback.
      await authFlowStore.put(state, {
        provider: providerName,
        codeVerifier: pkce.codeVerifier,
        nonce,
        redirectUri: query.data.redirect_uri,
        createdAt: Date.now(),
      }, 10 * 60);

      const authUrl = provider.buildAuthorizationUrl(
        state,
        nonce,
        pkce.codeChallenge,
      );

      logger.info('OIDC login initiated', {
        provider: providerName,
        requestId: req.requestId,
      });

      res.redirect(302, authUrl);
    } catch (err) {
      logger.error('Login route error', {
        error: (err as Error).message,
        requestId: req.requestId,
      });
      res.status(500).json({
        error: { code: 'INTERNAL', message: 'Login initiation failed' },
      });
    }
  });

  // -----------------------------------------------------------------------
  // GET /auth/callback -- handle OIDC callback
  // -----------------------------------------------------------------------

  router.get('/auth/callback', async (req: Request, res: Response): Promise<void> => {
    try {
      const { code, state, error, error_description } = req.query as Record<
        string,
        string | undefined
      >;

      // Handle provider-side errors.
      if (error) {
        logger.warn('OIDC callback error from provider', {
          error,
          error_description,
          requestId: req.requestId,
        });
        res.status(400).json({
          error: {
            code: 'OIDC_ERROR',
            message: error_description ?? error ?? 'Authentication failed',
          },
        });
        return;
      }

      if (!code || !state) {
        res.status(400).json({
          error: {
            code: 'MISSING_PARAMS',
            message: 'Missing code or state parameter',
          },
        });
        return;
      }

      // Look up the auth flow state.
      const flow = await authFlowStore.consume(state);
      if (!flow) {
        logger.warn('OIDC callback: unknown or expired state', {
          requestId: req.requestId,
        });
        res.status(400).json({
          error: {
            code: 'INVALID_STATE',
            message: 'Invalid or expired authentication state',
          },
        });
        return;
      }

      const provider = oidcRegistry.getOrThrow(flow.provider);

      // Exchange the authorization code for tokens (with PKCE verifier).
      const oidcTokens = await provider.exchangeCode(code, flow.codeVerifier);

      // Validate the ID token (signature, iss, aud, exp, nonce).
      const claims = await provider.validateIdToken(
        oidcTokens.idToken,
        flow.nonce,
      );

      // Derive user identity from OIDC claims.
      const userId = `${flow.provider}:${claims.sub}`;
      const roles = claims.roles ?? ['user'];
      const scopes = ['openid', 'profile', 'email'];

      // Create a session.
      const ipAddress =
        (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ??
        req.socket.remoteAddress ??
        'unknown';
      const deviceFingerprint =
        (req.headers['user-agent'] as string) ?? 'unknown';

      const session = await sessionManager.createSession(
        {
          userId,
          ipAddress,
          deviceFingerprint,
          privilegeLevel: 0,
          metadata: {
            provider: flow.provider,
            email: claims.email,
            name: claims.name,
          },
        },
        res,
      );

      // Issue platform access and refresh tokens.
      const accessResult = await tokenService.issueAccessToken(
        userId,
        roles,
        scopes,
        0,
        session.id,
      );

      const refreshRecord = await tokenService.issueRefreshToken(userId, session.id);

      // Set the CSRF token cookie.
      const csrfToken = SessionManager.generateCsrfToken(session.id);
      res.cookie(config.csrf.cookieName, csrfToken, {
        httpOnly: false, // Client JS needs to read it for the header.
        secure: config.sessions.cookieSecure,
        sameSite: config.sessions.cookieSameSite,
        path: '/',
        maxAge: config.sessions.absoluteTimeoutSeconds * 1000,
      });

      logger.info('OIDC authentication successful', {
        userId,
        provider: flow.provider,
        sessionId: session.id,
        requestId: req.requestId,
      });

      // If a redirect URI was provided, redirect there; otherwise return
      // the tokens in the response body.
      if (flow.redirectUri) {
        const redirectUrl = new URL(flow.redirectUri);
        redirectUrl.searchParams.set('login', 'success');
        res.redirect(302, redirectUrl.toString());
      } else {
        res.status(200).json({
          access_token: accessResult.token,
          refresh_token: refreshRecord.token,
          token_type: 'Bearer',
          expires_in: accessResult.expiresIn,
          session_id: session.id,
        });
      }
    } catch (err) {
      if (err instanceof OIDCError) {
        logger.warn('OIDC callback error', {
          code: err.code,
          message: err.message,
          requestId: req.requestId,
        });
        res.status(400).json({
          error: { code: err.code, message: 'Authentication failed' },
        });
        return;
      }

      logger.error('Callback route error', {
        error: (err as Error).message,
        stack: (err as Error).stack,
        requestId: req.requestId,
      });
      res.status(500).json({
        error: { code: 'INTERNAL', message: 'Authentication callback failed' },
      });
    }
  });

  // -----------------------------------------------------------------------
  // POST /auth/token/refresh -- rotate refresh token, issue new access token
  // -----------------------------------------------------------------------

  router.post(
    '/auth/token/refresh',
    validateBody(TokenRefreshSchema),
    async (req: Request, res: Response): Promise<void> => {
      try {
        const { refresh_token } = req.body as z.infer<typeof TokenRefreshSchema>;

        const existing = await tokenService.getRefreshToken(refresh_token);
        if (!existing) {
          throw new TokenError('Refresh token not found', 'TOKEN_NOT_FOUND');
        }

        // Bind refresh token use to the session lifetime: if the session was destroyed
        // (logout/compromise response) or expired, the refresh token family is revoked.
        const sessionCheck = await sessionManager.validateSession(existing.sessionId);
        if (!sessionCheck.valid) {
          await tokenService.revokeRefreshTokenFamily(existing.familyId);
          throw new TokenError('Refresh token session is invalid', 'TOKEN_REVOKED');
        }

        // Rotate the refresh token (old one is consumed).
        const newRefresh = await tokenService.rotateRefreshToken(refresh_token);

        // Look up user info from the refresh record to issue a new access token.
        // For simplicity, we re-issue with the same roles/scopes.
        // In production, roles would be re-fetched from the user store.
        const accessResult = await tokenService.issueAccessToken(
          newRefresh.userId,
          ['user'], // Roles would come from a user/role service.
          ['openid', 'profile', 'email'],
          0,
          newRefresh.sessionId,
        );

        // Treat refresh as session activity.
        await sessionManager.updateActivity(newRefresh.sessionId);

        logger.info('Token refresh successful', {
          userId: newRefresh.userId,
          newTokenId: newRefresh.tokenId,
          requestId: req.requestId,
        });

        res.status(200).json({
          access_token: accessResult.token,
          refresh_token: newRefresh.token,
          token_type: 'Bearer',
          expires_in: accessResult.expiresIn,
        });
      } catch (err) {
        if (err instanceof TokenError) {
          const status = 401;
          logger.warn('Token refresh failed', {
            code: err.code,
            message: err.message,
            requestId: req.requestId,
          });
          res.status(status).json({
            error: { code: err.code, message: err.message },
          });
          return;
        }

        logger.error('Token refresh error', {
          error: (err as Error).message,
          requestId: req.requestId,
        });
        res.status(500).json({
          error: { code: 'INTERNAL', message: 'Token refresh failed' },
        });
      }
    },
  );

  // -----------------------------------------------------------------------
  // POST /auth/logout -- destroy session and revoke tokens
  // -----------------------------------------------------------------------

  router.post(
    '/auth/logout',
    csrfProtection(),
    async (req: Request, res: Response): Promise<void> => {
      try {
        const sessionId = req.cookies?.[config.sessions.cookieName] as string | undefined;

        const sid = sessionId ?? req.tokenClaims?.sid;

        if (sessionId) {
          await sessionManager.destroySession(sessionId, res);
        }

        // Best-effort: revoke refresh tokens bound to this session.
        if (sid) {
          try {
            await tokenService.revokeSessionRefreshTokens(sid);
          } catch (err) {
            logger.error('Failed to revoke session refresh tokens on logout', {
              sessionId: sid,
              error: (err as Error).message,
              requestId: req.requestId,
            });
          }
        }

        // If an access token was presented, revoke it.
        if (req.tokenClaims?.jti) {
          await tokenService.revokeAccessToken(req.tokenClaims.jti, req.tokenClaims.exp);
        }

        // Clear the CSRF cookie.
        res.clearCookie(config.csrf.cookieName, {
          path: '/',
          secure: config.sessions.cookieSecure,
          sameSite: config.sessions.cookieSameSite,
        });

        logger.info('Logout successful', {
          sessionId,
          requestId: req.requestId,
        });

        res.status(200).json({ message: 'Logged out successfully' });
      } catch (err) {
        logger.error('Logout error', {
          error: (err as Error).message,
          requestId: req.requestId,
        });
        res.status(500).json({
          error: { code: 'INTERNAL', message: 'Logout failed' },
        });
      }
    },
  );

  // -----------------------------------------------------------------------
  // POST /auth/step-up/initiate -- start a step-up challenge
  // -----------------------------------------------------------------------

  router.post(
    '/auth/step-up/initiate',
    csrfProtection(),
    requireAuth(),
    validateBody(StepUpInitiateSchema),
    async (req: Request, res: Response): Promise<void> => {
      try {
        const userId = req.session?.userId ?? req.tokenClaims?.sub;
        if (!userId) {
          res.status(401).json({
            error: { code: 'AUTH_1001', message: 'User identity not found' },
          });
          return;
        }

        const { method } = req.body as z.infer<typeof StepUpInitiateSchema>;

        const result = await stepUpService.initiateStepUp(userId, method);

        logger.info('Step-up challenge initiated', {
          userId,
          method,
          challengeId: result.challengeId,
          requestId: req.requestId,
        });

        res.status(200).json(result);
      } catch (err) {
        if (err instanceof StepUpError) {
          res.status(400).json({
            error: { code: err.code, message: err.message },
          });
          return;
        }

        logger.error('Step-up initiate error', {
          error: (err as Error).message,
          requestId: req.requestId,
        });
        res.status(500).json({
          error: { code: 'INTERNAL', message: 'Step-up initiation failed' },
        });
      }
    },
  );

  // -----------------------------------------------------------------------
  // POST /auth/step-up/verify -- verify a step-up challenge
  // -----------------------------------------------------------------------

  router.post(
    '/auth/step-up/verify',
    csrfProtection(),
    requireAuth(),
    validateBody(StepUpVerifySchema),
    async (req: Request, res: Response): Promise<void> => {
      try {
        const userId = req.session?.userId ?? req.tokenClaims?.sub;
        if (!userId) {
          res.status(401).json({
            error: { code: 'AUTH_1001', message: 'User identity not found' },
          });
          return;
        }

        const { challenge_id, response } = req.body as z.infer<
          typeof StepUpVerifySchema
        >;

        const result = await stepUpService.verifyStepUp(
          userId,
          challenge_id,
          response,
        );

        if (result.success && req.session) {
          // Rotate the session on privilege escalation and update metadata.
          const rotated = await sessionManager.rotateSession(
            req.session.id,
            res,
            result.newLevel,
            { stepUpAt: new Date().toISOString() },
          );

	          if (rotated) {
	            // rotateSession already created the new session with updated metadata.

            // Issue a new access token with the elevated step-up level.
            const accessResult = await tokenService.issueAccessToken(
              userId,
              req.tokenClaims?.roles ?? ['user'],
              req.tokenClaims?.scopes ?? ['openid', 'profile', 'email'],
              result.newLevel,
              rotated.id,
            );

            // Update CSRF cookie for the new session.
            const csrfToken = SessionManager.generateCsrfToken(rotated.id);
            res.cookie(config.csrf.cookieName, csrfToken, {
              httpOnly: false,
              secure: config.sessions.cookieSecure,
              sameSite: config.sessions.cookieSameSite,
              path: '/',
              maxAge: config.sessions.absoluteTimeoutSeconds * 1000,
            });

            logger.info('Step-up verified and session elevated', {
              userId,
              newLevel: result.newLevel,
              newSessionId: rotated.id,
              requestId: req.requestId,
            });

            res.status(200).json({
              success: true,
              new_level: result.newLevel,
              access_token: accessResult.token,
              expires_in: accessResult.expiresIn,
            });
            return;
          }
        }

        res.status(200).json({
          success: result.success,
          new_level: result.newLevel,
          reason: result.reason,
        });
      } catch (err) {
        logger.error('Step-up verify error', {
          error: (err as Error).message,
          requestId: req.requestId,
        });
        res.status(500).json({
          error: { code: 'INTERNAL', message: 'Step-up verification failed' },
        });
      }
    },
  );

  // -----------------------------------------------------------------------
  // GET /.well-known/jwks.json -- served by JWKSManager
  // -----------------------------------------------------------------------

  jwksManager.mountRoute(router);

  // -----------------------------------------------------------------------
  // GET /auth/session -- current session info
  // -----------------------------------------------------------------------

  router.get(
    '/auth/session',
    requireAuth(),
    async (req: Request, res: Response): Promise<void> => {
      try {
        if (!req.session) {
          res.status(200).json({ authenticated: false });
          return;
        }

        const currentLevel = stepUpService.getStepUpLevel(req.session);

        res.status(200).json({
          authenticated: true,
          session: {
            id: req.session.id,
            userId: req.session.userId,
            createdAt: req.session.createdAt,
            lastActivity: req.session.lastActivity,
            expiresAt: req.session.expiresAt,
            privilegeLevel: currentLevel,
            ipAddress: req.session.ipAddress,
          },
        });
      } catch (err) {
        logger.error('Session info error', {
          error: (err as Error).message,
          requestId: req.requestId,
        });
        res.status(500).json({
          error: { code: 'INTERNAL', message: 'Failed to retrieve session' },
        });
      }
    },
  );

  // -----------------------------------------------------------------------
  // POST /auth/workload/token -- issue workload token (mTLS required in prod)
  // -----------------------------------------------------------------------

  router.post(
    '/auth/workload/token',
    validateBody(WorkloadTokenSchema),
    async (req: Request, res: Response): Promise<void> => {
      try {
        const { service_id, scopes } = req.body as z.infer<
          typeof WorkloadTokenSchema
        >;

        // Extract certificate fingerprint from the TLS connection.
        const certFingerprint =
          WorkloadIdentityService.extractFingerprintFromRequest(req);

        // In production, mTLS is mandatory for workload token issuance.
        // In development, allow requests without a client certificate.
        const isProduction = process.env['NODE_ENV'] === 'production';
        if (isProduction && !certFingerprint) {
          res.status(403).json({
            error: {
              code: 'MTLS_REQUIRED',
              message: 'Client certificate required for workload token issuance',
            },
          });
          return;
        }

        const result = await workloadService.issueWorkloadToken(
          service_id,
          scopes,
          certFingerprint,
        );

        logger.info('Workload token issued via API', {
          serviceId: service_id,
          requestId: req.requestId,
        });

        res.status(200).json({
          access_token: result.token,
          token_type: 'Bearer',
          expires_in: result.expiresIn,
        });
      } catch (err) {
        if (err instanceof WorkloadError) {
          const status = err.code === 'SERVICE_NOT_FOUND' ? 404 : 403;
          res.status(status).json({
            error: { code: err.code, message: err.message },
          });
          return;
        }

        logger.error('Workload token error', {
          error: (err as Error).message,
          requestId: req.requestId,
        });
        res.status(500).json({
          error: { code: 'INTERNAL', message: 'Workload token issuance failed' },
        });
      }
    },
  );

  return router;
}
