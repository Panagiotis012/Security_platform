import type { Request, Response } from 'express';
import { Router } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type WebAuthnCredential,
} from '@simplewebauthn/server';
import { csrfProtection, requireAuth, validateBody } from './middleware';
import type { WebAuthnStore } from '../webauthn/webauthn-store';
import { SessionManager } from '../sessions/session-manager';
import type { TokenService } from '../tokens/token-service';
import { config } from '../../config/default';
import { createLogger } from '../logger';

const logger = createLogger('webauthn-routes');

export interface WebAuthnRoutesDeps {
  store: WebAuthnStore;
  tokenService: TokenService;
  sessionManager: SessionManager;
}

const RegisterOptionsSchema = z.object({
  userName: z.string().min(1).max(256).optional(),
  userDisplayName: z.string().min(1).max(256).optional(),
});

const RegisterVerifySchema = z.object({
  challengeId: z.string().uuid(),
  response: z.unknown(),
});

const StepUpOptionsSchema = z.object({}).default({});

const StepUpVerifySchema = z.object({
  challengeId: z.string().uuid(),
  response: z.unknown(),
});

const ALLOWED_TRANSPORTS: ReadonlySet<AuthenticatorTransportFuture> = new Set([
  'ble',
  'cable',
  'hybrid',
  'internal',
  'nfc',
  'smart-card',
  'usb',
]);

function normalizeTransports(value: unknown): AuthenticatorTransportFuture[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const out: AuthenticatorTransportFuture[] = [];
  for (const v of value) {
    if (typeof v !== 'string') continue;
    if (ALLOWED_TRANSPORTS.has(v as AuthenticatorTransportFuture)) {
      out.push(v as AuthenticatorTransportFuture);
    }
  }
  return out.length > 0 ? out : undefined;
}

function credentialIdFromResponse(value: unknown): string | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const id = (value as { id?: unknown }).id;
  return typeof id === 'string' && id.length > 0 ? id : undefined;
}

function webAuthnConfig(): { rpName: string; rpID: string; origin: string } {
  const rpName = process.env['WEBAUTHN_RP_NAME'] ?? 'ZeroTrust';
  const rpID = process.env['WEBAUTHN_RP_ID'] ?? 'localhost';
  const origin = process.env['WEBAUTHN_ORIGIN'] ?? (process.env['IDENTITY_EXTERNAL_BASE_URL'] ?? 'https://localhost:8443');
  return { rpName, rpID, origin };
}

function toUint8Array(value: string): Uint8Array {
  // Convert a string to bytes in a way that is compatible across TS versions.
  const b = Buffer.from(value, 'utf8');
  const out = new Uint8Array(b.byteLength);
  out.set(b);
  return out;
}

function b64urlToBytes(b64url: string): Uint8Array {
  // base64url -> base64
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const b = Buffer.from(b64 + pad, 'base64');
  const out = new Uint8Array(b.byteLength);
  out.set(b);
  return out;
}

function bytesToB64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export function createWebAuthnRoutes(deps: WebAuthnRoutesDeps): Router {
  const router = Router();
  const cfg = webAuthnConfig();

  // -----------------------------------------------------------------------
  // POST /auth/webauthn/register/options
  // -----------------------------------------------------------------------
  router.post(
    '/auth/webauthn/register/options',
    csrfProtection(),
    requireAuth(),
    validateBody(RegisterOptionsSchema),
    async (req: Request, res: Response): Promise<void> => {
      const userId = req.session?.userId ?? req.tokenClaims?.sub;
      if (!userId) {
        res.status(401).json({ error: { code: 'AUTH_1001', message: 'User identity not found' } });
        return;
      }

      const body = req.body as z.infer<typeof RegisterOptionsSchema>;
      const userName = body.userName ?? userId;
      const userDisplayName = body.userDisplayName ?? userId;

      try {
        const existing = await deps.store.listCredentials(userId);
        const challengeId = uuidv4();

        const options = await generateRegistrationOptions({
          rpName: cfg.rpName,
          rpID: cfg.rpID,
          userName,
          userDisplayName,
          userID: toUint8Array(userId),
          attestationType: 'none',
          authenticatorSelection: {
            residentKey: 'preferred',
            userVerification: 'required',
          },
          excludeCredentials: existing.map((c) => ({
            id: c.credentialID,
            transports: normalizeTransports(c.transports),
          })),
        });

        await deps.store.putChallenge(userId, 'registration', challengeId, options.challenge, 10 * 60);

        res.status(200).json({
          challengeId,
          rpId: cfg.rpID,
          origin: cfg.origin,
          options,
        });
      } catch (err) {
        logger.error('webauthn register options failed', {
          userId,
          error: err instanceof Error ? err.message : String(err),
          requestId: req.requestId,
        });
        res.status(500).json({ error: { code: 'INTERNAL', message: 'Failed to generate WebAuthn options' } });
      }
    }
  );

  // -----------------------------------------------------------------------
  // POST /auth/webauthn/register/verify
  // -----------------------------------------------------------------------
  router.post(
    '/auth/webauthn/register/verify',
    csrfProtection(),
    requireAuth(),
    validateBody(RegisterVerifySchema),
    async (req: Request, res: Response): Promise<void> => {
      const userId = req.session?.userId ?? req.tokenClaims?.sub;
      if (!userId) {
        res.status(401).json({ error: { code: 'AUTH_1001', message: 'User identity not found' } });
        return;
      }

      const { challengeId, response } = req.body as z.infer<typeof RegisterVerifySchema>;

      try {
        const expectedChallenge = await deps.store.consumeChallenge(userId, 'registration', challengeId);
        if (!expectedChallenge) {
          res.status(400).json({ error: { code: 'INVALID_CHALLENGE', message: 'Unknown or expired challenge' } });
          return;
        }

        const verification = await verifyRegistrationResponse({
          response: response as RegistrationResponseJSON,
          expectedChallenge,
          expectedOrigin: cfg.origin,
          expectedRPID: cfg.rpID,
          requireUserVerification: true,
        });

        if (!verification.verified) {
          res.status(400).json({ verified: false });
          return;
        }

        const reg = verification.registrationInfo;
        const cred = reg.credential;

        await deps.store.putCredential(userId, {
          credentialID: cred.id,
          credentialPublicKeyB64: bytesToB64url(cred.publicKey),
          counter: cred.counter,
          transports: cred.transports,
          deviceType: reg.credentialDeviceType,
          backedUp: reg.credentialBackedUp,
          createdAt: new Date().toISOString(),
        });

        logger.info('webauthn credential registered', {
          userId,
          credentialId: cred.id,
          deviceType: reg.credentialDeviceType,
          backedUp: reg.credentialBackedUp,
          requestId: req.requestId,
        });

        res.status(200).json({ verified: true });
      } catch (err) {
        logger.error('webauthn register verify failed', {
          userId,
          error: err instanceof Error ? err.message : String(err),
          requestId: req.requestId,
        });
        res.status(400).json({ verified: false, error: { code: 'VERIFY_FAILED', message: 'WebAuthn registration verification failed' } });
      }
    }
  );

  // -----------------------------------------------------------------------
  // POST /auth/webauthn/step-up/options
  // -----------------------------------------------------------------------
  router.post(
    '/auth/webauthn/step-up/options',
    csrfProtection(),
    requireAuth(),
    validateBody(StepUpOptionsSchema),
    async (req: Request, res: Response): Promise<void> => {
      const userId = req.session?.userId ?? req.tokenClaims?.sub;
      if (!userId) {
        res.status(401).json({ error: { code: 'AUTH_1001', message: 'User identity not found' } });
        return;
      }

      try {
        const creds = await deps.store.listCredentials(userId);
        if (creds.length === 0) {
          res.status(400).json({ error: { code: 'NO_WEBAUTHN', message: 'No WebAuthn credentials registered' } });
          return;
        }

        const challengeId = uuidv4();
        const options = await generateAuthenticationOptions({
          rpID: cfg.rpID,
          userVerification: 'required',
          allowCredentials: creds.map((c) => ({
            id: c.credentialID,
            transports: normalizeTransports(c.transports),
          })),
        });

        await deps.store.putChallenge(userId, 'authentication', challengeId, options.challenge, 5 * 60);

        res.status(200).json({
          challengeId,
          rpId: cfg.rpID,
          origin: cfg.origin,
          options,
        });
      } catch (err) {
        logger.error('webauthn step-up options failed', {
          userId,
          error: err instanceof Error ? err.message : String(err),
          requestId: req.requestId,
        });
        res.status(500).json({ error: { code: 'INTERNAL', message: 'Failed to generate WebAuthn options' } });
      }
    }
  );

  // -----------------------------------------------------------------------
  // POST /auth/webauthn/step-up/verify
  // -----------------------------------------------------------------------
  router.post(
    '/auth/webauthn/step-up/verify',
    csrfProtection(),
    requireAuth(),
    validateBody(StepUpVerifySchema),
    async (req: Request, res: Response): Promise<void> => {
      const userId = req.session?.userId ?? req.tokenClaims?.sub;
      if (!userId) {
        res.status(401).json({ error: { code: 'AUTH_1001', message: 'User identity not found' } });
        return;
      }

      const { challengeId, response } = req.body as z.infer<typeof StepUpVerifySchema>;

      try {
        const expectedChallenge = await deps.store.consumeChallenge(userId, 'authentication', challengeId);
        if (!expectedChallenge) {
          res.status(400).json({ error: { code: 'INVALID_CHALLENGE', message: 'Unknown or expired challenge' } });
          return;
        }

        const creds = await deps.store.listCredentials(userId);
        const credentialId = credentialIdFromResponse(response);
        const match = credentialId ? creds.find((c) => c.credentialID === credentialId) : undefined;
        if (!match) {
          res.status(400).json({ error: { code: 'UNKNOWN_CREDENTIAL', message: 'Credential not registered' } });
          return;
        }

        const credential: WebAuthnCredential = {
          id: match.credentialID,
          publicKey: b64urlToBytes(match.credentialPublicKeyB64),
          counter: match.counter,
          transports: normalizeTransports(match.transports),
        };

        const verification = await verifyAuthenticationResponse({
          response: response as AuthenticationResponseJSON,
          expectedChallenge,
          expectedOrigin: cfg.origin,
          expectedRPID: cfg.rpID,
          credential,
          requireUserVerification: true,
        });

        if (!verification.verified) {
          res.status(401).json({ success: false, new_level: 0, reason: 'WebAuthn verification failed' });
          return;
        }

        // Update counter to prevent replays.
        await deps.store.updateCredentialUsage(userId, verification.authenticationInfo.credentialID, verification.authenticationInfo.newCounter);

        const stepUpAt = new Date().toISOString();
        const newLevel = 2;

        // If we have a session, rotate it to prevent fixation and to elevate privilege level.
        if (req.session) {
          const rotated = await deps.sessionManager.rotateSession(req.session.id, res, newLevel, { stepUpAt });
          if (rotated) {
            const accessResult = await deps.tokenService.issueAccessToken(
              userId,
              req.tokenClaims?.roles ?? ['user'],
              req.tokenClaims?.scopes ?? ['openid', 'profile', 'email'],
              newLevel,
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

            res.status(200).json({
              success: true,
              new_level: newLevel,
              access_token: accessResult.token,
              expires_in: accessResult.expiresIn,
            });
            return;
          }
        }

        // Token-only callers: mint a new access token with elevated step-up level.
        const accessResult = await deps.tokenService.issueAccessToken(
          userId,
          req.tokenClaims?.roles ?? ['user'],
          req.tokenClaims?.scopes ?? ['openid', 'profile', 'email'],
          newLevel,
          req.tokenClaims?.sid,
        );

        res.status(200).json({
          success: true,
          new_level: newLevel,
          access_token: accessResult.token,
          expires_in: accessResult.expiresIn,
        });
      } catch (err) {
        logger.error('webauthn step-up verify failed', {
          userId,
          error: err instanceof Error ? err.message : String(err),
          requestId: req.requestId,
        });
        res.status(500).json({ error: { code: 'INTERNAL', message: 'WebAuthn step-up verification failed' } });
      }
    }
  );

  return router;
}
