import type { NextFunction, Request, Response } from 'express';
import type { GatewayConfig } from '../../config/default';
import { globalMetrics } from '@zerotrust/shared';
import { createSecurityLogger } from './request-logger';
import type { BotChallengeStore } from '../state/bot-challenge-store';
import { extractClientIp } from '../utils/client-ip';
import { issueChallengeToken, verifyChallengeToken } from './bot-challenge-token';

function serializeCookie(
  name: string,
  value: string,
  options: {
    ttlSeconds: number;
    secure: boolean;
    httpOnly: boolean;
    sameSite: 'lax' | 'strict' | 'none';
    path: string;
    domain?: string;
  },
): string {
  const attributes = [
    `${name}=${encodeURIComponent(value)}`,
    `Max-Age=${Math.max(1, Math.floor(options.ttlSeconds))}`,
    `Path=${options.path || '/'}`,
  ];
  if (options.domain) attributes.push(`Domain=${options.domain}`);
  if (options.httpOnly) attributes.push('HttpOnly');
  if (options.secure) attributes.push('Secure');
  if (options.sameSite === 'none') attributes.push('SameSite=None');
  if (options.sameSite === 'strict') attributes.push('SameSite=Strict');
  if (options.sameSite === 'lax') attributes.push('SameSite=Lax');
  return attributes.join('; ');
}

function appendSetCookie(res: Response, cookie: string): void {
  const existing = res.getHeader('set-cookie');
  if (!existing) {
    res.setHeader('set-cookie', cookie);
    return;
  }
  if (Array.isArray(existing)) {
    res.setHeader('set-cookie', [...existing.map((v) => String(v)), cookie]);
    return;
  }
  res.setHeader('set-cookie', [String(existing), cookie]);
}

export function createBotChallengeMiddleware(
  config: GatewayConfig,
  deps: {
    challengeStore: BotChallengeStore;
  },
): (req: Request, res: Response, next: NextFunction) => Promise<void> {
  const securityLog = createSecurityLogger(config);
  const trustedProxies = new Set(config.rateLimit.trustedProxies);
  const maxXffDepth = config.rateLimit.xForwardedForMaxDepth;
  const allowlistedIps = new Set(config.adaptiveDefense.ipAllowlist);

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const secret = config.adaptiveDefense.challenge.secret;
    const headerName = config.adaptiveDefense.challenge.headerName.toLowerCase();
    const clearanceSecret = String(config.botManagement.clearance.secret || '').trim();

    if (!config.adaptiveDefense.enabled || !config.adaptiveDefense.challenge.enabled) {
      next();
      return;
    }
    if (!secret) {
      next();
      return;
    }
    if (req.path.startsWith('/internal/')) {
      next();
      return;
    }
    if (req.method.toUpperCase() === 'OPTIONS') {
      next();
      return;
    }

    const clientIp = extractClientIp(req, maxXffDepth, trustedProxies);
    if (allowlistedIps.has(clientIp)) {
      next();
      return;
    }

    const challenge = await deps.challengeStore.getChallenge(clientIp);
    if (!challenge) {
      next();
      return;
    }

    let activeBackoffMs = 0;
    try {
      activeBackoffMs = await deps.challengeStore.getInvalidAttemptBackoffMs(clientIp);
    } catch {
      activeBackoffMs = 0;
    }
    if (activeBackoffMs > 0) {
      const retryAfterSeconds = Math.max(1, Math.ceil(activeBackoffMs / 1000));
      recordCounter('bot_challenge_backoff_total');
      securityLog.warn({
        event: 'bot_challenge_backoff_enforced',
        ip: clientIp,
        path: req.path,
        method: req.method,
        retryAfterSeconds,
        correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
      });
      res.setHeader('retry-after', String(retryAfterSeconds));
      res.status(429).json({ error: 'bot_challenge_backoff', retryAfter: retryAfterSeconds });
      return;
    }

    const rawHeader = req.headers[headerName];
    const token = typeof rawHeader === 'string' ? rawHeader : '';
    if (token) {
      const verified = verifyChallengeToken({
        token,
        ip: clientIp,
        userAgent: String(req.headers['user-agent'] ?? ''),
        secret,
      });
      if (verified.ok) {
        try {
          await Promise.all([
            deps.challengeStore.clearChallenge(clientIp),
            deps.challengeStore.clearInvalidAttempts(clientIp),
          ]);
        } catch (err) {
          securityLog.error({
            event: 'bot_challenge_clear_store_error',
            ip: clientIp,
            path: req.path,
            method: req.method,
            error: err instanceof Error ? err.message : String(err),
            correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
          });
        }
        if (config.botManagement.clearance.enabled && clearanceSecret) {
          const clearanceIssue = issueChallengeToken({
            ip: clientIp,
            userAgent: String(req.headers['user-agent'] ?? ''),
            ttlSeconds: config.botManagement.clearance.ttlSeconds,
            secret: clearanceSecret,
          });
          appendSetCookie(
            res,
            serializeCookie(
              config.botManagement.clearance.cookieName,
              clearanceIssue.token,
              {
                ttlSeconds: config.botManagement.clearance.ttlSeconds,
                secure: config.botManagement.clearance.secure,
                httpOnly: config.botManagement.clearance.httpOnly,
                sameSite: config.botManagement.clearance.sameSite,
                path: config.botManagement.clearance.path,
                domain: config.botManagement.clearance.domain,
              },
            ),
          );
          recordCounter('bot_challenge_clearance_issued_total');
        }
        recordCounter('bot_challenge_pass_total');
        securityLog.info({
          event: 'bot_challenge_passed',
          ip: clientIp,
          path: req.path,
          method: req.method,
          correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
        });
        next();
        return;
      }

      let attempt = {
        blocked: false,
        retryAfterMs: 0,
        attempts: 0,
      };
      try {
        attempt = await deps.challengeStore.registerInvalidAttempt(clientIp, {
          maxInvalidAttempts: config.adaptiveDefense.challenge.maxInvalidAttempts,
          windowMs: config.adaptiveDefense.challenge.invalidAttemptWindowMs,
          backoffMs: config.adaptiveDefense.challenge.invalidAttemptBackoffMs,
        });
      } catch (err) {
        securityLog.error({
          event: 'bot_challenge_invalid_attempt_store_error',
          ip: clientIp,
          path: req.path,
          method: req.method,
          error: err instanceof Error ? err.message : String(err),
          correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
        });
      }

      if (attempt.blocked) {
        const retryAfterSeconds = Math.max(1, Math.ceil(Math.max(1, attempt.retryAfterMs) / 1000));
        recordCounter('bot_challenge_backoff_total');
        securityLog.warn({
          event: 'bot_challenge_backoff_enforced',
          ip: clientIp,
          path: req.path,
          method: req.method,
          attempts: attempt.attempts,
          retryAfterSeconds,
          reason: 'max_invalid_attempts',
          correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
        });
        res.setHeader('retry-after', String(retryAfterSeconds));
        res.status(429).json({ error: 'bot_challenge_backoff', retryAfter: retryAfterSeconds });
        return;
      }

      recordCounter('bot_challenge_invalid_token_total');
    }

    const remainingMs = Math.max(1_000, Date.parse(challenge.expiresAt) - Date.now());
    const issue = issueChallengeToken({
      ip: clientIp,
      userAgent: String(req.headers['user-agent'] ?? ''),
      ttlSeconds: Math.max(1, Math.ceil(Math.min(
        remainingMs,
        config.adaptiveDefense.challenge.tokenTtlMs,
      ) / 1000)),
      secret,
    });

    recordCounter('bot_challenge_required_total');
    securityLog.warn({
      event: 'bot_challenge_required',
      ip: clientIp,
      path: req.path,
      method: req.method,
      reason: challenge.reason,
      correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
    });

    res.setHeader('x-zt-bot-challenge', 'required');
    res.setHeader('x-zt-bot-challenge-header', config.adaptiveDefense.challenge.headerName);
    res.status(403).json({
      error: 'bot_challenge_required',
      challenge: {
        header: config.adaptiveDefense.challenge.headerName,
        token: issue.token,
        expiresAt: new Date(issue.expiresAtMs).toISOString(),
      },
    });
  };
}

function recordCounter(name: string): void {
  try {
    globalMetrics.recordCounter(name, 1, { service: 'gateway' });
  } catch {
    // Metrics must never affect request handling.
  }
}
