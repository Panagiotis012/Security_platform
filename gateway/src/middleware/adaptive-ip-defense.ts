import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { getRouteConfig, type GatewayConfig } from '../../config/default';
import { globalMetrics } from '@zerotrust/shared';
import { createSecurityLogger } from './request-logger';
import { extractClientIp } from '../utils/client-ip';
import type { SecurityStateStore } from '../state/security-state-store';
import type { IpReputationStore } from '../state/ip-reputation-store';
import type { BotChallengeStore } from '../state/bot-challenge-store';

interface EffectiveAdaptiveProfile {
  name: string;
  scoreWindowMs: number;
  blockThreshold: number;
  blockDurationMs: number;
  challengeThreshold: number;
  challengeDurationMs: number;
  challengeEnabled: boolean;
  signals: GatewayConfig['adaptiveDefense']['signals'];
}

interface AdaptiveSignal {
  kind: string;
  points: number;
}

export function createAdaptiveIpDefenseMiddleware(
  config: GatewayConfig,
  deps: {
    stateStore: SecurityStateStore;
    reputationStore: IpReputationStore;
    challengeStore: BotChallengeStore;
  },
): RequestHandler {
  if (!config.adaptiveDefense.enabled) {
    return (_req: Request, _res: Response, next: NextFunction): void => next();
  }

  const securityLog = createSecurityLogger(config);
  const allowlistedIps = new Set(config.adaptiveDefense.ipAllowlist);
  const trustedProxies = new Set(config.rateLimit.trustedProxies);
  const maxXffDepth = config.rateLimit.xForwardedForMaxDepth;

  return (req: Request, res: Response, next: NextFunction): void => {
    if (req.path.startsWith('/internal/')) {
      next();
      return;
    }

    const clientIp = extractClientIp(req, maxXffDepth, trustedProxies);
    if (allowlistedIps.has(clientIp)) {
      next();
      return;
    }

    const originalEnd = res.end;
    let handled = false;

    const handleFinalStatus = async (): Promise<void> => {
      if (handled) return;
      handled = true;

      const challengeResponse = res.getHeader('x-zt-bot-challenge');
      if (typeof challengeResponse === 'string' && challengeResponse.toLowerCase() === 'required') {
        return;
      }

      const profile = resolveProfile(req, config);
      const signals = classifySignals(req, res.statusCode, profile);
      if (signals.length === 0) return;
      const totalPoints = signals.reduce((sum, signal) => sum + signal.points, 0);
      if (totalPoints <= 0) return;
      const signalKinds = signals.map((s) => s.kind);
      const primarySignal = signalKinds[0] || 'unknown';

      try {
        for (const signal of signals) {
          recordAdaptiveMetric('adaptive_ip_signals_total', signal.kind);
        }

        const score = await deps.reputationStore.addScore(
          clientIp,
          totalPoints,
          profile.scoreWindowMs,
        );

        if (
          profile.challengeEnabled &&
          score.score >= profile.challengeThreshold &&
          score.score < profile.blockThreshold
        ) {
          const existingChallenge = await deps.challengeStore.getChallenge(clientIp);
          if (!existingChallenge) {
            await deps.challengeStore.setChallenge(
              clientIp,
              Math.max(1, Math.ceil(profile.challengeDurationMs / 1000)),
              `adaptive_ip_reputation:${primarySignal}`,
            );
            recordAdaptiveMetric('adaptive_ip_challenges_total', primarySignal);
            securityLog.warn({
              event: 'adaptive_ip_challenged',
              ip: clientIp,
              path: req.path,
              method: req.method,
              signal: primarySignal,
              signals: signalKinds,
              signalPoints: totalPoints,
              profile: profile.name,
              score: score.score,
              threshold: profile.challengeThreshold,
              challengeDurationMs: profile.challengeDurationMs,
              correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
            });
          }
        }

        if (score.score < profile.blockThreshold) return;

        const existing = await deps.stateStore.isIpBlocked(clientIp);
        if (existing) return;

        const ttlSeconds = Math.max(1, Math.ceil(profile.blockDurationMs / 1000));
        await deps.stateStore.blockIps([clientIp], ttlSeconds, {
          reason: `adaptive_ip_reputation:${primarySignal}`,
        });
        await deps.challengeStore.clearChallenge(clientIp);
        await deps.reputationStore.reset(clientIp);
        recordAdaptiveMetric('adaptive_ip_blocks_total', primarySignal);

        securityLog.warn({
          event: 'adaptive_ip_blocked',
          ip: clientIp,
          path: req.path,
          method: req.method,
          signal: primarySignal,
          signals: signalKinds,
          signalPoints: totalPoints,
          profile: profile.name,
          score: score.score,
          threshold: profile.blockThreshold,
          blockDurationMs: profile.blockDurationMs,
          correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
        });
      } catch (err) {
        securityLog.error({
          event: 'adaptive_ip_defense_error',
          ip: clientIp,
          path: req.path,
          method: req.method,
          signal: primarySignal,
          signals: signalKinds,
          error: err instanceof Error ? err.message : String(err),
          correlationId: (req.headers['x-correlation-id'] as string) || 'unknown',
        });
      }
    };

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    res.end = function adaptiveEnd(this: Response, ...args: any[]): Response {
      void handleFinalStatus();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return originalEnd.apply(this, args as any);
    };

    next();
  };
}

function classifySignals(
  req: Request,
  statusCode: number,
  profile: EffectiveAdaptiveProfile,
): AdaptiveSignal[] {
  const signals: AdaptiveSignal[] = [];

  if (statusCode === 429) {
    signals.push({ kind: 'rate_limit', points: profile.signals.rateLimitExceeded });
  }
  if (statusCode === 401) {
    signals.push({ kind: 'auth_failure', points: profile.signals.authFailure });
  }
  if (statusCode === 403) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const wafMatches = (req as any).wafMatches as unknown;
    if (Array.isArray(wafMatches) && wafMatches.length > 0) {
      signals.push({ kind: 'waf_block', points: profile.signals.wafBlock });
    } else {
      signals.push({ kind: 'forbidden', points: profile.signals.forbidden });
    }
  }

  const fingerprint = evaluateBotFingerprint(req);
  if (fingerprint.severity > 0 && profile.signals.botFingerprint > 0) {
    const multiplier = fingerprint.severity === 1 ? 0.5 : fingerprint.severity === 2 ? 1 : 1.25;
    const points = Math.max(1, Math.round(profile.signals.botFingerprint * multiplier));
    signals.push({ kind: 'bot_fingerprint', points });
  }

  return signals;
}

function evaluateBotFingerprint(req: Request): { severity: 0 | 1 | 2 | 3; reasons: string[] } {
  const reasons: string[] = [];
  let score = 0;

  const ua = String(req.headers['user-agent'] ?? '');
  if (!ua || ua.trim().length < 8) {
    score += 2;
    reasons.push('missing_or_short_ua');
  }

  const lowerUa = ua.toLowerCase();
  const automationMarkers = [
    'curl',
    'wget',
    'python-requests',
    'go-http-client',
    'headless',
    'phantomjs',
    'scrapy',
    'httpclient',
    'postmanruntime',
  ];
  if (automationMarkers.some((marker) => lowerUa.includes(marker))) {
    score += 3;
    reasons.push('automation_ua');
  }

  const accept = String(req.headers['accept'] ?? '');
  if (!accept || accept.trim().length === 0) {
    score += 1;
    reasons.push('missing_accept');
  }

  const forwardedFor = String(req.headers['x-forwarded-for'] ?? '');
  if (forwardedFor) {
    const hops = forwardedFor.split(',').map((v) => v.trim()).filter(Boolean);
    if (hops.length > 5) {
      score += 1;
      reasons.push('deep_xff_chain');
    }
  }

  let severity: 0 | 1 | 2 | 3 = 0;
  if (score >= 5) severity = 3;
  else if (score >= 3) severity = 2;
  else if (score >= 2) severity = 1;

  return { severity, reasons };
}

function resolveProfile(req: Request, config: GatewayConfig): EffectiveAdaptiveProfile {
  const base = config.adaptiveDefense;
  const routeConfig = getRouteConfig(config, req.path, req.method);
  const profileName = routeConfig?.adaptiveProfile;
  const overrides = profileName ? config.adaptiveDefense.profiles[profileName] : undefined;

  return {
    name: profileName && overrides ? profileName : 'default',
    scoreWindowMs: overrides?.scoreWindowMs ?? base.scoreWindowMs,
    blockThreshold: overrides?.blockThreshold ?? base.blockThreshold,
    blockDurationMs: overrides?.blockDurationMs ?? base.blockDurationMs,
    challengeThreshold: overrides?.challengeThreshold ?? base.challengeThreshold,
    challengeDurationMs: overrides?.challengeDurationMs ?? base.challenge.durationMs,
    challengeEnabled: overrides?.challengeEnabled ?? base.challenge.enabled,
    signals: {
      wafBlock: overrides?.signals?.wafBlock ?? base.signals.wafBlock,
      rateLimitExceeded: overrides?.signals?.rateLimitExceeded ?? base.signals.rateLimitExceeded,
      authFailure: overrides?.signals?.authFailure ?? base.signals.authFailure,
      forbidden: overrides?.signals?.forbidden ?? base.signals.forbidden,
      botFingerprint: overrides?.signals?.botFingerprint ?? base.signals.botFingerprint,
    },
  };
}

function recordAdaptiveMetric(metric: string, signal: string): void {
  try {
    globalMetrics.recordCounter(metric, 1, {
      service: 'gateway',
      signal,
    });
  } catch {
    // Metrics failures must never affect request handling.
  }
}
