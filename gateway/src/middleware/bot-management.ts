import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { GatewayConfig } from '../../config/default';
import { getRouteConfig } from '../../config/default';
import { createSecurityLogger } from './request-logger';
import { globalMetrics } from '@zerotrust/shared';
import { extractClientIp } from '../utils/client-ip';
import type { BotChallengeStore } from '../state/bot-challenge-store';
import { verifyChallengeToken } from './bot-challenge-token';

interface BotSignal {
  kind:
    | 'missing_user_agent'
    | 'automation_user_agent'
    | 'missing_accept'
    | 'missing_accept_language'
    | 'suspicious_path'
    | 'excessive_forwarded_chain'
    | 'headless_hints';
  points: number;
}

interface EffectiveBotManagementProfile {
  enabled: boolean;
  challengeThreshold: number;
  blockThreshold: number;
  challengeDurationMs: number;
  signals: GatewayConfig['botManagement']['signals'];
}

function headerToString(value: string | string[] | undefined): string {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.join(', ');
  return '';
}

function compileVerifiedBotRegex(patterns: string[]): RegExp[] {
  const compiled: RegExp[] = [];
  for (const raw of patterns) {
    const value = raw.trim();
    if (!value) continue;
    try {
      compiled.push(new RegExp(value, 'i'));
      continue;
    } catch {
      // Fall through to escaped literal below.
    }
    const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    compiled.push(new RegExp(escaped, 'i'));
  }
  return compiled;
}

function readCookieValue(req: Request, cookieName: string): string {
  const raw = req.headers['cookie'];
  const header = typeof raw === 'string' ? raw : '';
  if (!header) return '';

  const target = cookieName.trim();
  if (!target) return '';

  const segments = header.split(';');
  for (const segment of segments) {
    const entry = segment.trim();
    if (!entry) continue;
    const idx = entry.indexOf('=');
    if (idx <= 0) continue;
    const name = entry.slice(0, idx).trim();
    if (name !== target) continue;
    const value = entry.slice(idx + 1).trim();
    if (!value) return '';
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }
  return '';
}

function resolveProfile(config: GatewayConfig, req: Request): EffectiveBotManagementProfile {
  const route = getRouteConfig(config, req.path, req.method);
  const profileName = route?.botManagementProfile;
  const profile = profileName ? config.botManagement.profiles[profileName] : undefined;

  return {
    enabled: profile?.enabled ?? config.botManagement.enabled,
    challengeThreshold: profile?.challengeThreshold ?? config.botManagement.challengeThreshold,
    blockThreshold: profile?.blockThreshold ?? config.botManagement.blockThreshold,
    challengeDurationMs: profile?.challengeDurationMs ?? config.botManagement.challengeDurationMs,
    signals: {
      ...config.botManagement.signals,
      ...(profile?.signals ?? {}),
    },
  };
}

function detectSignals(
  req: Request,
  profile: EffectiveBotManagementProfile,
  maxXffDepth: number,
): BotSignal[] {
  const signals: BotSignal[] = [];
  const userAgent = headerToString(req.headers['user-agent'] as string | string[] | undefined).trim();
  const accept = headerToString(req.headers['accept'] as string | string[] | undefined).trim();
  const acceptLanguage = headerToString(req.headers['accept-language'] as string | string[] | undefined).trim();
  const secChUa = headerToString(req.headers['sec-ch-ua'] as string | string[] | undefined).trim();
  const xff = headerToString(req.headers['x-forwarded-for'] as string | string[] | undefined);

  if (!userAgent || userAgent.length < 6) {
    signals.push({ kind: 'missing_user_agent', points: profile.signals.missingUserAgent });
  }

  if (
    /(?:curl|wget|python-requests|httpclient|go-http-client|okhttp|postman|insomnia|scrapy|phantomjs|selenium|playwright|puppeteer|headless|node-fetch|axios|java\/)/i.test(userAgent)
  ) {
    signals.push({ kind: 'automation_user_agent', points: profile.signals.automationUserAgent });
  }

  if (!accept) {
    signals.push({ kind: 'missing_accept', points: profile.signals.missingAccept });
  }

  if (!acceptLanguage) {
    signals.push({ kind: 'missing_accept_language', points: profile.signals.missingAcceptLanguage });
  }

  if (
    /(?:\/wp-admin|\/wp-login|xmlrpc\.php|\/\.env|\/\.git|phpmyadmin|\/actuator|\/jmx-console|\/cgi-bin|\/vendor\/|\/hudson|\/jenkins|\/boaform|\/manager\/html)/i.test(req.path)
  ) {
    signals.push({ kind: 'suspicious_path', points: profile.signals.suspiciousPath });
  }

  const xffDepth = xff
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean)
    .length;
  if (xffDepth > Math.max(2, maxXffDepth + 1)) {
    signals.push({ kind: 'excessive_forwarded_chain', points: profile.signals.excessiveForwardedChain });
  }

  if (
    /headless/i.test(userAgent) ||
    /headless/i.test(secChUa) ||
    req.headers['x-playwright'] !== undefined ||
    req.headers['x-puppeteer'] !== undefined ||
    req.headers['x-cdp-session'] !== undefined
  ) {
    signals.push({ kind: 'headless_hints', points: profile.signals.headlessHints });
  }

  return signals.filter((s) => s.points > 0);
}

function classifyBotScore(
  score: number,
  profile: EffectiveBotManagementProfile,
): 'verified_good_bot' | 'likely_human' | 'suspicious_bot' | 'malicious_bot' {
  if (score <= 0) return 'likely_human';
  if (score >= profile.blockThreshold) return 'malicious_bot';
  if (score >= profile.challengeThreshold) return 'suspicious_bot';
  return 'likely_human';
}

function recordBotMetric(metric: 'detect' | 'challenge' | 'block' | 'clearance', classification: string): void {
  try {
    const metricName =
      metric === 'block'
        ? 'bot_management_blocks_total'
        : metric === 'challenge'
          ? 'bot_management_challenges_total'
          : metric === 'clearance'
            ? 'bot_management_clearance_pass_total'
          : 'bot_management_detections_total';
    globalMetrics.recordCounter(metricName, 1, {
      service: 'gateway',
      classification,
    });
  } catch {
    // Metrics must never break request handling.
  }
}

export function createBotManagementMiddleware(
  config: GatewayConfig,
  deps?: { challengeStore?: BotChallengeStore },
): RequestHandler {
  const securityLog = createSecurityLogger(config);
  const trustedProxies = new Set(config.rateLimit.trustedProxies);
  const maxXffDepth = config.rateLimit.xForwardedForMaxDepth;
  let runtimeSignature = '';
  let verifiedBotRegexes = compileVerifiedBotRegex(config.botManagement.verifiedBotUserAgentPatterns);
  let clearanceSecrets = [
    config.botManagement.clearance.secret,
    ...config.botManagement.clearance.previousSecrets,
  ].map((value) => String(value || '').trim()).filter(Boolean);

  const refreshRuntimeState = (): void => {
    const nextSignature = JSON.stringify({
      verifiedBotUserAgentPatterns: config.botManagement.verifiedBotUserAgentPatterns,
      clearanceSecret: config.botManagement.clearance.secret,
      clearancePreviousSecrets: config.botManagement.clearance.previousSecrets,
    });
    if (nextSignature === runtimeSignature) return;
    verifiedBotRegexes = compileVerifiedBotRegex(config.botManagement.verifiedBotUserAgentPatterns);
    clearanceSecrets = [
      config.botManagement.clearance.secret,
      ...config.botManagement.clearance.previousSecrets,
    ].map((value) => String(value || '').trim()).filter(Boolean);
    runtimeSignature = nextSignature;
  };

  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      refreshRuntimeState();
    } catch {
      // If dynamic bot-management config is invalid, fail-open and continue.
      next();
      return;
    }

    const profile = resolveProfile(config, req);
    if (!profile.enabled) {
      next();
      return;
    }

    const correlationId = (req.headers['x-correlation-id'] as string) || 'unknown';
    const clientIp = extractClientIp(req, maxXffDepth, trustedProxies);
    const userAgent = headerToString(req.headers['user-agent'] as string | string[] | undefined).trim();

    const isVerifiedBot = verifiedBotRegexes.some((re) => re.test(userAgent));
    if (isVerifiedBot) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (req as any).botScore = 0;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (req as any).botClassification = 'verified_good_bot';
      next();
      return;
    }

    const signals = detectSignals(req, profile, maxXffDepth);
    const score = signals.reduce((sum, signal) => sum + signal.points, 0);
    const classification = classifyBotScore(score, profile);
    const clearanceToken = readCookieValue(req, config.botManagement.clearance.cookieName);
    const clearanceAllowed =
      config.botManagement.clearance.enabled &&
      classification === 'suspicious_bot' &&
      clearanceToken.length > 0 &&
      clearanceSecrets.length > 0 &&
      clearanceSecrets.some((secret) =>
        verifyChallengeToken({
          token: clearanceToken,
          ip: clientIp,
          userAgent,
          secret,
        }).ok,
      );

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (req as any).botScore = score;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (req as any).botClassification = classification;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (req as any).botSignals = signals.map((s) => s.kind);

    if (clearanceAllowed) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (req as any).botClassification = 'likely_human';
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (req as any).botClearance = true;
      recordBotMetric('clearance', 'likely_human');
      securityLog.info({
        event: 'bot_management_clearance_passed',
        correlationId,
        ip: clientIp,
        method: req.method,
        path: req.path,
        score,
        signals: signals.map((s) => s.kind),
      });
      next();
      return;
    }

    if (classification === 'malicious_bot') {
      recordBotMetric('block', classification);
      securityLog.warn({
        event: 'bot_management_blocked',
        correlationId,
        ip: clientIp,
        method: req.method,
        path: req.path,
        score,
        classification,
        signals: signals.map((s) => s.kind),
      });
      res.status(403).json({ error: 'bot_blocked' });
      return;
    }

    if (classification === 'suspicious_bot') {
      recordBotMetric('challenge', classification);
      securityLog.warn({
        event: 'bot_management_challenged',
        correlationId,
        ip: clientIp,
        method: req.method,
        path: req.path,
        score,
        classification,
        signals: signals.map((s) => s.kind),
      });
      if (deps?.challengeStore) {
        void deps.challengeStore.setChallenge(
          clientIp,
          Math.max(1, Math.ceil(profile.challengeDurationMs / 1000)),
          'bot_management',
        );
      }
      res.setHeader('x-zt-bot-challenge', 'required');
      res.status(403).json({ error: 'bot_challenge_required' });
      return;
    }

    if (score > 0) {
      recordBotMetric('detect', classification);
      securityLog.info({
        event: 'bot_management_detected',
        correlationId,
        ip: clientIp,
        method: req.method,
        path: req.path,
        score,
        classification,
        signals: signals.map((s) => s.kind),
      });
    }

    next();
  };
}
