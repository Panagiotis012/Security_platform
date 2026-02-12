import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { createHash } from 'crypto';
import type { GatewayConfig} from '../../config/default';
import { getRouteConfig } from '../../config/default';
import { createSecurityLogger } from './request-logger';
import { globalMetrics } from '@zerotrust/shared';
import { extractClientIp } from '../utils/client-ip';
import type { BotChallengeStore } from '../state/bot-challenge-store';

/**
 * Web Application Firewall (WAF) middleware.
 *
 * Pattern-based detection for common attack vectors.
 * Defense in depth — not the primary control, but catches obvious attacks.
 *
 * - XSS payload detection
 * - SQL injection detection
 * - Command injection detection
 * - SSRF detection
 * - Path traversal detection
 * - Request scoring: accumulate risk across all patterns
 * - Configurable rule sets: enable/disable per route
 * - Full context logged on every block
 */

// ─── Rule Definitions ────────────────────────────────────────────────────────

interface WafRule {
  id: string;
  ruleSet: string;
  version?: string;
  description: string;
  pattern: RegExp;
  score: number;
  targets: ('url' | 'query' | 'body' | 'headers' | 'cookies')[];
  action?: 'block' | 'log' | 'challenge';
  rolloutPercent?: number;
}

interface WafRateRule {
  id: string;
  version?: string;
  description: string;
  pathPattern: RegExp;
  methods: Set<string>;
  threshold: number;
  windowMs: number;
  blockDurationMs: number;
  keyBy: 'ip' | 'ip_path' | 'ip_ua';
  action: 'block' | 'log' | 'challenge';
  rolloutPercent?: number;
}

interface WafRateRuleCounter {
  windowStartMs: number;
  count: number;
  blockedUntilMs: number;
  lastSeenMs: number;
}

const WAF_RULES: WafRule[] = [
  // ── XSS Rules ─────────────────────────────────────────────────────
  {
    id: 'XSS-001',
    ruleSet: 'xss',
    description: 'Script tag injection',
    pattern: /<script[\s>\/]/i,
    score: 25,
    targets: ['query', 'body', 'headers'],
  },
  {
    id: 'XSS-002',
    ruleSet: 'xss',
    description: 'Event handler injection',
    pattern: /\bon\w+\s*=\s*['"]/i,
    score: 20,
    targets: ['query', 'body', 'headers'],
  },
  {
    id: 'XSS-003',
    ruleSet: 'xss',
    description: 'JavaScript URI scheme',
    pattern: /javascript\s*:/i,
    score: 25,
    targets: ['query', 'body', 'url'],
  },
  {
    id: 'XSS-004',
    ruleSet: 'xss',
    description: 'Data URI with script content',
    pattern: /data\s*:[^,]*;base64/i,
    score: 15,
    targets: ['query', 'body', 'url'],
  },
  {
    id: 'XSS-005',
    ruleSet: 'xss',
    description: 'SVG onload/onerror',
    pattern: /<svg[^>]*\s+on\w+\s*=/i,
    score: 25,
    targets: ['query', 'body'],
  },
  {
    id: 'XSS-006',
    ruleSet: 'xss',
    description: 'Expression/eval injection',
    pattern: /(?:expression|eval|alert|confirm|prompt)\s*\(/i,
    score: 20,
    targets: ['query', 'body', 'headers'],
  },
  {
    id: 'XSS-007',
    ruleSet: 'xss',
    description: 'HTML entity obfuscation for script',
    pattern: /&#(?:x[0-9a-f]+|\d+);/i,
    score: 10,
    targets: ['query', 'body'],
  },
  {
    id: 'XSS-008',
    ruleSet: 'xss',
    description: 'Iframe injection',
    pattern: /<iframe[\s>]/i,
    score: 25,
    targets: ['query', 'body'],
  },

  // ── SQL Injection Rules ───────────────────────────────────────────
  {
    id: 'SQLI-001',
    ruleSet: 'sqli',
    description: 'SQL UNION SELECT',
    pattern: /union\s+(all\s+)?select/i,
    score: 30,
    targets: ['query', 'body', 'url'],
  },
  {
    id: 'SQLI-002',
    ruleSet: 'sqli',
    description: 'SQL comment sequence',
    pattern: /(?:--|#|\/\*)/,
    score: 10,
    targets: ['query', 'body', 'url'],
  },
  {
    id: 'SQLI-003',
    ruleSet: 'sqli',
    description: 'SQL OR/AND boolean injection',
    pattern: /(?:'\s*(?:or|and)\s*'?\s*['"=])|(?:"\s*(?:or|and)\s*"?\s*['"=])/i,
    score: 25,
    targets: ['query', 'body'],
  },
  {
    id: 'SQLI-004',
    ruleSet: 'sqli',
    description: 'SQL statement keywords',
    pattern: /(?:select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+(?:table|database|index)|alter\s+table|create\s+(?:table|database|index))\b/i,
    score: 25,
    targets: ['query', 'body'],
  },
  {
    id: 'SQLI-005',
    ruleSet: 'sqli',
    description: 'SQL function injection',
    pattern: /(?:concat|char|substr|ascii|hex|unhex|load_file|benchmark|sleep|waitfor|pg_sleep)\s*\(/i,
    score: 20,
    targets: ['query', 'body'],
  },
  {
    id: 'SQLI-006',
    ruleSet: 'sqli',
    description: 'Tautology (1=1 style)',
    pattern: /(?:'\s*=\s*'|"\s*=\s*"|1\s*=\s*1|1\s*=\s*'1')/,
    score: 20,
    targets: ['query', 'body'],
  },
  {
    id: 'SQLI-007',
    ruleSet: 'sqli',
    description: 'SQL batch separator',
    pattern: /;\s*(?:select|insert|update|delete|drop|exec|execute|xp_|sp_)\b/i,
    score: 30,
    targets: ['query', 'body'],
  },

  // ── Command Injection Rules ───────────────────────────────────────
  {
    id: 'CMDI-001',
    ruleSet: 'cmdi',
    description: 'Shell command chaining',
    pattern: /(?:[;|&`]\s*(?:cat|ls|dir|rm|mv|cp|wget|curl|nc|ncat|bash|sh|cmd|powershell|python|perl|ruby|php|node))\b/i,
    score: 30,
    targets: ['query', 'body', 'headers'],
  },
  {
    id: 'CMDI-002',
    ruleSet: 'cmdi',
    description: 'Backtick command substitution',
    pattern: /`[^`]+`/,
    score: 20,
    targets: ['query', 'body', 'headers'],
  },
  {
    id: 'CMDI-003',
    ruleSet: 'cmdi',
    description: 'Shell variable expansion',
    pattern: /\$\(.*\)/,
    score: 20,
    targets: ['query', 'body', 'headers'],
  },
  {
    id: 'CMDI-004',
    ruleSet: 'cmdi',
    description: 'Pipe to shell command',
    pattern: /\|\s*(?:bash|sh|zsh|ksh|csh|tcsh|cmd|powershell)\b/i,
    score: 30,
    targets: ['query', 'body'],
  },
  {
    id: 'CMDI-005',
    ruleSet: 'cmdi',
    description: 'Common reverse shell patterns',
    pattern: /(?:\/dev\/tcp\/|mkfifo|nc\s+-\w*e|bash\s+-i)/i,
    score: 40,
    targets: ['query', 'body', 'headers'],
  },

  // ── SSRF Rules ────────────────────────────────────────────────────
  {
    id: 'SSRF-001',
    ruleSet: 'ssrf',
    description: 'Internal IP address in request',
    pattern: /(?:127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|0\.0\.0\.0|localhost|::1|0x7f)/i,
    score: 25,
    targets: ['query', 'body', 'headers'],
  },
  {
    id: 'SSRF-002',
    ruleSet: 'ssrf',
    description: 'Cloud metadata endpoint',
    pattern: /(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)/,
    score: 40,
    targets: ['query', 'body', 'url', 'headers'],
  },
  {
    id: 'SSRF-003',
    ruleSet: 'ssrf',
    description: 'File protocol scheme',
    pattern: /file:\/\//i,
    score: 30,
    targets: ['query', 'body', 'url', 'headers'],
  },
  {
    id: 'SSRF-004',
    ruleSet: 'ssrf',
    description: 'Internal service scheme (gopher, dict)',
    pattern: /(?:gopher|dict|ftp|ldap|tftp):\/\//i,
    score: 30,
    targets: ['query', 'body', 'url', 'headers'],
  },

  // ── Path Traversal Rules ──────────────────────────────────────────
  {
    id: 'TRAV-001',
    ruleSet: 'traversal',
    description: 'Dot-dot-slash traversal',
    pattern: /(?:\.\.[\\/]|\.\.%2[fF]|%2[eE]%2[eE][\\/]|%2[eE]%2[eE]%2[fF])/,
    score: 30,
    targets: ['url', 'query', 'body'],
  },
  {
    id: 'TRAV-002',
    ruleSet: 'traversal',
    description: 'Sensitive file access attempt',
    pattern: /(?:\/etc\/(?:passwd|shadow|hosts)|\/proc\/self|\/var\/log|\.htaccess|web\.config|\.env|\.git)/i,
    score: 35,
    targets: ['url', 'query', 'body'],
  },
  {
    id: 'TRAV-003',
    ruleSet: 'traversal',
    description: 'Windows path traversal',
    pattern: /(?:[a-zA-Z]:\\|%5[cC])/,
    score: 20,
    targets: ['url', 'query', 'body'],
  },
];

function compileCustomWafRules(config: GatewayConfig): WafRule[] {
  const compiled: WafRule[] = [];
  const allowedVersions = new Set([
    ...config.waf.allowedRuleVersions,
    config.waf.managedRulesVersion,
  ]);
  for (const rule of config.waf.customRules) {
    try {
      if (!rule.enabled) continue;
      if (!allowedVersions.has(rule.version)) continue;
      const pattern = new RegExp(rule.pattern, rule.flags || 'i');
      compiled.push({
        id: rule.id,
        ruleSet: rule.ruleSet || 'custom',
        version: rule.version,
        description: rule.description || 'Custom WAF rule',
        pattern,
        score: rule.score,
        targets: rule.targets,
        action: rule.action,
        rolloutPercent: rule.rolloutPercent,
      });
    } catch {
      // Invalid custom regex should not crash runtime request path.
      // Config loader already validates shape; this catches runtime regex syntax issues.
      continue;
    }
  }
  return compiled;
}

function compileWafRateRules(config: GatewayConfig): WafRateRule[] {
  const compiled: WafRateRule[] = [];
  const allowedVersions = new Set([
    ...config.waf.allowedRuleVersions,
    config.waf.managedRulesVersion,
  ]);

  for (const rule of config.waf.rateRules) {
    try {
      if (!rule.enabled) continue;
      if (!allowedVersions.has(rule.version)) continue;
      const pathPattern = new RegExp(rule.pathPattern, 'i');
      const methods = new Set(rule.methods.map((m) => m.trim().toUpperCase()).filter(Boolean));
      compiled.push({
        id: rule.id,
        version: rule.version,
        description: rule.description,
        pathPattern,
        methods,
        threshold: rule.threshold,
        windowMs: rule.windowMs,
        blockDurationMs: rule.blockDurationMs,
        keyBy: rule.keyBy,
        action: rule.action,
        rolloutPercent: rule.rolloutPercent,
      });
    } catch {
      // Invalid regex should never crash the request path.
      continue;
    }
  }

  return compiled;
}

function shouldApplyRuleForRequest(rule: WafRule, req: Request): boolean {
  const rollout = Math.max(0, Math.min(100, Math.floor(rule.rolloutPercent ?? 100)));
  if (rollout >= 100) return true;
  if (rollout <= 0) return false;

  const seed = `${rule.id}|${req.ip}|${req.path}|${req.method}`;
  const hash = createHash('sha256').update(seed).digest('hex');
  const bucket = parseInt(hash.slice(0, 8), 16) % 100;
  return bucket < rollout;
}

function shouldApplyRateRuleForRequest(rule: WafRateRule, req: Request): boolean {
  if (rule.methods.size > 0 && !rule.methods.has(req.method.toUpperCase())) {
    return false;
  }
  if (!rule.pathPattern.test(req.path)) {
    return false;
  }

  const rollout = Math.max(0, Math.min(100, Math.floor(rule.rolloutPercent ?? 100)));
  if (rollout >= 100) return true;
  if (rollout <= 0) return false;

  const seed = `${rule.id}|${req.ip}|${req.path}|${req.method}`;
  const hash = createHash('sha256').update(seed).digest('hex');
  const bucket = parseInt(hash.slice(0, 8), 16) % 100;
  return bucket < rollout;
}

// ─── WAF Middleware ──────────────────────────────────────────────────────────

interface RuleMatch {
  rule: WafRule;
  target: string;
  matchedValue: string;
}

function buildRateRuleKey(rule: WafRateRule, req: Request, clientIp: string): string {
  if (rule.keyBy === 'ip_path') {
    return `${clientIp}|${req.path.toLowerCase()}`;
  }
  if (rule.keyBy === 'ip_ua') {
    const ua = String(req.headers['user-agent'] ?? '').slice(0, 128).toLowerCase();
    return `${clientIp}|${ua}`;
  }
  return clientIp;
}

function shouldCleanupRateRuleState(counter: number): boolean {
  return counter % 500 === 0;
}

export function createWafMiddleware(
  config: GatewayConfig,
  deps?: { challengeStore?: BotChallengeStore },
): RequestHandler {
  const securityLog = createSecurityLogger(config);
  let runtimeSignature = '';
  let customRules = compileCustomWafRules(config);
  let rateRules = compileWafRateRules(config);
  const rateRuleState = new Map<string, Map<string, WafRateRuleCounter>>();
  let rateRuleRequestCounter = 0;
  const trustedProxies = new Set(config.rateLimit.trustedProxies);
  const maxXffDepth = config.rateLimit.xForwardedForMaxDepth;

  const refreshRuntimeRules = (): void => {
    const nextSignature = JSON.stringify({
      enabled: config.waf.enabled,
      managedRulesVersion: config.waf.managedRulesVersion,
      allowedRuleVersions: config.waf.allowedRuleVersions,
      customRules: config.waf.customRules,
      rateRules: config.waf.rateRules,
    });
    if (nextSignature === runtimeSignature) return;
    customRules = compileCustomWafRules(config);
    rateRules = compileWafRateRules(config);
    rateRuleState.clear();
    runtimeSignature = nextSignature;
  };

  const recordWaf = (kind: 'block' | 'detect' | 'challenge', ruleSet: string): void => {
    try {
      const metric =
        kind === 'block'
          ? 'waf_blocks_total'
          : kind === 'challenge'
            ? 'waf_challenges_total'
            : 'waf_detections_total';
      globalMetrics.recordCounter(
        metric,
        1,
        { service: 'gateway', rule_set: ruleSet }
      );
    } catch {
      // Metrics must never affect request handling.
    }
  };

  const cleanupRateRuleState = (): void => {
    const now = Date.now();
    for (const rule of rateRules) {
      const byKey = rateRuleState.get(rule.id);
      if (!byKey || byKey.size === 0) continue;

      const ttlMs = Math.max(rule.windowMs, rule.blockDurationMs) * 4;
      for (const [key, entry] of byKey) {
        if (entry.lastSeenMs + ttlMs < now && entry.blockedUntilMs < now) {
          byKey.delete(key);
        }
      }
      if (byKey.size === 0) {
        rateRuleState.delete(rule.id);
      }
    }
  };

  const evaluateRateRule = (
    rule: WafRateRule,
    req: Request,
    clientIp: string,
  ): { triggered: boolean; retryAfterSeconds: number; count: number } => {
    let byKey = rateRuleState.get(rule.id);
    if (!byKey) {
      byKey = new Map<string, WafRateRuleCounter>();
      rateRuleState.set(rule.id, byKey);
    }

    const now = Date.now();
    const key = buildRateRuleKey(rule, req, clientIp);
    let entry = byKey.get(key);
    if (!entry) {
      entry = {
        windowStartMs: now,
        count: 0,
        blockedUntilMs: 0,
        lastSeenMs: now,
      };
      byKey.set(key, entry);
    }

    entry.lastSeenMs = now;

    if (entry.blockedUntilMs > now) {
      return {
        triggered: true,
        retryAfterSeconds: Math.max(1, Math.ceil((entry.blockedUntilMs - now) / 1000)),
        count: entry.count,
      };
    }

    if (now - entry.windowStartMs >= rule.windowMs) {
      entry.windowStartMs = now;
      entry.count = 0;
      entry.blockedUntilMs = 0;
    }

    entry.count += 1;
    if (entry.count > rule.threshold) {
      if (rule.action !== 'log') {
        entry.blockedUntilMs = now + rule.blockDurationMs;
      }
      return {
        triggered: true,
        retryAfterSeconds:
          rule.action === 'log'
            ? Math.max(1, Math.ceil(rule.windowMs / 1000))
            : Math.max(1, Math.ceil(rule.blockDurationMs / 1000)),
        count: entry.count,
      };
    }

    return { triggered: false, retryAfterSeconds: 0, count: entry.count };
  };

  return (req: Request, res: Response, next: NextFunction): void => {
    refreshRuntimeRules();

    if (!config.waf.enabled) {
      next();
      return;
    }

    const riskScoreThreshold = config.waf.riskScoreThreshold;
    const correlationId = (req.headers['x-correlation-id'] as string) || 'unknown';
    const routeConfig = getRouteConfig(config, req.path, req.method);
    const enabledRuleSets = routeConfig?.wafRuleSets ?? ['xss', 'sqli', 'cmdi', 'ssrf', 'traversal'];
    const clientIp = extractClientIp(req, maxXffDepth, trustedProxies);

    rateRuleRequestCounter += 1;
    if (shouldCleanupRateRuleState(rateRuleRequestCounter)) {
      cleanupRateRuleState();
    }

    const activeRateRules = rateRules.filter((rule) => shouldApplyRateRuleForRequest(rule, req));
    for (const rule of activeRateRules) {
      const outcome = evaluateRateRule(rule, req, clientIp);
      if (!outcome.triggered) {
        continue;
      }

      if (rule.action === 'log') {
        recordWaf('detect', 'rate');
        securityLog.info({
          event: 'waf_rate_rule_detected',
          correlationId,
          ip: clientIp,
          method: req.method,
          path: req.path,
          ruleId: rule.id,
          version: rule.version,
          description: rule.description,
          threshold: rule.threshold,
          count: outcome.count,
          windowMs: rule.windowMs,
          blockDurationMs: rule.blockDurationMs,
          action: 'log',
        });
        continue;
      }

      if (rule.action === 'challenge') {
        recordWaf('challenge', 'rate');
        securityLog.warn({
          event: 'waf_rate_rule_enforced',
          correlationId,
          ip: clientIp,
          method: req.method,
          path: req.path,
          ruleId: rule.id,
          version: rule.version,
          description: rule.description,
          threshold: rule.threshold,
          count: outcome.count,
          retryAfterSeconds: outcome.retryAfterSeconds,
          windowMs: rule.windowMs,
          blockDurationMs: rule.blockDurationMs,
          action: 'challenge',
        });

        if (deps?.challengeStore) {
          void deps.challengeStore.setChallenge(
            clientIp,
            Math.max(1, Math.ceil(config.waf.challengeDurationMs / 1000)),
            `waf_rate_rule:${rule.id}`,
          );
        }
        res.setHeader('x-zt-bot-challenge', 'required');
        res.setHeader('retry-after', String(outcome.retryAfterSeconds));
        res.status(403).json({ error: 'bot_challenge_required' });
        return;
      }

      recordWaf('block', 'rate');
      securityLog.warn({
        event: 'waf_rate_rule_enforced',
        correlationId,
        ip: clientIp,
        method: req.method,
        path: req.path,
        ruleId: rule.id,
        version: rule.version,
        description: rule.description,
        threshold: rule.threshold,
        count: outcome.count,
        retryAfterSeconds: outcome.retryAfterSeconds,
        windowMs: rule.windowMs,
        blockDurationMs: rule.blockDurationMs,
        action: 'block',
      });
      res.setHeader('retry-after', String(outcome.retryAfterSeconds));
      res.status(429).json({ error: 'rate_limited_by_waf' });
      return;
    }

    // Filter rules to only enabled sets for this route
    const activeRules = [...WAF_RULES, ...customRules].filter(rule => {
      if (!enabledRuleSets.includes(rule.ruleSet)) return false;
      const ruleSetConfig = config.waf.ruleSets[rule.ruleSet];
      if (ruleSetConfig?.enabled === false) return false;
      return shouldApplyRuleForRequest(rule, req);
    });

    let totalScore = 0;
    const matches: RuleMatch[] = [];

    // ── Collect values to inspect per target ──────────────────────────
    const targetValues: Record<string, string[]> = {
      url: [req.originalUrl || req.url],
      query: extractQueryValues(req),
      body: extractBodyValues(req),
      headers: extractHeaderValues(req),
      cookies: extractCookieValues(req),
    };

    // ── Run all active rules against their targets ────────────────────
    for (const rule of activeRules) {
      for (const target of rule.targets) {
        const values = targetValues[target];
        if (!values) continue;

        for (const value of values) {
          if (rule.pattern.test(value)) {
            totalScore += rule.score;
            matches.push({
              rule,
              target,
              matchedValue: truncate(value, 200),
            });
            break; // One match per rule per target is sufficient
          }
        }
      }

      // Early exit if threshold already exceeded
      if (totalScore >= riskScoreThreshold) break;
    }

    // ── Decision ──────────────────────────────────────────────────────
    if (totalScore >= riskScoreThreshold) {
      const blockingRuleSets = new Set(matches.map(m => m.rule.ruleSet));
      const actions = matches.map((m) => {
        if (m.rule.action) return m.rule.action;
        const ruleSetConfig = config.waf.ruleSets[m.rule.ruleSet];
        return ruleSetConfig?.action ?? 'block';
      });
      const shouldBlock = actions.includes('block');
      const shouldChallenge = !shouldBlock && actions.includes('challenge');

      // Low-cardinality metric for dashboards/alerts.
      for (const rs of blockingRuleSets) {
        if (shouldBlock) {
          recordWaf('block', rs);
        } else if (shouldChallenge) {
          recordWaf('challenge', rs);
        } else {
          recordWaf('detect', rs);
        }
      }

      securityLog.warn({
        event: shouldChallenge ? 'waf_challenge' : 'waf_block',
        correlationId,
        ip: req.ip,
        method: req.method,
        path: req.path,
        userAgent: req.headers['user-agent'],
        riskScore: totalScore,
        threshold: riskScoreThreshold,
        ruleSetsTriggered: Array.from(blockingRuleSets),
        matchCount: matches.length,
        matches: matches.map(m => ({
          ruleId: m.rule.id,
          ruleSet: m.rule.ruleSet,
          version: m.rule.version,
          description: m.rule.description,
          target: m.target,
          score: m.rule.score,
          matchedValue: m.matchedValue,
          action: m.rule.action ?? config.waf.ruleSets[m.rule.ruleSet]?.action ?? 'block',
        })),
        action: shouldBlock ? 'block' : shouldChallenge ? 'challenge' : 'log',
      });

      if (shouldBlock) {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }
      if (shouldChallenge) {
        if (deps?.challengeStore) {
          const clientIp = extractClientIp(req, maxXffDepth, trustedProxies);
          void deps.challengeStore.setChallenge(
            clientIp,
            Math.max(1, Math.ceil(config.waf.challengeDurationMs / 1000)),
            'waf_challenge',
          );
        }
        res.setHeader('x-zt-bot-challenge', 'required');
        res.status(403).json({ error: 'bot_challenge_required' });
        return;
      }
    } else if (matches.length > 0) {
      // Below threshold but some patterns matched — log for monitoring
      for (const rs of new Set(matches.map(m => m.rule.ruleSet))) {
        recordWaf('detect', rs);
      }

      securityLog.info({
        event: 'waf_detection',
        correlationId,
        ip: req.ip,
        method: req.method,
        path: req.path,
        riskScore: totalScore,
        threshold: riskScoreThreshold,
        matchCount: matches.length,
        matches: matches.map(m => ({
          ruleId: m.rule.id,
          ruleSet: m.rule.ruleSet,
          version: m.rule.version,
          description: m.rule.description,
          target: m.target,
          score: m.rule.score,
        })),
        action: 'monitor',
      });
    }

    // Attach risk score to request context for downstream decision-making
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (req as any).wafRiskScore = totalScore;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (req as any).wafMatches = matches.map(m => m.rule.id);

    next();
  };
}

// ─── Value Extraction Helpers ────────────────────────────────────────────────

function extractQueryValues(req: Request): string[] {
  const values: string[] = [];
  if (req.query) {
    flattenValues(req.query, values);
  }
  // Also include the raw query string
  const rawQuery = req.originalUrl?.split('?')[1];
  if (rawQuery) {
    values.push(rawQuery);
  }
  return values;
}

function extractBodyValues(req: Request): string[] {
  const values: string[] = [];
  if (req.body && typeof req.body === 'object') {
    flattenValues(req.body as Record<string, unknown>, values);
  } else if (typeof req.body === 'string') {
    values.push(req.body);
  }
  return values;
}

function extractHeaderValues(req: Request): string[] {
  const values: string[] = [];
  // Only inspect specific headers that are commonly targeted
  const inspectedHeaders = [
    'referer',
    'user-agent',
    'x-forwarded-for',
    'x-forwarded-host',
    'content-type',
    'accept',
  ];
  for (const header of inspectedHeaders) {
    const value = req.headers[header];
    if (typeof value === 'string') {
      values.push(value);
    } else if (Array.isArray(value)) {
      values.push(...value);
    }
  }
  return values;
}

function extractCookieValues(req: Request): string[] {
  const values: string[] = [];
  if (req.cookies && typeof req.cookies === 'object') {
    for (const value of Object.values(req.cookies as Record<string, unknown>)) {
      if (typeof value === 'string') {
        values.push(value);
      }
    }
  }
  return values;
}

function flattenValues(obj: unknown, result: string[], depth = 0): void {
  if (depth > 10) return; // Prevent stack overflow on deeply nested objects

  if (typeof obj === 'string') {
    result.push(obj);
  } else if (Array.isArray(obj)) {
    for (const item of obj) {
      flattenValues(item, result, depth + 1);
    }
  } else if (obj !== null && typeof obj === 'object') {
    for (const value of Object.values(obj)) {
      flattenValues(value, result, depth + 1);
    }
  } else if (obj !== null && obj !== undefined) {
    result.push(String(obj));
  }
}

function truncate(value: string, maxLength: number): string {
  if (value.length <= maxLength) return value;
  return value.substring(0, maxLength) + '...[truncated]';
}
