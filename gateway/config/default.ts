import { z } from 'zod';
import { readSecret } from '@zerotrust/shared';

function isEnabled(raw: string | undefined, defaultValue = false): boolean {
  if (raw === undefined) return defaultValue;
  return ['true', '1', 'yes'].includes(raw.toLowerCase());
}

function parseSecretKeyring(raw: string, variableName: string): Record<string, string> {
  const value = raw.trim();
  if (!value) return {};

  const result: Record<string, string> = {};
  const entries = value.split(',').map((e) => e.trim()).filter(Boolean);
  for (const entry of entries) {
    const eqIdx = entry.indexOf('=');
    const colonIdx = entry.indexOf(':');
    let idx = -1;
    if (eqIdx > 0) idx = eqIdx;
    if (colonIdx > 0 && (idx === -1 || colonIdx < idx)) idx = colonIdx;
    if (idx <= 0 || idx === entry.length - 1) {
      throw new Error(`Invalid ${variableName} entry "${entry}"`);
    }
    const keyId = entry.slice(0, idx).trim();
    const secret = entry.slice(idx + 1).trim();
    if (!keyId || !secret) {
      throw new Error(`Invalid ${variableName} entry "${entry}"`);
    }
    result[keyId] = secret;
  }
  return result;
}

// ─── Configuration Schema ────────────────────────────────────────────────────
// Validated at startup. If config is invalid, the gateway refuses to start.

const TlsConfigSchema = z.object({
  // Safer default: do not silently fall back to HTTP because cert/key are unset.
  enabled: z.boolean().default(false),
  certPath: z.string().optional(),
  keyPath: z.string().optional(),
  caPath: z.string().optional(),
  minVersion: z.enum(['TLSv1.2', 'TLSv1.3']).default('TLSv1.2'),
  ciphers: z.string().optional(),
  honorCipherOrder: z.boolean().default(true),
  sessionTimeout: z.number().default(300),
});

const MtlsConfigSchema = z.object({
  enabled: z.boolean().default(true),
  caPath: z.string().optional(),
  certPath: z.string().optional(),
  keyPath: z.string().optional(),
  rejectUnauthorized: z.boolean().default(true),
});

const RateLimitTierSchema = z.object({
  windowMs: z.number().default(60_000),
  maxRequests: z.number().default(100),
  burstMax: z.number().default(20),
  burstWindowMs: z.number().default(1_000),
});

const RouteRateLimitSchema = z.object({
  perIp: RateLimitTierSchema.optional(),
  perIdentity: RateLimitTierSchema.optional(),
  perRoute: RateLimitTierSchema.optional(),
  perTenant: RateLimitTierSchema.optional(),
});

const CorsRouteConfigSchema = z.object({
  allowedOrigins: z.array(z.string()).default([]),
  allowedMethods: z.array(z.string()).default(['GET', 'HEAD', 'OPTIONS']),
  allowedHeaders: z.array(z.string()).default(['Content-Type', 'Authorization', 'X-Request-Id']),
  exposedHeaders: z.array(z.string()).default([]),
  maxAge: z.number().default(600),
  credentials: z.boolean().default(false),
});

const EdgeCacheRouteConfigSchema = z.object({
  enabled: z.boolean().default(false),
  ttlSeconds: z.number().int().positive().max(60 * 60).optional(),
  staleWhileRevalidateSeconds: z.number().int().min(0).max(60 * 60).optional(),
  staleIfErrorSeconds: z.number().int().min(0).max(60 * 60 * 24).optional(),
  varyHeaders: z.array(z.string()).optional(),
  includeQueryString: z.boolean().optional(),
  ignoreQueryParams: z.array(z.string()).optional(),
  cacheAuthenticated: z.boolean().optional(),
  maxBodyBytes: z.number().int().positive().max(5 * 1024 * 1024).optional(),
  statusCodes: z.array(z.number().int().min(100).max(599)).optional(),
  respectOriginCacheControl: z.boolean().optional(),
});

const RouteCanaryConfigSchema = z.object({
  enabled: z.boolean().default(false),
  upstream: z.string().optional(),
  rolloutPercent: z.number().min(0).max(100).default(0),
  stickiness: z.enum(['ip', 'header', 'identity']).default('ip'),
  headerName: z.string().default('x-canary-key'),
});

const RouteConfigSchema = z.object({
  path: z.string(),
  upstream: z.string(),
  methods: z.array(z.string()).default(['GET', 'HEAD', 'OPTIONS']),
  authRequired: z.boolean().default(true),
  bodyLimitBytes: z.number().default(1_048_576), // 1MB
  timeoutMs: z.number().default(30_000),
  rateLimit: RouteRateLimitSchema.optional(),
  cors: CorsRouteConfigSchema.optional(),
  wafRuleSets: z.array(z.string()).default(['xss', 'sqli', 'cmdi', 'ssrf', 'traversal']),
  stripRequestHeaders: z.array(z.string()).default([]),
  requiredScopes: z.array(z.string()).default([]),
  stepUpRequired: z.boolean().default(false),
  adaptiveProfile: z.string().optional(),
  botManagementProfile: z.string().optional(),
  accessControlProfile: z.string().optional(),
  edgeCache: EdgeCacheRouteConfigSchema.optional(),
  canary: RouteCanaryConfigSchema.optional(),
});

const UpstreamServiceSchema = z.object({
  name: z.string(),
  url: z.string().url(),
  healthCheckPath: z.string().default('/health'),
  timeoutMs: z.number().default(30_000),
  retries: z.number().default(0),
  retryBudget: z.object({
    enabled: z.boolean().default(true),
    ratio: z.number().min(0).max(1).default(0.2),
    minRetryTokens: z.number().int().nonnegative().default(3),
    windowMs: z.number().int().positive().default(60_000),
  }).default({}),
  circuitBreaker: z.object({
    enabled: z.boolean().default(true),
    failureThreshold: z.number().default(5),
    resetTimeoutMs: z.number().default(30_000),
    halfOpenMaxRequests: z.number().default(3),
  }).default({}),
  pool: z.object({
    enabled: z.boolean().default(false),
    endpoints: z.array(z.object({
      url: z.string().url(),
      weight: z.number().int().positive().default(1),
      priority: z.number().int().nonnegative().default(0),
    })).default([]),
    steering: z.object({
      policy: z.enum(['weighted_random', 'latency_aware']).default('weighted_random'),
      latencyEwmaAlpha: z.number().min(0.01).max(1).default(0.2),
      defaultLatencyMs: z.number().int().positive().default(100),
    }).default({}),
    sessionAffinity: z.object({
      enabled: z.boolean().default(false),
      source: z.enum(['ip', 'header', 'cookie']).default('ip'),
      headerName: z.string().default('x-zt-affinity-key'),
      fallbackToIp: z.boolean().default(true),
      cookie: z.object({
        name: z.string().default('__zt_upstream_affinity'),
        ttlSeconds: z.number().int().positive().max(60 * 60 * 24 * 365).default(60 * 60 * 24 * 7),
        secure: z.boolean().default(true),
        httpOnly: z.boolean().default(true),
        sameSite: z.enum(['lax', 'strict', 'none']).default('lax'),
        path: z.string().default('/'),
        domain: z.string().optional(),
        secret: z.string().optional(),
        previousSecrets: z.array(z.string()).default([]),
      }).default({}),
    }).default({}),
    activeHealthChecks: z.object({
      enabled: z.boolean().default(false),
      intervalMs: z.number().int().positive().default(10_000),
      timeoutMs: z.number().int().positive().default(2_000),
      path: z.string().default('/health'),
      expectedStatusMin: z.number().int().min(100).max(599).default(200),
      expectedStatusMax: z.number().int().min(100).max(599).default(399),
    }).default({}),
    outlierEjection: z.object({
      enabled: z.boolean().default(true),
      consecutiveFailuresThreshold: z.number().int().positive().default(5),
      ejectionDurationMs: z.number().int().positive().default(30_000),
      maxEjectionPercent: z.number().min(1).max(100).default(50),
    }).default({}),
  }).optional(),
  mtls: MtlsConfigSchema.optional(),
});

const GreylistConfigSchema = z.object({
  enabled: z.boolean().default(true),
  failureWindowMs: z.number().default(300_000),       // 5 minutes
  failureThreshold: z.number().default(10),
  tightenedRateMultiplier: z.number().default(0.25),   // 25% of normal rate
  greylistDurationMs: z.number().default(600_000),     // 10 minutes
});

const AdaptiveDefenseSignalsSchema = z.object({
  wafBlock: z.number().int().nonnegative().default(50),
  rateLimitExceeded: z.number().int().nonnegative().default(30),
  authFailure: z.number().int().nonnegative().default(10),
  forbidden: z.number().int().nonnegative().default(5),
  botFingerprint: z.number().int().nonnegative().default(5),
});

const AdaptiveDefenseProfileSchema = z.object({
  scoreWindowMs: z.number().int().positive().optional(),
  blockThreshold: z.number().int().positive().optional(),
  blockDurationMs: z.number().int().positive().optional(),
  challengeThreshold: z.number().int().positive().optional(),
  challengeDurationMs: z.number().int().positive().optional(),
  challengeEnabled: z.boolean().optional(),
  signals: AdaptiveDefenseSignalsSchema.partial().optional(),
});

const BotManagementSignalsSchema = z.object({
  missingUserAgent: z.number().int().nonnegative().default(20),
  automationUserAgent: z.number().int().nonnegative().default(35),
  missingAccept: z.number().int().nonnegative().default(8),
  missingAcceptLanguage: z.number().int().nonnegative().default(6),
  suspiciousPath: z.number().int().nonnegative().default(12),
  excessiveForwardedChain: z.number().int().nonnegative().default(12),
  headlessHints: z.number().int().nonnegative().default(20),
});

const BotManagementProfileSchema = z.object({
  enabled: z.boolean().optional(),
  challengeThreshold: z.number().int().positive().optional(),
  blockThreshold: z.number().int().positive().optional(),
  challengeDurationMs: z.number().int().positive().optional(),
  signals: BotManagementSignalsSchema.partial().optional(),
});

const AccessControlPolicySchema = z.object({
  enabled: z.boolean().default(true),
  ipAllowlist: z.array(z.string()).default([]),
  ipDenylist: z.array(z.string()).default([]),
  countryAllowlist: z.array(z.string()).default([]),
  countryDenylist: z.array(z.string()).default([]),
  asnAllowlist: z.array(z.string()).default([]),
  asnDenylist: z.array(z.string()).default([]),
});

const JwtConfigSchema = z.object({
  jwksUri: z.string().url(),
  issuer: z.string(),
  audience: z.string(),
  algorithms: z.array(z.string()).default(['RS256', 'ES256']),
  maxTokenAgeSeconds: z.number().default(86_400),       // 24 hours
  clockToleranceSeconds: z.number().default(30),
  cookieName: z.string().default('__Host-session'),
  headerName: z.string().default('Authorization'),
  headerScheme: z.string().default('Bearer'),
  cacheEnabled: z.boolean().default(true),
  jwksCacheTtlMs: z.number().default(600_000),         // 10 min
});

const PdpConfigSchema = z.object({
  enabled: z.boolean().default(true),
  url: z.string().url(),
  internalAudience: z.string().default('policy-engine'),
  timeoutMs: z.number().default(2_000),
  cacheTtlMs: z.number().default(30_000),              // 30 seconds
  cacheMaxEntries: z.number().default(10_000),
  failClosed: z.boolean().default(true),                // DENY on PDP failure
  mtls: MtlsConfigSchema.optional(),
  breakGlassEnabled: z.boolean().default(false),
  breakGlassHeader: z.string().default('X-Break-Glass'),
  breakGlassSecret: z.string().optional(),
  // Additional guardrails: break-glass should be extremely scoped.
  // Empty allowlists mean "deny" (even if breakGlassEnabled is true).
  breakGlassAllowedIps: z.array(z.string()).default([]),
  breakGlassAllowedPaths: z.array(z.string()).default([]), // supports * and ** globs
});

const LoggingConfigSchema = z.object({
  level: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
  format: z.enum(['json', 'text']).default('json'),
  securityLogSeparate: z.boolean().default(true),
  securityLogPath: z.string().default('/tmp/security.log'),
  accessLogPath: z.string().default('/tmp/access.log'),
  redactFields: z.array(z.string()).default([
    'authorization',
    'cookie',
    'set-cookie',
    'x-api-key',
    'password',
    'secret',
    'token',
    'credit_card',
    'ssn',
  ]),
});

const WafCustomRuleSchema = z.object({
  id: z.string().min(1).max(64),
  ruleSet: z.string().min(1).max(64).default('custom'),
  version: z.string().min(1).max(64).default('v1'),
  enabled: z.boolean().default(true),
  rolloutPercent: z.number().min(0).max(100).default(100),
  description: z.string().min(1).max(256).default('Custom WAF rule'),
  pattern: z.string().min(1).max(2048),
  flags: z.string().max(16).default('i'),
  score: z.number().int().positive().max(200).default(25),
  targets: z.array(z.enum(['url', 'query', 'body', 'headers', 'cookies'])).min(1).default(['query', 'body']),
  action: z.enum(['block', 'log', 'challenge']).optional(),
});

const WafRateRuleSchema = z.object({
  id: z.string().min(1).max(64),
  version: z.string().min(1).max(64).default('v1'),
  enabled: z.boolean().default(true),
  rolloutPercent: z.number().min(0).max(100).default(100),
  description: z.string().min(1).max(256).default('WAF rate rule'),
  pathPattern: z.string().min(1).max(1024).default('.*'),
  methods: z.array(z.string().min(1).max(16)).default([]),
  threshold: z.number().int().positive().max(1_000_000),
  windowMs: z.number().int().positive().max(60 * 60 * 1000),
  blockDurationMs: z.number().int().positive().max(24 * 60 * 60 * 1000).default(60_000),
  keyBy: z.enum(['ip', 'ip_path', 'ip_ua']).default('ip'),
  action: z.enum(['block', 'log', 'challenge']).default('block'),
});

export const GatewayConfigSchema = z.object({
  server: z.object({
    port: z.number().default(8443),
    // Optional dedicated HTTP listener (used for local dev and LB health checks).
    // If TLS is enabled, this port should serve health checks and redirect other traffic to HTTPS.
    httpPort: z.number().optional(),
    host: z.string().default('0.0.0.0'),
    trustProxy: z.union([z.boolean(), z.number(), z.string()]).default(false),
    readTimeoutMs: z.number().default(5_000),
    writeTimeoutMs: z.number().default(30_000),
    idleTimeoutMs: z.number().default(60_000),
    keepAliveTimeoutMs: z.number().default(65_000),
    maxHeaderSize: z.number().default(32_768),          // 32KB total headers
    maxHeaderFieldSize: z.number().default(8_192),      // 8KB per header
  }).default({}),

  tls: TlsConfigSchema.default({}),

  cors: z.object({
    globalAllowedOrigins: z.array(z.string()).default([]),
    globalAllowedMethods: z.array(z.string()).default(['GET', 'HEAD', 'OPTIONS']),
    globalAllowedHeaders: z.array(z.string()).default(['Content-Type', 'Authorization', 'X-Request-Id']),
    globalExposedHeaders: z.array(z.string()).default([]),
    globalMaxAge: z.number().default(600),
    globalCredentials: z.boolean().default(false),
    preflightCacheTtl: z.number().default(600),
  }).default({}),

  rateLimit: z.object({
    global: z.object({
      perIp: RateLimitTierSchema.default({
        windowMs: 60_000,
        maxRequests: 200,
        burstMax: 50,
        burstWindowMs: 1_000,
      }),
      perIdentity: RateLimitTierSchema.default({
        windowMs: 60_000,
        maxRequests: 500,
        burstMax: 100,
        burstWindowMs: 1_000,
      }),
    }).default({}),
    tenant: z.object({
      enabled: z.boolean().default(false),
      keySource: z.enum(['identity', 'header']).default('identity'),
      headerName: z.string().default('x-tenant-id'),
      perTenant: RateLimitTierSchema.default({
        windowMs: 60_000,
        maxRequests: 2_000,
        burstMax: 300,
        burstWindowMs: 1_000,
      }),
    }).default({}),
    greylist: GreylistConfigSchema.default({}),
    xForwardedForMaxDepth: z.number().default(2),
    trustedProxies: z.array(z.string()).default([]),
  }).default({}),

  edgeCache: z.object({
    enabled: z.boolean().default(true),
    defaultTtlSeconds: z.number().int().positive().max(60 * 60).default(30),
    staleWhileRevalidateSeconds: z.number().int().min(0).max(60 * 60).default(15),
    staleIfErrorSeconds: z.number().int().min(0).max(60 * 60 * 24).default(120),
    varyHeaders: z.array(z.string()).default(['accept', 'accept-encoding', 'accept-language']),
    includeQueryString: z.boolean().default(true),
    ignoreQueryParams: z.array(z.string()).default(['_', 'cacheBust']),
    cacheAuthenticated: z.boolean().default(false),
    maxBodyBytes: z.number().int().positive().max(5 * 1024 * 1024).default(256 * 1024),
    statusCodes: z.array(z.number().int().min(100).max(599)).default([200]),
    respectOriginCacheControl: z.boolean().default(false),
    cacheTagHeader: z.string().default('cache-tag'),
    maxTagsPerEntry: z.number().int().positive().max(512).default(64),
    maxTagLength: z.number().int().positive().max(256).default(64),
    requestCoalescingEnabled: z.boolean().default(true),
    requestCoalescingWaitMs: z.number().int().positive().max(10_000).default(250),
    memoryMaxEntries: z.number().int().positive().max(1_000_000).default(50_000),
  }).default({}),

  adaptiveDefense: z.object({
    enabled: z.boolean().default(true),
    scoreWindowMs: z.number().int().positive().default(5 * 60 * 1000),
    blockThreshold: z.number().int().positive().default(100),
    blockDurationMs: z.number().int().positive().default(30 * 60 * 1000),
    challengeThreshold: z.number().int().positive().default(60),
    ipAllowlist: z.array(z.string()).default([]),
    signals: AdaptiveDefenseSignalsSchema.default({}),
    challenge: z.object({
      enabled: z.boolean().default(true),
      headerName: z.string().default('x-zt-bot-challenge-token'),
      tokenTtlMs: z.number().int().positive().default(120_000),
      durationMs: z.number().int().positive().default(10 * 60 * 1000),
      maxInvalidAttempts: z.number().int().positive().max(100).default(5),
      invalidAttemptWindowMs: z.number().int().positive().max(60 * 60 * 1000).default(120_000),
      invalidAttemptBackoffMs: z.number().int().positive().max(60 * 60 * 1000).default(15_000),
      secret: z.string().optional(),
    }).default({}),
    profiles: z.record(z.string(), AdaptiveDefenseProfileSchema).default({}),
    abuseIntel: z.object({
      enabled: z.boolean().default(true),
      sourceId: z.string().default('gateway-edge'),
      exportMaxEntries: z.number().int().positive().max(5000).default(1000),
      defaultBundleTtlSeconds: z.number().int().positive().max(60 * 60 * 24).default(900),
      signExports: z.boolean().default(true),
      requireSignedImports: z.boolean().default(true),
      signingKeyId: z.string().default('gateway-abuse-v1'),
      signingSecret: z.string().optional(),
      allowedSources: z.array(z.string()).default([]),
      allowedKeyIds: z.array(z.string()).default(['gateway-abuse-v1']),
      keyring: z.record(z.string(), z.string()).default({}),
      replayProtectionEnabled: z.boolean().default(true),
      replayCacheMaxEntries: z.number().int().positive().default(50_000),
      maxSkewSeconds: z.number().int().positive().default(300),
    }).default({}),
  }).default({}),

  botManagement: z.object({
    enabled: z.boolean().default(true),
    challengeThreshold: z.number().int().positive().default(35),
    blockThreshold: z.number().int().positive().default(70),
    challengeDurationMs: z.number().int().positive().default(10 * 60 * 1000),
    verifiedBotUserAgentPatterns: z.array(z.string()).default([
      'googlebot',
      'bingbot',
      'duckduckbot',
      'yandexbot',
      'slurp',
      'applebot',
      'baiduspider',
    ]),
    signals: BotManagementSignalsSchema.default({}),
    clearance: z.object({
      enabled: z.boolean().default(true),
      cookieName: z.string().default('__zt_bot_clearance'),
      ttlSeconds: z.number().int().positive().max(60 * 60 * 24 * 30).default(60 * 30),
      secure: z.boolean().default(true),
      httpOnly: z.boolean().default(true),
      sameSite: z.enum(['lax', 'strict', 'none']).default('lax'),
      path: z.string().default('/'),
      domain: z.string().optional(),
      secret: z.string().optional(),
      previousSecrets: z.array(z.string()).default([]),
    }).default({}),
    profiles: z.record(z.string(), BotManagementProfileSchema).default({}),
  }).default({}),

  accessControl: z.object({
    enabled: z.boolean().default(false),
    bypassInternal: z.boolean().default(true),
    countryHeader: z.string().default('x-geo-country'),
    asnHeader: z.string().default('x-geo-asn'),
    policy: AccessControlPolicySchema.default({}),
    profiles: z.record(z.string(), AccessControlPolicySchema.partial()).default({}),
  }).default({}),

  waf: z.object({
    enabled: z.boolean().default(true),
    riskScoreThreshold: z.number().default(50),
    challengeDurationMs: z.number().int().positive().default(10 * 60 * 1000),
    managedRulesVersion: z.string().default('v1'),
    allowedRuleVersions: z.array(z.string()).default(['v1']),
    ruleSets: z.record(z.string(), z.object({
      enabled: z.boolean().default(true),
      action: z.enum(['block', 'log', 'challenge']).default('block'),
    })).default({
      xss: { enabled: true, action: 'block' as const },
      sqli: { enabled: true, action: 'block' as const },
      cmdi: { enabled: true, action: 'block' as const },
      ssrf: { enabled: true, action: 'block' as const },
      traversal: { enabled: true, action: 'block' as const },
    }),
    customRules: z.array(WafCustomRuleSchema).default([]),
    rateRules: z.array(WafRateRuleSchema).default([]),
  }).default({}),

  jwt: JwtConfigSchema,
  pdp: PdpConfigSchema,

  logging: LoggingConfigSchema.default({}),

  // Internal service-to-service authentication for gateway -> upstream calls.
  // Strong defense-in-depth against lateral movement if network boundaries are misconfigured.
  internalAuth: z.object({
    enabled: z.boolean().default(false),
    secret: z.string().optional(),
    callerId: z.string().default('gateway'),
    callerKeyId: z.string().default('gateway-v1'),
    callerSecret: z.string().optional(),
    allowedSkewSeconds: z.number().default(60),
    requireNonce: z.boolean().default(true),
    requireCallerId: z.boolean().default(true),
    requireKeyId: z.boolean().default(true),
    allowedCallerIds: z.array(z.string()).default(['telemetry']),
    allowedKeyIds: z.array(z.string()).default(['telemetry-v1']),
    expectedAudience: z.string().default('gateway'),
    keyring: z.record(z.string(), z.string()).default({}),
    replayProtectionEnabled: z.boolean().default(true),
    replayCacheMaxEntries: z.number().int().positive().default(50_000),
  }).default({}),

  routes: z.array(RouteConfigSchema).default([]),

  upstreams: z.record(z.string(), UpstreamServiceSchema).default({}),

  bodyLimits: z.object({
    defaultMaxBytes: z.number().default(1_048_576),       // 1MB
    maxUploadBytes: z.number().default(10_485_760),       // 10MB
    allowedContentTypes: z.array(z.string()).default([
      'application/json',
      'application/x-www-form-urlencoded',
      'text/plain',
    ]),
    strictJsonParsing: z.boolean().default(true),
  }).default({}),

  allowedHttpMethods: z.array(z.string()).default([
    'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS',
  ]),

  healthCheck: z.object({
    path: z.string().default('/health'),
    enabled: z.boolean().default(true),
  }).default({}),
}).superRefine((cfg, ctx) => {
  // TLS invariants: if enabled, cert+key must be present.
  if (cfg.tls.enabled && (!cfg.tls.certPath || !cfg.tls.keyPath)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['tls'],
      message: 'tls.enabled=true requires tls.certPath and tls.keyPath',
    });
  }

  // Break-glass invariants: if enabled, require secret + explicit allowlists.
  if (cfg.pdp.breakGlassEnabled) {
    if (!cfg.pdp.breakGlassSecret) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['pdp', 'breakGlassSecret'],
        message: 'pdp.breakGlassEnabled=true requires pdp.breakGlassSecret',
      });
    }
    if (cfg.pdp.breakGlassAllowedIps.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['pdp', 'breakGlassAllowedIps'],
        message: 'pdp.breakGlassEnabled=true requires a non-empty pdp.breakGlassAllowedIps allowlist',
      });
    }
    if (cfg.pdp.breakGlassAllowedPaths.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['pdp', 'breakGlassAllowedPaths'],
        message: 'pdp.breakGlassEnabled=true requires a non-empty pdp.breakGlassAllowedPaths allowlist',
      });
    }
  }

  // Internal auth invariants.
  if (cfg.internalAuth.enabled && !cfg.internalAuth.secret) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['internalAuth', 'secret'],
      message: 'internalAuth.enabled=true requires internalAuth.secret (or INTERNAL_SHARED_SECRET env var)',
    });
  }

  if (cfg.adaptiveDefense.challengeThreshold >= cfg.adaptiveDefense.blockThreshold) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['adaptiveDefense', 'challengeThreshold'],
      message: 'adaptiveDefense.challengeThreshold must be less than adaptiveDefense.blockThreshold',
    });
  }

  for (const [name, profile] of Object.entries(cfg.adaptiveDefense.profiles)) {
    if (
      profile.challengeThreshold !== undefined &&
      profile.blockThreshold !== undefined &&
      profile.challengeThreshold >= profile.blockThreshold
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['adaptiveDefense', 'profiles', name],
        message: 'challengeThreshold must be less than blockThreshold for adaptive defense profiles',
      });
    }
  }

  if (cfg.botManagement.challengeThreshold >= cfg.botManagement.blockThreshold) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['botManagement', 'challengeThreshold'],
      message: 'botManagement.challengeThreshold must be less than botManagement.blockThreshold',
    });
  }

  for (const [name, profile] of Object.entries(cfg.botManagement.profiles)) {
    if (
      profile.challengeThreshold !== undefined &&
      profile.blockThreshold !== undefined &&
      profile.challengeThreshold >= profile.blockThreshold
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['botManagement', 'profiles', name],
        message: 'challengeThreshold must be less than blockThreshold for bot management profiles',
      });
    }
  }

  if (cfg.botManagement.clearance.sameSite === 'none' && cfg.botManagement.clearance.secure !== true) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['botManagement', 'clearance'],
      message: 'botManagement.clearance.sameSite=none requires botManagement.clearance.secure=true',
    });
  }

  // PDP mTLS invariants.
  if (cfg.pdp.mtls?.enabled) {
    if (!cfg.pdp.mtls.caPath || !cfg.pdp.mtls.certPath || !cfg.pdp.mtls.keyPath) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['pdp', 'mtls'],
        message: 'pdp.mtls.enabled=true requires pdp.mtls.caPath, pdp.mtls.certPath, and pdp.mtls.keyPath',
      });
    }
  }

  // Upstream mTLS invariants.
  for (const [name, upstream] of Object.entries(cfg.upstreams)) {
    if (upstream.mtls?.enabled) {
      if (!upstream.mtls.caPath || !upstream.mtls.certPath || !upstream.mtls.keyPath) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['upstreams', name, 'mtls'],
          message: 'upstreams[*].mtls.enabled=true requires mtls.caPath, mtls.certPath, and mtls.keyPath',
        });
      }
    }

    if (upstream.pool?.enabled && (!upstream.pool.endpoints || upstream.pool.endpoints.length === 0)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['upstreams', name, 'pool', 'endpoints'],
        message: 'upstreams[*].pool.enabled=true requires at least one pool endpoint',
      });
    }
    if (
      upstream.pool?.activeHealthChecks &&
      upstream.pool.activeHealthChecks.expectedStatusMin > upstream.pool.activeHealthChecks.expectedStatusMax
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['upstreams', name, 'pool', 'activeHealthChecks'],
        message: 'activeHealthChecks.expectedStatusMin must be <= expectedStatusMax',
      });
    }
    if (
      upstream.pool?.sessionAffinity?.enabled &&
      upstream.pool.sessionAffinity.source === 'cookie' &&
      upstream.pool.sessionAffinity.cookie.sameSite === 'none' &&
      upstream.pool.sessionAffinity.cookie.secure !== true
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['upstreams', name, 'pool', 'sessionAffinity', 'cookie'],
        message: 'sessionAffinity.cookie.sameSite=none requires sessionAffinity.cookie.secure=true',
      });
    }
    if (
      upstream.pool?.sessionAffinity?.enabled &&
      upstream.pool.sessionAffinity.source === 'cookie' &&
      !upstream.pool.sessionAffinity.cookie.secret &&
      upstream.pool.sessionAffinity.fallbackToIp === false
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['upstreams', name, 'pool', 'sessionAffinity'],
        message: 'cookie session affinity requires cookie.secret or fallbackToIp=true',
      });
    }
  }

  for (let i = 0; i < cfg.routes.length; i += 1) {
    const route = cfg.routes[i];
    if (!route) continue;
    if (!route.canary?.enabled) continue;
    const canaryUpstream = String(route.canary.upstream ?? '').trim();
    if (!canaryUpstream) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['routes', i, 'canary', 'upstream'],
        message: 'routes[*].canary.upstream is required when canary.enabled=true',
      });
      continue;
    }
    if (!cfg.upstreams[canaryUpstream]) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['routes', i, 'canary', 'upstream'],
        message: `routes[*].canary.upstream "${canaryUpstream}" is not configured`,
      });
    }
  }
});

export type GatewayConfig = z.infer<typeof GatewayConfigSchema>;
export type RouteConfig = z.infer<typeof RouteConfigSchema>;
export type UpstreamService = z.infer<typeof UpstreamServiceSchema>;
export type RateLimitTier = z.infer<typeof RateLimitTierSchema>;
export type CorsRouteConfig = z.infer<typeof CorsRouteConfigSchema>;

// ─── Default configuration ───────────────────────────────────────────────────
// In production, override via GATEWAY_CONFIG env var pointing to a JSON file,
// or via individual environment variables.

export function loadConfig(): GatewayConfig {
  const envOverrides: Record<string, unknown> = {};

  // Map environment variables to config paths
  if (process.env['GATEWAY_PORT']) {
    envOverrides.server = { ...((envOverrides.server as Record<string, unknown>) ?? {}), port: parseInt(process.env['GATEWAY_PORT'], 10) };
  }
  if (process.env['PORT'] && !process.env['GATEWAY_PORT']) {
    envOverrides.server = { ...((envOverrides.server as Record<string, unknown>) ?? {}), port: parseInt(process.env['PORT'], 10) };
  }
  if (process.env['HTTP_PORT']) {
    envOverrides.server = { ...((envOverrides.server as Record<string, unknown>) ?? {}), httpPort: parseInt(process.env['HTTP_PORT'], 10) };
  }
  if (process.env['GATEWAY_HOST']) {
    envOverrides.server = { ...((envOverrides.server as Record<string, unknown>) ?? {}), host: process.env['GATEWAY_HOST'] };
  }
  if (process.env['HOST'] && !process.env['GATEWAY_HOST']) {
    envOverrides.server = { ...((envOverrides.server as Record<string, unknown>) ?? {}), host: process.env['HOST'] };
  }
  if (process.env['GATEWAY_TRUST_PROXY']) {
    const tp = process.env['GATEWAY_TRUST_PROXY'];
    const parsed = tp === 'true' ? true : tp === 'false' ? false : isNaN(Number(tp)) ? tp : Number(tp);
    envOverrides.server = { ...((envOverrides.server as Record<string, unknown>) ?? {}), trustProxy: parsed };
  }
  if (process.env['TRUSTED_PROXIES']) {
    const proxies = process.env['TRUSTED_PROXIES']
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    envOverrides.rateLimit = {
      ...((envOverrides.rateLimit as Record<string, unknown>) ?? {}),
      trustedProxies: proxies,
    };
    // If trusted proxies are configured, Express must be told to trust proxy
    // so `req.ip` and `req.secure` are computed correctly.
    if (proxies.length > 0 && process.env['GATEWAY_TRUST_PROXY'] === undefined) {
      envOverrides.server = { ...((envOverrides.server as Record<string, unknown>) ?? {}), trustProxy: true };
    }
  }
  if (process.env['RATE_LIMIT_TENANT_ENABLED']) {
    const raw = process.env['RATE_LIMIT_TENANT_ENABLED'].toLowerCase();
    envOverrides.rateLimit = {
      ...((envOverrides.rateLimit as Record<string, unknown>) ?? {}),
      tenant: {
        ...((((envOverrides.rateLimit as Record<string, unknown>) ?? {})['tenant'] as Record<string, unknown>) ?? {}),
        enabled: raw === 'true' || raw === '1' || raw === 'yes',
      },
    };
  }
  if (process.env['RATE_LIMIT_TENANT_KEY_SOURCE']) {
    envOverrides.rateLimit = {
      ...((envOverrides.rateLimit as Record<string, unknown>) ?? {}),
      tenant: {
        ...((((envOverrides.rateLimit as Record<string, unknown>) ?? {})['tenant'] as Record<string, unknown>) ?? {}),
        keySource: process.env['RATE_LIMIT_TENANT_KEY_SOURCE'],
      },
    };
  }
  if (process.env['RATE_LIMIT_TENANT_HEADER']) {
    envOverrides.rateLimit = {
      ...((envOverrides.rateLimit as Record<string, unknown>) ?? {}),
      tenant: {
        ...((((envOverrides.rateLimit as Record<string, unknown>) ?? {})['tenant'] as Record<string, unknown>) ?? {}),
        headerName: process.env['RATE_LIMIT_TENANT_HEADER'],
      },
    };
  }
  if (process.env['RATE_LIMIT_TENANT_WINDOW_MS']) {
    const rateLimit = ((envOverrides.rateLimit as Record<string, unknown>) ?? {}) as Record<string, unknown>;
    const tenant = ((rateLimit['tenant'] as Record<string, unknown>) ?? {}) as Record<string, unknown>;
    const perTenant = ((tenant['perTenant'] as Record<string, unknown>) ?? {}) as Record<string, unknown>;
    envOverrides.rateLimit = {
      ...rateLimit,
      tenant: {
        ...tenant,
        perTenant: {
          ...perTenant,
          windowMs: parseInt(process.env['RATE_LIMIT_TENANT_WINDOW_MS'], 10),
        },
      },
    };
  }
  if (process.env['RATE_LIMIT_TENANT_MAX_REQUESTS']) {
    const rateLimit = ((envOverrides.rateLimit as Record<string, unknown>) ?? {}) as Record<string, unknown>;
    const tenant = ((rateLimit['tenant'] as Record<string, unknown>) ?? {}) as Record<string, unknown>;
    const perTenant = ((tenant['perTenant'] as Record<string, unknown>) ?? {}) as Record<string, unknown>;
    envOverrides.rateLimit = {
      ...rateLimit,
      tenant: {
        ...tenant,
        perTenant: {
          ...perTenant,
          maxRequests: parseInt(process.env['RATE_LIMIT_TENANT_MAX_REQUESTS'], 10),
        },
      },
    };
  }
  if (process.env['RATE_LIMIT_TENANT_BURST_MAX']) {
    const rateLimit = ((envOverrides.rateLimit as Record<string, unknown>) ?? {}) as Record<string, unknown>;
    const tenant = ((rateLimit['tenant'] as Record<string, unknown>) ?? {}) as Record<string, unknown>;
    const perTenant = ((tenant['perTenant'] as Record<string, unknown>) ?? {}) as Record<string, unknown>;
    envOverrides.rateLimit = {
      ...rateLimit,
      tenant: {
        ...tenant,
        perTenant: {
          ...perTenant,
          burstMax: parseInt(process.env['RATE_LIMIT_TENANT_BURST_MAX'], 10),
        },
      },
    };
  }
  if (process.env['RATE_LIMIT_TENANT_BURST_WINDOW_MS']) {
    const rateLimit = ((envOverrides.rateLimit as Record<string, unknown>) ?? {}) as Record<string, unknown>;
    const tenant = ((rateLimit['tenant'] as Record<string, unknown>) ?? {}) as Record<string, unknown>;
    const perTenant = ((tenant['perTenant'] as Record<string, unknown>) ?? {}) as Record<string, unknown>;
    envOverrides.rateLimit = {
      ...rateLimit,
      tenant: {
        ...tenant,
        perTenant: {
          ...perTenant,
          burstWindowMs: parseInt(process.env['RATE_LIMIT_TENANT_BURST_WINDOW_MS'], 10),
        },
      },
    };
  }
  if (process.env['EDGE_CACHE_ENABLED']) {
    const raw = process.env['EDGE_CACHE_ENABLED'].toLowerCase();
    envOverrides.edgeCache = {
      ...((envOverrides.edgeCache as Record<string, unknown>) ?? {}),
      enabled: raw === 'true' || raw === '1' || raw === 'yes',
    };
  }
  if (process.env['EDGE_CACHE_DEFAULT_TTL_SECONDS']) {
    envOverrides.edgeCache = {
      ...((envOverrides.edgeCache as Record<string, unknown>) ?? {}),
      defaultTtlSeconds: parseInt(process.env['EDGE_CACHE_DEFAULT_TTL_SECONDS'], 10),
    };
  }
  if (process.env['EDGE_CACHE_STALE_WHILE_REVALIDATE_SECONDS']) {
    envOverrides.edgeCache = {
      ...((envOverrides.edgeCache as Record<string, unknown>) ?? {}),
      staleWhileRevalidateSeconds: parseInt(process.env['EDGE_CACHE_STALE_WHILE_REVALIDATE_SECONDS'], 10),
    };
  }
  if (process.env['EDGE_CACHE_STALE_IF_ERROR_SECONDS']) {
    envOverrides.edgeCache = {
      ...((envOverrides.edgeCache as Record<string, unknown>) ?? {}),
      staleIfErrorSeconds: parseInt(process.env['EDGE_CACHE_STALE_IF_ERROR_SECONDS'], 10),
    };
  }
  if (process.env['EDGE_CACHE_VARY_HEADERS']) {
    const varyHeaders = process.env['EDGE_CACHE_VARY_HEADERS']
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    envOverrides.edgeCache = {
      ...((envOverrides.edgeCache as Record<string, unknown>) ?? {}),
      varyHeaders,
    };
  }
  if (process.env['EDGE_CACHE_INCLUDE_QUERY_STRING']) {
    const raw = process.env['EDGE_CACHE_INCLUDE_QUERY_STRING'].toLowerCase();
    envOverrides.edgeCache = {
      ...((envOverrides.edgeCache as Record<string, unknown>) ?? {}),
      includeQueryString: raw === 'true' || raw === '1' || raw === 'yes',
    };
  }
  if (process.env['EDGE_CACHE_IGNORE_QUERY_PARAMS']) {
    const ignoreQueryParams = process.env['EDGE_CACHE_IGNORE_QUERY_PARAMS']
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    envOverrides.edgeCache = {
      ...((envOverrides.edgeCache as Record<string, unknown>) ?? {}),
      ignoreQueryParams,
    };
  }
  if (process.env['EDGE_CACHE_CACHE_AUTHENTICATED']) {
    const raw = process.env['EDGE_CACHE_CACHE_AUTHENTICATED'].toLowerCase();
    envOverrides.edgeCache = {
      ...((envOverrides.edgeCache as Record<string, unknown>) ?? {}),
      cacheAuthenticated: raw === 'true' || raw === '1' || raw === 'yes',
    };
  }
  if (process.env['EDGE_CACHE_MAX_BODY_BYTES']) {
    envOverrides.edgeCache = {
      ...((envOverrides.edgeCache as Record<string, unknown>) ?? {}),
      maxBodyBytes: parseInt(process.env['EDGE_CACHE_MAX_BODY_BYTES'], 10),
    };
  }
  if (process.env['EDGE_CACHE_STATUS_CODES']) {
    const statusCodes = process.env['EDGE_CACHE_STATUS_CODES']
      .split(',')
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => Number.isInteger(n));
    envOverrides.edgeCache = {
      ...((envOverrides.edgeCache as Record<string, unknown>) ?? {}),
      statusCodes,
    };
  }
  if (process.env['EDGE_CACHE_RESPECT_ORIGIN_CACHE_CONTROL']) {
    const raw = process.env['EDGE_CACHE_RESPECT_ORIGIN_CACHE_CONTROL'].toLowerCase();
    envOverrides.edgeCache = {
      ...((envOverrides.edgeCache as Record<string, unknown>) ?? {}),
      respectOriginCacheControl: raw === 'true' || raw === '1' || raw === 'yes',
    };
  }
  if (process.env['EDGE_CACHE_TAG_HEADER']) {
    envOverrides.edgeCache = {
      ...((envOverrides.edgeCache as Record<string, unknown>) ?? {}),
      cacheTagHeader: process.env['EDGE_CACHE_TAG_HEADER'],
    };
  }
  if (process.env['EDGE_CACHE_MAX_TAGS_PER_ENTRY']) {
    envOverrides.edgeCache = {
      ...((envOverrides.edgeCache as Record<string, unknown>) ?? {}),
      maxTagsPerEntry: parseInt(process.env['EDGE_CACHE_MAX_TAGS_PER_ENTRY'], 10),
    };
  }
  if (process.env['EDGE_CACHE_MAX_TAG_LENGTH']) {
    envOverrides.edgeCache = {
      ...((envOverrides.edgeCache as Record<string, unknown>) ?? {}),
      maxTagLength: parseInt(process.env['EDGE_CACHE_MAX_TAG_LENGTH'], 10),
    };
  }
  if (process.env['EDGE_CACHE_REQUEST_COALESCING_ENABLED']) {
    const raw = process.env['EDGE_CACHE_REQUEST_COALESCING_ENABLED'].toLowerCase();
    envOverrides.edgeCache = {
      ...((envOverrides.edgeCache as Record<string, unknown>) ?? {}),
      requestCoalescingEnabled: raw === 'true' || raw === '1' || raw === 'yes',
    };
  }
  if (process.env['EDGE_CACHE_REQUEST_COALESCING_WAIT_MS']) {
    envOverrides.edgeCache = {
      ...((envOverrides.edgeCache as Record<string, unknown>) ?? {}),
      requestCoalescingWaitMs: parseInt(process.env['EDGE_CACHE_REQUEST_COALESCING_WAIT_MS'], 10),
    };
  }
  if (process.env['EDGE_CACHE_MEMORY_MAX_ENTRIES']) {
    envOverrides.edgeCache = {
      ...((envOverrides.edgeCache as Record<string, unknown>) ?? {}),
      memoryMaxEntries: parseInt(process.env['EDGE_CACHE_MEMORY_MAX_ENTRIES'], 10),
    };
  }
  if (process.env['WAF_ENABLED']) {
    const raw = process.env['WAF_ENABLED'].toLowerCase();
    envOverrides.waf = {
      ...((envOverrides.waf as Record<string, unknown>) ?? {}),
      enabled: raw === 'true' || raw === '1' || raw === 'yes',
    };
  }
  if (process.env['WAF_RISK_SCORE_THRESHOLD']) {
    envOverrides.waf = {
      ...((envOverrides.waf as Record<string, unknown>) ?? {}),
      riskScoreThreshold: parseInt(process.env['WAF_RISK_SCORE_THRESHOLD'], 10),
    };
  }
  if (process.env['WAF_CHALLENGE_DURATION_MS']) {
    envOverrides.waf = {
      ...((envOverrides.waf as Record<string, unknown>) ?? {}),
      challengeDurationMs: parseInt(process.env['WAF_CHALLENGE_DURATION_MS'], 10),
    };
  }
  if (process.env['WAF_MANAGED_RULES_VERSION']) {
    envOverrides.waf = {
      ...((envOverrides.waf as Record<string, unknown>) ?? {}),
      managedRulesVersion: process.env['WAF_MANAGED_RULES_VERSION'],
    };
  }
  if (process.env['WAF_ALLOWED_RULE_VERSIONS']) {
    const allowedRuleVersions = process.env['WAF_ALLOWED_RULE_VERSIONS']
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    envOverrides.waf = {
      ...((envOverrides.waf as Record<string, unknown>) ?? {}),
      allowedRuleVersions,
    };
  }
  if (process.env['WAF_CUSTOM_RULES_JSON']) {
    try {
      const parsed = JSON.parse(process.env['WAF_CUSTOM_RULES_JSON']) as unknown[];
      envOverrides.waf = {
        ...((envOverrides.waf as Record<string, unknown>) ?? {}),
        customRules: parsed,
      };
    } catch (err) {
      console.error(`Failed to parse WAF_CUSTOM_RULES_JSON: ${(err as Error).message}`);
      process.exit(1);
    }
  }
  if (process.env['WAF_RATE_RULES_JSON']) {
    try {
      const parsed = JSON.parse(process.env['WAF_RATE_RULES_JSON']) as unknown[];
      envOverrides.waf = {
        ...((envOverrides.waf as Record<string, unknown>) ?? {}),
        rateRules: parsed,
      };
    } catch (err) {
      console.error(`Failed to parse WAF_RATE_RULES_JSON: ${(err as Error).message}`);
      process.exit(1);
    }
  }
  if (process.env['ADAPTIVE_DEFENSE_ENABLED']) {
    const raw = process.env['ADAPTIVE_DEFENSE_ENABLED'].toLowerCase();
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      enabled: raw === 'true' || raw === '1' || raw === 'yes',
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_SCORE_WINDOW_MS']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      scoreWindowMs: parseInt(process.env['ADAPTIVE_DEFENSE_SCORE_WINDOW_MS'], 10),
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_BLOCK_THRESHOLD']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      blockThreshold: parseInt(process.env['ADAPTIVE_DEFENSE_BLOCK_THRESHOLD'], 10),
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_BLOCK_DURATION_MS']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      blockDurationMs: parseInt(process.env['ADAPTIVE_DEFENSE_BLOCK_DURATION_MS'], 10),
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_SCORE_WAF_BLOCK']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      signals: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['signals'] as Record<string, unknown>) ?? {}),
        wafBlock: parseInt(process.env['ADAPTIVE_DEFENSE_SCORE_WAF_BLOCK'], 10),
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_SCORE_RATE_LIMIT']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      signals: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['signals'] as Record<string, unknown>) ?? {}),
        rateLimitExceeded: parseInt(process.env['ADAPTIVE_DEFENSE_SCORE_RATE_LIMIT'], 10),
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_SCORE_AUTH_FAILURE']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      signals: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['signals'] as Record<string, unknown>) ?? {}),
        authFailure: parseInt(process.env['ADAPTIVE_DEFENSE_SCORE_AUTH_FAILURE'], 10),
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_SCORE_FORBIDDEN']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      signals: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['signals'] as Record<string, unknown>) ?? {}),
        forbidden: parseInt(process.env['ADAPTIVE_DEFENSE_SCORE_FORBIDDEN'], 10),
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_SCORE_BOT_FINGERPRINT']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      signals: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['signals'] as Record<string, unknown>) ?? {}),
        botFingerprint: parseInt(process.env['ADAPTIVE_DEFENSE_SCORE_BOT_FINGERPRINT'], 10),
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_CHALLENGE_ENABLED']) {
    const raw = process.env['ADAPTIVE_DEFENSE_CHALLENGE_ENABLED'].toLowerCase();
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      challenge: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['challenge'] as Record<string, unknown>) ?? {}),
        enabled: raw === 'true' || raw === '1' || raw === 'yes',
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_CHALLENGE_THRESHOLD']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      challengeThreshold: parseInt(process.env['ADAPTIVE_DEFENSE_CHALLENGE_THRESHOLD'], 10),
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_CHALLENGE_DURATION_MS']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      challenge: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['challenge'] as Record<string, unknown>) ?? {}),
        durationMs: parseInt(process.env['ADAPTIVE_DEFENSE_CHALLENGE_DURATION_MS'], 10),
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_CHALLENGE_TOKEN_TTL_MS']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      challenge: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['challenge'] as Record<string, unknown>) ?? {}),
        tokenTtlMs: parseInt(process.env['ADAPTIVE_DEFENSE_CHALLENGE_TOKEN_TTL_MS'], 10),
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_CHALLENGE_MAX_INVALID_ATTEMPTS']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      challenge: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['challenge'] as Record<string, unknown>) ?? {}),
        maxInvalidAttempts: parseInt(process.env['ADAPTIVE_DEFENSE_CHALLENGE_MAX_INVALID_ATTEMPTS'], 10),
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_CHALLENGE_INVALID_ATTEMPT_WINDOW_MS']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      challenge: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['challenge'] as Record<string, unknown>) ?? {}),
        invalidAttemptWindowMs: parseInt(process.env['ADAPTIVE_DEFENSE_CHALLENGE_INVALID_ATTEMPT_WINDOW_MS'], 10),
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_CHALLENGE_INVALID_ATTEMPT_BACKOFF_MS']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      challenge: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['challenge'] as Record<string, unknown>) ?? {}),
        invalidAttemptBackoffMs: parseInt(process.env['ADAPTIVE_DEFENSE_CHALLENGE_INVALID_ATTEMPT_BACKOFF_MS'], 10),
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_CHALLENGE_HEADER']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      challenge: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['challenge'] as Record<string, unknown>) ?? {}),
        headerName: process.env['ADAPTIVE_DEFENSE_CHALLENGE_HEADER'],
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_PROFILES_JSON']) {
    try {
      const parsed = JSON.parse(process.env['ADAPTIVE_DEFENSE_PROFILES_JSON']) as Record<string, unknown>;
      envOverrides.adaptiveDefense = {
        ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
        profiles: parsed,
      };
    } catch (err) {
      console.error(`Failed to parse ADAPTIVE_DEFENSE_PROFILES_JSON: ${(err as Error).message}`);
      process.exit(1);
    }
  }
  if (process.env['ADAPTIVE_DEFENSE_IP_ALLOWLIST']) {
    const ipAllowlist = process.env['ADAPTIVE_DEFENSE_IP_ALLOWLIST']
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      ipAllowlist,
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_ENABLED']) {
    const raw = process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_ENABLED'].toLowerCase();
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      abuseIntel: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['abuseIntel'] as Record<string, unknown>) ?? {}),
        enabled: raw === 'true' || raw === '1' || raw === 'yes',
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_SOURCE_ID']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      abuseIntel: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['abuseIntel'] as Record<string, unknown>) ?? {}),
        sourceId: process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_SOURCE_ID'],
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_EXPORT_MAX_ENTRIES']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      abuseIntel: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['abuseIntel'] as Record<string, unknown>) ?? {}),
        exportMaxEntries: parseInt(process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_EXPORT_MAX_ENTRIES'], 10),
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_DEFAULT_TTL_SECONDS']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      abuseIntel: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['abuseIntel'] as Record<string, unknown>) ?? {}),
        defaultBundleTtlSeconds: parseInt(process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_DEFAULT_TTL_SECONDS'], 10),
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_SIGN_EXPORTS']) {
    const raw = process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_SIGN_EXPORTS'].toLowerCase();
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      abuseIntel: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['abuseIntel'] as Record<string, unknown>) ?? {}),
        signExports: raw === 'true' || raw === '1' || raw === 'yes',
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_REQUIRE_SIGNED_IMPORTS']) {
    const raw = process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_REQUIRE_SIGNED_IMPORTS'].toLowerCase();
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      abuseIntel: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['abuseIntel'] as Record<string, unknown>) ?? {}),
        requireSignedImports: raw === 'true' || raw === '1' || raw === 'yes',
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_SIGNING_KEY_ID']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      abuseIntel: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['abuseIntel'] as Record<string, unknown>) ?? {}),
        signingKeyId: process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_SIGNING_KEY_ID'],
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_ALLOWED_SOURCES']) {
    const allowedSources = process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_ALLOWED_SOURCES']
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      abuseIntel: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['abuseIntel'] as Record<string, unknown>) ?? {}),
        allowedSources,
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_ALLOWED_KEY_IDS']) {
    const allowedKeyIds = process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_ALLOWED_KEY_IDS']
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      abuseIntel: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['abuseIntel'] as Record<string, unknown>) ?? {}),
        allowedKeyIds,
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_REPLAY_PROTECTION_ENABLED']) {
    const raw = process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_REPLAY_PROTECTION_ENABLED'].toLowerCase();
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      abuseIntel: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['abuseIntel'] as Record<string, unknown>) ?? {}),
        replayProtectionEnabled: raw === 'true' || raw === '1' || raw === 'yes',
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_REPLAY_CACHE_MAX_ENTRIES']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      abuseIntel: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['abuseIntel'] as Record<string, unknown>) ?? {}),
        replayCacheMaxEntries: parseInt(process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_REPLAY_CACHE_MAX_ENTRIES'], 10),
      },
    };
  }
  if (process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_MAX_SKEW_SECONDS']) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      abuseIntel: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['abuseIntel'] as Record<string, unknown>) ?? {}),
        maxSkewSeconds: parseInt(process.env['ADAPTIVE_DEFENSE_ABUSE_INTEL_MAX_SKEW_SECONDS'], 10),
      },
    };
  }
  const abuseIntelSigningSecret = readSecret('ADAPTIVE_DEFENSE_ABUSE_INTEL_SIGNING_SECRET', { defaultValue: '' });
  if (abuseIntelSigningSecret) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      abuseIntel: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['abuseIntel'] as Record<string, unknown>) ?? {}),
        signingSecret: abuseIntelSigningSecret,
      },
    };
  }
  const abuseIntelKeyringRaw = readSecret('ADAPTIVE_DEFENSE_ABUSE_INTEL_KEYRING', { defaultValue: '' });
  if (abuseIntelKeyringRaw) {
    try {
      const keyring = parseSecretKeyring(abuseIntelKeyringRaw, 'ADAPTIVE_DEFENSE_ABUSE_INTEL_KEYRING');
      envOverrides.adaptiveDefense = {
        ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
        abuseIntel: {
          ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['abuseIntel'] as Record<string, unknown>) ?? {}),
          keyring,
        },
      };
    } catch (err) {
      console.error(`Failed to parse ADAPTIVE_DEFENSE_ABUSE_INTEL_KEYRING: ${(err as Error).message}`);
      process.exit(1);
    }
  }
  if (process.env['BOT_MANAGEMENT_ENABLED']) {
    const raw = process.env['BOT_MANAGEMENT_ENABLED'].toLowerCase();
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      enabled: raw === 'true' || raw === '1' || raw === 'yes',
    };
  }
  if (process.env['BOT_MANAGEMENT_CHALLENGE_THRESHOLD']) {
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      challengeThreshold: parseInt(process.env['BOT_MANAGEMENT_CHALLENGE_THRESHOLD'], 10),
    };
  }
  if (process.env['BOT_MANAGEMENT_BLOCK_THRESHOLD']) {
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      blockThreshold: parseInt(process.env['BOT_MANAGEMENT_BLOCK_THRESHOLD'], 10),
    };
  }
  if (process.env['BOT_MANAGEMENT_CHALLENGE_DURATION_MS']) {
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      challengeDurationMs: parseInt(process.env['BOT_MANAGEMENT_CHALLENGE_DURATION_MS'], 10),
    };
  }
  if (process.env['BOT_MANAGEMENT_VERIFIED_BOT_UA_PATTERNS']) {
    const patterns = process.env['BOT_MANAGEMENT_VERIFIED_BOT_UA_PATTERNS']
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      verifiedBotUserAgentPatterns: patterns,
    };
  }
  if (process.env['BOT_MANAGEMENT_SCORE_MISSING_UA']) {
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      signals: {
        ...((((envOverrides.botManagement as Record<string, unknown>) ?? {})['signals'] as Record<string, unknown>) ?? {}),
        missingUserAgent: parseInt(process.env['BOT_MANAGEMENT_SCORE_MISSING_UA'], 10),
      },
    };
  }
  if (process.env['BOT_MANAGEMENT_SCORE_AUTOMATION_UA']) {
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      signals: {
        ...((((envOverrides.botManagement as Record<string, unknown>) ?? {})['signals'] as Record<string, unknown>) ?? {}),
        automationUserAgent: parseInt(process.env['BOT_MANAGEMENT_SCORE_AUTOMATION_UA'], 10),
      },
    };
  }
  if (process.env['BOT_MANAGEMENT_SCORE_MISSING_ACCEPT']) {
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      signals: {
        ...((((envOverrides.botManagement as Record<string, unknown>) ?? {})['signals'] as Record<string, unknown>) ?? {}),
        missingAccept: parseInt(process.env['BOT_MANAGEMENT_SCORE_MISSING_ACCEPT'], 10),
      },
    };
  }
  if (process.env['BOT_MANAGEMENT_SCORE_MISSING_ACCEPT_LANGUAGE']) {
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      signals: {
        ...((((envOverrides.botManagement as Record<string, unknown>) ?? {})['signals'] as Record<string, unknown>) ?? {}),
        missingAcceptLanguage: parseInt(process.env['BOT_MANAGEMENT_SCORE_MISSING_ACCEPT_LANGUAGE'], 10),
      },
    };
  }
  if (process.env['BOT_MANAGEMENT_SCORE_SUSPICIOUS_PATH']) {
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      signals: {
        ...((((envOverrides.botManagement as Record<string, unknown>) ?? {})['signals'] as Record<string, unknown>) ?? {}),
        suspiciousPath: parseInt(process.env['BOT_MANAGEMENT_SCORE_SUSPICIOUS_PATH'], 10),
      },
    };
  }
  if (process.env['BOT_MANAGEMENT_SCORE_XFF_CHAIN']) {
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      signals: {
        ...((((envOverrides.botManagement as Record<string, unknown>) ?? {})['signals'] as Record<string, unknown>) ?? {}),
        excessiveForwardedChain: parseInt(process.env['BOT_MANAGEMENT_SCORE_XFF_CHAIN'], 10),
      },
    };
  }
  if (process.env['BOT_MANAGEMENT_SCORE_HEADLESS_HINTS']) {
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      signals: {
        ...((((envOverrides.botManagement as Record<string, unknown>) ?? {})['signals'] as Record<string, unknown>) ?? {}),
        headlessHints: parseInt(process.env['BOT_MANAGEMENT_SCORE_HEADLESS_HINTS'], 10),
      },
    };
  }
  if (process.env['BOT_MANAGEMENT_PROFILES_JSON']) {
    try {
      const parsed = JSON.parse(process.env['BOT_MANAGEMENT_PROFILES_JSON']) as Record<string, unknown>;
      envOverrides.botManagement = {
        ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
        profiles: parsed,
      };
    } catch (err) {
      console.error(`Failed to parse BOT_MANAGEMENT_PROFILES_JSON: ${(err as Error).message}`);
      process.exit(1);
    }
  }
  if (process.env['BOT_MANAGEMENT_CLEARANCE_ENABLED']) {
    const raw = process.env['BOT_MANAGEMENT_CLEARANCE_ENABLED'].toLowerCase();
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      clearance: {
        ...((((envOverrides.botManagement as Record<string, unknown>) ?? {})['clearance'] as Record<string, unknown>) ?? {}),
        enabled: raw === 'true' || raw === '1' || raw === 'yes',
      },
    };
  }
  if (process.env['BOT_MANAGEMENT_CLEARANCE_COOKIE_NAME']) {
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      clearance: {
        ...((((envOverrides.botManagement as Record<string, unknown>) ?? {})['clearance'] as Record<string, unknown>) ?? {}),
        cookieName: process.env['BOT_MANAGEMENT_CLEARANCE_COOKIE_NAME'],
      },
    };
  }
  if (process.env['BOT_MANAGEMENT_CLEARANCE_TTL_SECONDS']) {
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      clearance: {
        ...((((envOverrides.botManagement as Record<string, unknown>) ?? {})['clearance'] as Record<string, unknown>) ?? {}),
        ttlSeconds: parseInt(process.env['BOT_MANAGEMENT_CLEARANCE_TTL_SECONDS'], 10),
      },
    };
  }
  if (process.env['BOT_MANAGEMENT_CLEARANCE_SECURE']) {
    const raw = process.env['BOT_MANAGEMENT_CLEARANCE_SECURE'].toLowerCase();
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      clearance: {
        ...((((envOverrides.botManagement as Record<string, unknown>) ?? {})['clearance'] as Record<string, unknown>) ?? {}),
        secure: raw === 'true' || raw === '1' || raw === 'yes',
      },
    };
  }
  if (process.env['BOT_MANAGEMENT_CLEARANCE_HTTP_ONLY']) {
    const raw = process.env['BOT_MANAGEMENT_CLEARANCE_HTTP_ONLY'].toLowerCase();
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      clearance: {
        ...((((envOverrides.botManagement as Record<string, unknown>) ?? {})['clearance'] as Record<string, unknown>) ?? {}),
        httpOnly: raw === 'true' || raw === '1' || raw === 'yes',
      },
    };
  }
  if (process.env['BOT_MANAGEMENT_CLEARANCE_SAME_SITE']) {
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      clearance: {
        ...((((envOverrides.botManagement as Record<string, unknown>) ?? {})['clearance'] as Record<string, unknown>) ?? {}),
        sameSite: process.env['BOT_MANAGEMENT_CLEARANCE_SAME_SITE'],
      },
    };
  }
  if (process.env['BOT_MANAGEMENT_CLEARANCE_PATH']) {
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      clearance: {
        ...((((envOverrides.botManagement as Record<string, unknown>) ?? {})['clearance'] as Record<string, unknown>) ?? {}),
        path: process.env['BOT_MANAGEMENT_CLEARANCE_PATH'],
      },
    };
  }
  if (process.env['BOT_MANAGEMENT_CLEARANCE_DOMAIN']) {
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      clearance: {
        ...((((envOverrides.botManagement as Record<string, unknown>) ?? {})['clearance'] as Record<string, unknown>) ?? {}),
        domain: process.env['BOT_MANAGEMENT_CLEARANCE_DOMAIN'],
      },
    };
  }
  const botClearanceSecret = readSecret('BOT_MANAGEMENT_CLEARANCE_SECRET', { defaultValue: '' });
  if (botClearanceSecret) {
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      clearance: {
        ...((((envOverrides.botManagement as Record<string, unknown>) ?? {})['clearance'] as Record<string, unknown>) ?? {}),
        secret: botClearanceSecret,
      },
    };
  }
  const botClearancePreviousSecretsRaw = readSecret('BOT_MANAGEMENT_CLEARANCE_PREVIOUS_SECRETS', { defaultValue: '' });
  const botClearancePreviousSecrets = botClearancePreviousSecretsRaw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (botClearancePreviousSecrets.length > 0) {
    envOverrides.botManagement = {
      ...((envOverrides.botManagement as Record<string, unknown>) ?? {}),
      clearance: {
        ...((((envOverrides.botManagement as Record<string, unknown>) ?? {})['clearance'] as Record<string, unknown>) ?? {}),
        previousSecrets: botClearancePreviousSecrets,
      },
    };
  }
  if (process.env['ACCESS_CONTROL_ENABLED']) {
    const raw = process.env['ACCESS_CONTROL_ENABLED'].toLowerCase();
    envOverrides.accessControl = {
      ...((envOverrides.accessControl as Record<string, unknown>) ?? {}),
      enabled: raw === 'true' || raw === '1' || raw === 'yes',
    };
  }
  if (process.env['ACCESS_CONTROL_BYPASS_INTERNAL']) {
    const raw = process.env['ACCESS_CONTROL_BYPASS_INTERNAL'].toLowerCase();
    envOverrides.accessControl = {
      ...((envOverrides.accessControl as Record<string, unknown>) ?? {}),
      bypassInternal: raw === 'true' || raw === '1' || raw === 'yes',
    };
  }
  if (process.env['ACCESS_CONTROL_COUNTRY_HEADER']) {
    envOverrides.accessControl = {
      ...((envOverrides.accessControl as Record<string, unknown>) ?? {}),
      countryHeader: process.env['ACCESS_CONTROL_COUNTRY_HEADER'],
    };
  }
  if (process.env['ACCESS_CONTROL_ASN_HEADER']) {
    envOverrides.accessControl = {
      ...((envOverrides.accessControl as Record<string, unknown>) ?? {}),
      asnHeader: process.env['ACCESS_CONTROL_ASN_HEADER'],
    };
  }
  if (process.env['ACCESS_CONTROL_IP_ALLOWLIST']) {
    const values = process.env['ACCESS_CONTROL_IP_ALLOWLIST']
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    envOverrides.accessControl = {
      ...((envOverrides.accessControl as Record<string, unknown>) ?? {}),
      policy: {
        ...((((envOverrides.accessControl as Record<string, unknown>) ?? {})['policy'] as Record<string, unknown>) ?? {}),
        ipAllowlist: values,
      },
    };
  }
  if (process.env['ACCESS_CONTROL_IP_DENYLIST']) {
    const values = process.env['ACCESS_CONTROL_IP_DENYLIST']
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    envOverrides.accessControl = {
      ...((envOverrides.accessControl as Record<string, unknown>) ?? {}),
      policy: {
        ...((((envOverrides.accessControl as Record<string, unknown>) ?? {})['policy'] as Record<string, unknown>) ?? {}),
        ipDenylist: values,
      },
    };
  }
  if (process.env['ACCESS_CONTROL_COUNTRY_ALLOWLIST']) {
    const values = process.env['ACCESS_CONTROL_COUNTRY_ALLOWLIST']
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    envOverrides.accessControl = {
      ...((envOverrides.accessControl as Record<string, unknown>) ?? {}),
      policy: {
        ...((((envOverrides.accessControl as Record<string, unknown>) ?? {})['policy'] as Record<string, unknown>) ?? {}),
        countryAllowlist: values,
      },
    };
  }
  if (process.env['ACCESS_CONTROL_COUNTRY_DENYLIST']) {
    const values = process.env['ACCESS_CONTROL_COUNTRY_DENYLIST']
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    envOverrides.accessControl = {
      ...((envOverrides.accessControl as Record<string, unknown>) ?? {}),
      policy: {
        ...((((envOverrides.accessControl as Record<string, unknown>) ?? {})['policy'] as Record<string, unknown>) ?? {}),
        countryDenylist: values,
      },
    };
  }
  if (process.env['ACCESS_CONTROL_ASN_ALLOWLIST']) {
    const values = process.env['ACCESS_CONTROL_ASN_ALLOWLIST']
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    envOverrides.accessControl = {
      ...((envOverrides.accessControl as Record<string, unknown>) ?? {}),
      policy: {
        ...((((envOverrides.accessControl as Record<string, unknown>) ?? {})['policy'] as Record<string, unknown>) ?? {}),
        asnAllowlist: values,
      },
    };
  }
  if (process.env['ACCESS_CONTROL_ASN_DENYLIST']) {
    const values = process.env['ACCESS_CONTROL_ASN_DENYLIST']
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    envOverrides.accessControl = {
      ...((envOverrides.accessControl as Record<string, unknown>) ?? {}),
      policy: {
        ...((((envOverrides.accessControl as Record<string, unknown>) ?? {})['policy'] as Record<string, unknown>) ?? {}),
        asnDenylist: values,
      },
    };
  }
  if (process.env['ACCESS_CONTROL_PROFILES_JSON']) {
    try {
      const parsed = JSON.parse(process.env['ACCESS_CONTROL_PROFILES_JSON']) as Record<string, unknown>;
      envOverrides.accessControl = {
        ...((envOverrides.accessControl as Record<string, unknown>) ?? {}),
        profiles: parsed,
      };
    } catch (err) {
      console.error(`Failed to parse ACCESS_CONTROL_PROFILES_JSON: ${(err as Error).message}`);
      process.exit(1);
    }
  }
  if (process.env['TLS_CERT_PATH']) {
    envOverrides.tls = { ...((envOverrides.tls as Record<string, unknown>) ?? {}), certPath: process.env['TLS_CERT_PATH'], enabled: true };
  }
  if (process.env['TLS_KEY_PATH']) {
    envOverrides.tls = { ...((envOverrides.tls as Record<string, unknown>) ?? {}), keyPath: process.env['TLS_KEY_PATH'], enabled: true };
  }
  if (process.env['TLS_CA_PATH']) {
    envOverrides.tls = { ...((envOverrides.tls as Record<string, unknown>) ?? {}), caPath: process.env['TLS_CA_PATH'] };
  }
  if (process.env['TLS_ENABLED']) {
    const raw = process.env['TLS_ENABLED'].toLowerCase();
    const enabled = raw === 'true' || raw === '1' || raw === 'yes';
    envOverrides.tls = { ...((envOverrides.tls as Record<string, unknown>) ?? {}), enabled };
  }
  if (process.env['JWKS_URI']) {
    envOverrides.jwt = { ...((envOverrides.jwt as Record<string, unknown>) ?? {}), jwksUri: process.env['JWKS_URI'] };
  }
  if (process.env['JWT_ISSUER']) {
    envOverrides.jwt = { ...((envOverrides.jwt as Record<string, unknown>) ?? {}), issuer: process.env['JWT_ISSUER'] };
  }
  if (process.env['JWT_AUDIENCE']) {
    envOverrides.jwt = { ...((envOverrides.jwt as Record<string, unknown>) ?? {}), audience: process.env['JWT_AUDIENCE'] };
  }
  if (process.env['PDP_URL']) {
    envOverrides.pdp = { ...((envOverrides.pdp as Record<string, unknown>) ?? {}), url: process.env['PDP_URL'] };
  }
  if (process.env['UPSTREAM_POOLS_JSON']) {
    try {
      const parsed = JSON.parse(process.env['UPSTREAM_POOLS_JSON']) as Record<string, unknown>;
      const existingUpstreams = (envOverrides.upstreams as Record<string, unknown>) ?? {};
      const mergedUpstreams: Record<string, unknown> = { ...existingUpstreams };

      for (const [name, pool] of Object.entries(parsed)) {
        const upstreamConfig = (mergedUpstreams[name] as Record<string, unknown>) ?? {};
        mergedUpstreams[name] = {
          ...upstreamConfig,
          pool,
        };
      }

      envOverrides.upstreams = mergedUpstreams;
    } catch (err) {
      console.error(`Failed to parse UPSTREAM_POOLS_JSON: ${(err as Error).message}`);
      process.exit(1);
    }
  }
  if (process.env['UPSTREAM_RETRY_BUDGETS_JSON']) {
    try {
      const parsed = JSON.parse(process.env['UPSTREAM_RETRY_BUDGETS_JSON']) as Record<string, unknown>;
      const existingUpstreams = (envOverrides.upstreams as Record<string, unknown>) ?? {};
      const mergedUpstreams: Record<string, unknown> = { ...existingUpstreams };

      for (const [name, retryBudget] of Object.entries(parsed)) {
        const upstreamConfig = (mergedUpstreams[name] as Record<string, unknown>) ?? {};
        mergedUpstreams[name] = {
          ...upstreamConfig,
          retryBudget,
        };
      }

      envOverrides.upstreams = mergedUpstreams;
    } catch (err) {
      console.error(`Failed to parse UPSTREAM_RETRY_BUDGETS_JSON: ${(err as Error).message}`);
      process.exit(1);
    }
  }
  const upstreamAffinityCookieSecret = readSecret('UPSTREAM_AFFINITY_COOKIE_SECRET', { defaultValue: '' });
  if (upstreamAffinityCookieSecret) {
    const existingUpstreams = (envOverrides.upstreams as Record<string, unknown>) ?? {};
    const mergedUpstreams: Record<string, unknown> = { ...existingUpstreams };

    for (const [name, upstreamValue] of Object.entries(mergedUpstreams)) {
      const upstreamConfig = (upstreamValue as Record<string, unknown>) ?? {};
      const pool = (upstreamConfig['pool'] as Record<string, unknown>) ?? {};
      const sessionAffinity = (pool['sessionAffinity'] as Record<string, unknown>) ?? {};
      const cookie = (sessionAffinity['cookie'] as Record<string, unknown>) ?? {};

      mergedUpstreams[name] = {
        ...upstreamConfig,
        pool: {
          ...pool,
          sessionAffinity: {
            ...sessionAffinity,
            cookie: {
              ...cookie,
              secret: cookie['secret'] ?? upstreamAffinityCookieSecret,
            },
          },
        },
      };
    }

    envOverrides.upstreams = mergedUpstreams;
  }
  const upstreamAffinityCookiePreviousSecretsRaw = readSecret('UPSTREAM_AFFINITY_COOKIE_PREVIOUS_SECRETS', { defaultValue: '' });
  const upstreamAffinityCookiePreviousSecrets = upstreamAffinityCookiePreviousSecretsRaw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (upstreamAffinityCookiePreviousSecrets.length > 0) {
      const existingUpstreams = (envOverrides.upstreams as Record<string, unknown>) ?? {};
      const mergedUpstreams: Record<string, unknown> = { ...existingUpstreams };

      for (const [name, upstreamValue] of Object.entries(mergedUpstreams)) {
        const upstreamConfig = (upstreamValue as Record<string, unknown>) ?? {};
        const pool = (upstreamConfig['pool'] as Record<string, unknown>) ?? {};
        const sessionAffinity = (pool['sessionAffinity'] as Record<string, unknown>) ?? {};
        const cookie = (sessionAffinity['cookie'] as Record<string, unknown>) ?? {};

        mergedUpstreams[name] = {
          ...upstreamConfig,
          pool: {
            ...pool,
            sessionAffinity: {
              ...sessionAffinity,
              cookie: {
                ...cookie,
                previousSecrets:
                  Array.isArray(cookie['previousSecrets']) && (cookie['previousSecrets'] as unknown[]).length > 0
                    ? cookie['previousSecrets']
                    : upstreamAffinityCookiePreviousSecrets,
              },
            },
          },
        };
      }

      envOverrides.upstreams = mergedUpstreams;
  }
  if (process.env['PDP_INTERNAL_AUDIENCE']) {
    envOverrides.pdp = {
      ...((envOverrides.pdp as Record<string, unknown>) ?? {}),
      internalAudience: process.env['PDP_INTERNAL_AUDIENCE'],
    };
  }
  if (process.env['PDP_BREAK_GLASS_SECRET']) {
    envOverrides.pdp = {
      ...((envOverrides.pdp as Record<string, unknown>) ?? {}),
      breakGlassSecret: process.env['PDP_BREAK_GLASS_SECRET'],
      breakGlassEnabled: true,
    };
  }
  if (process.env['PDP_BREAK_GLASS_ALLOWED_IPS']) {
    const ips = process.env['PDP_BREAK_GLASS_ALLOWED_IPS']
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    envOverrides.pdp = { ...((envOverrides.pdp as Record<string, unknown>) ?? {}), breakGlassAllowedIps: ips };
  }
  if (process.env['PDP_BREAK_GLASS_ALLOWED_PATHS']) {
    const paths = process.env['PDP_BREAK_GLASS_ALLOWED_PATHS']
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    envOverrides.pdp = { ...((envOverrides.pdp as Record<string, unknown>) ?? {}), breakGlassAllowedPaths: paths };
  }
  if (process.env['LOG_LEVEL']) {
    envOverrides.logging = { ...((envOverrides.logging as Record<string, unknown>) ?? {}), level: process.env['LOG_LEVEL'] };
  }
  if (process.env['CORS_ALLOWED_ORIGINS']) {
    const origins = process.env['CORS_ALLOWED_ORIGINS'].split(',').map(o => o.trim()).filter(Boolean);
    envOverrides.cors = { ...((envOverrides.cors as Record<string, unknown>) ?? {}), globalAllowedOrigins: origins };
  }

  // Internal auth: default ON in production unless explicitly disabled.
  // Disable via INTERNAL_AUTH_ENABLED=false (or by running with NODE_ENV != production).
  if (process.env['NODE_ENV'] === 'production' && process.env['INTERNAL_AUTH_ENABLED'] === undefined) {
    envOverrides.internalAuth = { ...((envOverrides.internalAuth as Record<string, unknown>) ?? {}), enabled: true };
  }
  if (process.env['INTERNAL_AUTH_ENABLED']) {
    const raw = process.env['INTERNAL_AUTH_ENABLED'].toLowerCase();
    const enabled = raw === 'true' || raw === '1' || raw === 'yes';
    envOverrides.internalAuth = { ...((envOverrides.internalAuth as Record<string, unknown>) ?? {}), enabled };
  }
  if (process.env['INTERNAL_AUTH_CALLER_ID']) {
    envOverrides.internalAuth = {
      ...((envOverrides.internalAuth as Record<string, unknown>) ?? {}),
      callerId: process.env['INTERNAL_AUTH_CALLER_ID'],
    };
  }
  if (process.env['INTERNAL_AUTH_CALLER_KEY_ID']) {
    envOverrides.internalAuth = {
      ...((envOverrides.internalAuth as Record<string, unknown>) ?? {}),
      callerKeyId: process.env['INTERNAL_AUTH_CALLER_KEY_ID'],
    };
  }
  const internalSharedSecret = readSecret('INTERNAL_SHARED_SECRET', { defaultValue: '' });
  if (internalSharedSecret) {
    envOverrides.internalAuth = {
      ...((envOverrides.internalAuth as Record<string, unknown>) ?? {}),
      secret: internalSharedSecret,
      enabled: true,
    };
  }
  const adaptiveChallengeSecret = readSecret('ADAPTIVE_DEFENSE_CHALLENGE_SECRET', { defaultValue: '' });
  if (adaptiveChallengeSecret) {
    envOverrides.adaptiveDefense = {
      ...((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {}),
      challenge: {
        ...((((envOverrides.adaptiveDefense as Record<string, unknown>) ?? {})['challenge'] as Record<string, unknown>) ?? {}),
        secret: adaptiveChallengeSecret,
      },
    };
  }
  const internalCallerSecret = readSecret('INTERNAL_AUTH_CALLER_SECRET', { defaultValue: '' });
  if (internalCallerSecret) {
    envOverrides.internalAuth = {
      ...((envOverrides.internalAuth as Record<string, unknown>) ?? {}),
      callerSecret: internalCallerSecret,
    };
  }
  if (process.env['INTERNAL_AUTH_SKEW_SECONDS']) {
    envOverrides.internalAuth = {
      ...((envOverrides.internalAuth as Record<string, unknown>) ?? {}),
      allowedSkewSeconds: parseInt(process.env['INTERNAL_AUTH_SKEW_SECONDS'], 10),
    };
  }
  if (process.env['INTERNAL_AUTH_REQUIRE_NONCE']) {
    const raw = process.env['INTERNAL_AUTH_REQUIRE_NONCE'].toLowerCase();
    const requireNonce = raw === 'true' || raw === '1' || raw === 'yes';
    envOverrides.internalAuth = {
      ...((envOverrides.internalAuth as Record<string, unknown>) ?? {}),
      requireNonce,
    };
  }
  if (process.env['INTERNAL_AUTH_REQUIRE_CALLER']) {
    const raw = process.env['INTERNAL_AUTH_REQUIRE_CALLER'].toLowerCase();
    const requireCallerId = raw === 'true' || raw === '1' || raw === 'yes';
    envOverrides.internalAuth = {
      ...((envOverrides.internalAuth as Record<string, unknown>) ?? {}),
      requireCallerId,
    };
  }
  if (process.env['INTERNAL_AUTH_REQUIRE_KEY_ID']) {
    const raw = process.env['INTERNAL_AUTH_REQUIRE_KEY_ID'].toLowerCase();
    const requireKeyId = raw === 'true' || raw === '1' || raw === 'yes';
    envOverrides.internalAuth = {
      ...((envOverrides.internalAuth as Record<string, unknown>) ?? {}),
      requireKeyId,
    };
  }
  if (process.env['INTERNAL_AUTH_ALLOWED_CALLERS']) {
    const callers = process.env['INTERNAL_AUTH_ALLOWED_CALLERS']
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    envOverrides.internalAuth = {
      ...((envOverrides.internalAuth as Record<string, unknown>) ?? {}),
      allowedCallerIds: callers,
    };
  }
  if (process.env['INTERNAL_AUTH_ALLOWED_KEY_IDS']) {
    const keyIds = process.env['INTERNAL_AUTH_ALLOWED_KEY_IDS']
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    envOverrides.internalAuth = {
      ...((envOverrides.internalAuth as Record<string, unknown>) ?? {}),
      allowedKeyIds: keyIds,
    };
  }
  const keyringRaw = readSecret('INTERNAL_AUTH_KEYRING', { defaultValue: '' });
  if (keyringRaw) {
    try {
      const keyring = parseSecretKeyring(keyringRaw, 'INTERNAL_AUTH_KEYRING');
      envOverrides.internalAuth = {
        ...((envOverrides.internalAuth as Record<string, unknown>) ?? {}),
        keyring,
      };
    } catch (err) {
      console.error(`Failed to parse INTERNAL_AUTH_KEYRING: ${(err as Error).message}`);
      process.exit(1);
    }
  }
  if (process.env['INTERNAL_AUTH_EXPECTED_AUDIENCE']) {
    envOverrides.internalAuth = {
      ...((envOverrides.internalAuth as Record<string, unknown>) ?? {}),
      expectedAudience: process.env['INTERNAL_AUTH_EXPECTED_AUDIENCE'],
    };
  }
  if (process.env['INTERNAL_AUTH_REPLAY_PROTECTION_ENABLED']) {
    const raw = process.env['INTERNAL_AUTH_REPLAY_PROTECTION_ENABLED'].toLowerCase();
    const replayProtectionEnabled = raw === 'true' || raw === '1' || raw === 'yes';
    envOverrides.internalAuth = {
      ...((envOverrides.internalAuth as Record<string, unknown>) ?? {}),
      replayProtectionEnabled,
    };
  }
  if (process.env['INTERNAL_AUTH_REPLAY_CACHE_MAX_ENTRIES']) {
    envOverrides.internalAuth = {
      ...((envOverrides.internalAuth as Record<string, unknown>) ?? {}),
      replayCacheMaxEntries: parseInt(process.env['INTERNAL_AUTH_REPLAY_CACHE_MAX_ENTRIES'], 10),
    };
  }

  // Load config file if specified
  let fileConfig: Record<string, unknown> = {};
  const configPath = process.env['GATEWAY_CONFIG'];
  if (configPath) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      fileConfig = require(configPath) as Record<string, unknown>;
    } catch (err) {
      console.error(`Failed to load config from ${configPath}:`, err);
      process.exit(1);
    }
  }

  // Merge: file config < env overrides
  const merged = deepMerge(fileConfig, envOverrides);

  if (upstreamAffinityCookieSecret || upstreamAffinityCookiePreviousSecrets.length > 0) {
    const upstreams = (merged['upstreams'] as Record<string, unknown>) ?? {};
    const mergedUpstreams: Record<string, unknown> = { ...upstreams };

    for (const [name, upstreamValue] of Object.entries(mergedUpstreams)) {
      const upstream = (upstreamValue as Record<string, unknown>) ?? {};
      const pool = (upstream['pool'] as Record<string, unknown>) ?? {};
      const sessionAffinity = (pool['sessionAffinity'] as Record<string, unknown>) ?? {};
      const cookie = (sessionAffinity['cookie'] as Record<string, unknown>) ?? {};

      mergedUpstreams[name] = {
        ...upstream,
        pool: {
          ...pool,
          sessionAffinity: {
            ...sessionAffinity,
            cookie: {
              ...cookie,
              secret: cookie['secret'] ?? upstreamAffinityCookieSecret,
              previousSecrets:
                Array.isArray(cookie['previousSecrets']) && (cookie['previousSecrets'] as unknown[]).length > 0
                  ? cookie['previousSecrets']
                  : upstreamAffinityCookiePreviousSecrets,
            },
          },
        },
      };
    }

    merged['upstreams'] = mergedUpstreams;
  }

  // Validate with Zod — fail hard on invalid config
  const result = GatewayConfigSchema.safeParse(merged);
  if (!result.success) {
    console.error('Gateway configuration validation failed:');
    for (const issue of result.error.issues) {
      console.error(`  ${issue.path.join('.')}: ${issue.message}`);
    }
    process.exit(1);
  }

  const data = result.data;
  if (!data.internalAuth.callerSecret && data.internalAuth.secret) {
    data.internalAuth.callerSecret = data.internalAuth.secret;
  }
  if (!data.adaptiveDefense.challenge.secret && data.internalAuth.secret) {
    data.adaptiveDefense.challenge.secret = data.internalAuth.secret;
  }
  if (!data.botManagement.clearance.secret) {
    data.botManagement.clearance.secret = data.adaptiveDefense.challenge.secret || data.internalAuth.secret;
  }
  if (!data.adaptiveDefense.abuseIntel.signingSecret) {
    data.adaptiveDefense.abuseIntel.signingSecret =
      data.adaptiveDefense.challenge.secret || data.internalAuth.secret;
  }
  if (
    Object.keys(data.internalAuth.keyring).length === 0 &&
    data.internalAuth.secret &&
    data.internalAuth.allowedKeyIds.length > 0
  ) {
    const fallbackKeyring: Record<string, string> = {};
    for (const keyId of data.internalAuth.allowedKeyIds) {
      fallbackKeyring[keyId] = data.internalAuth.secret;
    }
    data.internalAuth.keyring = fallbackKeyring;
  }
  if (
    Object.keys(data.adaptiveDefense.abuseIntel.keyring).length === 0 &&
    data.adaptiveDefense.abuseIntel.signingSecret &&
    data.adaptiveDefense.abuseIntel.allowedKeyIds.length > 0
  ) {
    const fallbackKeyring: Record<string, string> = {};
    for (const keyId of data.adaptiveDefense.abuseIntel.allowedKeyIds) {
      fallbackKeyring[keyId] = data.adaptiveDefense.abuseIntel.signingSecret;
    }
    data.adaptiveDefense.abuseIntel.keyring = fallbackKeyring;
  }

  // Runtime policy checks: fail-fast on insecure production settings.
  if (process.env['NODE_ENV'] === 'production') {
    if (!data.tls.enabled) {
      console.error('Refusing to start: gateway TLS must be enabled in production.');
      process.exit(1);
    }

    if (!data.internalAuth.enabled) {
      console.error('Refusing to start: INTERNAL_AUTH_ENABLED=false is not allowed in production.');
      process.exit(1);
    }
    if (!data.internalAuth.requireNonce) {
      console.error('Refusing to start: INTERNAL_AUTH_REQUIRE_NONCE=false is not allowed in production.');
      process.exit(1);
    }
    if (!data.internalAuth.requireCallerId) {
      console.error('Refusing to start: INTERNAL_AUTH_REQUIRE_CALLER=false is not allowed in production.');
      process.exit(1);
    }
    if (!data.internalAuth.requireKeyId) {
      console.error('Refusing to start: INTERNAL_AUTH_REQUIRE_KEY_ID=false is not allowed in production.');
      process.exit(1);
    }
    if (!data.internalAuth.callerId || data.internalAuth.callerId.trim().length === 0) {
      console.error('Refusing to start: INTERNAL_AUTH_CALLER_ID must be set in production.');
      process.exit(1);
    }
    if (!data.internalAuth.callerKeyId || data.internalAuth.callerKeyId.trim().length === 0) {
      console.error('Refusing to start: INTERNAL_AUTH_CALLER_KEY_ID must be set in production.');
      process.exit(1);
    }
    if (!data.internalAuth.expectedAudience || data.internalAuth.expectedAudience.trim().length === 0) {
      console.error('Refusing to start: INTERNAL_AUTH_EXPECTED_AUDIENCE must be set in production.');
      process.exit(1);
    }
    if (!data.internalAuth.allowedCallerIds || data.internalAuth.allowedCallerIds.length === 0) {
      console.error('Refusing to start: INTERNAL_AUTH_ALLOWED_CALLERS must be non-empty in production.');
      process.exit(1);
    }
    if (!data.internalAuth.allowedKeyIds || data.internalAuth.allowedKeyIds.length === 0) {
      console.error('Refusing to start: INTERNAL_AUTH_ALLOWED_KEY_IDS must be non-empty in production.');
      process.exit(1);
    }
    if (Object.keys(data.internalAuth.keyring).length === 0) {
      console.error('Refusing to start: INTERNAL_AUTH_KEYRING must be non-empty in production.');
      process.exit(1);
    }
    if (!data.internalAuth.replayProtectionEnabled) {
      console.error('Refusing to start: INTERNAL_AUTH_REPLAY_PROTECTION_ENABLED=false is not allowed in production.');
      process.exit(1);
    }
    if (!data.adaptiveDefense.enabled) {
      console.error('Refusing to start: ADAPTIVE_DEFENSE_ENABLED=false is not allowed in production.');
      process.exit(1);
    }
    if (!data.adaptiveDefense.challenge.enabled) {
      console.error('Refusing to start: ADAPTIVE_DEFENSE_CHALLENGE_ENABLED=false is not allowed in production.');
      process.exit(1);
    }
    if (!data.waf.enabled) {
      console.error('Refusing to start: WAF_ENABLED=false is not allowed in production.');
      process.exit(1);
    }
    if (data.edgeCache.cacheAuthenticated) {
      console.error('Refusing to start: EDGE_CACHE_CACHE_AUTHENTICATED=true is not allowed globally in production.');
      process.exit(1);
    }
    if (!data.adaptiveDefense.abuseIntel.enabled) {
      console.error('Refusing to start: ADAPTIVE_DEFENSE_ABUSE_INTEL_ENABLED=false is not allowed in production.');
      process.exit(1);
    }
    if (!data.adaptiveDefense.abuseIntel.signExports) {
      console.error('Refusing to start: ADAPTIVE_DEFENSE_ABUSE_INTEL_SIGN_EXPORTS=false is not allowed in production.');
      process.exit(1);
    }
    if (!data.adaptiveDefense.abuseIntel.requireSignedImports) {
      console.error('Refusing to start: ADAPTIVE_DEFENSE_ABUSE_INTEL_REQUIRE_SIGNED_IMPORTS=false is not allowed in production.');
      process.exit(1);
    }
    if (!data.adaptiveDefense.abuseIntel.replayProtectionEnabled) {
      console.error('Refusing to start: ADAPTIVE_DEFENSE_ABUSE_INTEL_REPLAY_PROTECTION_ENABLED=false is not allowed in production.');
      process.exit(1);
    }
    if (!data.adaptiveDefense.abuseIntel.signingKeyId || data.adaptiveDefense.abuseIntel.signingKeyId.trim().length === 0) {
      console.error('Refusing to start: ADAPTIVE_DEFENSE_ABUSE_INTEL_SIGNING_KEY_ID must be set in production.');
      process.exit(1);
    }
    if (!data.adaptiveDefense.abuseIntel.allowedSources || data.adaptiveDefense.abuseIntel.allowedSources.length === 0) {
      console.error('Refusing to start: ADAPTIVE_DEFENSE_ABUSE_INTEL_ALLOWED_SOURCES must be non-empty in production.');
      process.exit(1);
    }
    if (!data.adaptiveDefense.abuseIntel.allowedKeyIds || data.adaptiveDefense.abuseIntel.allowedKeyIds.length === 0) {
      console.error('Refusing to start: ADAPTIVE_DEFENSE_ABUSE_INTEL_ALLOWED_KEY_IDS must be non-empty in production.');
      process.exit(1);
    }
    if (Object.keys(data.adaptiveDefense.abuseIntel.keyring).length === 0) {
      console.error('Refusing to start: ADAPTIVE_DEFENSE_ABUSE_INTEL_KEYRING must be non-empty in production.');
      process.exit(1);
    }
    if (data.adaptiveDefense.challengeThreshold >= data.adaptiveDefense.blockThreshold) {
      console.error('Refusing to start: adaptive defense challenge threshold must be lower than block threshold.');
      process.exit(1);
    }
    const adaptiveSignalsTotal =
      data.adaptiveDefense.signals.wafBlock +
      data.adaptiveDefense.signals.rateLimitExceeded +
      data.adaptiveDefense.signals.authFailure +
      data.adaptiveDefense.signals.forbidden +
      data.adaptiveDefense.signals.botFingerprint;
    if (adaptiveSignalsTotal <= 0) {
      console.error('Refusing to start: adaptive defense signal scores must not all be zero in production.');
      process.exit(1);
    }
    const adaptiveSecret = data.adaptiveDefense.challenge.secret ?? '';
    const adaptiveSecretLooksDefault =
      adaptiveSecret.toLowerCase().includes('change-me') ||
      adaptiveSecret.toLowerCase().includes('not-secure');
    if (!adaptiveSecret || adaptiveSecretLooksDefault || adaptiveSecret.length < 32) {
      console.error('Refusing to start: ADAPTIVE_DEFENSE_CHALLENGE_SECRET is missing/weak/default in production.');
      process.exit(1);
    }
    const abuseIntelSecret = data.adaptiveDefense.abuseIntel.signingSecret ?? '';
    const abuseIntelSecretLooksDefault =
      abuseIntelSecret.toLowerCase().includes('change-me') ||
      abuseIntelSecret.toLowerCase().includes('not-secure');
    if (!abuseIntelSecret || abuseIntelSecretLooksDefault || abuseIntelSecret.length < 32) {
      console.error('Refusing to start: ADAPTIVE_DEFENSE_ABUSE_INTEL_SIGNING_SECRET is missing/weak/default in production.');
      process.exit(1);
    }

    const secret = data.internalAuth.secret ?? '';
    const looksDefault = secret.toLowerCase().includes('change-me') || secret.toLowerCase().includes('not-secure');
    if (!secret || looksDefault || secret.length < 32) {
      console.error('Refusing to start: INTERNAL_SHARED_SECRET is missing/weak/default in production.');
      process.exit(1);
    }

    if (!isEnabled(process.env['GATEWAY_MTLS_REQUIRED'], false)) {
      console.error('Refusing to start: GATEWAY_MTLS_REQUIRED=true is required in production.');
      process.exit(1);
    }

    if (isEnabled(process.env['TOKEN_ENFORCEMENT_FAIL_OPEN'], false)) {
      console.error('Refusing to start: TOKEN_ENFORCEMENT_FAIL_OPEN=true is not allowed in production.');
      process.exit(1);
    }
    if (!data.pdp.internalAudience || data.pdp.internalAudience.trim().length === 0) {
      console.error('Refusing to start: PDP_INTERNAL_AUDIENCE must be set in production.');
      process.exit(1);
    }
  }

  return data;
}

function deepMerge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = { ...target };
  for (const key of Object.keys(source)) {
    const sourceVal = source[key];
    const targetVal = target[key];
    if (
      sourceVal !== null &&
      sourceVal !== undefined &&
      typeof sourceVal === 'object' &&
      !Array.isArray(sourceVal) &&
      targetVal !== null &&
      targetVal !== undefined &&
      typeof targetVal === 'object' &&
      !Array.isArray(targetVal)
    ) {
      result[key] = deepMerge(targetVal as Record<string, unknown>, sourceVal as Record<string, unknown>);
    } else if (sourceVal !== undefined) {
      result[key] = sourceVal;
    }
  }
  return result;
}

export function getRouteConfig(config: GatewayConfig, path: string, method: string): RouteConfig | undefined {
  return config.routes.find(r => {
    const pathMatch = path === r.path || path.startsWith(r.path + '/') || matchPattern(r.path, path);
    const methodMatch = r.methods.includes(method.toUpperCase()) || r.methods.includes('*');
    return pathMatch && methodMatch;
  });
}

function matchPattern(pattern: string, path: string): boolean {
  if (!pattern.includes('*')) return false;
  return globToRegExp(pattern).test(path);
}

function globToRegExp(glob: string): RegExp {
  // Supports:
  // - *  : any chars except '/'
  // - ** : any chars (including '/')
  // Everything else is treated literally.
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const tokenized = escaped.replace(/\*\*/g, '<<DOUBLESTAR>>');
  const singleStar = tokenized.replace(/\*/g, '[^/]*');
  const regexStr = '^' + singleStar.replace(/<<DOUBLESTAR>>/g, '.*') + '$';
  return new RegExp(regexStr);
}
