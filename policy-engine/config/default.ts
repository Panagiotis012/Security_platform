export interface PolicyEngineConfig {
  server: {
    port: number;
    host: string;
    shutdownTimeoutMs: number;
  };
  authorization: {
    defaultEffect: 'DENY';
    maxEvaluationTimeMs: number;
    enableCache: boolean;
    cacheTtlSeconds: number;
    maxPoliciesPerEvaluation: number;
  };
  redis: {
    host: string;
    port: number;
    password: string | undefined;
    db: number;
    keyPrefix: string;
    connectTimeoutMs: number;
  };
  logging: {
    level: string;
    format: 'json' | 'text';
    decisionLogEnabled: boolean;
    decisionLogMaxEntries: number;
    includeAttributes: boolean;
  };
  healthCheck: {
    path: string;
    allowedWithoutAuth: string[];
  };
  admin: {
    jwtSecret: string;
    tokenIssuer: string;
    requiredRole: string;
  };
}

import { readSecret } from '@zerotrust/shared';

const config: PolicyEngineConfig = {
  server: {
    port: parseInt(process.env.PDP_PORT || process.env.PORT || '8181', 10),
    host: process.env.PDP_HOST || process.env.HOST || '0.0.0.0',
    shutdownTimeoutMs: parseInt(process.env.PDP_SHUTDOWN_TIMEOUT_MS || '10000', 10),
  },
  authorization: {
    defaultEffect: 'DENY',
    maxEvaluationTimeMs: parseInt(process.env.PDP_MAX_EVAL_TIME_MS || '100', 10),
    enableCache: process.env.PDP_CACHE_ENABLED !== 'false',
    cacheTtlSeconds: parseInt(process.env.PDP_CACHE_TTL_SECONDS || '60', 10),
    maxPoliciesPerEvaluation: parseInt(process.env.PDP_MAX_POLICIES || '500', 10),
  },
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
    password: readSecret('REDIS_PASSWORD', { allowEmpty: true }) || undefined,
    db: parseInt(process.env.REDIS_DB || '0', 10),
    keyPrefix: process.env.REDIS_KEY_PREFIX || 'pdp:',
    connectTimeoutMs: parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '5000', 10),
  },
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    format: (process.env.LOG_FORMAT as 'json' | 'text') || 'json',
    decisionLogEnabled: process.env.DECISION_LOG_ENABLED !== 'false',
    decisionLogMaxEntries: parseInt(process.env.DECISION_LOG_MAX_ENTRIES || '100000', 10),
    includeAttributes: process.env.LOG_INCLUDE_ATTRIBUTES !== 'false',
  },
  healthCheck: {
    path: '/health',
    allowedWithoutAuth: [
      '/health',
      '/ready',
      '/metrics',
    ],
  },
  admin: {
    jwtSecret: readSecret('PDP_ADMIN_JWT_SECRET', { defaultValue: 'change-me-in-production-this-is-not-secure' }),
    tokenIssuer: process.env.PDP_TOKEN_ISSUER || 'zerotrust-platform',
    requiredRole: process.env.PDP_ADMIN_ROLE || 'pdp:admin',
  },
};

export default config;
