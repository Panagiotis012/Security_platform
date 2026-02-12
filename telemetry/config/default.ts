// ─── Telemetry & Detection Plane Configuration ───
// All thresholds are tunable. In production, override via environment variables or config service.

export interface DetectionThresholds {
  bruteForce: {
    maxFailedLogins: number;
    windowMinutes: number;
  };
  credentialStuffing: {
    maxDistinctUsernames: number;
    windowMinutes: number;
    ipRangePrefixLength: number;
  };
  passwordSpraying: {
    minAffectedAccounts: number;
    maxPerAccountAttempts: number;
    windowMinutes: number;
  };
  tokenReplay: {
    enabled: boolean;
  };
  impossibleTravel: {
    maxDistanceKm: number;
    minTimeHours: number;
  };
  massExport: {
    maxRecordsPerWindow: number;
    maxBytesPerWindow: number;
    windowMinutes: number;
  };
  privilegeEscalation: {
    maxDeniedAdminAttempts: number;
    windowMinutes: number;
  };
  anomalousAccessPattern: {
    baselineWindowDays: number;
    stdDevMultiplier: number;
    unusualHoursStart: number;
    unusualHoursEnd: number;
  };
  policyViolationSurge: {
    surgeMultiplier: number;
    windowMinutes: number;
    minBaselineCount: number;
  };
  sessionAnomaly: {
    enabled: boolean;
  };
}

export interface AlertRoutingConfig {
  critical: {
    channels: ('webhook' | 'log' | 'queue')[];
    webhookUrl: string;
    maxResponseTimeMs: number;
  };
  high: {
    channels: ('webhook' | 'log' | 'queue')[];
    webhookUrl: string;
    maxResponseTimeMs: number;
  };
  medium: {
    channels: ('webhook' | 'log' | 'queue')[];
    maxResponseTimeMs: number;
  };
  low: {
    channels: ('log' | 'queue')[];
    maxResponseTimeMs: number;
  };
}

export interface RetentionConfig {
  auditLogRetentionDays: number;
  alertRetentionDays: number;
  metricsRetentionDays: number;
  hashChainRetentionDays: number;
}

export interface ResponseHookConfig {
  blockIp: {
    enabled: boolean;
    defaultDurationMinutes: number;
    maxDurationMinutes: number;
    gatewayServiceUrl: string;
  };
  revokeSessions: {
    enabled: boolean;
    identityServiceUrl: string;
  };
  requireStepUp: {
    enabled: boolean;
    gatewayServiceUrl: string;
    requiredLevel: number;
    durationMinutes: number;
  };
  throttleUser: {
    enabled: boolean;
    reducedRatePercent: number;
    durationMinutes: number;
    gatewayServiceUrl: string;
  };
  rotateCredentials: {
    enabled: boolean;
    identityServiceUrl: string;
  };
}

export interface SuppressionConfig {
  /** Default suppression window in seconds: alerts for the same detection+actor are deduplicated */
  defaultWindowSeconds: number;
  /** Per-detection overrides keyed by detection ID */
  perDetection: Record<string, number>;
}

export interface TelemetryConfig {
  server: {
    port: number;
    host: string;
  };
  redis: {
    host: string;
    port: number;
    keyPrefix: string;
  };
  detectionEngine: {
    evaluationIntervalSeconds: number;
    eventWindowMinutes: number;
    maxEventsPerEvaluation: number;
  };
  detectionThresholds: DetectionThresholds;
  alertRouting: AlertRoutingConfig;
  retention: RetentionConfig;
  responseHooks: ResponseHookConfig;
  suppression: SuppressionConfig;
  piiFields: string[];
}

const DEFAULT_GATEWAY_URL =
  process.env.NODE_ENV === 'production' ? 'https://gateway:8443' : 'http://localhost:8443';
const DEFAULT_IDENTITY_URL =
  process.env.NODE_ENV === 'production' ? 'https://identity:8182' : 'http://localhost:8182';

// Alert webhooks are optional. Prefer per-severity overrides, but allow a single
// ALERT_WEBHOOK_URL to cover all severities for simple Slack/Teams/PagerDuty setups.
const CRITICAL_ALERT_WEBHOOK_URL = process.env.ALERT_CRITICAL_WEBHOOK || process.env.ALERT_WEBHOOK_URL || '';
const HIGH_ALERT_WEBHOOK_URL = process.env.ALERT_HIGH_WEBHOOK || process.env.ALERT_WEBHOOK_URL || '';

const config: TelemetryConfig = {
  server: {
    port: parseInt(process.env.TELEMETRY_PORT || process.env.PORT || '8183', 10),
    host: process.env.TELEMETRY_HOST || process.env.HOST || '0.0.0.0',
  },

  redis: {
    host: process.env.REDIS_HOST || '127.0.0.1',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
    keyPrefix: 'telemetry:',
  },

  detectionEngine: {
    evaluationIntervalSeconds: parseInt(process.env.DETECTION_INTERVAL || '30', 10),
    // Must cover the largest built-in detection lookback window (e.g. impossible travel checks up to 1 hour).
    eventWindowMinutes: parseInt(process.env.DETECTION_WINDOW || '60', 10),
    maxEventsPerEvaluation: 10000,
  },

  detectionThresholds: {
    bruteForce: {
      maxFailedLogins: parseInt(process.env.BF_MAX_FAILURES || '10', 10),
      windowMinutes: parseInt(process.env.BF_WINDOW || '5', 10),
    },
    credentialStuffing: {
      maxDistinctUsernames: parseInt(process.env.CS_MAX_USERNAMES || '20', 10),
      windowMinutes: parseInt(process.env.CS_WINDOW || '10', 10),
      ipRangePrefixLength: 24,
    },
    passwordSpraying: {
      minAffectedAccounts: parseInt(process.env.PS_MIN_ACCOUNTS || '10', 10),
      maxPerAccountAttempts: parseInt(process.env.PS_MAX_PER_ACCOUNT || '3', 10),
      windowMinutes: parseInt(process.env.PS_WINDOW || '15', 10),
    },
    tokenReplay: {
      enabled: process.env.TR_ENABLED !== 'false',
    },
    impossibleTravel: {
      maxDistanceKm: parseInt(process.env.IT_MAX_DISTANCE || '500', 10),
      minTimeHours: parseFloat(process.env.IT_MIN_TIME || '1'),
    },
    massExport: {
      maxRecordsPerWindow: parseInt(process.env.ME_MAX_RECORDS || '100', 10),
      maxBytesPerWindow: parseInt(process.env.ME_MAX_BYTES || '52428800', 10), // 50MB
      windowMinutes: parseInt(process.env.ME_WINDOW || '5', 10),
    },
    privilegeEscalation: {
      maxDeniedAdminAttempts: parseInt(process.env.PE_MAX_DENIED || '5', 10),
      windowMinutes: parseInt(process.env.PE_WINDOW || '10', 10),
    },
    anomalousAccessPattern: {
      baselineWindowDays: parseInt(process.env.AA_BASELINE_DAYS || '7', 10),
      stdDevMultiplier: parseFloat(process.env.AA_STDDEV_MULT || '2.5'),
      unusualHoursStart: parseInt(process.env.AA_UNUSUAL_START || '0', 10),
      unusualHoursEnd: parseInt(process.env.AA_UNUSUAL_END || '6', 10),
    },
    policyViolationSurge: {
      surgeMultiplier: parseFloat(process.env.PV_SURGE_MULT || '5'),
      windowMinutes: parseInt(process.env.PV_WINDOW || '10', 10),
      minBaselineCount: parseInt(process.env.PV_MIN_BASELINE || '5', 10),
    },
    sessionAnomaly: {
      enabled: process.env.SA_ENABLED !== 'false',
    },
  },

  alertRouting: {
    critical: {
      channels: CRITICAL_ALERT_WEBHOOK_URL ? ['webhook', 'log'] : ['log'],
      webhookUrl: CRITICAL_ALERT_WEBHOOK_URL,
      maxResponseTimeMs: 5000,
    },
    high: {
      channels: HIGH_ALERT_WEBHOOK_URL ? ['webhook', 'log'] : ['log'],
      webhookUrl: HIGH_ALERT_WEBHOOK_URL,
      maxResponseTimeMs: 15000,
    },
    medium: {
      channels: ['log', 'queue'],
      maxResponseTimeMs: 60000,
    },
    low: {
      channels: ['log'],
      maxResponseTimeMs: 300000,
    },
  },

  retention: {
    auditLogRetentionDays: parseInt(process.env.AUDIT_RETENTION_DAYS || '365', 10),
    alertRetentionDays: parseInt(process.env.ALERT_RETENTION_DAYS || '90', 10),
    metricsRetentionDays: parseInt(process.env.METRICS_RETENTION_DAYS || '30', 10),
    hashChainRetentionDays: parseInt(process.env.HASHCHAIN_RETENTION_DAYS || '730', 10),
  },

  responseHooks: {
    blockIp: {
      enabled: process.env.HOOK_BLOCK_IP !== 'false',
      defaultDurationMinutes: parseInt(process.env.HOOK_BLOCK_DURATION || '30', 10),
      maxDurationMinutes: parseInt(process.env.HOOK_BLOCK_MAX || '1440', 10),
      gatewayServiceUrl: process.env.GATEWAY_SERVICE_URL || DEFAULT_GATEWAY_URL,
    },
    revokeSessions: {
      enabled: process.env.HOOK_REVOKE_SESSIONS !== 'false',
      identityServiceUrl: process.env.IDENTITY_SERVICE_URL || DEFAULT_IDENTITY_URL,
    },
    requireStepUp: {
      enabled: process.env.HOOK_STEP_UP !== 'false',
      gatewayServiceUrl: process.env.GATEWAY_SERVICE_URL || DEFAULT_GATEWAY_URL,
      requiredLevel: parseInt(process.env.HOOK_STEP_UP_LEVEL || '1', 10),
      durationMinutes: parseInt(process.env.HOOK_STEP_UP_DURATION || '60', 10),
    },
    throttleUser: {
      enabled: process.env.HOOK_THROTTLE !== 'false',
      reducedRatePercent: parseInt(process.env.HOOK_THROTTLE_PERCENT || '25', 10),
      durationMinutes: parseInt(process.env.HOOK_THROTTLE_DURATION || '60', 10),
      gatewayServiceUrl: process.env.GATEWAY_SERVICE_URL || DEFAULT_GATEWAY_URL,
    },
    rotateCredentials: {
      enabled: process.env.HOOK_ROTATE_CREDS === 'true',
      identityServiceUrl: process.env.IDENTITY_SERVICE_URL || DEFAULT_IDENTITY_URL,
    },
  },

  suppression: {
    defaultWindowSeconds: parseInt(process.env.SUPPRESSION_DEFAULT || '300', 10),
    perDetection: {
      'brute-force': 600,
      'credential-stuffing': 900,
      'password-spraying': 900,
      'token-replay': 60,
      'impossible-travel': 3600,
      'mass-export': 300,
      'privilege-escalation': 600,
      'anomalous-access': 1800,
      'policy-violation-surge': 600,
      'session-anomaly': 300,
    },
  },

  piiFields: [
    'email',
    'phone',
    'ssn',
    'creditCard',
    'password',
    'secret',
    'token',
    'apiKey',
    'authorization',
  ],
};

export default config;
