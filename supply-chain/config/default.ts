/**
 * Supply Chain & Deployment Integrity Plane - Default Configuration
 *
 * Centralized configuration for all supply chain security controls.
 * In production, sensitive values (signing keys, secrets) would come
 * from a secrets manager or environment variables.
 */

export interface PipelineAllowlistEntry {
  pipelineId: string;
  name: string;
  repository: string;
  environments: string[];
  trustedSince: string;
}

export interface SigningKeyConfig {
  algorithm: 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512';
  keySize: number;
  rotationIntervalDays: number;
  maxKeyAgeDays: number;
  requireHSM: boolean;
}

export interface AdmissionPolicyConfig {
  environment: string;
  requireSignature: boolean;
  requireProvenance: boolean;
  requireAllowlistedPipeline: boolean;
  requireSBOM: boolean;
  requireNoKnownVulns: boolean;
  requireApproval: boolean;
  vulnSeverityThreshold: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface HardeningRequirement {
  environment: string;
  runAsNonRoot: boolean;
  readOnlyRootFilesystem: boolean;
  disallowPrivilegeEscalation: boolean;
  dropAllCapabilities: boolean;
  requireSeccompProfile: boolean;
  requireResourceLimits: boolean;
  disallowHostNamespaces: boolean;
  requireNetworkPolicy: boolean;
  maxCpuLimit: string;
  maxMemoryLimit: string;
}

export interface BreakGlassConfig {
  enabled: boolean;
  ttlMinutes: number;
  requireJustification: boolean;
  requireApproverRole: string;
  maxConsecutiveUses: number;
  notifyChannels: string[];
  auditRetentionDays: number;
}

export interface SupplyChainConfig {
  server: {
    port: number;
    host: string;
    requestTimeoutMs: number;
  };
  allowlistedPipelines: PipelineAllowlistEntry[];
  signing: {
    defaultAlgorithm: SigningKeyConfig['algorithm'];
    environments: Record<string, SigningKeyConfig>;
    trustedKeyIds: string[];
  };
  admissionPolicies: AdmissionPolicyConfig[];
  vulnerability: {
    severityThresholds: Record<string, 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>;
    autoBlockCritical: boolean;
    gracePeriodsHours: Record<string, number>;
    exemptComponents: string[];
  };
  hardening: HardeningRequirement[];
  breakGlass: BreakGlassConfig;
  sbom: {
    specVersion: string;
    format: 'CycloneDX';
    includeTransitive: boolean;
    hashAlgorithms: string[];
  };
  provenance: {
    requireReproducible: boolean;
    slsaLevelTarget: number;
    attestationTTLDays: number;
  };
  audit: {
    logAllDecisions: boolean;
    retentionDays: number;
    alertOnDeny: boolean;
  };
}

const defaultConfig: SupplyChainConfig = {
  server: {
    port: parseInt(process.env.SUPPLY_CHAIN_PORT || process.env.PORT || '8184', 10),
    host: process.env.SUPPLY_CHAIN_HOST || process.env.HOST || '0.0.0.0',
    requestTimeoutMs: parseInt(process.env.SUPPLY_CHAIN_REQUEST_TIMEOUT_MS || '30000', 10),
  },

  allowlistedPipelines: [
    {
      pipelineId: 'github-actions-main',
      name: 'GitHub Actions - Main Pipeline',
      repository: 'org/platform-core',
      environments: ['dev', 'staging', 'production'],
      trustedSince: '2024-01-01T00:00:00Z',
    },
    {
      pipelineId: 'github-actions-services',
      name: 'GitHub Actions - Microservices',
      repository: 'org/microservices',
      environments: ['dev', 'staging', 'production'],
      trustedSince: '2024-01-01T00:00:00Z',
    },
    {
      pipelineId: 'gitlab-ci-infra',
      name: 'GitLab CI - Infrastructure',
      repository: 'org/infrastructure',
      environments: ['dev', 'staging'],
      trustedSince: '2024-03-01T00:00:00Z',
    },
    {
      pipelineId: 'jenkins-legacy',
      name: 'Jenkins - Legacy Builds',
      repository: 'org/legacy-app',
      environments: ['dev'],
      trustedSince: '2023-06-01T00:00:00Z',
    },
  ],

  signing: {
    defaultAlgorithm: 'ES256',
    environments: {
      dev: {
        algorithm: 'ES256',
        keySize: 256,
        rotationIntervalDays: 90,
        maxKeyAgeDays: 365,
        requireHSM: false,
      },
      staging: {
        algorithm: 'ES256',
        keySize: 256,
        rotationIntervalDays: 60,
        maxKeyAgeDays: 180,
        requireHSM: false,
      },
      production: {
        algorithm: 'ES256',
        keySize: 256,
        rotationIntervalDays: 30,
        maxKeyAgeDays: 90,
        requireHSM: true,
      },
    },
    trustedKeyIds: [],
  },

  admissionPolicies: [
    {
      environment: 'dev',
      requireSignature: true,
      requireProvenance: false,
      requireAllowlistedPipeline: false,
      requireSBOM: true,
      requireNoKnownVulns: false,
      requireApproval: false,
      vulnSeverityThreshold: 'CRITICAL',
    },
    {
      environment: 'staging',
      requireSignature: true,
      requireProvenance: true,
      requireAllowlistedPipeline: true,
      requireSBOM: true,
      requireNoKnownVulns: true,
      requireApproval: false,
      vulnSeverityThreshold: 'HIGH',
    },
    {
      environment: 'production',
      requireSignature: true,
      requireProvenance: true,
      requireAllowlistedPipeline: true,
      requireSBOM: true,
      requireNoKnownVulns: true,
      requireApproval: true,
      vulnSeverityThreshold: 'HIGH',
    },
  ],

  vulnerability: {
    severityThresholds: {
      dev: 'CRITICAL',
      staging: 'HIGH',
      production: 'HIGH',
    },
    autoBlockCritical: true,
    gracePeriodsHours: {
      CRITICAL: 0,
      HIGH: 72,
      MEDIUM: 168,
      LOW: 720,
    },
    exemptComponents: [],
  },

  hardening: [
    {
      environment: 'dev',
      runAsNonRoot: true,
      readOnlyRootFilesystem: false,
      disallowPrivilegeEscalation: true,
      dropAllCapabilities: false,
      requireSeccompProfile: false,
      requireResourceLimits: true,
      disallowHostNamespaces: true,
      requireNetworkPolicy: false,
      maxCpuLimit: '2000m',
      maxMemoryLimit: '4Gi',
    },
    {
      environment: 'staging',
      runAsNonRoot: true,
      readOnlyRootFilesystem: true,
      disallowPrivilegeEscalation: true,
      dropAllCapabilities: true,
      requireSeccompProfile: true,
      requireResourceLimits: true,
      disallowHostNamespaces: true,
      requireNetworkPolicy: true,
      maxCpuLimit: '1000m',
      maxMemoryLimit: '2Gi',
    },
    {
      environment: 'production',
      runAsNonRoot: true,
      readOnlyRootFilesystem: true,
      disallowPrivilegeEscalation: true,
      dropAllCapabilities: true,
      requireSeccompProfile: true,
      requireResourceLimits: true,
      disallowHostNamespaces: true,
      requireNetworkPolicy: true,
      maxCpuLimit: '1000m',
      maxMemoryLimit: '2Gi',
    },
  ],

  breakGlass: {
    enabled: true,
    ttlMinutes: 30,
    requireJustification: true,
    requireApproverRole: 'security-admin',
    maxConsecutiveUses: 3,
    notifyChannels: ['#security-alerts', '#incident-response'],
    auditRetentionDays: 2555, // ~7 years for compliance
  },

  sbom: {
    specVersion: '1.5',
    format: 'CycloneDX',
    includeTransitive: true,
    hashAlgorithms: ['SHA-256', 'SHA-512'],
  },

  provenance: {
    requireReproducible: false,
    slsaLevelTarget: 3,
    attestationTTLDays: 365,
  },

  audit: {
    logAllDecisions: true,
    retentionDays: 2555,
    alertOnDeny: true,
  },
};

export default defaultConfig;

/**
 * Merge environment-specific overrides with default configuration.
 */
export function loadConfig(overrides?: Partial<SupplyChainConfig>): SupplyChainConfig {
  if (!overrides) {
    return { ...defaultConfig };
  }
  return {
    ...defaultConfig,
    ...overrides,
    server: { ...defaultConfig.server, ...(overrides.server ?? {}) },
    signing: { ...defaultConfig.signing, ...(overrides.signing ?? {}) },
    vulnerability: { ...defaultConfig.vulnerability, ...(overrides.vulnerability ?? {}) },
    breakGlass: { ...defaultConfig.breakGlass, ...(overrides.breakGlass ?? {}) },
    sbom: { ...defaultConfig.sbom, ...(overrides.sbom ?? {}) },
    provenance: { ...defaultConfig.provenance, ...(overrides.provenance ?? {}) },
    audit: { ...defaultConfig.audit, ...(overrides.audit ?? {}) },
  };
}
