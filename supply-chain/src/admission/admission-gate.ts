/**
 * Admission Gate
 *
 * The core enforcement point for the Supply Chain & Deployment Integrity Plane.
 * Evaluates deploy requests against all configured policies. ALL checks must
 * pass for an ALLOW decision. If ANY check fails, the request is DENIED.
 *
 * Supports emergency break-glass override for incident response scenarios,
 * which is logged, time-limited, and requires justification.
 */

import { v4 as uuidv4 } from 'uuid';
import winston from 'winston';
import type {
  DeployPolicy,
  DeployRequest,
  PolicyResult,
  RequireApproval} from './deploy-policies';
import {
  RequireSignature,
  RequireProvenance,
  RequireAllowlistedPipeline,
  RequireSBOM,
  RequireNoKnownVulns
} from './deploy-policies';
import type { ArtifactSigner } from '../signing/artifact-signer';
import type { KeyRegistry } from '../signing/key-registry';
import type { InMemoryProvenanceStore } from '../provenance/provenance-store';
import type { InMemorySBOMStore } from '../sbom/sbom-store';
import type { VulnerabilityChecker, Severity } from '../vulnerability/vuln-checker';
import type { AdmissionPolicyConfig, BreakGlassConfig } from '../../config/default';
import defaultConfig from '../../config/default';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'admission-gate' },
  transports: [new winston.transports.Console()],
});

// ── Types ──

export type AdmissionVerdict = 'ALLOW' | 'DENY';

export interface AdmissionDecision {
  id: string;
  verdict: AdmissionVerdict;
  request: DeployRequest;
  policyResults: PolicyResult[];
  failedPolicies: string[];
  passedPolicies: string[];
  isBreakGlass: boolean;
  breakGlassInfo?: {
    justification: string;
    approver: string;
    expiresAt: string;
  };
  decidedAt: string;
  evaluationDurationMs: number;
}

export interface BreakGlassRequest {
  artifactDigest: string;
  environment: string;
  requestor: string;
  justification: string;
  approver: string;
  approverRole: string;
}

interface BreakGlassToken {
  id: string;
  artifactDigest: string;
  environment: string;
  requestor: string;
  justification: string;
  approver: string;
  createdAt: string;
  expiresAt: string;
  used: boolean;
}

export interface AdmissionGateDeps {
  signer: ArtifactSigner;
  keyRegistry: KeyRegistry;
  provenanceStore: InMemoryProvenanceStore;
  sbomStore: InMemorySBOMStore;
  vulnChecker: VulnerabilityChecker;
  approvalPolicy: RequireApproval;
}

export class AdmissionGate {
  private readonly signer: ArtifactSigner;
  private readonly keyRegistry: KeyRegistry;
  private readonly provenanceStore: InMemoryProvenanceStore;
  private readonly sbomStore: InMemorySBOMStore;
  private readonly vulnChecker: VulnerabilityChecker;
  private readonly approvalPolicy: RequireApproval;
  private readonly policyConfigs: Map<string, AdmissionPolicyConfig> = new Map();
  private readonly breakGlassConfig: BreakGlassConfig;
  private readonly breakGlassTokens: Map<string, BreakGlassToken> = new Map();
  private readonly auditLog: AdmissionDecision[] = [];
  private consecutiveBreakGlassUses = 0;

  constructor(deps: AdmissionGateDeps, breakGlassConfig?: BreakGlassConfig) {
    this.signer = deps.signer;
    this.keyRegistry = deps.keyRegistry;
    this.provenanceStore = deps.provenanceStore;
    this.sbomStore = deps.sbomStore;
    this.vulnChecker = deps.vulnChecker;
    this.approvalPolicy = deps.approvalPolicy;
    this.breakGlassConfig = breakGlassConfig ?? defaultConfig.breakGlass;

    // Load per-environment policy configs
    for (const policyConfig of defaultConfig.admissionPolicies) {
      this.policyConfigs.set(policyConfig.environment, policyConfig);
    }
  }

  /**
   * Evaluate a deploy request against all applicable policies.
   * Returns an AdmissionDecision with ALLOW or DENY.
   */
  evaluate(request: DeployRequest): AdmissionDecision {
    const startTime = Date.now();
    const decisionId = uuidv4();

    logger.info('Evaluating admission request', {
      decisionId,
      artifactDigest: request.artifactDigest,
      imageRef: request.imageRef,
      environment: request.environment,
      requestor: request.requestor,
      pipelineId: request.pipelineId,
    });

    // Check for break-glass token
    const breakGlassKey = `${request.artifactDigest}:${request.environment}`;
    const breakGlassToken = this.breakGlassTokens.get(breakGlassKey);

    if (breakGlassToken && !breakGlassToken.used && new Date(breakGlassToken.expiresAt) > new Date()) {
      // Mark token as used
      breakGlassToken.used = true;
      this.consecutiveBreakGlassUses++;

      const decision: AdmissionDecision = {
        id: decisionId,
        verdict: 'ALLOW',
        request,
        policyResults: [],
        failedPolicies: [],
        passedPolicies: ['BREAK_GLASS_OVERRIDE'],
        isBreakGlass: true,
        breakGlassInfo: {
          justification: breakGlassToken.justification,
          approver: breakGlassToken.approver,
          expiresAt: breakGlassToken.expiresAt,
        },
        decidedAt: new Date().toISOString(),
        evaluationDurationMs: Date.now() - startTime,
      };

      this.auditLog.push(decision);

      logger.warn('BREAK-GLASS admission override used', {
        decisionId,
        artifactDigest: request.artifactDigest,
        environment: request.environment,
        requestor: request.requestor,
        justification: breakGlassToken.justification,
        approver: breakGlassToken.approver,
        consecutiveUses: this.consecutiveBreakGlassUses,
      });

      return decision;
    }

    // Reset consecutive break-glass counter on normal evaluation
    this.consecutiveBreakGlassUses = 0;

    // Build the set of applicable policies for this environment
    const policies = this.buildPoliciesForEnvironment(request.environment);

    // Evaluate all policies
    const policyResults: PolicyResult[] = [];
    const failedPolicies: string[] = [];
    const passedPolicies: string[] = [];

    for (const policy of policies) {
      const result = policy.evaluate(request);
      policyResults.push(result);

      if (result.pass) {
        passedPolicies.push(result.policyName);
      } else {
        failedPolicies.push(result.policyName);
      }
    }

    const verdict: AdmissionVerdict = failedPolicies.length === 0 ? 'ALLOW' : 'DENY';

    const decision: AdmissionDecision = {
      id: decisionId,
      verdict,
      request,
      policyResults,
      failedPolicies,
      passedPolicies,
      isBreakGlass: false,
      decidedAt: new Date().toISOString(),
      evaluationDurationMs: Date.now() - startTime,
    };

    this.auditLog.push(decision);

    if (verdict === 'DENY') {
      logger.warn('Admission DENIED', {
        decisionId,
        artifactDigest: request.artifactDigest,
        environment: request.environment,
        requestor: request.requestor,
        failedPolicies,
        reasons: policyResults
          .filter((r) => !r.pass)
          .map((r) => r.reason),
      });
    } else {
      logger.info('Admission ALLOWED', {
        decisionId,
        artifactDigest: request.artifactDigest,
        environment: request.environment,
        requestor: request.requestor,
        passedPolicies,
      });
    }

    return decision;
  }

  /**
   * Issue a break-glass override token for emergency deployments.
   * The token is time-limited and requires justification.
   */
  issueBreakGlass(bgRequest: BreakGlassRequest): BreakGlassToken {
    if (!this.breakGlassConfig.enabled) {
      throw new Error('Break-glass is disabled by configuration');
    }

    if (this.breakGlassConfig.requireJustification && !bgRequest.justification.trim()) {
      throw new Error('Break-glass requires a justification');
    }

    if (bgRequest.approverRole !== this.breakGlassConfig.requireApproverRole) {
      throw new Error(
        `Break-glass requires approver with role "${this.breakGlassConfig.requireApproverRole}", got "${bgRequest.approverRole}"`
      );
    }

    if (this.consecutiveBreakGlassUses >= this.breakGlassConfig.maxConsecutiveUses) {
      throw new Error(
        `Maximum consecutive break-glass uses (${this.breakGlassConfig.maxConsecutiveUses}) reached. Normal admission process must be used.`
      );
    }

    const now = new Date();
    const expiresAt = new Date(
      now.getTime() + this.breakGlassConfig.ttlMinutes * 60 * 1000
    );

    const token: BreakGlassToken = {
      id: uuidv4(),
      artifactDigest: bgRequest.artifactDigest,
      environment: bgRequest.environment,
      requestor: bgRequest.requestor,
      justification: bgRequest.justification,
      approver: bgRequest.approver,
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      used: false,
    };

    const key = `${bgRequest.artifactDigest}:${bgRequest.environment}`;
    this.breakGlassTokens.set(key, token);

    logger.warn('Break-glass token issued', {
      tokenId: token.id,
      artifactDigest: bgRequest.artifactDigest,
      environment: bgRequest.environment,
      requestor: bgRequest.requestor,
      approver: bgRequest.approver,
      justification: bgRequest.justification,
      expiresAt: token.expiresAt,
      notifyChannels: this.breakGlassConfig.notifyChannels,
    });

    return token;
  }

  /**
   * Get the full admission audit log.
   */
  getAuditLog(limit: number = 100): AdmissionDecision[] {
    return this.auditLog.slice(-limit);
  }

  /**
   * Get admission decisions for a specific environment.
   */
  getDecisionsByEnvironment(environment: string): AdmissionDecision[] {
    return this.auditLog.filter((d) => d.request.environment === environment);
  }

  /**
   * Get the policy configuration for an environment.
   */
  getPolicyConfig(environment: string): AdmissionPolicyConfig | undefined {
    return this.policyConfigs.get(environment);
  }

  /**
   * Update the policy config for an environment at runtime.
   */
  updatePolicyConfig(environment: string, config: AdmissionPolicyConfig): void {
    this.policyConfigs.set(environment, config);
    logger.info('Policy configuration updated', { environment, config });
  }

  /**
   * Get statistics about admission decisions.
   */
  getStats(): {
    total: number;
    allowed: number;
    denied: number;
    breakGlass: number;
    byEnvironment: Record<string, { allowed: number; denied: number }>;
  } {
    let allowed = 0;
    let denied = 0;
    let breakGlass = 0;
    const byEnvironment: Record<string, { allowed: number; denied: number }> = {};

    for (const decision of this.auditLog) {
      if (decision.verdict === 'ALLOW') allowed++;
      else denied++;
      if (decision.isBreakGlass) breakGlass++;

      const env = decision.request.environment;
      if (!byEnvironment[env]) {
        byEnvironment[env] = { allowed: 0, denied: 0 };
      }
      if (decision.verdict === 'ALLOW') byEnvironment[env].allowed++;
      else byEnvironment[env].denied++;
    }

    return {
      total: this.auditLog.length,
      allowed,
      denied,
      breakGlass,
      byEnvironment,
    };
  }

  // ── Private ──

  /**
   * Build the list of policies to evaluate based on the environment's configuration.
   */
  private buildPoliciesForEnvironment(environment: string): DeployPolicy[] {
    const config = this.policyConfigs.get(environment);
    if (!config) {
      // Default to most restrictive if no config found
      logger.warn('No policy config found for environment, using maximum restriction', {
        environment,
      });
      return this.buildAllPolicies('HIGH');
    }

    const policies: DeployPolicy[] = [];

    if (config.requireSignature) {
      policies.push(new RequireSignature(this.signer, this.keyRegistry));
    }

    if (config.requireProvenance) {
      policies.push(new RequireProvenance(this.provenanceStore));
    }

    if (config.requireAllowlistedPipeline) {
      policies.push(new RequireAllowlistedPipeline());
    }

    if (config.requireSBOM) {
      policies.push(new RequireSBOM(this.sbomStore));
    }

    if (config.requireNoKnownVulns) {
      policies.push(
        new RequireNoKnownVulns(
          this.sbomStore,
          this.vulnChecker,
          config.vulnSeverityThreshold
        )
      );
    }

    if (config.requireApproval) {
      policies.push(this.approvalPolicy);
    }

    return policies;
  }

  private buildAllPolicies(severityThreshold: Severity): DeployPolicy[] {
    return [
      new RequireSignature(this.signer, this.keyRegistry),
      new RequireProvenance(this.provenanceStore),
      new RequireAllowlistedPipeline(),
      new RequireSBOM(this.sbomStore),
      new RequireNoKnownVulns(this.sbomStore, this.vulnChecker, severityThreshold),
      this.approvalPolicy,
    ];
  }
}

export default AdmissionGate;
