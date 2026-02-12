/**
 * Deploy Policies
 *
 * Individual policy checks that compose the admission gate.
 * Each policy evaluates a deploy request against a specific criterion
 * and returns a pass/fail result with reasoning.
 */

import winston from 'winston';
import type { ArtifactSigner } from '../signing/artifact-signer';
import type { KeyRegistry } from '../signing/key-registry';
import type { InMemoryProvenanceStore } from '../provenance/provenance-store';
import type { InMemorySBOMStore } from '../sbom/sbom-store';
import type { VulnerabilityChecker, Severity } from '../vulnerability/vuln-checker';
import defaultConfig from '../../config/default';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'deploy-policies' },
  transports: [new winston.transports.Console()],
});

// ── Types ──

export interface DeployRequest {
  artifactDigest: string;
  imageRef: string;
  namespace: string;
  environment: string;
  requestor: string;
  pipelineId: string;
  buildId?: string;
  approvalToken?: string;
  metadata?: Record<string, string>;
}

export interface PolicyResult {
  pass: boolean;
  policyName: string;
  reason: string;
  details?: Record<string, unknown>;
}

export interface DeployPolicy {
  name: string;
  evaluate(request: DeployRequest): PolicyResult;
}

// ── Policy Implementations ──

/**
 * Requires that the artifact is signed by a key from the trusted key allowlist.
 */
export class RequireSignature implements DeployPolicy {
  readonly name = 'RequireSignature';

  constructor(
    private readonly signer: ArtifactSigner,
    private readonly keyRegistry: KeyRegistry
  ) {}

  evaluate(request: DeployRequest): PolicyResult {
    const signatures = this.signer.getSignatures(request.artifactDigest);

    if (signatures.length === 0) {
      return {
        pass: false,
        policyName: this.name,
        reason: `No signatures found for artifact ${request.artifactDigest}`,
      };
    }

    // Verify at least one signature is from a trusted, non-revoked key
    for (const sig of signatures) {
      const key = this.keyRegistry.getKey(sig.keyId);
      if (!key) continue;

      if (!this.keyRegistry.isValidForVerification(sig.keyId)) {
        continue;
      }

      // Verify the signature is cryptographically valid
      const valid = this.signer.verifySignatureByKeyId(
        request.artifactDigest,
        sig.signature,
        sig.keyId
      );

      if (valid) {
        // Check environment match
        if (key.environment === request.environment || key.environment === 'all') {
          logger.info('Signature policy passed', {
            artifactDigest: request.artifactDigest,
            keyId: sig.keyId,
            environment: request.environment,
          });
          return {
            pass: true,
            policyName: this.name,
            reason: `Valid signature from key ${sig.keyId}`,
            details: { keyId: sig.keyId, keyEnvironment: key.environment },
          };
        }
      }
    }

    return {
      pass: false,
      policyName: this.name,
      reason: `No valid signature from a trusted key for environment ${request.environment}`,
      details: { signatureCount: signatures.length },
    };
  }
}

/**
 * Requires that a provenance attestation exists and is valid.
 */
export class RequireProvenance implements DeployPolicy {
  readonly name = 'RequireProvenance';

  constructor(private readonly provenanceStore: InMemoryProvenanceStore) {}

  evaluate(request: DeployRequest): PolicyResult {
    const attestation = this.provenanceStore.retrieve(request.artifactDigest);

    if (!attestation) {
      return {
        pass: false,
        policyName: this.name,
        reason: `No provenance attestation found for artifact ${request.artifactDigest}`,
      };
    }

    // Verify the attestation subject matches
    const subjectMatch = attestation.statement.subject.some(
      (s) => s.digest.sha256 === request.artifactDigest
    );

    if (!subjectMatch) {
      return {
        pass: false,
        policyName: this.name,
        reason: 'Provenance attestation subject does not match artifact digest',
      };
    }

    // Verify attestation has signatures
    if (attestation.signatures.length === 0) {
      return {
        pass: false,
        policyName: this.name,
        reason: 'Provenance attestation has no signatures',
      };
    }

    logger.info('Provenance policy passed', {
      artifactDigest: request.artifactDigest,
      attestationId: attestation.id,
      slsaLevel: attestation.metadata.slsaLevel,
    });

    return {
      pass: true,
      policyName: this.name,
      reason: `Valid provenance attestation found (SLSA Level ${attestation.metadata.slsaLevel})`,
      details: {
        attestationId: attestation.id,
        repository: attestation.buildInfo.repository,
        commitHash: attestation.buildInfo.commitHash,
        slsaLevel: attestation.metadata.slsaLevel,
      },
    };
  }
}

/**
 * Requires that the build came from an allowlisted CI/CD pipeline.
 */
export class RequireAllowlistedPipeline implements DeployPolicy {
  readonly name = 'RequireAllowlistedPipeline';

  private readonly allowlist: Map<string, { environments: string[]; name: string }>;

  constructor(
    allowlistedPipelines?: Array<{ pipelineId: string; environments: string[]; name: string }>
  ) {
    this.allowlist = new Map();
    const pipelines = allowlistedPipelines ?? defaultConfig.allowlistedPipelines;
    for (const p of pipelines) {
      this.allowlist.set(p.pipelineId, {
        environments: p.environments,
        name: p.name,
      });
    }
  }

  evaluate(request: DeployRequest): PolicyResult {
    if (!request.pipelineId) {
      return {
        pass: false,
        policyName: this.name,
        reason: 'No pipeline ID provided in deploy request',
      };
    }

    const pipeline = this.allowlist.get(request.pipelineId);
    if (!pipeline) {
      return {
        pass: false,
        policyName: this.name,
        reason: `Pipeline ${request.pipelineId} is not on the allowlist`,
        details: {
          allowlistedPipelines: Array.from(this.allowlist.keys()),
        },
      };
    }

    // Check that the pipeline is allowed for the target environment
    if (!pipeline.environments.includes(request.environment)) {
      return {
        pass: false,
        policyName: this.name,
        reason: `Pipeline ${request.pipelineId} (${pipeline.name}) is not allowed for environment ${request.environment}`,
        details: {
          allowedEnvironments: pipeline.environments,
          requestedEnvironment: request.environment,
        },
      };
    }

    logger.info('Pipeline allowlist policy passed', {
      pipelineId: request.pipelineId,
      pipelineName: pipeline.name,
      environment: request.environment,
    });

    return {
      pass: true,
      policyName: this.name,
      reason: `Pipeline ${request.pipelineId} (${pipeline.name}) is allowlisted for ${request.environment}`,
    };
  }
}

/**
 * Requires that an SBOM is present for the build.
 */
export class RequireSBOM implements DeployPolicy {
  readonly name = 'RequireSBOM';

  constructor(private readonly sbomStore: InMemorySBOMStore) {}

  evaluate(request: DeployRequest): PolicyResult {
    // Use buildId if available, otherwise use artifact digest as lookup
    const lookupId = request.buildId ?? request.artifactDigest;
    const exists = this.sbomStore.exists(lookupId);

    if (!exists) {
      return {
        pass: false,
        policyName: this.name,
        reason: `No SBOM found for build ${lookupId}`,
      };
    }

    const stored = this.sbomStore.retrieve(lookupId);
    if (!stored) {
      return {
        pass: false,
        policyName: this.name,
        reason: `SBOM retrieval failed for build ${lookupId}`,
      };
    }

    logger.info('SBOM policy passed', {
      buildId: lookupId,
      componentCount: stored.sbom.components.length,
    });

    return {
      pass: true,
      policyName: this.name,
      reason: `SBOM present with ${stored.sbom.components.length} components`,
      details: {
        buildId: lookupId,
        componentCount: stored.sbom.components.length,
        sbomId: stored.id,
      },
    };
  }
}

/**
 * Requires that no critical/high vulnerabilities are present in the SBOM.
 */
export class RequireNoKnownVulns implements DeployPolicy {
  readonly name = 'RequireNoKnownVulns';

  constructor(
    private readonly sbomStore: InMemorySBOMStore,
    private readonly vulnChecker: VulnerabilityChecker,
    private readonly severityThreshold: Severity = 'HIGH'
  ) {}

  evaluate(request: DeployRequest): PolicyResult {
    const lookupId = request.buildId ?? request.artifactDigest;
    const stored = this.sbomStore.retrieve(lookupId);

    if (!stored) {
      return {
        pass: false,
        policyName: this.name,
        reason: `Cannot check vulnerabilities: SBOM not found for build ${lookupId}`,
      };
    }

    const result = this.vulnChecker.checkSBOM({
      components: stored.sbom.components.map((c) => ({
        name: c.name,
        version: c.version,
      })),
    });

    if (this.vulnChecker.exceedsThreshold(result.findings, this.severityThreshold)) {
      const blockingFindings = result.findings.filter((f) => {
        const order: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
        return order[f.severity] >= order[this.severityThreshold];
      });

      return {
        pass: false,
        policyName: this.name,
        reason: `${blockingFindings.length} vulnerabilities at or above ${this.severityThreshold} severity found`,
        details: {
          findings: blockingFindings.map((f) => ({
            component: f.component,
            version: f.version,
            cveId: f.cveId,
            severity: f.severity,
          })),
          summary: result.summary,
        },
      };
    }

    logger.info('Vulnerability policy passed', {
      buildId: lookupId,
      threshold: this.severityThreshold,
      totalFindings: result.findings.length,
    });

    return {
      pass: true,
      policyName: this.name,
      reason: `No vulnerabilities at or above ${this.severityThreshold} severity`,
      details: {
        summary: result.summary,
        checkId: result.checkId,
      },
    };
  }
}

/**
 * Requires manual approval for certain environments.
 */
export class RequireApproval implements DeployPolicy {
  readonly name = 'RequireApproval';

  private readonly approvals: Map<string, { approver: string; approvedAt: string; expiresAt: string }> =
    new Map();

  /**
   * Record an approval for a specific artifact and environment.
   */
  recordApproval(
    artifactDigest: string,
    environment: string,
    approver: string,
    ttlMinutes: number = 60
  ): void {
    const key = `${artifactDigest}:${environment}`;
    const now = new Date();
    const expires = new Date(now.getTime() + ttlMinutes * 60 * 1000);

    this.approvals.set(key, {
      approver,
      approvedAt: now.toISOString(),
      expiresAt: expires.toISOString(),
    });

    logger.info('Approval recorded', {
      artifactDigest,
      environment,
      approver,
      expiresAt: expires.toISOString(),
    });
  }

  evaluate(request: DeployRequest): PolicyResult {
    const key = `${request.artifactDigest}:${request.environment}`;
    const approval = this.approvals.get(key);

    if (!approval) {
      return {
        pass: false,
        policyName: this.name,
        reason: `No approval found for artifact ${request.artifactDigest} in environment ${request.environment}`,
      };
    }

    // Check if approval has expired
    if (new Date(approval.expiresAt) < new Date()) {
      this.approvals.delete(key);
      return {
        pass: false,
        policyName: this.name,
        reason: `Approval for artifact ${request.artifactDigest} has expired`,
        details: { approvedAt: approval.approvedAt, expiredAt: approval.expiresAt },
      };
    }

    logger.info('Approval policy passed', {
      artifactDigest: request.artifactDigest,
      environment: request.environment,
      approver: approval.approver,
    });

    return {
      pass: true,
      policyName: this.name,
      reason: `Approved by ${approval.approver}`,
      details: {
        approver: approval.approver,
        approvedAt: approval.approvedAt,
        expiresAt: approval.expiresAt,
      },
    };
  }
}

export default {
  RequireSignature,
  RequireProvenance,
  RequireAllowlistedPipeline,
  RequireSBOM,
  RequireNoKnownVulns,
  RequireApproval,
};
