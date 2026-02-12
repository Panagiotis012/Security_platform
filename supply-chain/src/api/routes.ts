/**
 * API Routes
 *
 * REST API endpoints for the Supply Chain & Deployment Integrity Plane.
 * All endpoints are versioned under /v1 and follow consistent
 * request/response patterns with Zod validation.
 */

import type { Request, Response, NextFunction } from 'express';
import { Router } from 'express';
import { z } from 'zod';
import winston from 'winston';
import type { SBOMGenerator } from '../sbom/sbom-generator';
import type { InMemorySBOMStore } from '../sbom/sbom-store';
import type { ProvenanceAttestor } from '../provenance/attestation';
import type { InMemoryProvenanceStore } from '../provenance/provenance-store';
import type { ArtifactSigner } from '../signing/artifact-signer';
import type { KeyRegistry } from '../signing/key-registry';
import type { SupplyChainKeystore } from '../signing/keystore';
import type { AdmissionGate } from '../admission/admission-gate';
import type { RequireApproval } from '../admission/deploy-policies';
import type { HardeningValidator } from '../runtime/hardening-validator';
import type { VulnerabilityChecker } from '../vulnerability/vuln-checker';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'api-routes' },
  transports: [new winston.transports.Console()],
});

const SUPPLY_CHAIN_ADMIN_ROLES = ['admin', 'security-admin'] as const;

function parseCsvHeader(value: string | string[] | undefined): string[] {
  const raw = Array.isArray(value) ? value.join(',') : (value ?? '');
  return raw
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

export function requireGatewayPrincipal() {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = String(req.headers['x-authenticated-user'] ?? '').trim();
    if (!user) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    next();
  };
}

export function requireAnyRole(allowedRoles: readonly string[]) {
  const allowed = new Set(allowedRoles.map((r) => r.toLowerCase()));
  return (req: Request, res: Response, next: NextFunction): void => {
    const roles = parseCsvHeader(req.headers['x-authenticated-roles'] as string | string[] | undefined);
    const ok = roles.some((r) => allowed.has(r));
    if (!ok) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }
    next();
  };
}

export function requireStepUpLevel(requiredLevel: number) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const raw = String(req.headers['x-step-up-level'] ?? '0').trim();
    const level = Number.parseInt(raw, 10);
    if (!Number.isFinite(level) || level < requiredLevel) {
      res.setHeader('x-zt-step-up-required', 'true');
      res.setHeader('x-zt-required-step-up-level', String(requiredLevel));
      res.status(403).json({ error: 'Step-up authentication required' });
      return;
    }
    next();
  };
}

// ── Zod Schemas ──

const SBOMGenerateSchema = z.object({
  projectName: z.string().min(1),
  projectVersion: z.string().min(1),
  projectId: z.string().optional(),
  buildId: z.string().min(1),
  components: z.array(
    z.object({
      name: z.string().min(1),
      version: z.string().min(1),
      license: z.string().optional(),
      scope: z.enum(['required', 'optional']).optional(),
    })
  ),
});

const SBOMSearchSchema = z.object({
  componentName: z.string().min(1),
  version: z.string().optional(),
});

const ProvenanceAttestSchema = z.object({
  artifactDigest: z.string().min(1),
  artifactName: z.string().min(1),
  buildInfo: z.object({
    repository: z.string().min(1),
    commitHash: z.string().min(1),
    branch: z.string().min(1),
    pipelineId: z.string().min(1),
    pipelineUrl: z.string().min(1),
    builder: z.object({
      id: z.string().min(1),
      version: z.string().min(1),
    }),
    buildStarted: z.string().min(1),
    buildFinished: z.string().min(1),
    dependencies: z.array(
      z.object({
        name: z.string(),
        version: z.string(),
        digest: z.string().optional(),
      })
    ),
    environment: z.object({
      os: z.string(),
      arch: z.string(),
      nodeVersion: z.string(),
    }),
    reproducible: z.boolean(),
    tags: z.array(z.string()).optional(),
  }),
});

const SignArtifactSchema = z.object({
  artifactDigest: z.string().min(1),
  keyId: z.string().min(1),
  metadata: z.record(z.string()).optional(),
});

const VerifySignatureSchema = z.object({
  artifactDigest: z.string().min(1),
  signature: z.string().min(1),
  keyId: z.string().min(1),
});

const AdmissionEvaluateSchema = z.object({
  artifactDigest: z.string().min(1),
  imageRef: z.string().min(1),
  namespace: z.string().min(1),
  environment: z.string().min(1),
  requestor: z.string().min(1),
  pipelineId: z.string().min(1),
  buildId: z.string().optional(),
  approvalToken: z.string().optional(),
  metadata: z.record(z.string()).optional(),
});

const RuntimeValidateSchema = z.object({
  name: z.string().min(1),
  image: z.string().min(1),
  environment: z.string().optional(),
  securityContext: z
    .object({
      runAsNonRoot: z.boolean().optional(),
      runAsUser: z.number().optional(),
      runAsGroup: z.number().optional(),
      readOnlyRootFilesystem: z.boolean().optional(),
      allowPrivilegeEscalation: z.boolean().optional(),
      privileged: z.boolean().optional(),
      capabilities: z
        .object({
          add: z.array(z.string()).optional(),
          drop: z.array(z.string()).optional(),
        })
        .optional(),
      seccompProfile: z
        .object({
          type: z.enum(['RuntimeDefault', 'Localhost', 'Unconfined']),
          localhostProfile: z.string().optional(),
        })
        .optional(),
    })
    .optional(),
  resources: z
    .object({
      limits: z
        .object({
          cpu: z.string().optional(),
          memory: z.string().optional(),
          'ephemeral-storage': z.string().optional(),
        })
        .optional(),
      requests: z
        .object({
          cpu: z.string().optional(),
          memory: z.string().optional(),
          'ephemeral-storage': z.string().optional(),
        })
        .optional(),
    })
    .optional(),
  hostNetwork: z.boolean().optional(),
  hostPID: z.boolean().optional(),
  hostIPC: z.boolean().optional(),
  networkPolicy: z
    .object({
      egressDefined: z.boolean(),
      ingressDefined: z.boolean(),
      defaultDeny: z.boolean().optional(),
    })
    .optional(),
  serviceAccountName: z.string().optional(),
  automountServiceAccountToken: z.boolean().optional(),
  ports: z
    .array(
      z.object({
        containerPort: z.number(),
        protocol: z.string(),
        hostPort: z.number().optional(),
      })
    )
    .optional(),
});

const VulnCheckSchema = z.object({
  components: z.array(
    z.object({
      name: z.string().min(1),
      version: z.string().min(1),
    })
  ),
});

const KeyRotateSchema = z.object({
  keyId: z.string().min(1),
  performedBy: z.string().min(1),
});

// ── Services Container ──

export interface RouteServices {
  sbomGenerator: SBOMGenerator;
  sbomStore: InMemorySBOMStore;
  provenanceAttestor: ProvenanceAttestor;
  provenanceStore: InMemoryProvenanceStore;
  artifactSigner: ArtifactSigner;
  keyRegistry: KeyRegistry;
  keystore?: SupplyChainKeystore;
  admissionGate: AdmissionGate;
  approvalPolicy: RequireApproval;
  hardeningValidator: HardeningValidator;
  vulnChecker: VulnerabilityChecker;
}

/**
 * Validation middleware factory using Zod schemas.
 */
function validate(schema: z.ZodSchema) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      res.status(400).json({
        error: 'Validation failed',
        details: result.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      });
      return;
    }
    req.body = result.data;
    next();
  };
}

/**
 * Create all API routes with the given service dependencies.
 */
export function createRoutes(services: RouteServices): Router {
  const router = Router();
  router.use('/v1', requireGatewayPrincipal());

  // ────────────────────────────────────────────
  // SBOM Endpoints
  // ────────────────────────────────────────────

  /**
   * POST /v1/sbom/generate
   * Generate an SBOM from uploaded component data.
   */
  router.post(
    '/v1/sbom/generate',
    validate(SBOMGenerateSchema),
    (req: Request, res: Response) => {
      try {
        const { projectName, projectVersion, projectId, buildId, components } = req.body;

        const sbom = services.sbomGenerator.generateFromComponents(
          projectName,
          projectVersion,
          components,
          projectId
        );

        const stored = services.sbomStore.store(
          buildId,
          projectId ?? projectName,
          sbom,
          'api'
        );

        logger.info('SBOM generated via API', {
          buildId,
          projectName,
          componentCount: components.length,
        });

        res.status(201).json({
          success: true,
          buildId,
          sbomId: stored.id,
          digest: stored.digest,
          componentCount: sbom.components.length,
          vulnerabilities: sbom.vulnerabilities?.length ?? 0,
        });
      } catch (err) {
        logger.error('SBOM generation failed', { error: (err as Error).message });
        res.status(500).json({ error: (err as Error).message });
      }
    }
  );

  /**
   * GET /v1/sbom/:buildId
   * Retrieve the SBOM for a build.
   */
  router.get('/v1/sbom/:buildId', (req: Request, res: Response) => {
    try {
      const stored = services.sbomStore.retrieve(req.params.buildId);
      if (!stored) {
        res.status(404).json({ error: `SBOM not found for build ${req.params.buildId}` });
        return;
      }
      res.json({
        success: true,
        buildId: stored.buildId,
        projectId: stored.projectId,
        storedAt: stored.storedAt,
        digest: stored.digest,
        sbom: stored.sbom,
      });
    } catch (err) {
      logger.error('SBOM retrieval failed', { error: (err as Error).message });
      res.status(500).json({ error: (err as Error).message });
    }
  });

  /**
   * POST /v1/sbom/search
   * Search SBOMs by component name and optional version.
   */
  router.post(
    '/v1/sbom/search',
    validate(SBOMSearchSchema),
    (req: Request, res: Response) => {
      try {
        const { componentName, version } = req.body;
        const results = services.sbomStore.search(componentName, version);
        res.json({ success: true, results, count: results.length });
      } catch (err) {
        logger.error('SBOM search failed', { error: (err as Error).message });
        res.status(500).json({ error: (err as Error).message });
      }
    }
  );

  // ────────────────────────────────────────────
  // Provenance Endpoints
  // ────────────────────────────────────────────

  /**
   * POST /v1/provenance/attest
   * Create a provenance attestation for an artifact.
   */
  router.post(
    '/v1/provenance/attest',
    validate(ProvenanceAttestSchema),
    (req: Request, res: Response) => {
      try {
        const { artifactDigest, artifactName, buildInfo } = req.body;

        const attestation = services.provenanceAttestor.createAttestation(
          artifactDigest,
          artifactName,
          buildInfo
        );

        services.provenanceStore.store(artifactDigest, attestation);

        logger.info('Provenance attestation created via API', {
          artifactDigest,
          attestationId: attestation.id,
        });

        res.status(201).json({
          success: true,
          attestationId: attestation.id,
          artifactDigest,
          slsaLevel: attestation.metadata.slsaLevel,
          attestedAt: attestation.attestedAt,
        });
      } catch (err) {
        logger.error('Provenance attestation failed', { error: (err as Error).message });
        res.status(500).json({ error: (err as Error).message });
      }
    }
  );

  /**
   * GET /v1/provenance/:artifactDigest
   * Retrieve provenance attestation for an artifact.
   */
  router.get('/v1/provenance/:artifactDigest', (req: Request, res: Response) => {
    try {
      const attestation = services.provenanceStore.retrieve(req.params.artifactDigest);
      if (!attestation) {
        res.status(404).json({
          error: `No provenance attestation found for artifact ${req.params.artifactDigest}`,
        });
        return;
      }
      res.json({ success: true, attestation });
    } catch (err) {
      logger.error('Provenance retrieval failed', { error: (err as Error).message });
      res.status(500).json({ error: (err as Error).message });
    }
  });

  // ────────────────────────────────────────────
  // Signing Endpoints
  // ────────────────────────────────────────────

  /**
   * POST /v1/sign
   * Sign an artifact digest.
   */
  router.post(
    '/v1/sign',
    requireAnyRole(SUPPLY_CHAIN_ADMIN_ROLES),
    requireStepUpLevel(2),
    validate(SignArtifactSchema),
    (req: Request, res: Response) => {
      try {
        const { artifactDigest, keyId, metadata } = req.body;

        // Verify key is valid for signing
        if (!services.keyRegistry.isValidForSigning(keyId)) {
          res.status(403).json({
            error: `Key ${keyId} is not valid for signing (may be rotated, revoked, or not found)`,
          });
          return;
        }

        const signature = services.artifactSigner.signArtifact(
          artifactDigest,
          keyId,
          metadata ?? {}
        );

        logger.info('Artifact signed via API', {
          artifactDigest,
          keyId,
        });

        res.status(201).json({
          success: true,
          signature,
        });
      } catch (err) {
        logger.error('Signing failed', { error: (err as Error).message });
        res.status(500).json({ error: (err as Error).message });
      }
    }
  );

  /**
   * POST /v1/verify
   * Verify an artifact signature.
   */
  router.post(
    '/v1/verify',
    validate(VerifySignatureSchema),
    (req: Request, res: Response) => {
      try {
        const { artifactDigest, signature, keyId } = req.body;

        // Check if key is valid for verification
        if (!services.keyRegistry.isValidForVerification(keyId)) {
          res.status(403).json({
            error: `Key ${keyId} is not valid for verification (revoked or not found)`,
          });
          return;
        }

        const valid = services.artifactSigner.verifySignatureByKeyId(
          artifactDigest,
          signature,
          keyId
        );

        res.json({
          success: true,
          valid,
          artifactDigest,
          keyId,
          verifiedAt: new Date().toISOString(),
        });
      } catch (err) {
        logger.error('Verification failed', { error: (err as Error).message });
        res.status(500).json({ error: (err as Error).message });
      }
    }
  );

  // ────────────────────────────────────────────
  // Admission Endpoints
  // ────────────────────────────────────────────

  /**
   * POST /v1/admission/evaluate
   * Evaluate a deployment request against all admission policies.
   */
  router.post(
    '/v1/admission/evaluate',
    requireAnyRole(SUPPLY_CHAIN_ADMIN_ROLES),
    requireStepUpLevel(2),
    validate(AdmissionEvaluateSchema),
    (req: Request, res: Response) => {
      try {
        const decision = services.admissionGate.evaluate(req.body);

        const statusCode = decision.verdict === 'ALLOW' ? 200 : 403;

        res.status(statusCode).json({
          success: true,
          decision: {
            id: decision.id,
            verdict: decision.verdict,
            passedPolicies: decision.passedPolicies,
            failedPolicies: decision.failedPolicies,
            policyResults: decision.policyResults,
            isBreakGlass: decision.isBreakGlass,
            breakGlassInfo: decision.breakGlassInfo,
            decidedAt: decision.decidedAt,
            evaluationDurationMs: decision.evaluationDurationMs,
          },
        });
      } catch (err) {
        logger.error('Admission evaluation failed', { error: (err as Error).message });
        res.status(500).json({ error: (err as Error).message });
      }
    }
  );

  // ────────────────────────────────────────────
  // Runtime Hardening Endpoints
  // ────────────────────────────────────────────

  /**
   * POST /v1/runtime/validate
   * Validate a container configuration against hardening requirements.
   */
  router.post(
    '/v1/runtime/validate',
    requireStepUpLevel(2),
    validate(RuntimeValidateSchema),
    (req: Request, res: Response) => {
      try {
        const result = services.hardeningValidator.validateContainerConfig(req.body);

        res.json({
          success: true,
          result,
        });
      } catch (err) {
        logger.error('Runtime validation failed', { error: (err as Error).message });
        res.status(500).json({ error: (err as Error).message });
      }
    }
  );

  // ────────────────────────────────────────────
  // Vulnerability Endpoints
  // ────────────────────────────────────────────

  /**
   * POST /v1/vuln/check
   * Check components for known vulnerabilities.
   */
  router.post(
    '/v1/vuln/check',
    requireStepUpLevel(2),
    validate(VulnCheckSchema),
    (req: Request, res: Response) => {
      try {
        const result = services.vulnChecker.checkSBOM(req.body);
        res.json({ success: true, result });
      } catch (err) {
        logger.error('Vulnerability check failed', { error: (err as Error).message });
        res.status(500).json({ error: (err as Error).message });
      }
    }
  );

  // ────────────────────────────────────────────
  // Key Management Endpoints (Admin)
  // ────────────────────────────────────────────

  /**
   * GET /v1/keys
   * List all active signing keys.
   */
  router.get('/v1/keys', requireAnyRole(SUPPLY_CHAIN_ADMIN_ROLES), (_req: Request, res: Response) => {
    try {
      const keys = services.keyRegistry.listActiveKeys();
      const stats = services.keyRegistry.getStats();

      res.json({
        success: true,
        keys: keys.map((k) => ({
          keyId: k.keyId,
          algorithm: k.algorithm,
          state: k.state,
          purpose: k.purpose,
          environment: k.environment,
          createdAt: k.createdAt,
          fingerprint: k.fingerprint,
          expiresAt: k.expiresAt,
        })),
        stats,
      });
    } catch (err) {
      logger.error('Key listing failed', { error: (err as Error).message });
      res.status(500).json({ error: (err as Error).message });
    }
  });

  /**
   * POST /v1/keys/rotate
   * Rotate a signing key.
   */
  router.post(
    '/v1/keys/rotate',
    requireAnyRole(SUPPLY_CHAIN_ADMIN_ROLES),
    requireStepUpLevel(2),
    validate(KeyRotateSchema),
    async (req: Request, res: Response) => {
      try {
        const { keyId, performedBy } = req.body;

        const rotationResult = services.keyRegistry.rotateKey(keyId, performedBy);

        // Generate a new key pair for the replacement
        const oldKey = services.keyRegistry.getKey(keyId);
        if (oldKey) {
          const newKeyPair = await services.artifactSigner.generateSigningKeyPair(
            'EC-P256-SHA256',
            oldKey.purpose as 'artifact-signing' | 'image-signing' | 'attestation-signing',
            oldKey.environment,
            // Keep the key ID consistent between registry + key material storage.
            rotationResult.newKeyId ?? undefined
          );

          // Register the new key
          const newKeyId = rotationResult.newKeyId ?? newKeyPair.keyId;
          const registered = services.keyRegistry.registerKey(
            newKeyId,
            newKeyPair.publicKeyPem,
            {
              algorithm: newKeyPair.metadata.algorithm,
              purpose: oldKey.purpose,
              environment: oldKey.environment,
              createdBy: performedBy,
            }
          );

          // Persist changes (best-effort) if an encrypted keystore is configured.
          if (services.keystore) {
            try {
              await services.keystore.updateRecord(oldKey);
            } catch (err) {
              logger.error('Failed to persist rotated key metadata to keystore', {
                keyId,
                error: (err as Error).message,
              });
            }

            try {
              await services.keystore.upsert(registered, newKeyPair.privateKeyPem);
            } catch (err) {
              logger.error('Failed to persist new signing key to keystore', {
                keyId: registered.keyId,
                error: (err as Error).message,
              });
            }
          }

          res.json({
            success: true,
            rotation: rotationResult,
            newKeyId: registered.keyId,
            newKeyFingerprint: registered.fingerprint,
          });
        } else {
          res.json({ success: true, rotation: rotationResult });
        }
      } catch (err) {
        logger.error('Key rotation failed', { error: (err as Error).message });
        res.status(500).json({ error: (err as Error).message });
      }
    }
  );

  return router;
}

export default createRoutes;
