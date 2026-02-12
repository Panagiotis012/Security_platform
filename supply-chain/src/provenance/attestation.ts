/**
 * Provenance Attestation
 *
 * Creates SLSA-style provenance attestations that bind an artifact
 * to its build process. Attestations are signed with the platform
 * signing key and stored for later verification during admission.
 *
 * Format follows SLSA provenance specification for interoperability.
 */

import * as crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'provenance-attestor' },
  transports: [new winston.transports.Console()],
});

// ── Build Info Types ──

export interface BuilderInfo {
  id: string;
  version: string;
}

export interface BuildEnvironment {
  os: string;
  arch: string;
  nodeVersion: string;
  envVars?: Record<string, string>;
}

export interface BuildDependency {
  name: string;
  version: string;
  digest?: string;
}

export interface BuildInfo {
  repository: string;
  commitHash: string;
  branch: string;
  pipelineId: string;
  pipelineUrl: string;
  builder: BuilderInfo;
  buildStarted: string;
  buildFinished: string;
  dependencies: BuildDependency[];
  environment: BuildEnvironment;
  reproducible: boolean;
  tags?: string[];
}

// ── SLSA-style Attestation Types ──

export interface ResourceDescriptor {
  name: string;
  digest: Record<string, string>;
  uri?: string;
  mediaType?: string;
}

export interface ProvenancePredicate {
  buildDefinition: {
    buildType: string;
    externalParameters: {
      repository: string;
      ref: string;
      commitHash: string;
    };
    internalParameters: {
      pipelineId: string;
      pipelineUrl: string;
    };
    resolvedDependencies: ResourceDescriptor[];
  };
  runDetails: {
    builder: {
      id: string;
      version: Record<string, string>;
    };
    metadata: {
      invocationId: string;
      startedOn: string;
      finishedOn: string;
    };
    byproducts: ResourceDescriptor[];
  };
}

export interface InTotoStatement {
  _type: string;
  subject: ResourceDescriptor[];
  predicateType: string;
  predicate: ProvenancePredicate;
}

export interface SignedAttestation {
  id: string;
  statement: InTotoStatement;
  signatures: Array<{
    keyId: string;
    sig: string;
    algorithm: string;
  }>;
  attestedAt: string;
  buildInfo: BuildInfo;
  environment: BuildEnvironment;
  metadata: {
    reproducible: boolean;
    slsaLevel: number;
    tags: string[];
  };
}

// ── Signing Key Interface ──

export interface AttestationSigningKey {
  keyId: string;
  privateKey: crypto.KeyObject;
  algorithm: string;
}

export class ProvenanceAttestor {
  private signingKey: AttestationSigningKey | null = null;

  constructor(signingKey?: AttestationSigningKey) {
    if (signingKey) {
      this.signingKey = signingKey;
    }
  }

  /**
   * Initialize with a generated signing key pair for attestations.
   */
  async initializeSigningKey(): Promise<{ keyId: string; publicKey: string }> {
    return new Promise((resolve, reject) => {
      crypto.generateKeyPair(
        'ec',
        {
          namedCurve: 'P-256',
        },
        (err, publicKey, privateKey) => {
          if (err) {
            reject(new Error(`Failed to generate attestation signing key: ${err.message}`));
            return;
          }

          const keyId = `attestation-key-${uuidv4().slice(0, 8)}`;

          this.signingKey = {
            keyId,
            privateKey,
            algorithm: 'ECDSA-P256-SHA256',
          };

          const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;

          logger.info('Attestation signing key initialized', { keyId });
          resolve({ keyId, publicKey: publicKeyPem });
        }
      );
    });
  }

  /**
   * Set a signing key from external source (e.g., KMS).
   */
  setSigningKey(key: AttestationSigningKey): void {
    this.signingKey = key;
    logger.info('External signing key set', { keyId: key.keyId });
  }

  /**
   * Create a signed SLSA-style provenance attestation for an artifact.
   */
  createAttestation(
    artifactDigest: string,
    artifactName: string,
    buildInfo: BuildInfo
  ): SignedAttestation {
    if (!this.signingKey) {
      throw new Error('Signing key not initialized. Call initializeSigningKey() first.');
    }

    // Build the in-toto statement
    const statement: InTotoStatement = {
      _type: 'https://in-toto.io/Statement/v1',
      subject: [
        {
          name: artifactName,
          digest: {
            sha256: artifactDigest,
          },
        },
      ],
      predicateType: 'https://slsa.dev/provenance/v1',
      predicate: {
        buildDefinition: {
          buildType: `https://security-platform.internal/build-types/node-ci/v1`,
          externalParameters: {
            repository: buildInfo.repository,
            ref: `refs/heads/${buildInfo.branch}`,
            commitHash: buildInfo.commitHash,
          },
          internalParameters: {
            pipelineId: buildInfo.pipelineId,
            pipelineUrl: buildInfo.pipelineUrl,
          },
          resolvedDependencies: buildInfo.dependencies.map((dep) => ({
            name: dep.name,
            digest: dep.digest
              ? { sha256: dep.digest }
              : { sha256: crypto.createHash('sha256').update(`${dep.name}@${dep.version}`).digest('hex') },
          })),
        },
        runDetails: {
          builder: {
            id: buildInfo.builder.id,
            version: { builderVersion: buildInfo.builder.version },
          },
          metadata: {
            invocationId: uuidv4(),
            startedOn: buildInfo.buildStarted,
            finishedOn: buildInfo.buildFinished,
          },
          byproducts: [],
        },
      },
    };

    // Sign the statement
    const statementBytes = Buffer.from(JSON.stringify(statement), 'utf-8');
    const signature = crypto.sign('SHA256', statementBytes, this.signingKey.privateKey);

    const slsaLevel = this.computeSlsaLevel(buildInfo);

    const attestation: SignedAttestation = {
      id: uuidv4(),
      statement,
      signatures: [
        {
          keyId: this.signingKey.keyId,
          sig: signature.toString('base64'),
          algorithm: this.signingKey.algorithm,
        },
      ],
      attestedAt: new Date().toISOString(),
      buildInfo,
      environment: buildInfo.environment,
      metadata: {
        reproducible: buildInfo.reproducible,
        slsaLevel,
        tags: buildInfo.tags ?? [],
      },
    };

    logger.info('Provenance attestation created', {
      attestationId: attestation.id,
      artifactDigest,
      artifactName,
      repository: buildInfo.repository,
      commitHash: buildInfo.commitHash,
      pipelineId: buildInfo.pipelineId,
      slsaLevel,
    });

    return attestation;
  }

  /**
   * Verify the signature on an attestation.
   */
  verifyAttestationSignature(
    attestation: SignedAttestation,
    publicKey: crypto.KeyObject | string
  ): boolean {
    if (attestation.signatures.length === 0) {
      logger.warn('No signatures found on attestation', { attestationId: attestation.id });
      return false;
    }

    const statementBytes = Buffer.from(JSON.stringify(attestation.statement), 'utf-8');

    for (const sig of attestation.signatures) {
      try {
        const signatureBuffer = Buffer.from(sig.sig, 'base64');
        const keyObj = typeof publicKey === 'string'
          ? crypto.createPublicKey(publicKey)
          : publicKey;

        const isValid = crypto.verify('SHA256', statementBytes, keyObj, signatureBuffer);

        if (!isValid) {
          logger.warn('Attestation signature verification failed', {
            attestationId: attestation.id,
            keyId: sig.keyId,
          });
          return false;
        }
      } catch (err) {
        logger.error('Attestation signature verification error', {
          attestationId: attestation.id,
          keyId: sig.keyId,
          error: (err as Error).message,
        });
        return false;
      }
    }

    logger.info('Attestation signature verified', {
      attestationId: attestation.id,
      sigCount: attestation.signatures.length,
    });

    return true;
  }

  /**
   * Get the public key for the current signing key (for distribution/verification).
   */
  getPublicKey(): string | null {
    if (!this.signingKey) return null;

    // Derive public key from private key
    const publicKey = crypto.createPublicKey(this.signingKey.privateKey);
    return publicKey.export({ type: 'spki', format: 'pem' }) as string;
  }

  /**
   * Compute an estimated SLSA level based on build info properties.
   * This is a simplified heuristic; real SLSA levels require specific
   * builder and process requirements.
   */
  private computeSlsaLevel(buildInfo: BuildInfo): number {
    let level = 1; // Base: build process exists

    // Level 2: Version controlled + authenticated build service
    if (buildInfo.repository && buildInfo.commitHash && buildInfo.pipelineId) {
      level = 2;
    }

    // Level 3: Hardened build platform, non-falsifiable provenance
    if (
      level >= 2 &&
      buildInfo.builder.id &&
      buildInfo.builder.version &&
      buildInfo.pipelineUrl &&
      buildInfo.environment.os &&
      buildInfo.environment.arch
    ) {
      level = 3;
    }

    // Level 4: requires reproducibility among other guarantees
    if (level >= 3 && buildInfo.reproducible) {
      level = 4;
    }

    return level;
  }
}

export default ProvenanceAttestor;
