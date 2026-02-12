/**
 * Provenance Store
 *
 * Stores and retrieves provenance attestations linked to artifact digests.
 * Supports verification, lookup by pipeline, and lookup by repository.
 */

import * as crypto from 'crypto';
import winston from 'winston';
import type { SignedAttestation } from './attestation';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'provenance-store' },
  transports: [new winston.transports.Console()],
});

export interface ProvenanceStore {
  store(artifactDigest: string, attestation: SignedAttestation): void;
  retrieve(artifactDigest: string): SignedAttestation | null;
  verifyAttestation(artifactDigest: string, publicKey: crypto.KeyObject | string): boolean;
  listByPipeline(pipelineId: string): SignedAttestation[];
  listByRepository(repo: string): SignedAttestation[];
  exists(artifactDigest: string): boolean;
  count(): number;
}

export class InMemoryProvenanceStore implements ProvenanceStore {
  /** Primary index: artifactDigest → attestation */
  private readonly attestations: Map<string, SignedAttestation> = new Map();
  /** Secondary index: pipelineId → set of artifact digests */
  private readonly pipelineIndex: Map<string, Set<string>> = new Map();
  /** Secondary index: repository → set of artifact digests */
  private readonly repoIndex: Map<string, Set<string>> = new Map();

  /**
   * Store a provenance attestation linked to an artifact digest.
   * Once stored, the attestation is immutable.
   */
  store(artifactDigest: string, attestation: SignedAttestation): void {
    if (this.attestations.has(artifactDigest)) {
      throw new Error(
        `Attestation for artifact ${artifactDigest} already exists and is immutable`
      );
    }

    // Deep freeze to enforce immutability
    const frozen = Object.freeze(
      JSON.parse(JSON.stringify(attestation))
    ) as SignedAttestation;

    this.attestations.set(artifactDigest, frozen);

    // Update pipeline index
    const pipelineId = attestation.buildInfo.pipelineId;
    if (!this.pipelineIndex.has(pipelineId)) {
      this.pipelineIndex.set(pipelineId, new Set());
    }
    this.pipelineIndex.get(pipelineId)!.add(artifactDigest);

    // Update repository index
    const repo = attestation.buildInfo.repository;
    if (!this.repoIndex.has(repo)) {
      this.repoIndex.set(repo, new Set());
    }
    this.repoIndex.get(repo)!.add(artifactDigest);

    logger.info('Provenance attestation stored', {
      artifactDigest,
      attestationId: attestation.id,
      pipelineId,
      repository: repo,
      commitHash: attestation.buildInfo.commitHash,
    });
  }

  /**
   * Retrieve the provenance attestation for a given artifact digest.
   */
  retrieve(artifactDigest: string): SignedAttestation | null {
    const attestation = this.attestations.get(artifactDigest);
    if (!attestation) {
      logger.debug('Attestation not found', { artifactDigest });
      return null;
    }
    return attestation;
  }

  /**
   * Verify the provenance attestation for an artifact:
   * 1. The attestation exists
   * 2. The signature is cryptographically valid
   * 3. The attestation subject matches the artifact digest
   */
  verifyAttestation(
    artifactDigest: string,
    publicKey: crypto.KeyObject | string
  ): boolean {
    const attestation = this.attestations.get(artifactDigest);
    if (!attestation) {
      logger.warn('Verification failed: attestation not found', { artifactDigest });
      return false;
    }

    // Verify the subject matches the requested artifact
    const subjectMatch = attestation.statement.subject.some(
      (s) => s.digest.sha256 === artifactDigest
    );
    if (!subjectMatch) {
      logger.warn('Verification failed: subject digest mismatch', {
        artifactDigest,
        attestationId: attestation.id,
      });
      return false;
    }

    // Verify signature(s)
    if (attestation.signatures.length === 0) {
      logger.warn('Verification failed: no signatures on attestation', {
        artifactDigest,
        attestationId: attestation.id,
      });
      return false;
    }

    const statementBytes = Buffer.from(
      JSON.stringify(attestation.statement),
      'utf-8'
    );

    for (const sig of attestation.signatures) {
      try {
        const signatureBuffer = Buffer.from(sig.sig, 'base64');
        const keyObj =
          typeof publicKey === 'string'
            ? crypto.createPublicKey(publicKey)
            : publicKey;

        const isValid = crypto.verify(
          'SHA256',
          statementBytes,
          keyObj,
          signatureBuffer
        );

        if (!isValid) {
          logger.warn('Verification failed: invalid signature', {
            artifactDigest,
            attestationId: attestation.id,
            keyId: sig.keyId,
          });
          return false;
        }
      } catch (err) {
        logger.error('Verification error', {
          artifactDigest,
          attestationId: attestation.id,
          error: (err as Error).message,
        });
        return false;
      }
    }

    logger.info('Provenance attestation verified', {
      artifactDigest,
      attestationId: attestation.id,
    });

    return true;
  }

  /**
   * List all attestations from a specific CI/CD pipeline.
   */
  listByPipeline(pipelineId: string): SignedAttestation[] {
    const digests = this.pipelineIndex.get(pipelineId);
    if (!digests) {
      return [];
    }

    const results: SignedAttestation[] = [];
    for (const digest of digests) {
      const attestation = this.attestations.get(digest);
      if (attestation) {
        results.push(attestation);
      }
    }

    return results.sort(
      (a, b) =>
        new Date(b.attestedAt).getTime() - new Date(a.attestedAt).getTime()
    );
  }

  /**
   * List all attestations from a specific repository.
   */
  listByRepository(repo: string): SignedAttestation[] {
    const digests = this.repoIndex.get(repo);
    if (!digests) {
      return [];
    }

    const results: SignedAttestation[] = [];
    for (const digest of digests) {
      const attestation = this.attestations.get(digest);
      if (attestation) {
        results.push(attestation);
      }
    }

    return results.sort(
      (a, b) =>
        new Date(b.attestedAt).getTime() - new Date(a.attestedAt).getTime()
    );
  }

  /**
   * Check if an attestation exists for a given artifact digest.
   */
  exists(artifactDigest: string): boolean {
    return this.attestations.has(artifactDigest);
  }

  /**
   * Get the total number of stored attestations.
   */
  count(): number {
    return this.attestations.size;
  }
}

export default InMemoryProvenanceStore;
