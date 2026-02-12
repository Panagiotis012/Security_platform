/**
 * Artifact Signer
 *
 * Provides cryptographic signing and verification of artifact digests.
 * Supports both RSA-4096 and EC P-256 key pairs. In production, private
 * keys would be stored in a KMS/HSM; this implementation uses an
 * interface abstraction to allow pluggable key backends.
 *
 * Separate signing keys are maintained per environment (dev/staging/prod).
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
  defaultMeta: { service: 'artifact-signer' },
  transports: [new winston.transports.Console()],
});

// ── Types ──

export type SigningAlgorithm = 'RSA-4096-SHA256' | 'EC-P256-SHA256';

export interface KeyMetadata {
  keyId: string;
  algorithm: SigningAlgorithm;
  created: string;
  purpose: 'artifact-signing' | 'image-signing' | 'attestation-signing';
  environment: string;
  rotatedFrom?: string;
  expiresAt?: string;
}

export interface KeyPairResult {
  keyId: string;
  publicKeyPem: string;
  privateKeyPem: string;
  metadata: KeyMetadata;
}

export interface ArtifactSignature {
  keyId: string;
  algorithm: string;
  signature: string;
  timestamp: string;
  artifactDigest: string;
  metadata: Record<string, string>;
}

export interface ImageSignature extends ArtifactSignature {
  imageRef: string;
  imageDigest: string;
  mediaType: string;
}

/**
 * Key provider interface. In production, implement with KMS/HSM backend.
 */
export interface KeyProvider {
  getPrivateKey(keyId: string): crypto.KeyObject | null;
  getPublicKey(keyId: string): crypto.KeyObject | null;
  storeKeyPair(
    keyId: string,
    privateKey: crypto.KeyObject,
    publicKey: crypto.KeyObject,
    metadata: KeyMetadata
  ): void;
}

/**
 * In-memory key provider for development and testing.
 * In production, replace with KMS-backed implementation.
 */
export class InMemoryKeyProvider implements KeyProvider {
  private readonly privateKeys: Map<string, crypto.KeyObject> = new Map();
  private readonly publicKeys: Map<string, crypto.KeyObject> = new Map();
  private readonly keyMetadata: Map<string, KeyMetadata> = new Map();

  getPrivateKey(keyId: string): crypto.KeyObject | null {
    return this.privateKeys.get(keyId) ?? null;
  }

  getPublicKey(keyId: string): crypto.KeyObject | null {
    return this.publicKeys.get(keyId) ?? null;
  }

  storeKeyPair(
    keyId: string,
    privateKey: crypto.KeyObject,
    publicKey: crypto.KeyObject,
    metadata: KeyMetadata
  ): void {
    this.privateKeys.set(keyId, privateKey);
    this.publicKeys.set(keyId, publicKey);
    this.keyMetadata.set(keyId, metadata);
  }

  getMetadata(keyId: string): KeyMetadata | null {
    return this.keyMetadata.get(keyId) ?? null;
  }
}

export class ArtifactSigner {
  private readonly keyProvider: KeyProvider;
  private readonly signatures: Map<string, ArtifactSignature[]> = new Map();

  constructor(keyProvider?: KeyProvider) {
    this.keyProvider = keyProvider ?? new InMemoryKeyProvider();
  }

  /**
   * Generate a new signing key pair.
   */
  async generateSigningKeyPair(
    algorithm: SigningAlgorithm = 'EC-P256-SHA256',
    purpose: KeyMetadata['purpose'] = 'artifact-signing',
    environment: string = 'dev',
    keyIdOverride?: string
  ): Promise<KeyPairResult> {
    return new Promise((resolve, reject) => {
      // Allow a caller to pre-allocate a key ID (e.g. registry-driven rotation)
      // so the key material and registry metadata remain consistent.
      const keyId = (keyIdOverride ?? `sign-${environment}-${uuidv4().slice(0, 12)}`).trim();
      if (!keyId) {
        reject(new Error('Key generation failed: keyId is empty'));
        return;
      }

      const keyGenCallback = (
        err: Error | null,
        publicKey: crypto.KeyObject,
        privateKey: crypto.KeyObject
      ) => {
        if (err) {
          reject(new Error(`Key generation failed: ${err.message}`));
          return;
        }

        const metadata: KeyMetadata = {
          keyId,
          algorithm,
          created: new Date().toISOString(),
          purpose,
          environment,
        };

        this.keyProvider.storeKeyPair(keyId, privateKey, publicKey, metadata);

        const publicKeyPem = publicKey.export({
          type: 'spki',
          format: 'pem',
        }) as string;
        const privateKeyPem = privateKey.export({
          type: 'pkcs8',
          format: 'pem',
        }) as string;

        logger.info('Signing key pair generated', {
          keyId,
          algorithm,
          purpose,
          environment,
        });

        resolve({ keyId, publicKeyPem, privateKeyPem, metadata });
      };

      if (algorithm === 'RSA-4096-SHA256') {
        crypto.generateKeyPair(
          'rsa',
          {
            modulusLength: 4096,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
          },
          (err, pubPem, privPem) => {
            if (err) {
              reject(err);
              return;
            }
            const publicKey = crypto.createPublicKey(pubPem);
            const privateKey = crypto.createPrivateKey(privPem);
            keyGenCallback(null, publicKey, privateKey);
          }
        );
      } else {
        // EC P-256
        crypto.generateKeyPair(
          'ec',
          {
            namedCurve: 'P-256',
          },
          (err, publicKey, privateKey) => {
            if (err) {
              keyGenCallback(err, undefined as never, undefined as never);
              return;
            }
            keyGenCallback(null, publicKey, privateKey);
          }
        );
      }
    });
  }

  /**
   * Sign an artifact digest with the specified key.
   */
  signArtifact(
    artifactDigest: string,
    keyId: string,
    metadata: Record<string, string> = {}
  ): ArtifactSignature {
    const privateKey = this.keyProvider.getPrivateKey(keyId);
    if (!privateKey) {
      throw new Error(`Signing key ${keyId} not found`);
    }

    const payload = Buffer.from(artifactDigest, 'utf-8');
    const signature = crypto.sign('SHA256', payload, privateKey);

    const artifactSignature: ArtifactSignature = {
      keyId,
      algorithm: this.getAlgorithmString(privateKey),
      signature: signature.toString('base64'),
      timestamp: new Date().toISOString(),
      artifactDigest,
      metadata,
    };

    // Store signature for audit trail
    if (!this.signatures.has(artifactDigest)) {
      this.signatures.set(artifactDigest, []);
    }
    this.signatures.get(artifactDigest)!.push(artifactSignature);

    logger.info('Artifact signed', {
      artifactDigest,
      keyId,
      algorithm: artifactSignature.algorithm,
    });

    return artifactSignature;
  }

  /**
   * Verify a signature over an artifact digest.
   */
  verifySignature(
    artifactDigest: string,
    signature: string,
    publicKey: crypto.KeyObject | string
  ): boolean {
    try {
      const payload = Buffer.from(artifactDigest, 'utf-8');
      const signatureBuffer = Buffer.from(signature, 'base64');

      const keyObj =
        typeof publicKey === 'string'
          ? crypto.createPublicKey(publicKey)
          : publicKey;

      const isValid = crypto.verify('SHA256', payload, keyObj, signatureBuffer);

      logger.info('Signature verification result', {
        artifactDigest,
        valid: isValid,
      });

      return isValid;
    } catch (err) {
      logger.error('Signature verification error', {
        artifactDigest,
        error: (err as Error).message,
      });
      return false;
    }
  }

  /**
   * Verify a signature using a keyId (looks up the public key from the key provider).
   */
  verifySignatureByKeyId(
    artifactDigest: string,
    signature: string,
    keyId: string
  ): boolean {
    const publicKey = this.keyProvider.getPublicKey(keyId);
    if (!publicKey) {
      logger.warn('Public key not found for verification', { keyId });
      return false;
    }
    return this.verifySignature(artifactDigest, signature, publicKey);
  }

  /**
   * Sign a container image digest with additional image metadata.
   */
  signImage(
    imageDigest: string,
    imageRef: string,
    keyId: string,
    metadata: Record<string, string> = {}
  ): ImageSignature {
    const privateKey = this.keyProvider.getPrivateKey(keyId);
    if (!privateKey) {
      throw new Error(`Signing key ${keyId} not found`);
    }

    // Sign the image digest combined with the image reference
    const payload = Buffer.from(`${imageDigest}:${imageRef}`, 'utf-8');
    const signature = crypto.sign('SHA256', payload, privateKey);

    const imageSignature: ImageSignature = {
      keyId,
      algorithm: this.getAlgorithmString(privateKey),
      signature: signature.toString('base64'),
      timestamp: new Date().toISOString(),
      artifactDigest: imageDigest,
      imageRef,
      imageDigest,
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      metadata,
    };

    // Store for audit
    if (!this.signatures.has(imageDigest)) {
      this.signatures.set(imageDigest, []);
    }
    this.signatures.get(imageDigest)!.push(imageSignature);

    logger.info('Container image signed', {
      imageDigest,
      imageRef,
      keyId,
    });

    return imageSignature;
  }

  /**
   * Verify a container image signature.
   */
  verifyImageSignature(
    imageDigest: string,
    imageRef: string,
    signature: string,
    publicKey: crypto.KeyObject | string
  ): boolean {
    try {
      const payload = Buffer.from(`${imageDigest}:${imageRef}`, 'utf-8');
      const signatureBuffer = Buffer.from(signature, 'base64');

      const keyObj =
        typeof publicKey === 'string'
          ? crypto.createPublicKey(publicKey)
          : publicKey;

      const isValid = crypto.verify('SHA256', payload, keyObj, signatureBuffer);

      logger.info('Image signature verification result', {
        imageDigest,
        imageRef,
        valid: isValid,
      });

      return isValid;
    } catch (err) {
      logger.error('Image signature verification error', {
        imageDigest,
        imageRef,
        error: (err as Error).message,
      });
      return false;
    }
  }

  /**
   * Get all signatures for an artifact.
   */
  getSignatures(artifactDigest: string): ArtifactSignature[] {
    return this.signatures.get(artifactDigest) ?? [];
  }

  /**
   * Get the public key PEM for a given key ID.
   */
  getPublicKeyPem(keyId: string): string | null {
    const publicKey = this.keyProvider.getPublicKey(keyId);
    if (!publicKey) return null;
    return publicKey.export({ type: 'spki', format: 'pem' }) as string;
  }

  /**
   * Get the key provider (for registry integration).
   */
  getKeyProvider(): KeyProvider {
    return this.keyProvider;
  }

  private getAlgorithmString(key: crypto.KeyObject): string {
    const keyDetail = key.asymmetricKeyType;
    if (keyDetail === 'rsa') return 'RSA-4096-SHA256';
    if (keyDetail === 'ec') return 'EC-P256-SHA256';
    return 'unknown';
  }
}

export default ArtifactSigner;
