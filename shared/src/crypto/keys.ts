/**
 * Key management utilities for the Zero Trust security platform.
 *
 * Uses the `jose` library for all JWK / JWS / JWE operations.
 * Designed as a pluggable abstraction: the in-process implementation stores
 * keys in memory, but the interface is compatible with external KMS / HSM
 * backends (AWS KMS, HashiCorp Vault, Azure Key Vault, etc.).
 *
 * Features:
 *  - Generate RSA and EC key pairs.
 *  - Sign and verify arbitrary payloads (JWS compact serialization).
 *  - Key rotation with metadata tracking.
 *  - Public key export (JWK format) for JWKS endpoints.
 */

import * as jose from 'jose';
import { v4 as uuidv4 } from 'uuid';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type KeyAlgorithm = 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512';

export interface KeyMetadata {
  /** Unique key identifier (kid). */
  kid: string;
  /** Algorithm this key is intended for. */
  algorithm: KeyAlgorithm;
  /** When the key was generated. */
  createdAt: string;
  /** When the key was rotated out (undefined if current). */
  rotatedAt?: string;
  /** Whether this key is the active signing key. */
  active: boolean;
  /** Usage: signing or encryption. */
  use: 'sig' | 'enc';
  /** Optional label / description. */
  label?: string;
}

export interface ManagedKeyPair {
  metadata: KeyMetadata;
  privateKey: jose.KeyLike;
  publicKey: jose.KeyLike;
  publicJwk: jose.JWK;
}

export interface SignResult {
  /** Compact JWS token. */
  jws: string;
  /** Key ID used for signing. */
  kid: string;
}

export interface VerifyResult {
  /** The decoded payload. */
  payload: Uint8Array;
  /** Protected header from the JWS. */
  protectedHeader: jose.JWSHeaderParameters;
}

// ---------------------------------------------------------------------------
// KeyManager
// ---------------------------------------------------------------------------

export class KeyManager {
  /** All managed key pairs, indexed by kid. */
  private readonly keys: Map<string, ManagedKeyPair> = new Map();

  /** Index of active signing key per algorithm. */
  private readonly activeKeys: Map<KeyAlgorithm, string> = new Map();

  // -----------------------------------------------------------------------
  // Key generation
  // -----------------------------------------------------------------------

  /**
   * Generate a new key pair for the given algorithm and register it.
   *
   * @param algorithm  JWS algorithm identifier.
   * @param options    Optional label and whether to set as active immediately.
   * @returns          The metadata (including kid) of the new key.
   */
  public async generateKeyPair(
    algorithm: KeyAlgorithm,
    options: { label?: string; setActive?: boolean } = {},
  ): Promise<KeyMetadata> {
    const kid = uuidv4();
    const setActive = options.setActive ?? true;

    const { publicKey, privateKey } = await this.generateRawKeyPair(algorithm);

    const publicJwk = await jose.exportJWK(publicKey);
    publicJwk.kid = kid;
    publicJwk.alg = algorithm;
    publicJwk.use = 'sig';

    const metadata: KeyMetadata = {
      kid,
      algorithm,
      createdAt: new Date().toISOString(),
      active: setActive,
      use: 'sig',
      label: options.label,
    };

    const managed: ManagedKeyPair = {
      metadata,
      privateKey,
      publicKey,
      publicJwk,
    };

    this.keys.set(kid, managed);

    if (setActive) {
      // Deactivate the previous active key for this algorithm.
      const previousKid = this.activeKeys.get(algorithm);
      if (previousKid) {
        const prev = this.keys.get(previousKid);
        if (prev) {
          prev.metadata.active = false;
        }
      }
      this.activeKeys.set(algorithm, kid);
    }

    return { ...metadata };
  }

  // -----------------------------------------------------------------------
  // Signing
  // -----------------------------------------------------------------------

  /**
   * Sign a payload using the active key for the given algorithm.
   *
   * @param payload    The data to sign (string or Uint8Array).
   * @param algorithm  Algorithm to use. Must have an active key.
   * @returns          Compact JWS + kid.
   */
  public async signPayload(
    payload: string | Uint8Array,
    algorithm: KeyAlgorithm,
  ): Promise<SignResult> {
    const kid = this.activeKeys.get(algorithm);
    if (!kid) {
      throw new Error(
        `No active signing key for algorithm ${algorithm}. Generate one first.`,
      );
    }
    return this.signWithKey(payload, kid);
  }

  /**
   * Sign a payload using a specific key (by kid).
   */
  public async signWithKey(
    payload: string | Uint8Array,
    kid: string,
  ): Promise<SignResult> {
    const managed = this.keys.get(kid);
    if (!managed) {
      throw new Error(`Key not found: ${kid}`);
    }

    const data =
      typeof payload === 'string'
        ? new TextEncoder().encode(payload)
        : payload;

    const jws = await new jose.CompactSign(data)
      .setProtectedHeader({
        alg: managed.metadata.algorithm,
        kid: managed.metadata.kid,
      })
      .sign(managed.privateKey);

    return { jws, kid: managed.metadata.kid };
  }

  // -----------------------------------------------------------------------
  // Verification
  // -----------------------------------------------------------------------

  /**
   * Verify a compact JWS.  The `kid` header is used to look up the
   * correct public key.
   *
   * @param jws  The compact JWS string.
   * @returns    The verified payload and protected header.
   * @throws     On invalid signature, unknown key, etc.
   */
  public async verifySignature(jws: string): Promise<VerifyResult> {
    // Decode the header to find the kid.
    const header = jose.decodeProtectedHeader(jws);
    const kid = header.kid;

    if (!kid) {
      throw new Error('JWS missing kid in protected header.');
    }

    const managed = this.keys.get(kid);
    if (!managed) {
      throw new Error(`Verification failed: unknown key ${kid}`);
    }

    const { payload, protectedHeader } = await jose.compactVerify(
      jws,
      managed.publicKey,
    );

    return { payload, protectedHeader };
  }

  // -----------------------------------------------------------------------
  // Key rotation
  // -----------------------------------------------------------------------

  /**
   * Rotate the active key for a given algorithm.  Generates a new key pair,
   * marks the old key as rotated (but retains it for verification of
   * previously-signed payloads).
   */
  public async rotateKey(
    algorithm: KeyAlgorithm,
    options: { label?: string } = {},
  ): Promise<{ newKid: string; oldKid: string | undefined }> {
    const oldKid = this.activeKeys.get(algorithm);

    if (oldKid) {
      const oldManaged = this.keys.get(oldKid);
      if (oldManaged) {
        oldManaged.metadata.active = false;
        oldManaged.metadata.rotatedAt = new Date().toISOString();
      }
    }

    const newMeta = await this.generateKeyPair(algorithm, {
      label: options.label,
      setActive: true,
    });

    return { newKid: newMeta.kid, oldKid };
  }

  // -----------------------------------------------------------------------
  // Public key access
  // -----------------------------------------------------------------------

  /**
   * Get the public JWK for a specific key.
   */
  public getPublicKey(kid: string): jose.JWK | undefined {
    return this.keys.get(kid)?.publicJwk;
  }

  /**
   * Get the active public key for an algorithm.
   */
  public getActivePublicKey(algorithm: KeyAlgorithm): jose.JWK | undefined {
    const kid = this.activeKeys.get(algorithm);
    if (!kid) return undefined;
    return this.keys.get(kid)?.publicJwk;
  }

  /**
   * Export all public keys as a JWKS (JSON Web Key Set).
   * Suitable for serving on a `/.well-known/jwks.json` endpoint.
   */
  public getJWKS(options: { activeOnly?: boolean } = {}): { keys: jose.JWK[] } {
    const jwks: jose.JWK[] = [];
    for (const managed of this.keys.values()) {
      if (options.activeOnly && !managed.metadata.active) continue;
      jwks.push({ ...managed.publicJwk });
    }
    return { keys: jwks };
  }

  // -----------------------------------------------------------------------
  // Metadata
  // -----------------------------------------------------------------------

  /**
   * Get metadata for a specific key.
   */
  public getKeyMetadata(kid: string): KeyMetadata | undefined {
    const managed = this.keys.get(kid);
    return managed ? { ...managed.metadata } : undefined;
  }

  /**
   * List metadata for all managed keys.
   */
  public listKeys(options: { activeOnly?: boolean } = {}): KeyMetadata[] {
    const result: KeyMetadata[] = [];
    for (const managed of this.keys.values()) {
      if (options.activeOnly && !managed.metadata.active) continue;
      result.push({ ...managed.metadata });
    }
    return result;
  }

  /**
   * Remove a key by kid.  Refuses to remove the active signing key
   * unless `force` is set.
   */
  public removeKey(kid: string, force: boolean = false): boolean {
    const managed = this.keys.get(kid);
    if (!managed) return false;

    if (managed.metadata.active && !force) {
      throw new Error(
        `Cannot remove active key ${kid}. Rotate first or use force=true.`,
      );
    }

    // Clean up active index if forcing.
    if (managed.metadata.active) {
      this.activeKeys.delete(managed.metadata.algorithm);
    }

    this.keys.delete(kid);
    return true;
  }

  // -----------------------------------------------------------------------
  // Internals
  // -----------------------------------------------------------------------

  private async generateRawKeyPair(
    algorithm: KeyAlgorithm,
  ): Promise<jose.GenerateKeyPairResult> {
    switch (algorithm) {
      case 'RS256':
      case 'RS384':
      case 'RS512':
        return jose.generateKeyPair(algorithm, {
          modulusLength: 2048,
          extractable: true,
        });
      case 'ES256':
        return jose.generateKeyPair(algorithm, {
          crv: 'P-256',
          extractable: true,
        });
      case 'ES384':
        return jose.generateKeyPair(algorithm, {
          crv: 'P-384',
          extractable: true,
        });
      case 'ES512':
        return jose.generateKeyPair(algorithm, {
          crv: 'P-521',
          extractable: true,
        });
      default: {
        const _exhaustive: never = algorithm;
        throw new Error(`Unsupported algorithm: ${String(_exhaustive)}`);
      }
    }
  }
}
