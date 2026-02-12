/**
 * JWKS (JSON Web Key Set) Manager.
 *
 * Manages asymmetric key pairs used to sign and verify JWTs:
 *  - Generates RS256 or ES256 key pairs using the `jose` library.
 *  - Exposes the public keys at /.well-known/jwks.json.
 *  - Supports key rotation: the current signing key and the previous key
 *    are both published so relying parties can verify tokens signed with
 *    either key during the rotation window.
 *  - Each key is identified by a unique `kid` (key ID).
 */

import * as jose from 'jose';
import { v4 as uuidv4 } from 'uuid';
import type { Router, Request, Response } from 'express';
import fs from 'fs';
import crypto from 'crypto';
import { createLogger } from '../logger';

const logger = createLogger('jwks');

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ManagedKey {
  /** Unique key identifier (written into JWT header as `kid`). */
  kid: string;
  /** The full key pair (private key used for signing). */
  privateKey: jose.KeyLike;
  /** The public key (served via JWKS). */
  publicKey: jose.KeyLike;
  /** Algorithm this key is used with. */
  algorithm: 'RS256' | 'ES256';
  /** ISO-8601 timestamp when this key was generated. */
  createdAt: string;
  /** Whether this key is the current signing key. */
  active: boolean;
}

export interface JWKSPublicResponse {
  keys: jose.JWK[];
}

// ---------------------------------------------------------------------------
// JWKS Manager
// ---------------------------------------------------------------------------

export class JWKSManager {
  /** Ordered list: index 0 = current signing key, index 1 = previous key. */
  private keys: ManagedKey[] = [];
  private readonly algorithm: 'RS256' | 'ES256';
  private initialized = false;

  constructor(algorithm: 'RS256' | 'ES256' = 'ES256') {
    this.algorithm = algorithm;
  }

  // -----------------------------------------------------------------------
  // Initialization
  // -----------------------------------------------------------------------

  /**
   * Generate the initial signing key pair.  Must be called before any
   * signing or JWKS serving can take place.
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    // Prefer a stable, provisioned signing key when available (e.g. mounted at
    // /keys/token-signing.key). This prevents token outages across restarts.
    const loaded = await this.loadProvisionedKey();
    const key = loaded ?? await this.generateKey();
    this.keys = [key];
    this.initialized = true;

    logger.info('JWKS manager initialized', {
      kid: key.kid,
      algorithm: key.algorithm,
      source: loaded ? 'provisioned' : 'generated',
    });
  }

  // -----------------------------------------------------------------------
  // Key rotation
  // -----------------------------------------------------------------------

  /**
   * Rotate keys: generate a new signing key and demote the current one.
   * Only the two most recent keys are kept; older keys are discarded.
   */
  async rotateKeys(): Promise<ManagedKey> {
    this.ensureInitialized();

    const newKey = await this.generateKey();

    // Demote all existing keys.
    for (const k of this.keys) {
      k.active = false;
    }

    // Keep at most 2 keys (current + previous).
    this.keys = [newKey, ...this.keys].slice(0, 2);

    logger.info('JWKS key rotated', {
      newKid: newKey.kid,
      totalKeys: this.keys.length,
    });

    return newKey;
  }

  // -----------------------------------------------------------------------
  // Accessors
  // -----------------------------------------------------------------------

  /** Return the current active signing key. */
  getSigningKey(): ManagedKey {
    this.ensureInitialized();
    const active = this.keys.find((k) => k.active);
    if (!active) {
      throw new Error('No active signing key available');
    }
    return active;
  }

  /** Return all published keys (for JWKS endpoint). */
  getAllKeys(): readonly ManagedKey[] {
    this.ensureInitialized();
    return this.keys;
  }

  /** Find a key by its kid (used during token verification). */
  getKeyByKid(kid: string): ManagedKey | undefined {
    return this.keys.find((k) => k.kid === kid);
  }

  // -----------------------------------------------------------------------
  // JWKS JSON representation
  // -----------------------------------------------------------------------

  /**
   * Build the JWKS JSON response containing all published public keys.
   */
  async toJWKS(): Promise<JWKSPublicResponse> {
    this.ensureInitialized();

    const jwks: jose.JWK[] = [];

    for (const managed of this.keys) {
      const jwk = await jose.exportJWK(managed.publicKey);
      jwk.kid = managed.kid;
      jwk.alg = managed.algorithm;
      jwk.use = 'sig';
      jwk.key_ops = ['verify'];
      jwks.push(jwk);
    }

    return { keys: jwks };
  }

  // -----------------------------------------------------------------------
  // Express route handler
  // -----------------------------------------------------------------------

  /**
   * Mount the /.well-known/jwks.json endpoint on the given router.
   */
  mountRoute(router: Router): void {
    router.get('/.well-known/jwks.json', async (_req: Request, res: Response) => {
      try {
        const jwks = await this.toJWKS();
        res.setHeader('Cache-Control', 'public, max-age=900, stale-while-revalidate=60');
        res.setHeader('Content-Type', 'application/json');
        res.json(jwks);
      } catch (err) {
        logger.error('Failed to serve JWKS', { error: (err as Error).message });
        res.status(500).json({ error: 'Internal server error' });
      }
    });
  }

  // -----------------------------------------------------------------------
  // Internal helpers
  // -----------------------------------------------------------------------

  private async generateKey(): Promise<ManagedKey> {
    const kid = uuidv4();
    const alg = this.algorithm;

    let keyPair: jose.GenerateKeyPairResult;

    if (alg === 'RS256') {
      keyPair = await jose.generateKeyPair('RS256', {
        modulusLength: 2048,
        extractable: true,
      });
    } else {
      // ES256 uses P-256 curve
      keyPair = await jose.generateKeyPair('ES256', {
        extractable: true,
      });
    }

    return {
      kid,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      algorithm: alg,
      createdAt: new Date().toISOString(),
      active: true,
    };
  }

  private async loadProvisionedKey(): Promise<ManagedKey | null> {
    const keyPath = process.env['TOKEN_SIGNING_KEY_PATH'] ?? '/keys/token-signing.key';
    const pubPath = process.env['TOKEN_SIGNING_PUB_PATH'] ?? '/keys/token-signing.pub';
    const kidOverride = (process.env['TOKEN_SIGNING_KID'] ?? '').trim();

    if (!fs.existsSync(keyPath) || !fs.existsSync(pubPath)) return null;

    try {
      const privatePem = fs.readFileSync(keyPath, 'utf8');
      const publicPem = fs.readFileSync(pubPath, 'utf8');

      const alg = this.algorithm;

      // `jose` supports PKCS8 private keys. If a different PEM format is
      // provisioned, this will fail and we will fall back to generated keys.
      const privateKey = await jose.importPKCS8(privatePem, alg);
      const publicKey = await jose.importSPKI(publicPem, alg);

      // Deterministic kid derived from the public key material (stable across restarts).
      const derivedKid = crypto
        .createHash('sha256')
        .update(publicPem, 'utf8')
        .digest('base64url')
        .slice(0, 32);

      return {
        kid: kidOverride || derivedKid,
        privateKey,
        publicKey,
        algorithm: alg,
        createdAt: new Date().toISOString(),
        active: true,
      };
    } catch (err) {
      logger.warn('Failed to load provisioned token signing key; falling back to generated key', {
        algorithm: this.algorithm,
        keyPath,
        pubPath,
        error: err instanceof Error ? err.message : String(err),
      });
      return null;
    }
  }

  private ensureInitialized(): void {
    if (!this.initialized || this.keys.length === 0) {
      throw new Error(
        'JWKSManager has not been initialized. Call initialize() first.',
      );
    }
  }
}
