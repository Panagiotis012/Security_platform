/**
 * Key Registry
 *
 * Manages the lifecycle of signing keys: registration, rotation, revocation.
 * Every key operation is audited. Keys transition through states:
 * ACTIVE → ROTATED (still valid for verification) → REVOKED (invalid).
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
  defaultMeta: { service: 'key-registry' },
  transports: [new winston.transports.Console()],
});

// ── Types ──

export type KeyState = 'ACTIVE' | 'ROTATED' | 'REVOKED';

export interface RegisteredKey {
  keyId: string;
  publicKeyPem: string;
  algorithm: string;
  state: KeyState;
  purpose: string;
  environment: string;
  createdAt: string;
  createdBy: string;
  rotatedAt?: string;
  rotatedTo?: string;
  revokedAt?: string;
  revokedBy?: string;
  revokedReason?: string;
  expiresAt?: string;
  fingerprint: string;
  metadata: Record<string, string>;
}

export interface KeyAuditEntry {
  id: string;
  timestamp: string;
  action: 'REGISTER' | 'ROTATE' | 'REVOKE' | 'ACCESS' | 'VERIFY';
  keyId: string;
  performedBy: string;
  details: Record<string, string>;
  sourceIp?: string;
}

export interface RotationResult {
  oldKeyId: string;
  oldKeyState: KeyState;
  newKeyId: string | null;
  message: string;
}

export class KeyRegistry {
  private readonly keys: Map<string, RegisteredKey> = new Map();
  private readonly auditLog: KeyAuditEntry[] = [];

  /**
   * Import a key record without generating new timestamps or audit entries.
   * Intended for restoring state from persistent storage at startup.
   */
  importKey(record: RegisteredKey): void {
    this.keys.set(record.keyId, { ...record });
  }

  /**
   * Register a new signing key in the registry.
   */
  registerKey(
    keyId: string,
    publicKeyPem: string,
    options: {
      algorithm?: string;
      purpose?: string;
      environment?: string;
      createdBy?: string;
      expiresAt?: string;
      metadata?: Record<string, string>;
    } = {}
  ): RegisteredKey {
    if (this.keys.has(keyId)) {
      throw new Error(`Key ${keyId} is already registered`);
    }

    const {
      algorithm = 'EC-P256-SHA256',
      purpose = 'artifact-signing',
      environment = 'dev',
      createdBy = 'system',
      expiresAt,
      metadata = {},
    } = options;

    // Compute key fingerprint (SHA-256 of DER-encoded public key)
    const publicKey = crypto.createPublicKey(publicKeyPem);
    const derBuffer = publicKey.export({ type: 'spki', format: 'der' });
    const fingerprint = crypto
      .createHash('sha256')
      .update(derBuffer)
      .digest('hex');

    const registeredKey: RegisteredKey = {
      keyId,
      publicKeyPem,
      algorithm,
      state: 'ACTIVE',
      purpose,
      environment,
      createdAt: new Date().toISOString(),
      createdBy,
      expiresAt,
      fingerprint,
      metadata,
    };

    this.keys.set(keyId, registeredKey);

    this.addAuditEntry({
      action: 'REGISTER',
      keyId,
      performedBy: createdBy,
      details: {
        algorithm,
        purpose,
        environment,
        fingerprint,
      },
    });

    logger.info('Key registered', {
      keyId,
      algorithm,
      purpose,
      environment,
      fingerprint,
    });

    return registeredKey;
  }

  /**
   * Retrieve a key and its metadata.
   */
  getKey(keyId: string, accessedBy: string = 'system'): RegisteredKey | null {
    const key = this.keys.get(keyId);
    if (!key) {
      return null;
    }

    this.addAuditEntry({
      action: 'ACCESS',
      keyId,
      performedBy: accessedBy,
      details: { state: key.state },
    });

    return { ...key };
  }

  /**
   * Rotate a key: mark the old key as ROTATED (still valid for verification
   * of previously signed artifacts) and return information for creating a new key.
   */
  rotateKey(
    oldKeyId: string,
    performedBy: string = 'system'
  ): RotationResult {
    const oldKey = this.keys.get(oldKeyId);
    if (!oldKey) {
      throw new Error(`Key ${oldKeyId} not found`);
    }

    if (oldKey.state === 'REVOKED') {
      throw new Error(`Cannot rotate revoked key ${oldKeyId}`);
    }

    if (oldKey.state === 'ROTATED') {
      throw new Error(`Key ${oldKeyId} has already been rotated`);
    }

    // Mark old key as ROTATED
    const newKeyId = `sign-${oldKey.environment}-${uuidv4().slice(0, 12)}`;

    oldKey.state = 'ROTATED';
    oldKey.rotatedAt = new Date().toISOString();
    oldKey.rotatedTo = newKeyId;

    this.addAuditEntry({
      action: 'ROTATE',
      keyId: oldKeyId,
      performedBy,
      details: {
        previousState: 'ACTIVE',
        newState: 'ROTATED',
        replacedBy: newKeyId,
      },
    });

    logger.info('Key rotated', {
      oldKeyId,
      newKeyId,
      performedBy,
    });

    return {
      oldKeyId,
      oldKeyState: 'ROTATED',
      newKeyId,
      message: `Key ${oldKeyId} marked as ROTATED. Register the new key with ID ${newKeyId}.`,
    };
  }

  /**
   * List all active (non-revoked) keys.
   * Includes ROTATED keys since they are still valid for verification.
   */
  listActiveKeys(): RegisteredKey[] {
    const activeKeys: RegisteredKey[] = [];
    for (const key of this.keys.values()) {
      if (key.state !== 'REVOKED') {
        activeKeys.push({ ...key });
      }
    }
    return activeKeys.sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
  }

  /**
   * List all keys, including revoked ones.
   */
  listAllKeys(): RegisteredKey[] {
    return Array.from(this.keys.values()).map((k) => ({ ...k }));
  }

  /**
   * List keys filtered by environment.
   */
  listKeysByEnvironment(environment: string): RegisteredKey[] {
    return Array.from(this.keys.values())
      .filter((k) => k.environment === environment && k.state !== 'REVOKED')
      .map((k) => ({ ...k }));
  }

  /**
   * Revoke a key with a mandatory reason.
   * Revoked keys cannot be used for signing or verification.
   */
  revokeKey(
    keyId: string,
    reason: string,
    performedBy: string = 'system'
  ): RegisteredKey {
    const key = this.keys.get(keyId);
    if (!key) {
      throw new Error(`Key ${keyId} not found`);
    }

    if (key.state === 'REVOKED') {
      throw new Error(`Key ${keyId} is already revoked`);
    }

    if (!reason || reason.trim().length === 0) {
      throw new Error('Revocation reason is required');
    }

    const previousState = key.state;
    key.state = 'REVOKED';
    key.revokedAt = new Date().toISOString();
    key.revokedBy = performedBy;
    key.revokedReason = reason;

    this.addAuditEntry({
      action: 'REVOKE',
      keyId,
      performedBy,
      details: {
        previousState,
        newState: 'REVOKED',
        reason,
      },
    });

    logger.warn('Key revoked', {
      keyId,
      reason,
      performedBy,
      previousState,
    });

    return { ...key };
  }

  /**
   * Check if a key is valid for signing (must be ACTIVE).
   */
  isValidForSigning(keyId: string): boolean {
    const key = this.keys.get(keyId);
    if (!key) return false;
    if (key.state !== 'ACTIVE') return false;

    // Check expiration
    if (key.expiresAt && new Date(key.expiresAt) < new Date()) {
      return false;
    }

    return true;
  }

  /**
   * Check if a key is valid for verification (ACTIVE or ROTATED).
   */
  isValidForVerification(keyId: string): boolean {
    const key = this.keys.get(keyId);
    if (!key) return false;
    if (key.state === 'REVOKED') return false;

    // Even expired keys can verify old signatures if not revoked
    return true;
  }

  /**
   * Get the audit log for a specific key.
   */
  getKeyAuditLog(keyId: string): KeyAuditEntry[] {
    return this.auditLog.filter((entry) => entry.keyId === keyId);
  }

  /**
   * Get the full audit log.
   */
  getFullAuditLog(limit: number = 100): KeyAuditEntry[] {
    return this.auditLog.slice(-limit);
  }

  /**
   * Get count of keys by state.
   */
  getStats(): Record<KeyState, number> & { total: number } {
    let active = 0;
    let rotated = 0;
    let revoked = 0;

    for (const key of this.keys.values()) {
      switch (key.state) {
        case 'ACTIVE': active++; break;
        case 'ROTATED': rotated++; break;
        case 'REVOKED': revoked++; break;
      }
    }

    return {
      ACTIVE: active,
      ROTATED: rotated,
      REVOKED: revoked,
      total: this.keys.size,
    };
  }

  // ── Private ──

  private addAuditEntry(
    entry: Omit<KeyAuditEntry, 'id' | 'timestamp'>
  ): void {
    const auditEntry: KeyAuditEntry = {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      ...entry,
    };
    this.auditLog.push(auditEntry);
  }
}

export default KeyRegistry;
