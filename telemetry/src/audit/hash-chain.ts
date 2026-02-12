// ─── Tamper-Evident Hash Chain ───
// Provides cryptographic proof that audit logs have not been modified, deleted, or reordered.
// Each entry is hashed with SHA-256(previousHash + serializedEntry), creating a verifiable chain.

import { createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  defaultMeta: { service: 'hash-chain' },
  transports: [new winston.transports.Console()],
});

export interface HashChainEntry<T = unknown> {
  index: number;
  entryId: string;
  timestamp: string;
  data: T;
  hash: string;
  previousHash: string;
}

export interface ChainVerificationResult {
  valid: boolean;
  checkedFrom: number;
  checkedTo: number;
  brokenAtIndex?: number;
  expectedHash?: string;
  actualHash?: string;
}

export class TamperEvidentLog<T = unknown> {
  private chain: HashChainEntry<T>[] = [];
  private readonly genesisHash = '0'.repeat(64); // SHA-256 length zero hash

  /**
   * Compute SHA-256 of previousHash concatenated with the canonical JSON serialization of the entry data.
   */
  private computeHash(previousHash: string, data: T, index: number, timestamp: string, entryId: string): string {
    const payload = JSON.stringify({
      index,
      entryId,
      timestamp,
      data,
      previousHash,
    });
    return createHash('sha256').update(payload).digest('hex');
  }

  /**
   * Append a new entry to the chain. Returns the full chain entry with its hash.
   */
  append(data: T): HashChainEntry<T> {
    const index = this.chain.length;
    const previousHash = index === 0 ? this.genesisHash : this.chain[index - 1].hash;
    const entryId = uuidv4();
    const timestamp = new Date().toISOString();

    const hash = this.computeHash(previousHash, data, index, timestamp, entryId);

    const entry: HashChainEntry<T> = {
      index,
      entryId,
      timestamp,
      data,
      hash,
      previousHash,
    };

    this.chain.push(entry);

    logger.debug('Chain entry appended', { index, hash: hash.slice(0, 16) + '...', previousHash: previousHash.slice(0, 16) + '...' });

    return entry;
  }

  /**
   * Verify the integrity of the chain between startIndex and endIndex (inclusive).
   * If any entry has been tampered with, the hashes will not match.
   */
  verify(startIndex: number = 0, endIndex?: number): ChainVerificationResult {
    const effectiveEnd = endIndex !== undefined ? Math.min(endIndex, this.chain.length - 1) : this.chain.length - 1;

    if (this.chain.length === 0) {
      return { valid: true, checkedFrom: 0, checkedTo: -1 };
    }

    if (startIndex < 0 || startIndex > effectiveEnd) {
      return { valid: true, checkedFrom: startIndex, checkedTo: effectiveEnd };
    }

    for (let i = startIndex; i <= effectiveEnd; i++) {
      const entry = this.chain[i];
      const expectedPrevHash = i === 0 ? this.genesisHash : this.chain[i - 1].hash;

      // Verify the previousHash pointer
      if (entry.previousHash !== expectedPrevHash) {
        logger.error('CRITICAL: Hash chain broken - previousHash mismatch', {
          index: i,
          expected: expectedPrevHash.slice(0, 16),
          actual: entry.previousHash.slice(0, 16),
        });

        this.raiseChainIntegrityAlert(i, expectedPrevHash, entry.previousHash);

        return {
          valid: false,
          checkedFrom: startIndex,
          checkedTo: effectiveEnd,
          brokenAtIndex: i,
          expectedHash: expectedPrevHash,
          actualHash: entry.previousHash,
        };
      }

      // Recompute and verify the entry's own hash
      const recomputedHash = this.computeHash(
        entry.previousHash,
        entry.data,
        entry.index,
        entry.timestamp,
        entry.entryId,
      );

      if (recomputedHash !== entry.hash) {
        logger.error('CRITICAL: Hash chain broken - entry hash mismatch (data tampered)', {
          index: i,
          expected: recomputedHash.slice(0, 16),
          actual: entry.hash.slice(0, 16),
        });

        this.raiseChainIntegrityAlert(i, recomputedHash, entry.hash);

        return {
          valid: false,
          checkedFrom: startIndex,
          checkedTo: effectiveEnd,
          brokenAtIndex: i,
          expectedHash: recomputedHash,
          actualHash: entry.hash,
        };
      }
    }

    logger.info('Hash chain verification passed', { from: startIndex, to: effectiveEnd });

    return {
      valid: true,
      checkedFrom: startIndex,
      checkedTo: effectiveEnd,
    };
  }

  /**
   * Get the head (latest entry) of the chain.
   */
  getHead(): HashChainEntry<T> | null {
    if (this.chain.length === 0) {
      return null;
    }
    return { ...this.chain[this.chain.length - 1] };
  }

  /**
   * Get the total number of entries in the chain.
   */
  getLength(): number {
    return this.chain.length;
  }

  /**
   * Get a specific entry by index (read-only copy).
   */
  getEntry(index: number): HashChainEntry<T> | null {
    if (index < 0 || index >= this.chain.length) {
      return null;
    }
    return { ...this.chain[index] };
  }

  /**
   * Get entries in a range (read-only copies).
   */
  getRange(startIndex: number, endIndex: number): HashChainEntry<T>[] {
    const start = Math.max(0, startIndex);
    const end = Math.min(endIndex, this.chain.length - 1);
    return this.chain.slice(start, end + 1).map((e) => ({ ...e }));
  }

  /**
   * Raise a critical security alert when the chain integrity is broken.
   * In production, this would integrate with the AlertManager to send immediate notifications.
   */
  private raiseChainIntegrityAlert(brokenIndex: number, expectedHash: string, actualHash: string): void {
    const alert = {
      severity: 'CRITICAL',
      type: 'HASH_CHAIN_INTEGRITY_VIOLATION',
      message: `Tamper-evident log integrity broken at index ${brokenIndex}`,
      details: {
        brokenIndex,
        expectedHash,
        actualHash,
        chainLength: this.chain.length,
        timestamp: new Date().toISOString(),
      },
    };

    // Log at emergency level - this is the most critical alert possible
    logger.error('SECURITY ALERT: HASH CHAIN INTEGRITY VIOLATION', alert);

    // Store the alert for the AlertManager to pick up
    // In production, this would also trigger an immediate webhook
    TamperEvidentLog.integrityAlerts.push(alert);
  }

  /** Static storage for integrity alerts that the AlertManager polls */
  static integrityAlerts: Array<{
    severity: string;
    type: string;
    message: string;
    details: Record<string, unknown>;
  }> = [];

  /**
   * Drain and return any pending integrity alerts.
   */
  static drainIntegrityAlerts(): Array<{
    severity: string;
    type: string;
    message: string;
    details: Record<string, unknown>;
  }> {
    const alerts = [...TamperEvidentLog.integrityAlerts];
    TamperEvidentLog.integrityAlerts = [];
    return alerts;
  }
}
