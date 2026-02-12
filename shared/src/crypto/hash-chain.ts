/**
 * Tamper-evident hash chain for audit logs.
 *
 * Each entry is cryptographically chained to its predecessor using SHA-256.
 * The chain is append-only; entries cannot be modified or removed once
 * appended without breaking the integrity chain.
 *
 * Verification traverses the full chain and recomputes every hash to detect
 * any tampering, insertion, deletion, or reordering.
 */

import { createHash } from 'crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HashChainEntry<T> {
  /** The original data stored in this entry. */
  data: T;
  /** SHA-256 hash of (previousHash + canonical(data)). */
  hash: string;
  /** Hash of the preceding entry (empty string for the genesis entry). */
  previousHash: string;
  /** Zero-based position in the chain. */
  index: number;
  /** Timestamp when the entry was appended. */
  timestamp: string;
}

export interface HashChainVerificationResult {
  /** Whether the entire chain is valid. */
  valid: boolean;
  /** Total number of entries verified. */
  entriesVerified: number;
  /** Index of the first broken link (undefined if chain is valid). */
  brokenAtIndex?: number;
  /** Description of the integrity failure. */
  error?: string;
}

// ---------------------------------------------------------------------------
// HashChain
// ---------------------------------------------------------------------------

export class HashChain<T = unknown> {
  private readonly entries: Array<HashChainEntry<T>> = [];

  /**
   * Create a new, empty hash chain.
   *
   * Optionally hydrate from a previously-persisted chain (e.g. loaded from
   * storage).  The caller should verify integrity after hydration.
   */
  constructor(existingEntries?: ReadonlyArray<HashChainEntry<T>>) {
    if (existingEntries && existingEntries.length > 0) {
      this.entries.push(...existingEntries.map((e) => ({ ...e })));
    }
  }

  // -----------------------------------------------------------------------
  // Public API
  // -----------------------------------------------------------------------

  /**
   * Append a new entry to the chain.
   *
   * @param data  The data to store. Must be JSON-serializable.
   * @returns     The new chain entry including its computed hash.
   */
  public append(data: T): HashChainEntry<T> {
    const index = this.entries.length;
    const previousHash =
      index > 0 ? this.entries[index - 1]!.hash : '';
    const timestamp = new Date().toISOString();
    const hash = HashChain.computeHash(previousHash, data);

    const entry: HashChainEntry<T> = {
      data,
      hash,
      previousHash,
      index,
      timestamp,
    };

    this.entries.push(entry);
    return { ...entry };
  }

  /**
   * Verify the integrity of the entire chain held in memory.
   */
  public verify(): HashChainVerificationResult {
    return HashChain.verifyChain(this.entries);
  }

  /**
   * Return a read-only copy of all entries.
   */
  public getEntries(): ReadonlyArray<HashChainEntry<T>> {
    return this.entries.map((e) => ({ ...e }));
  }

  /**
   * Return the entry at a specific index.
   */
  public getEntry(index: number): HashChainEntry<T> | undefined {
    const entry = this.entries[index];
    return entry ? { ...entry } : undefined;
  }

  /**
   * Get the latest entry (head of the chain).
   */
  public getHead(): HashChainEntry<T> | undefined {
    if (this.entries.length === 0) return undefined;
    const head = this.entries[this.entries.length - 1]!;
    return { ...head };
  }

  /**
   * Number of entries in the chain.
   */
  public get length(): number {
    return this.entries.length;
  }

  // -----------------------------------------------------------------------
  // Static helpers
  // -----------------------------------------------------------------------

  /**
   * Compute the SHA-256 hash for a chain entry.
   *
   * hash = SHA256( previousHash || canonicalize(data) )
   */
  public static computeHash<U>(previousHash: string, data: U): string {
    const canonical = HashChain.canonicalize(data);
    const input = `${previousHash}${canonical}`;
    return createHash('sha256').update(input, 'utf8').digest('hex');
  }

  /**
   * Verify the integrity of an externally-supplied chain.
   *
   * Checks:
   *  1. Indexes are sequential starting from 0.
   *  2. Each entry's `previousHash` matches the prior entry's `hash`.
   *  3. Each entry's `hash` is the correct SHA-256 of its inputs.
   */
  public static verifyChain<U>(
    chain: ReadonlyArray<HashChainEntry<U>>,
  ): HashChainVerificationResult {
    if (chain.length === 0) {
      return { valid: true, entriesVerified: 0 };
    }

    for (let i = 0; i < chain.length; i++) {
      const entry = chain[i]!;

      // Index must be sequential.
      if (entry.index !== i) {
        return {
          valid: false,
          entriesVerified: i,
          brokenAtIndex: i,
          error: `Expected index ${i} but found ${entry.index}.`,
        };
      }

      // The genesis entry must have an empty previousHash.
      if (i === 0 && entry.previousHash !== '') {
        return {
          valid: false,
          entriesVerified: 0,
          brokenAtIndex: 0,
          error: 'Genesis entry has a non-empty previousHash.',
        };
      }

      // Check previousHash links.
      if (i > 0) {
        const predecessor = chain[i - 1]!;
        if (entry.previousHash !== predecessor.hash) {
          return {
            valid: false,
            entriesVerified: i,
            brokenAtIndex: i,
            error: `Entry ${i} previousHash does not match entry ${i - 1} hash.`,
          };
        }
      }

      // Recompute and compare hash.
      const expectedHash = HashChain.computeHash(
        entry.previousHash,
        entry.data,
      );
      if (entry.hash !== expectedHash) {
        return {
          valid: false,
          entriesVerified: i,
          brokenAtIndex: i,
          error: `Entry ${i} hash mismatch: expected ${expectedHash}, found ${entry.hash}.`,
        };
      }
    }

    return { valid: true, entriesVerified: chain.length };
  }

  /**
   * Deterministic JSON serialization for hashing.
   *
   * Sorts object keys recursively to guarantee the same data always
   * produces the same canonical string regardless of insertion order.
   */
  public static canonicalize<U>(data: U): string {
    return JSON.stringify(data, (_key, value: unknown) => {
      if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
        // Sort keys deterministically.
        const sorted: Record<string, unknown> = {};
        for (const k of Object.keys(value as Record<string, unknown>).sort()) {
          sorted[k] = (value as Record<string, unknown>)[k];
        }
        return sorted;
      }
      return value;
    });
  }
}
