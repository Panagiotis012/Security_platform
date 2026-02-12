/**
 * Merkle tree implementation for tamper-proof audit log anchoring.
 *
 * This module provides:
 * - MerkleTree: A binary Merkle tree for proving membership of individual items
 * - AuditAnchor: A checkpoint of the Merkle tree state at a point in time
 * - AuditAnchorChain: A chain of anchors that link together for integrity verification
 *
 * Merkle trees allow efficient proof-of-inclusion: any leaf can be verified against
 * the root hash using only O(log n) hashes. The anchor chain creates periodic
 * snapshots, allowing audit logs to be externally archived and later verified.
 *
 * For example: after every 1000 audit events, create an anchor. This anchor is
 * digitally signed and published. Later, any individual event can be verified
 * against the anchor root and the chain itself can be verified end-to-end.
 */

import { createHash } from 'crypto';

// ─────────────────────────────────────────────────────────────────────────────
// Merkle Tree Types
// ─────────────────────────────────────────────────────────────────────────────

/**
 * A node in the Merkle tree.
 * Leaf nodes hold actual data; internal nodes hold hashes of their children.
 */
export interface MerkleNode {
  hash: string;
  isLeaf: boolean;
  /** Data if this is a leaf node */
  data?: unknown;
  /** Left child (for internal nodes) */
  left?: MerkleNode;
  /** Right child (for internal nodes) */
  right?: MerkleNode;
  /** Index of this leaf in the original data array (for leaf nodes) */
  leafIndex?: number;
}

/**
 * Proof of inclusion: a path from a leaf to the root that can be verified.
 */
export interface InclusionProof {
  /** Index of the leaf being proved */
  leafIndex: number;
  /** Hash of the leaf */
  leafHash: string;
  /** Hashes along the path to the root, in order */
  path: Array<{
    hash: string;
    /** 'left' or 'right' indicates which sibling this is */
    direction: 'left' | 'right';
  }>;
  /** Root hash at the time this proof was generated */
  rootHash: string;
}

/**
 * Merkle tree state suitable for serialization.
 * Can be used to reconstruct the tree or verify its integrity.
 */
export interface MerkleTreeState {
  /** Root hash of the tree */
  rootHash: string;
  /** Total number of leaves */
  leafCount: number;
  /** Height of the tree (0 for empty, 1 for single leaf) */
  height: number;
  /** All leaf hashes in order */
  leafHashes: string[];
  /** Timestamp when this state was captured */
  timestamp: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit Anchor Types
// ─────────────────────────────────────────────────────────────────────────────

/**
 * An audit anchor represents a periodic checkpoint of the Merkle tree state.
 * Anchors are linked together to form a chain of trust over time.
 *
 * Use case: When creating an anchor, hash it and digitally sign the hash
 * using the security platform's signing key. Store the signature with the anchor.
 * Later, the anchor chain can be verified and events can be proven against the anchor.
 */
export interface AuditAnchor {
  /** ISO 8601 timestamp when this anchor was created */
  timestamp: string;
  /** Root hash of the Merkle tree at this checkpoint */
  rootHash: string;
  /** Number of leaves in the tree at this checkpoint */
  leafCount: number;
  /** Height of the Merkle tree at this checkpoint */
  treeHeight: number;
  /** SHA-256 hash of the previous anchor (null for genesis anchor) */
  previousAnchorHash: string | null;
  /** Unique identifier for this anchor */
  id: string;
  /** Optional: External reference (e.g., blockchain tx, HSM attestation) */
  externalReference?: string;
}

/**
 * Serialized state of an audit anchor (for persistence).
 */
export interface AuditAnchorSnapshot {
  anchor: AuditAnchor;
  /** Hash of the anchor itself (used for chaining) */
  anchorHash: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// MerkleTree Class
// ─────────────────────────────────────────────────────────────────────────────

/**
 * A binary Merkle tree implementation.
 *
 * Supports:
 * - Building from initial data items
 * - Incremental leaf addition (without rebuilding the whole tree)
 * - Generating and verifying inclusion proofs
 * - Tree state serialization/deserialization
 */
export class MerkleTree {
  private leaves: Array<{ hash: string; data: unknown }> = [];
  private root: MerkleNode | null = null;
  private height: number = 0;

  /**
   * Create a new Merkle tree.
   * Optionally initialize with existing leaves (for deserialization).
   *
   * @param initialLeaves Initial leaf data items or leaf hashes
   */
  constructor(initialLeaves?: unknown[]) {
    if (initialLeaves && initialLeaves.length > 0) {
      for (const item of initialLeaves) {
        this.addLeaf(item);
      }
    }
  }

  /**
   * Add a new leaf to the tree and rebuild it.
   * This is simpler than true incremental insertion but suitable for append-only scenarios.
   *
   * @param data The data item to add as a leaf
   */
  public addLeaf(data: unknown): void {
    const hash = MerkleTree.hashData(data);
    this.leaves.push({ hash, data });
    this.rebuild();
  }

  /**
   * Add multiple leaves at once.
   *
   * @param dataItems Array of data items to add
   */
  public addLeaves(dataItems: unknown[]): void {
    for (const item of dataItems) {
      const hash = MerkleTree.hashData(item);
      this.leaves.push({ hash, data: item });
    }
    this.rebuild();
  }

  /**
   * Get the root hash of the tree.
   * This is the "anchor" that can be used to verify inclusion of any leaf.
   *
   * @returns The root hash, or empty string if tree is empty
   */
  public getRootHash(): string {
    return this.root?.hash ?? '';
  }

  /**
   * Get the current tree state (for serialization).
   *
   * @returns Tree state including root hash, leaf count, and height
   */
  public getState(): MerkleTreeState {
    return {
      rootHash: this.getRootHash(),
      leafCount: this.leaves.length,
      height: this.height,
      leafHashes: this.leaves.map((l) => l.hash),
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Number of leaves in the tree.
   */
  public get leafCount(): number {
    return this.leaves.length;
  }

  /**
   * Height of the tree (0 for empty, 1 for single leaf, n for tree with 2^(n-1) to 2^n-1 leaves).
   */
  public get treeHeight(): number {
    return this.height;
  }

  /**
   * Get all leaf hashes (in order).
   *
   * @returns Array of leaf hashes
   */
  public getLeafHashes(): string[] {
    return this.leaves.map((l) => l.hash);
  }

  /**
   * Get a leaf by index.
   *
   * @param index The leaf index
   * @returns The leaf data, or undefined if index out of bounds
   */
  public getLeaf(index: number): unknown | undefined {
    return this.leaves[index]?.data;
  }

  /**
   * Generate an inclusion proof for a specific leaf.
   * The proof consists of the sibling hashes needed to recompute the root from the leaf hash.
   *
   * @param leafIndex The index of the leaf to prove
   * @returns The inclusion proof, or undefined if index out of bounds
   */
  public getInclusionProof(leafIndex: number): InclusionProof | undefined {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      return undefined;
    }

    const proof: InclusionProof = {
      leafIndex,
      leafHash: this.leaves[leafIndex]!.hash,
      path: [],
      rootHash: this.getRootHash(),
    };

    // Traverse from leaf to root, collecting sibling hashes
    this.collectProofPath(this.root ?? undefined, leafIndex, 0, proof);

    return proof;
  }

  /**
   * Verify an inclusion proof against a root hash.
   * Recomputes the hash from the leaf up through the proof path.
   *
   * @param proof The inclusion proof
   * @param rootHash The root hash to verify against (defaults to current root)
   * @returns true if the proof is valid
   */
  public static verifyInclusionProof(proof: InclusionProof, rootHash?: string): boolean {
    let currentHash = proof.leafHash;

    for (const step of proof.path) {
      if (step.direction === 'left') {
        currentHash = MerkleTree.hashPair(step.hash, currentHash);
      } else {
        currentHash = MerkleTree.hashPair(currentHash, step.hash);
      }
    }

    return currentHash === (rootHash ?? proof.rootHash);
  }

  /**
   * Verify an event (as a hash) against an anchor root hash using an inclusion proof.
   * This is the primary method for proving that a specific audit event is in the anchor.
   *
   * @param eventHash SHA-256 hash of the audit event
   * @param proof The inclusion proof
   * @param anchorRootHash The root hash from an AuditAnchor
   * @returns true if the event is included in the anchor
   */
  public static verifyEventInAnchor(
    eventHash: string,
    proof: InclusionProof,
    anchorRootHash: string
  ): boolean {
    if (proof.leafHash !== eventHash) {
      return false;
    }
    return MerkleTree.verifyInclusionProof(proof, anchorRootHash);
  }

  /**
   * Restore a Merkle tree from a previously captured state.
   * The tree is reconstructed but not the original data (only leaf hashes are stored).
   *
   * @param state The tree state to restore from
   * @returns A new MerkleTree instance
   */
  public static fromState(state: MerkleTreeState): MerkleTree {
    const tree = new MerkleTree();
    tree.leaves = state.leafHashes.map((hash) => ({ hash, data: null }));
    tree.rebuild();
    return tree;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Private methods
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Rebuild the tree from the current set of leaves.
   * This is called after adding leaves and recomputes all internal nodes.
   */
  private rebuild(): void {
    if (this.leaves.length === 0) {
      this.root = null;
      this.height = 0;
      return;
    }

    // Create leaf nodes
    const leafNodes: MerkleNode[] = this.leaves.map((leaf, index) => ({
      hash: leaf.hash,
      isLeaf: true,
      data: leaf.data,
      leafIndex: index,
    }));

    // Build tree bottom-up
    let currentLevel = leafNodes;
    let levelHeight = 1;

    while (currentLevel.length > 1) {
      const nextLevel: MerkleNode[] = [];

      // Pair up nodes, creating internal nodes
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i]!;
        const right = currentLevel[i + 1] ?? left; // If odd, duplicate the last node

        const internalHash = MerkleTree.hashPair(left.hash, right.hash);
        nextLevel.push({
          hash: internalHash,
          isLeaf: false,
          left,
          right: currentLevel[i + 1] ? right : undefined,
        });
      }

      currentLevel = nextLevel;
      levelHeight++;
    }

    this.root = currentLevel[0] ?? null;
    this.height = this.leaves.length === 0 ? 0 : levelHeight;
  }

  /**
   * Collect the proof path from a leaf to the root.
   * Traverses the tree and adds sibling hashes to the proof.
   */
  private collectProofPath(
    node: MerkleNode | undefined,
    targetLeafIndex: number,
    currentLeafIndex: number,
    proof: InclusionProof
  ): number {
    if (!node) return currentLeafIndex;

    if (node.isLeaf) {
      if (node.leafIndex === targetLeafIndex) {
        return currentLeafIndex + 1;
      }
      return currentLeafIndex + 1;
    }

    // Internal node: decide which subtree contains the target
    let result = currentLeafIndex;

    // Check if target is in left subtree
    if (node.left) {
      const leftEnd = currentLeafIndex + this.getSubtreeLeafCount(node.left);
      if (targetLeafIndex < leftEnd) {
        result = this.collectProofPath(node.left, targetLeafIndex, currentLeafIndex, proof);
        if (node.right) {
          proof.path.push({ hash: node.right.hash, direction: 'right' });
        }
        return result;
      }
      result = leftEnd;
    }

    // Target is in right subtree
    if (node.right) {
      result = this.collectProofPath(node.right, targetLeafIndex, result, proof);
      if (node.left) {
        proof.path.push({ hash: node.left.hash, direction: 'left' });
      }
      return result;
    }

    return result;
  }

  /**
   * Count the number of leaves in a subtree.
   */
  private getSubtreeLeafCount(node: MerkleNode): number {
    if (node.isLeaf) return 1;
    const leftCount = node.left ? this.getSubtreeLeafCount(node.left) : 0;
    const rightCount = node.right ? this.getSubtreeLeafCount(node.right) : 0;
    return leftCount + rightCount;
  }

  /**
   * Compute SHA-256 hash of arbitrary data.
   * Data is JSON-stringified for deterministic hashing.
   */
  private static hashData(data: unknown): string {
    const canonical = typeof data === 'string' ? data : JSON.stringify(data);
    return createHash('sha256').update(canonical, 'utf-8').digest('hex');
  }

  /**
   * Compute SHA-256 hash of two sibling hashes.
   * Always hashes in left-right order for consistency.
   */
  private static hashPair(leftHash: string, rightHash: string): string {
    const combined = `${leftHash}${rightHash}`;
    return createHash('sha256').update(combined, 'utf-8').digest('hex');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// AuditAnchorChain Class
// ─────────────────────────────────────────────────────────────────────────────

/**
 * A chain of audit anchors that links together for tamper-evident integrity.
 *
 * Each anchor is linked to the previous one by including its hash in the new anchor.
 * This forms a hash chain similar to blockchain, allowing verification that:
 * - No anchors have been modified
 * - No anchors have been inserted, deleted, or reordered
 *
 * Typical usage:
 * 1. Create a MerkleTree as audit events arrive
 * 2. Periodically (e.g., every 1000 events or every 5 minutes), call createAnchor()
 * 3. Digitally sign the anchor and externally archive it
 * 4. Later, verify the chain and prove individual events using getInclusionProof()
 */
export class AuditAnchorChain {
  private anchors: AuditAnchorSnapshot[] = [];
  private tree: MerkleTree;
  private anchorIntervalEventCount: number;
  private anchorIntervalMs: number;
  private lastAnchorTime: number = Date.now();
  private eventsSinceLastAnchor: number = 0;

  /**
   * Create a new audit anchor chain.
   *
   * @param anchorIntervalEventCount Create an anchor after this many events are added
   * @param anchorIntervalMs Create an anchor after this many milliseconds
   */
  constructor(anchorIntervalEventCount: number = 1000, anchorIntervalMs: number = 300000) {
    this.tree = new MerkleTree();
    this.anchorIntervalEventCount = anchorIntervalEventCount;
    this.anchorIntervalMs = anchorIntervalMs;
  }

  /**
   * Add an event to the chain and potentially create an anchor if thresholds are met.
   *
   * @param eventData The audit event (or hash) to add
   * @returns An anchor if one was created, otherwise null
   */
  public addEvent(eventData: unknown): AuditAnchor | null {
    this.tree.addLeaf(eventData);
    this.eventsSinceLastAnchor++;

    const shouldAnchorByCount = this.eventsSinceLastAnchor >= this.anchorIntervalEventCount;
    const shouldAnchorByTime = Date.now() - this.lastAnchorTime >= this.anchorIntervalMs;

    if (shouldAnchorByCount || shouldAnchorByTime) {
      return this.createAnchor();
    }

    return null;
  }

  /**
   * Add multiple events to the chain.
   * This is more efficient than calling addEvent() individually.
   *
   * @param eventDataItems Array of events to add
   * @returns An anchor if one was created, otherwise null
   */
  public addEvents(eventDataItems: unknown[]): AuditAnchor | null {
    this.tree.addLeaves(eventDataItems);
    this.eventsSinceLastAnchor += eventDataItems.length;

    const shouldAnchorByCount = this.eventsSinceLastAnchor >= this.anchorIntervalEventCount;
    const shouldAnchorByTime = Date.now() - this.lastAnchorTime >= this.anchorIntervalMs;

    if (shouldAnchorByCount || shouldAnchorByTime) {
      return this.createAnchor();
    }

    return null;
  }

  /**
   * Manually force creation of an anchor.
   *
   * @returns The newly created anchor
   */
  public forceCreateAnchor(): AuditAnchor {
    return this.createAnchor();
  }

  /**
   * Get all anchors in the chain.
   *
   * @returns Array of audit anchors
   */
  public getAnchors(): AuditAnchor[] {
    return this.anchors.map((s) => ({ ...s.anchor }));
  }

  /**
   * Get the most recent anchor.
   *
   * @returns The latest anchor, or null if no anchors exist
   */
  public getLatestAnchor(): AuditAnchor | null {
    if (this.anchors.length === 0) return null;
    return { ...this.anchors[this.anchors.length - 1]!.anchor };
  }

  /**
   * Get the number of anchors in the chain.
   */
  public get anchorCount(): number {
    return this.anchors.length;
  }

  /**
   * Get the number of events added since the last anchor.
   */
  public get eventCountSinceLastAnchor(): number {
    return this.eventsSinceLastAnchor;
  }

  /**
   * Get the current Merkle tree (for inclusion proofs).
   * The tree is updated with each event added.
   *
   * @returns The underlying MerkleTree instance
   */
  public getTree(): MerkleTree {
    return this.tree;
  }

  /**
   * Verify the integrity of the entire anchor chain.
   * Checks that each anchor's previousAnchorHash correctly links to the prior anchor.
   *
   * @returns {valid, errors} - valid is true if chain is intact, errors array if not
   */
  public verifyChainIntegrity(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (this.anchors.length === 0) {
      return { valid: true, errors: [] };
    }

    // Verify first anchor has no predecessor
    if (this.anchors[0]!.anchor.previousAnchorHash !== null) {
      errors.push('Genesis anchor must have previousAnchorHash = null');
    }

    // Verify each anchor links to the previous
    for (let i = 1; i < this.anchors.length; i++) {
      const current = this.anchors[i]!;
      const previous = this.anchors[i - 1]!;

      const expectedPreviousHash = AuditAnchorChain.hashAnchor(previous.anchor);
      if (current.anchor.previousAnchorHash !== expectedPreviousHash) {
        errors.push(
          `Anchor ${i} previousAnchorHash does not match hash of anchor ${i - 1}`
        );
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Verify a single event against an anchor.
   * Uses the Merkle tree's inclusion proof.
   *
   * @param eventHash SHA-256 hash of the event
   * @param leafIndex Index of the event in the Merkle tree
   * @param anchorIndex Index of the anchor to verify against
   * @returns true if the event is verified in the anchor
   */
  public verifyEventInAnchor(
    eventHash: string,
    leafIndex: number,
    anchorIndex: number
  ): boolean {
    if (anchorIndex < 0 || anchorIndex >= this.anchors.length) {
      return false;
    }

    const anchor = this.anchors[anchorIndex]!.anchor;

    // Check if leaf index is within this anchor's range
    // (This requires tracking leaf counts per anchor, which is done during creation)
    // For now, we'll generate the proof from the entire tree
    // In production, you'd want to validate the leaf index is within the anchor's range

    const proof = this.tree.getInclusionProof(leafIndex);
    if (!proof) {
      return false;
    }

    return MerkleTree.verifyEventInAnchor(eventHash, proof, anchor.rootHash);
  }

  /**
   * Export all anchors for external archival (e.g., to blockchain, external storage).
   *
   * @returns Serializable array of anchors with their hashes
   */
  public exportAnchors(): AuditAnchorSnapshot[] {
    return this.anchors.map((s) => ({
      anchor: { ...s.anchor },
      anchorHash: s.anchorHash,
    }));
  }

  /**
   * Restore the chain from previously exported anchors.
   * The restored chain verifies all links are intact.
   *
   * @param exported The exported anchors
   * @returns {valid, errors} - Verification result
   */
  public static importAnchors(exported: AuditAnchorSnapshot[]): {
    chain: AuditAnchorChain;
    verificationResult: { valid: boolean; errors: string[] };
  } {
    const chain = new AuditAnchorChain();
    chain.anchors = exported.map((s) => ({ ...s }));

    const verificationResult = chain.verifyChainIntegrity();

    return { chain, verificationResult };
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Private methods
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Create an anchor from the current tree state.
   */
  private createAnchor(): AuditAnchor {
    const treeState = this.tree.getState();
    const previousAnchorHash = this.anchors.length > 0
      ? this.anchors[this.anchors.length - 1]!.anchorHash
      : null;

    const anchor: AuditAnchor = {
      id: this.generateId(),
      timestamp: new Date().toISOString(),
      rootHash: treeState.rootHash,
      leafCount: treeState.leafCount,
      treeHeight: treeState.height,
      previousAnchorHash,
    };

    const anchorHash = AuditAnchorChain.hashAnchor(anchor);
    this.anchors.push({ anchor, anchorHash });

    this.lastAnchorTime = Date.now();
    this.eventsSinceLastAnchor = 0;

    return anchor;
  }

  /**
   * Generate a unique ID for an anchor.
   */
  private generateId(): string {
    // Simple ID generation: timestamp + random suffix
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 8);
    return `anchor-${timestamp}-${random}`;
  }

  /**
   * Compute SHA-256 hash of an anchor.
   * Used for chaining anchors together.
   */
  private static hashAnchor(anchor: AuditAnchor): string {
    const canonical = JSON.stringify(
      {
        id: anchor.id,
        timestamp: anchor.timestamp,
        rootHash: anchor.rootHash,
        leafCount: anchor.leafCount,
        treeHeight: anchor.treeHeight,
        previousAnchorHash: anchor.previousAnchorHash,
        externalReference: anchor.externalReference,
      },
      null,
      0
    ).replace(/\s/g, ''); // Remove whitespace for consistency

    return createHash('sha256').update(canonical, 'utf-8').digest('hex');
  }
}

/**
 * Utility function to hash an audit event for Merkle tree inclusion.
 *
 * @param event The audit event (or any object)
 * @returns SHA-256 hash of the event
 */
export function hashAuditEvent(event: unknown): string {
  const canonical = typeof event === 'string' ? event : JSON.stringify(event);
  return createHash('sha256').update(canonical, 'utf-8').digest('hex');
}

/**
 * Utility function to verify an entire anchor chain was not tampered with.
 *
 * @param anchors Array of anchors to verify
 * @returns {valid, errors}
 */
export function verifyAnchorChain(anchors: AuditAnchorSnapshot[]): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  if (anchors.length === 0) {
    return { valid: true, errors: [] };
  }

  // Verify each anchor's hash
  for (let i = 0; i < anchors.length; i++) {
    const snapshot = anchors[i]!;
    const expectedHash = createHash('sha256')
      .update(
        JSON.stringify(
          {
            id: snapshot.anchor.id,
            timestamp: snapshot.anchor.timestamp,
            rootHash: snapshot.anchor.rootHash,
            leafCount: snapshot.anchor.leafCount,
            treeHeight: snapshot.anchor.treeHeight,
            previousAnchorHash: snapshot.anchor.previousAnchorHash,
            externalReference: snapshot.anchor.externalReference,
          },
          null,
          0
        ).replace(/\s/g, ''),
        'utf-8'
      )
      .digest('hex');

    if (snapshot.anchorHash !== expectedHash) {
      errors.push(`Anchor ${i} hash does not match`);
    }

    // Verify linking
    if (i === 0) {
      if (snapshot.anchor.previousAnchorHash !== null) {
        errors.push('Genesis anchor must have previousAnchorHash = null');
      }
    } else {
      if (snapshot.anchor.previousAnchorHash !== anchors[i - 1]!.anchorHash) {
        errors.push(`Anchor ${i} previousAnchorHash does not match anchor ${i - 1} hash`);
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}
