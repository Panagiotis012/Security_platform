/**
 * SBOM Store
 *
 * Immutable storage for Software Bills of Materials linked to builds.
 * Supports retrieval, search by component, diff between builds,
 * and listing by project.
 */

import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import winston from 'winston';
import type { CycloneDXBom, CycloneDXComponent } from './sbom-generator';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'sbom-store' },
  transports: [new winston.transports.Console()],
});

export interface StoredSBOM {
  id: string;
  buildId: string;
  projectId: string;
  sbom: CycloneDXBom;
  storedAt: string;
  storedBy: string;
  immutable: true;
  version: number;
  digest: string;
}

export interface SBOMSearchResult {
  buildId: string;
  projectId: string;
  componentName: string;
  componentVersion: string;
  componentPurl: string;
  storedAt: string;
}

export interface SBOMDiffResult {
  buildId1: string;
  buildId2: string;
  added: CycloneDXComponent[];
  removed: CycloneDXComponent[];
  changed: Array<{
    name: string;
    oldVersion: string;
    newVersion: string;
    purl: string;
  }>;
  unchanged: number;
  summary: string;
}

export interface SBOMStore {
  store(buildId: string, projectId: string, sbom: CycloneDXBom, storedBy?: string): StoredSBOM;
  retrieve(buildId: string): StoredSBOM | null;
  search(componentName: string, version?: string): SBOMSearchResult[];
  diff(buildId1: string, buildId2: string): SBOMDiffResult | null;
  listByProject(projectId: string): StoredSBOM[];
  exists(buildId: string): boolean;
  count(): number;
}

/**
 * Compute a digest of the SBOM for immutability verification.
 */
function computeSBOMDigest(sbom: CycloneDXBom): string {
  const canonical = JSON.stringify(sbom, Object.keys(sbom).sort());
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

export class InMemorySBOMStore implements SBOMStore {
  private readonly sboms: Map<string, StoredSBOM> = new Map();
  private readonly projectIndex: Map<string, Set<string>> = new Map();
  private readonly componentIndex: Map<string, Set<string>> = new Map();

  /**
   * Store an SBOM linked to a build. Once stored, it becomes immutable.
   */
  store(buildId: string, projectId: string, sbom: CycloneDXBom, storedBy: string = 'system'): StoredSBOM {
    if (this.sboms.has(buildId)) {
      throw new Error(`SBOM for build ${buildId} already exists and is immutable`);
    }

    const digest = computeSBOMDigest(sbom);
    const stored: StoredSBOM = {
      id: uuidv4(),
      buildId,
      projectId,
      sbom: Object.freeze(JSON.parse(JSON.stringify(sbom))) as CycloneDXBom,
      storedAt: new Date().toISOString(),
      storedBy,
      immutable: true,
      version: 1,
      digest,
    };

    this.sboms.set(buildId, stored);

    // Update project index
    if (!this.projectIndex.has(projectId)) {
      this.projectIndex.set(projectId, new Set());
    }
    this.projectIndex.get(projectId)!.add(buildId);

    // Update component index for search
    for (const component of sbom.components) {
      const key = component.name.toLowerCase();
      if (!this.componentIndex.has(key)) {
        this.componentIndex.set(key, new Set());
      }
      this.componentIndex.get(key)!.add(buildId);

      // Also index with version for exact matches
      const versionKey = `${key}@${component.version}`;
      if (!this.componentIndex.has(versionKey)) {
        this.componentIndex.set(versionKey, new Set());
      }
      this.componentIndex.get(versionKey)!.add(buildId);
    }

    logger.info('SBOM stored', {
      buildId,
      projectId,
      componentCount: sbom.components.length,
      digest,
      storedBy,
    });

    return stored;
  }

  /**
   * Retrieve the SBOM for a given build.
   */
  retrieve(buildId: string): StoredSBOM | null {
    const stored = this.sboms.get(buildId);
    if (!stored) {
      logger.warn('SBOM not found', { buildId });
      return null;
    }

    // Verify integrity
    const currentDigest = computeSBOMDigest(stored.sbom);
    if (currentDigest !== stored.digest) {
      logger.error('SBOM integrity violation detected!', {
        buildId,
        expectedDigest: stored.digest,
        actualDigest: currentDigest,
      });
      throw new Error(`Integrity violation: SBOM for build ${buildId} has been tampered with`);
    }

    return stored;
  }

  /**
   * Search for builds containing a specific dependency.
   * Optionally filter by version.
   */
  search(componentName: string, version?: string): SBOMSearchResult[] {
    const results: SBOMSearchResult[] = [];
    const searchKey = version
      ? `${componentName.toLowerCase()}@${version}`
      : componentName.toLowerCase();

    const buildIds = this.componentIndex.get(searchKey);
    if (!buildIds) {
      return results;
    }

    for (const buildId of buildIds) {
      const stored = this.sboms.get(buildId);
      if (!stored) continue;

      const matchingComponents = stored.sbom.components.filter((c) => {
        const nameMatch = c.name.toLowerCase() === componentName.toLowerCase();
        if (version) {
          return nameMatch && c.version === version;
        }
        return nameMatch;
      });

      for (const component of matchingComponents) {
        results.push({
          buildId,
          projectId: stored.projectId,
          componentName: component.name,
          componentVersion: component.version,
          componentPurl: component.purl,
          storedAt: stored.storedAt,
        });
      }
    }

    logger.info('SBOM search completed', {
      componentName,
      version,
      resultCount: results.length,
    });

    return results;
  }

  /**
   * Compare SBOMs between two builds, showing added, removed, and changed dependencies.
   */
  diff(buildId1: string, buildId2: string): SBOMDiffResult | null {
    const sbom1 = this.sboms.get(buildId1);
    const sbom2 = this.sboms.get(buildId2);

    if (!sbom1 || !sbom2) {
      logger.warn('Cannot diff: one or both SBOMs not found', { buildId1, buildId2 });
      return null;
    }

    const components1 = new Map<string, CycloneDXComponent>();
    const components2 = new Map<string, CycloneDXComponent>();

    for (const c of sbom1.sbom.components) {
      components1.set(c.name, c);
    }
    for (const c of sbom2.sbom.components) {
      components2.set(c.name, c);
    }

    const added: CycloneDXComponent[] = [];
    const removed: CycloneDXComponent[] = [];
    const changed: Array<{ name: string; oldVersion: string; newVersion: string; purl: string }> = [];
    let unchanged = 0;

    // Find added and changed
    for (const [name, comp2] of components2) {
      const comp1 = components1.get(name);
      if (!comp1) {
        added.push(comp2);
      } else if (comp1.version !== comp2.version) {
        changed.push({
          name,
          oldVersion: comp1.version,
          newVersion: comp2.version,
          purl: comp2.purl,
        });
      } else {
        unchanged++;
      }
    }

    // Find removed
    for (const [name, comp1] of components1) {
      if (!components2.has(name)) {
        removed.push(comp1);
      }
    }

    const parts: string[] = [];
    if (added.length > 0) parts.push(`${added.length} added`);
    if (removed.length > 0) parts.push(`${removed.length} removed`);
    if (changed.length > 0) parts.push(`${changed.length} changed`);
    parts.push(`${unchanged} unchanged`);

    const result: SBOMDiffResult = {
      buildId1,
      buildId2,
      added,
      removed,
      changed,
      unchanged,
      summary: parts.join(', '),
    };

    logger.info('SBOM diff completed', {
      buildId1,
      buildId2,
      added: added.length,
      removed: removed.length,
      changed: changed.length,
      unchanged,
    });

    return result;
  }

  /**
   * List all SBOMs for a given project, sorted by storage time (newest first).
   */
  listByProject(projectId: string): StoredSBOM[] {
    const buildIds = this.projectIndex.get(projectId);
    if (!buildIds) {
      return [];
    }

    const results: StoredSBOM[] = [];
    for (const buildId of buildIds) {
      const stored = this.sboms.get(buildId);
      if (stored) {
        results.push(stored);
      }
    }

    return results.sort((a, b) =>
      new Date(b.storedAt).getTime() - new Date(a.storedAt).getTime()
    );
  }

  /**
   * Check if an SBOM exists for a given build.
   */
  exists(buildId: string): boolean {
    return this.sboms.has(buildId);
  }

  /**
   * Get the total number of stored SBOMs.
   */
  count(): number {
    return this.sboms.size;
  }
}

export default InMemorySBOMStore;
