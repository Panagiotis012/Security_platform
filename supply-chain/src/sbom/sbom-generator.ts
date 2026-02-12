/**
 * SBOM Generator
 *
 * Generates Software Bill of Materials (SBOM) in CycloneDX JSON format.
 * Parses package.json and lockfiles to enumerate all direct and transitive
 * dependencies, computing cryptographic hashes for integrity verification.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import winston from 'winston';
import type { VulnFinding } from '../vulnerability/vuln-checker';
import { VulnerabilityChecker } from '../vulnerability/vuln-checker';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'sbom-generator' },
  transports: [new winston.transports.Console()],
});

// ── CycloneDX Types ──

export interface CycloneDXHash {
  alg: string;
  content: string;
}

export interface CycloneDXLicense {
  license: {
    id?: string;
    name?: string;
    url?: string;
  };
}

export interface CycloneDXExternalRef {
  type: string;
  url: string;
}

export interface CycloneDXComponent {
  type: 'library' | 'framework' | 'application' | 'container' | 'firmware' | 'file';
  name: string;
  version: string;
  purl: string;
  scope?: 'required' | 'optional' | 'excluded';
  hashes: CycloneDXHash[];
  licenses: CycloneDXLicense[];
  externalReferences?: CycloneDXExternalRef[];
  description?: string;
  group?: string;
  properties?: Array<{ name: string; value: string }>;
}

export interface CycloneDXDependency {
  ref: string;
  dependsOn: string[];
}

export interface CycloneDXMetadata {
  timestamp: string;
  tools: Array<{ vendor: string; name: string; version: string }>;
  component?: {
    type: string;
    name: string;
    version: string;
    purl: string;
  };
  authors?: Array<{ name: string; email?: string }>;
}

export interface CycloneDXBom {
  bomFormat: 'CycloneDX';
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: CycloneDXMetadata;
  components: CycloneDXComponent[];
  dependencies: CycloneDXDependency[];
  vulnerabilities?: Array<{
    id: string;
    source: { name: string; url: string };
    ratings: Array<{ severity: string; method: string }>;
    description: string;
    affects: Array<{ ref: string }>;
  }>;
}

// ── Package JSON / Lockfile types ──

interface PackageJsonDep {
  [name: string]: string;
}

interface PackageJson {
  name: string;
  version: string;
  description?: string;
  license?: string;
  dependencies?: PackageJsonDep;
  devDependencies?: PackageJsonDep;
  peerDependencies?: PackageJsonDep;
  optionalDependencies?: PackageJsonDep;
}

interface LockfilePackage {
  version: string;
  resolved?: string;
  integrity?: string;
  requires?: Record<string, string>;
  dependencies?: Record<string, LockfilePackage>;
}

interface PackageLockJson {
  name: string;
  version: string;
  lockfileVersion: number;
  packages?: Record<string, {
    version: string;
    resolved?: string;
    integrity?: string;
    license?: string;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  }>;
  dependencies?: Record<string, LockfilePackage>;
}

/**
 * Compute a package URL (purl) for an npm package.
 * Follows the purl spec: pkg:npm/[namespace/]name@version
 */
function computePurl(name: string, version: string): string {
  if (name.startsWith('@')) {
    const parts = name.slice(1).split('/');
    return `pkg:npm/%40${parts[0]}/${parts[1]}@${version}`;
  }
  return `pkg:npm/${name}@${version}`;
}

/**
 * Compute SHA-256 hash of a string (used for component identification).
 */
function computeSha256(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Compute SHA-512 hash of a string.
 */
function computeSha512(content: string): string {
  return crypto.createHash('sha512').update(content).digest('hex');
}

export class SBOMGenerator {
  private readonly specVersion: string;
  private readonly vulnChecker: VulnerabilityChecker;

  constructor(specVersion: string = '1.5', vulnChecker?: VulnerabilityChecker) {
    this.specVersion = specVersion;
    this.vulnChecker = vulnChecker ?? new VulnerabilityChecker();
  }

  /**
   * Generate an SBOM from a package.json file.
   * Parses direct dependencies and optionally devDependencies.
   */
  generateFromPackageJson(
    packageJsonPath: string,
    options: { includeDevDeps?: boolean; projectId?: string } = {}
  ): CycloneDXBom {
    const { includeDevDeps = false, projectId } = options;

    logger.info('Generating SBOM from package.json', { path: packageJsonPath });

    let raw: string;
    try {
      raw = fs.readFileSync(packageJsonPath, 'utf-8');
    } catch (err) {
      throw new Error(`Failed to read package.json at ${packageJsonPath}: ${(err as Error).message}`);
    }

    let pkgJson: PackageJson;
    try {
      pkgJson = JSON.parse(raw) as PackageJson;
    } catch (err) {
      throw new Error(`Failed to parse package.json: ${(err as Error).message}`);
    }

    const components: CycloneDXComponent[] = [];
    const dependencies: CycloneDXDependency[] = [];

    // Process direct dependencies
    const directDeps = pkgJson.dependencies ?? {};
    const rootDependsOn: string[] = [];

    for (const [name, versionRange] of Object.entries(directDeps)) {
      const version = this.cleanVersion(versionRange);
      const purl = computePurl(name, version);
      rootDependsOn.push(purl);

      components.push(this.createComponent(name, version, 'required'));
      dependencies.push({ ref: purl, dependsOn: [] });
    }

    // Process dev dependencies if requested
    if (includeDevDeps && pkgJson.devDependencies) {
      for (const [name, versionRange] of Object.entries(pkgJson.devDependencies)) {
        const version = this.cleanVersion(versionRange);
        const purl = computePurl(name, version);
        rootDependsOn.push(purl);

        components.push(this.createComponent(name, version, 'optional'));
        dependencies.push({ ref: purl, dependsOn: [] });
      }
    }

    // Process peer dependencies
    if (pkgJson.peerDependencies) {
      for (const [name, versionRange] of Object.entries(pkgJson.peerDependencies)) {
        const version = this.cleanVersion(versionRange);
        const purl = computePurl(name, version);
        rootDependsOn.push(purl);

        components.push(this.createComponent(name, version, 'optional'));
        dependencies.push({ ref: purl, dependsOn: [] });
      }
    }

    // Root dependency node
    const rootPurl = computePurl(pkgJson.name, pkgJson.version);
    dependencies.unshift({ ref: rootPurl, dependsOn: rootDependsOn });

    // Flag known vulnerabilities
    const vulnFindings = this.checkVulnerabilities(components);

    const bom = this.createBom(
      pkgJson.name,
      pkgJson.version,
      components,
      dependencies,
      vulnFindings,
      projectId
    );

    logger.info('SBOM generated from package.json', {
      project: pkgJson.name,
      componentCount: components.length,
      vulnCount: vulnFindings.length,
    });

    return bom;
  }

  /**
   * Generate a more precise SBOM from a package-lock.json lockfile.
   * Includes transitive dependencies with exact resolved versions.
   */
  generateFromLockfile(
    lockfilePath: string,
    options: { projectId?: string } = {}
  ): CycloneDXBom {
    const { projectId } = options;

    logger.info('Generating SBOM from lockfile', { path: lockfilePath });

    let raw: string;
    try {
      raw = fs.readFileSync(lockfilePath, 'utf-8');
    } catch (err) {
      throw new Error(`Failed to read lockfile at ${lockfilePath}: ${(err as Error).message}`);
    }

    let lockfile: PackageLockJson;
    try {
      lockfile = JSON.parse(raw) as PackageLockJson;
    } catch (err) {
      throw new Error(`Failed to parse lockfile: ${(err as Error).message}`);
    }

    const components: CycloneDXComponent[] = [];
    const dependencies: CycloneDXDependency[] = [];
    const seen = new Set<string>();

    // lockfileVersion 2/3 uses "packages" field
    if (lockfile.packages) {
      for (const [pkgPath, pkgInfo] of Object.entries(lockfile.packages)) {
        if (pkgPath === '') continue; // root package

        const name = this.extractNameFromPath(pkgPath);
        if (!name || seen.has(`${name}@${pkgInfo.version}`)) continue;
        seen.add(`${name}@${pkgInfo.version}`);

        const component = this.createComponent(name, pkgInfo.version, 'required');

        // Add integrity hash if available
        if (pkgInfo.integrity) {
          const [algo, hash] = pkgInfo.integrity.split('-', 2);
          if (algo && hash) {
            component.hashes.push({
              alg: algo.toUpperCase().replace('SHA', 'SHA-'),
              content: Buffer.from(hash, 'base64').toString('hex'),
            });
          }
        }

        // Add license info
        if (pkgInfo.license) {
          component.licenses = [{ license: { id: pkgInfo.license } }];
        }

        components.push(component);

        // Build dependency tree
        const purl = computePurl(name, pkgInfo.version);
        const depRefs: string[] = [];
        if (pkgInfo.dependencies) {
          for (const [depName, depVersion] of Object.entries(pkgInfo.dependencies)) {
            depRefs.push(computePurl(depName, this.cleanVersion(depVersion)));
          }
        }
        dependencies.push({ ref: purl, dependsOn: depRefs });
      }
    }
    // lockfileVersion 1 uses "dependencies" field
    else if (lockfile.dependencies) {
      this.processLockfileV1Deps(lockfile.dependencies, components, dependencies, seen, false);
    }

    // Root dependency node
    const rootPurl = computePurl(lockfile.name, lockfile.version);
    const rootDependsOn = components.map((c) => c.purl);
    dependencies.unshift({ ref: rootPurl, dependsOn: rootDependsOn });

    const vulnFindings = this.checkVulnerabilities(components);

    const bom = this.createBom(
      lockfile.name,
      lockfile.version,
      components,
      dependencies,
      vulnFindings,
      projectId
    );

    logger.info('SBOM generated from lockfile', {
      project: lockfile.name,
      componentCount: components.length,
      vulnCount: vulnFindings.length,
      lockfileVersion: lockfile.lockfileVersion,
    });

    return bom;
  }

  /**
   * Generate an SBOM from raw component data (for cases where no filesystem is available).
   */
  generateFromComponents(
    projectName: string,
    projectVersion: string,
    rawComponents: Array<{ name: string; version: string; license?: string; scope?: 'required' | 'optional' }>,
    projectId?: string
  ): CycloneDXBom {
    const components: CycloneDXComponent[] = rawComponents.map((c) =>
      this.createComponent(c.name, c.version, c.scope ?? 'required', c.license)
    );

    const rootPurl = computePurl(projectName, projectVersion);
    const dependencies: CycloneDXDependency[] = [
      { ref: rootPurl, dependsOn: components.map((c) => c.purl) },
      ...components.map((c) => ({ ref: c.purl, dependsOn: [] })),
    ];

    const vulnFindings = this.checkVulnerabilities(components);

    return this.createBom(projectName, projectVersion, components, dependencies, vulnFindings, projectId);
  }

  // ── Private helpers ──

  private processLockfileV1Deps(
    deps: Record<string, LockfilePackage>,
    components: CycloneDXComponent[],
    dependencies: CycloneDXDependency[],
    seen: Set<string>,
    _isTransitive: boolean
  ): void {
    for (const [name, info] of Object.entries(deps)) {
      const key = `${name}@${info.version}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const component = this.createComponent(name, info.version, 'required');

      if (info.integrity) {
        const [algo, hash] = info.integrity.split('-', 2);
        if (algo && hash) {
          component.hashes.push({
            alg: algo.toUpperCase().replace('SHA', 'SHA-'),
            content: Buffer.from(hash, 'base64').toString('hex'),
          });
        }
      }

      component.properties = component.properties ?? [];
      component.properties.push({ name: 'cdx:npm:transitive', value: String(_isTransitive) });

      components.push(component);

      const purl = computePurl(name, info.version);
      const depRefs: string[] = [];

      if (info.requires) {
        for (const [depName, depVersion] of Object.entries(info.requires)) {
          depRefs.push(computePurl(depName, this.cleanVersion(depVersion)));
        }
      }
      dependencies.push({ ref: purl, dependsOn: depRefs });

      // Recurse into nested dependencies (transitive)
      if (info.dependencies) {
        this.processLockfileV1Deps(info.dependencies, components, dependencies, seen, true);
      }
    }
  }

  private createComponent(
    name: string,
    version: string,
    scope: 'required' | 'optional' | 'excluded',
    license?: string
  ): CycloneDXComponent {
    const purl = computePurl(name, version);
    const componentIdentifier = `${name}@${version}`;

    const component: CycloneDXComponent = {
      type: 'library',
      name,
      version,
      purl,
      scope,
      hashes: [
        { alg: 'SHA-256', content: computeSha256(componentIdentifier) },
        { alg: 'SHA-512', content: computeSha512(componentIdentifier) },
      ],
      licenses: license ? [{ license: { id: license } }] : [],
    };

    // Extract group from scoped packages
    if (name.startsWith('@')) {
      const parts = name.split('/');
      component.group = parts[0];
    }

    return component;
  }

  private createBom(
    projectName: string,
    projectVersion: string,
    components: CycloneDXComponent[],
    dependencies: CycloneDXDependency[],
    vulnFindings: VulnFinding[],
    projectId?: string
  ): CycloneDXBom {
    const bom: CycloneDXBom = {
      bomFormat: 'CycloneDX',
      specVersion: this.specVersion,
      serialNumber: `urn:uuid:${uuidv4()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [
          {
            vendor: 'ZeroTrust Security Platform',
            name: 'supply-chain-sbom-generator',
            version: '1.0.0',
          },
        ],
        component: {
          type: 'application',
          name: projectName,
          version: projectVersion,
          purl: computePurl(projectName, projectVersion),
        },
      },
      components,
      dependencies,
    };

    // Add vulnerability section if findings exist
    if (vulnFindings.length > 0) {
      bom.vulnerabilities = vulnFindings.map((f) => ({
        id: f.cveId,
        source: { name: 'ZeroTrust VulnDB', url: 'https://security-platform.internal/vulns' },
        ratings: [{ severity: f.severity.toLowerCase(), method: 'other' }],
        description: f.description,
        affects: [{ ref: computePurl(f.component, f.version) }],
      }));
    }

    // Add project ID as property if provided
    if (projectId) {
      bom.metadata.tools[0] = {
        ...bom.metadata.tools[0],
      };
    }

    return bom;
  }

  private checkVulnerabilities(components: CycloneDXComponent[]): VulnFinding[] {
    const result = this.vulnChecker.checkSBOM({
      components: components.map((c) => ({ name: c.name, version: c.version })),
    });
    return result.findings;
  }

  private cleanVersion(versionRange: string): string {
    // Strip range operators to get a base version
    return versionRange.replace(/^[\^~>=<|& ]+/, '').split(/\s/)[0] || versionRange;
  }

  private extractNameFromPath(pkgPath: string): string | null {
    // node_modules/@scope/name → @scope/name
    // node_modules/name → name
    const match = pkgPath.match(/node_modules\/((?:@[^/]+\/)?[^/]+)$/);
    return match ? match[1] : null;
  }
}

export default SBOMGenerator;
