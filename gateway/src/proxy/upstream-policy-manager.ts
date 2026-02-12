import { createHash } from 'crypto';
import {
  GatewayConfigSchema,
  type GatewayConfig,
  type UpstreamService,
} from '../../config/default';

export interface UpstreamRoutingPolicyIssue {
  path: string;
  message: string;
}

export interface UpstreamRoutingPolicyPreviewSuccess {
  ok: true;
  currentRevision: string;
  nextRevision: string;
  changed: boolean;
  changedUpstreams: string[];
  upstreams: Record<string, UpstreamService>;
}

export interface UpstreamRoutingPolicyPreviewFailure {
  ok: false;
  issues: UpstreamRoutingPolicyIssue[];
}

export type UpstreamRoutingPolicyPreviewResult =
  | UpstreamRoutingPolicyPreviewSuccess
  | UpstreamRoutingPolicyPreviewFailure;

export interface UpstreamRoutingPolicyApplySuccess {
  ok: true;
  previousRevision: string;
  revision: string;
  changed: boolean;
  changedUpstreams: string[];
}

export interface UpstreamRoutingPolicyApplyFailure {
  ok: false;
  issues: UpstreamRoutingPolicyIssue[];
}

export type UpstreamRoutingPolicyApplyResult =
  | UpstreamRoutingPolicyApplySuccess
  | UpstreamRoutingPolicyApplyFailure;

export interface UpstreamRoutingPolicySnapshot {
  revision: string;
  upstreamCount: number;
  upstreams: Record<string, UpstreamService>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function deepMerge(base: unknown, patch: unknown): unknown {
  if (patch === undefined) return base;
  if (Array.isArray(patch)) return [...patch];
  if (!isRecord(base) || !isRecord(patch)) return patch;

  const merged: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(patch)) {
    merged[key] = deepMerge(base[key], value);
  }
  return merged;
}

function canonicalize(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'number' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const fields = keys.map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`);
  return `{${fields.join(',')}}`;
}

function cloneUpstreams(
  upstreams: Record<string, UpstreamService>,
): Record<string, UpstreamService> {
  return JSON.parse(JSON.stringify(upstreams)) as Record<string, UpstreamService>;
}

export function computeUpstreamRoutingPolicyRevision(
  upstreams: Record<string, UpstreamService>,
): string {
  const digest = createHash('sha256')
    .update(canonicalize(upstreams), 'utf8')
    .digest('hex');
  return `ur:${digest.slice(0, 32)}`;
}

export class UpstreamRoutingPolicyManager {
  private revision: string;

  constructor(private readonly config: GatewayConfig) {
    this.revision = computeUpstreamRoutingPolicyRevision(this.config.upstreams);
  }

  public getRevision(): string {
    return this.revision;
  }

  public getSnapshot(): UpstreamRoutingPolicySnapshot {
    const cloned = cloneUpstreams(this.config.upstreams);
    return {
      revision: this.revision,
      upstreamCount: Object.keys(cloned).length,
      upstreams: cloned,
    };
  }

  public getUpstream(name: string): UpstreamService | undefined {
    return this.config.upstreams[name];
  }

  public previewPatch(
    patch: Record<string, Record<string, unknown>>,
  ): UpstreamRoutingPolicyPreviewResult {
    if (!isRecord(patch) || Object.keys(patch).length === 0) {
      return {
        ok: false,
        issues: [{ path: 'upstreams', message: 'at least one upstream patch is required' }],
      };
    }

    const currentUpstreams = this.config.upstreams;
    const patchedUpstreams = cloneUpstreams(currentUpstreams);

    for (const [upstreamName, rawPatch] of Object.entries(patch)) {
      if (!currentUpstreams[upstreamName]) {
        return {
          ok: false,
          issues: [{
            path: `upstreams.${upstreamName}`,
            message: 'unknown upstream',
          }],
        };
      }
      if (!isRecord(rawPatch)) {
        return {
          ok: false,
          issues: [{
            path: `upstreams.${upstreamName}`,
            message: 'upstream patch must be an object',
          }],
        };
      }

      patchedUpstreams[upstreamName] = deepMerge(
        patchedUpstreams[upstreamName],
        rawPatch,
      ) as UpstreamService;
    }

    return this.previewReplace(patchedUpstreams);
  }

  public applyPatch(
    patch: Record<string, Record<string, unknown>>,
  ): UpstreamRoutingPolicyApplyResult {
    const preview = this.previewPatch(patch);
    if (!preview.ok) {
      return {
        ok: false,
        issues: preview.issues,
      };
    }
    return this.commit(preview.upstreams, preview.changedUpstreams, preview.nextRevision);
  }

  public previewReplace(
    nextUpstreams: Record<string, UpstreamService>,
  ): UpstreamRoutingPolicyPreviewResult {
    if (!isRecord(nextUpstreams)) {
      return {
        ok: false,
        issues: [{ path: 'upstreams', message: 'upstreams must be an object' }],
      };
    }

    const currentNames = Object.keys(this.config.upstreams).sort();
    const nextNames = Object.keys(nextUpstreams).sort();
    if (currentNames.length !== nextNames.length || currentNames.some((name, idx) => nextNames[idx] !== name)) {
      return {
        ok: false,
        issues: [{
          path: 'upstreams',
          message: 'upstream set mismatch; replacement must include the same upstream names',
        }],
      };
    }

    const candidateRaw = deepMerge(this.config as unknown as Record<string, unknown>, {
      upstreams: nextUpstreams,
    }) as GatewayConfig;
    const parsed = GatewayConfigSchema.safeParse(candidateRaw);
    if (!parsed.success) {
      return {
        ok: false,
        issues: parsed.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      };
    }

    const normalizedUpstreams = parsed.data.upstreams;
    for (const [name, upstream] of Object.entries(normalizedUpstreams)) {
      if (upstream.name !== name) {
        return {
          ok: false,
          issues: [{
            path: `upstreams.${name}.name`,
            message: 'upstream.name must match the upstream map key',
          }],
        };
      }
    }

    const changedUpstreams: string[] = [];
    for (const [name, upstream] of Object.entries(normalizedUpstreams)) {
      const current = this.config.upstreams[name];
      if (!current || canonicalize(current) !== canonicalize(upstream)) {
        changedUpstreams.push(name);
      }
    }

    const nextRevision = computeUpstreamRoutingPolicyRevision(normalizedUpstreams);
    return {
      ok: true,
      currentRevision: this.revision,
      nextRevision,
      changed: changedUpstreams.length > 0,
      changedUpstreams,
      upstreams: cloneUpstreams(normalizedUpstreams),
    };
  }

  public replaceAll(
    upstreams: Record<string, UpstreamService>,
  ): UpstreamRoutingPolicyApplyResult {
    const preview = this.previewReplace(upstreams);
    if (!preview.ok) {
      return {
        ok: false,
        issues: preview.issues,
      };
    }
    return this.commit(preview.upstreams, preview.changedUpstreams, preview.nextRevision);
  }

  public isRevisionCompatible(
    revision: string,
    upstreams: Record<string, UpstreamService>,
  ): boolean {
    return computeUpstreamRoutingPolicyRevision(upstreams) === revision;
  }

  private commit(
    upstreams: Record<string, UpstreamService>,
    changedUpstreams: string[],
    nextRevision: string,
  ): UpstreamRoutingPolicyApplySuccess {
    const previousRevision = this.revision;
    this.config.upstreams = upstreams;
    this.revision = nextRevision;
    return {
      ok: true,
      previousRevision,
      revision: nextRevision,
      changed: changedUpstreams.length > 0,
      changedUpstreams,
    };
  }
}

