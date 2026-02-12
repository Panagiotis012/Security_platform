import { createHash } from 'crypto';
import {
  GatewayConfigSchema,
  type GatewayConfig,
  type RouteConfig,
} from '../../config/default';

export interface RoutePolicyIssue {
  path: string;
  message: string;
}

export interface RoutePolicyPatchUpdate {
  path: string;
  method?: string;
  patch: Record<string, unknown>;
}

export interface RoutePolicyPreviewSuccess {
  ok: true;
  currentRevision: string;
  nextRevision: string;
  changed: boolean;
  changedRoutes: string[];
  routes: RouteConfig[];
}

export interface RoutePolicyPreviewFailure {
  ok: false;
  issues: RoutePolicyIssue[];
}

export type RoutePolicyPreviewResult =
  | RoutePolicyPreviewSuccess
  | RoutePolicyPreviewFailure;

export interface RoutePolicyApplySuccess {
  ok: true;
  previousRevision: string;
  revision: string;
  changed: boolean;
  changedRoutes: string[];
}

export interface RoutePolicyApplyFailure {
  ok: false;
  issues: RoutePolicyIssue[];
}

export type RoutePolicyApplyResult =
  | RoutePolicyApplySuccess
  | RoutePolicyApplyFailure;

export interface RoutePolicySnapshot {
  revision: string;
  routeCount: number;
  routes: RouteConfig[];
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

function cloneRoutes(routes: RouteConfig[]): RouteConfig[] {
  return JSON.parse(JSON.stringify(routes)) as RouteConfig[];
}

function describeRoute(route: RouteConfig): string {
  const methods = route.methods.map((method) => method.toUpperCase()).join(',');
  return `${route.path}|${methods}`;
}

function equalRouteSets(a: RouteConfig[], b: RouteConfig[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (canonicalize(a[i]) !== canonicalize(b[i])) return false;
  }
  return true;
}

export function computeRoutePolicyRevision(routes: RouteConfig[]): string {
  const digest = createHash('sha256')
    .update(canonicalize(routes), 'utf8')
    .digest('hex');
  return `rr:${digest.slice(0, 32)}`;
}

export class RoutePolicyManager {
  private revision: string;

  constructor(private readonly config: GatewayConfig) {
    this.revision = computeRoutePolicyRevision(this.config.routes);
  }

  public getRevision(): string {
    return this.revision;
  }

  public getSnapshot(): RoutePolicySnapshot {
    const routes = cloneRoutes(this.config.routes);
    return {
      revision: this.revision,
      routeCount: routes.length,
      routes,
    };
  }

  public previewPatch(updates: RoutePolicyPatchUpdate[]): RoutePolicyPreviewResult {
    if (!Array.isArray(updates) || updates.length === 0) {
      return {
        ok: false,
        issues: [{ path: 'updates', message: 'at least one route update is required' }],
      };
    }

    const nextRoutes = cloneRoutes(this.config.routes);
    const issues: RoutePolicyIssue[] = [];
    for (let i = 0; i < updates.length; i += 1) {
      const update = updates[i];
      if (!update || typeof update !== 'object') {
        issues.push({
          path: `updates.${i}`,
          message: 'route update must be an object',
        });
        continue;
      }

      const path = String(update.path ?? '').trim();
      if (!path || !path.startsWith('/')) {
        issues.push({
          path: `updates.${i}.path`,
          message: 'path must be a non-empty route path starting with "/"',
        });
        continue;
      }

      if (!isRecord(update.patch)) {
        issues.push({
          path: `updates.${i}.patch`,
          message: 'patch must be an object',
        });
        continue;
      }

      const method = update.method ? String(update.method).trim().toUpperCase() : '';
      const matched: number[] = [];
      for (let idx = 0; idx < nextRoutes.length; idx += 1) {
        const route = nextRoutes[idx];
        if (!route) continue;
        if (route.path !== path) continue;
        if (!method) {
          matched.push(idx);
          continue;
        }
        const routeMethods = new Set(route.methods.map((entry) => entry.toUpperCase()));
        if (routeMethods.has(method) || routeMethods.has('*')) {
          matched.push(idx);
        }
      }

      if (matched.length === 0) {
        issues.push({
          path: `updates.${i}`,
          message: `no route matched path="${path}"${method ? ` method="${method}"` : ''}`,
        });
        continue;
      }

      for (const idx of matched) {
        nextRoutes[idx] = deepMerge(nextRoutes[idx], update.patch) as RouteConfig;
      }
    }

    if (issues.length > 0) {
      return { ok: false, issues };
    }

    return this.previewReplace(nextRoutes);
  }

  public applyPatch(updates: RoutePolicyPatchUpdate[]): RoutePolicyApplyResult {
    const preview = this.previewPatch(updates);
    if (!preview.ok) {
      return { ok: false, issues: preview.issues };
    }
    return this.commit(preview.routes, preview.changedRoutes, preview.nextRevision);
  }

  public previewReplace(routes: RouteConfig[]): RoutePolicyPreviewResult {
    if (!Array.isArray(routes)) {
      return {
        ok: false,
        issues: [{ path: 'routes', message: 'routes must be an array' }],
      };
    }

    const candidateRaw = deepMerge(this.config as unknown as Record<string, unknown>, {
      routes,
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

    const normalizedRoutes = parsed.data.routes;
    const upstreamNames = new Set(Object.keys(parsed.data.upstreams));
    const routeIssues: RoutePolicyIssue[] = [];
    normalizedRoutes.forEach((route, idx) => {
      if (!upstreamNames.has(route.upstream)) {
        routeIssues.push({
          path: `routes.${idx}.upstream`,
          message: `unknown upstream "${route.upstream}"`,
        });
      }
    });
    if (routeIssues.length > 0) {
      return {
        ok: false,
        issues: routeIssues,
      };
    }

    const currentRoutes = this.config.routes;
    const changed = !equalRouteSets(currentRoutes, normalizedRoutes);
    const changedRoutes: string[] = [];
    const maxLength = Math.max(currentRoutes.length, normalizedRoutes.length);
    for (let i = 0; i < maxLength; i += 1) {
      const current = currentRoutes[i];
      const next = normalizedRoutes[i];
      if (!current && next) {
        changedRoutes.push(describeRoute(next));
        continue;
      }
      if (current && !next) {
        changedRoutes.push(describeRoute(current));
        continue;
      }
      if (current && next && canonicalize(current) !== canonicalize(next)) {
        changedRoutes.push(describeRoute(next));
      }
    }

    const nextRevision = computeRoutePolicyRevision(normalizedRoutes);
    return {
      ok: true,
      currentRevision: this.revision,
      nextRevision,
      changed,
      changedRoutes,
      routes: cloneRoutes(normalizedRoutes),
    };
  }

  public replaceAll(routes: RouteConfig[]): RoutePolicyApplyResult {
    const preview = this.previewReplace(routes);
    if (!preview.ok) {
      return { ok: false, issues: preview.issues };
    }
    return this.commit(preview.routes, preview.changedRoutes, preview.nextRevision);
  }

  public isRevisionCompatible(revision: string, routes: RouteConfig[]): boolean {
    return computeRoutePolicyRevision(routes) === revision;
  }

  private commit(
    routes: RouteConfig[],
    changedRoutes: string[],
    nextRevision: string,
  ): RoutePolicyApplySuccess {
    const previousRevision = this.revision;
    this.config.routes = routes;
    this.revision = nextRevision;
    return {
      ok: true,
      previousRevision,
      revision: nextRevision,
      changed: changedRoutes.length > 0,
      changedRoutes,
    };
  }
}
