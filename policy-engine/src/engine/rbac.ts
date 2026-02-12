import type { Actor, PolicySubject } from '../models/policy-schema';

/**
 * Default role hierarchy for the platform.
 * Higher-level roles inherit all permissions of lower-level roles.
 * Structure: role -> list of roles it inherits (directly).
 */
const DEFAULT_ROLE_HIERARCHY: Record<string, string[]> = {
  admin: ['manager'],
  manager: ['user'],
  user: ['viewer'],
  viewer: [],
};

/**
 * Default role-to-permission mapping.
 * Maps roles to the set of permissions they directly grant.
 */
const DEFAULT_ROLE_PERMISSIONS: Record<string, string[]> = {
  admin: ['*', 'admin:*', 'policy:write', 'policy:read', 'audit:read', 'user:manage'],
  manager: ['resource:write', 'resource:read', 'resource:delete', 'user:read', 'report:read'],
  user: ['resource:read', 'resource:write', 'profile:read', 'profile:write'],
  viewer: ['resource:read', 'profile:read'],
};

/**
 * RBACEvaluator handles Role-Based Access Control evaluation
 * with support for role hierarchies, scoped roles, and permission inheritance.
 */
export class RBACEvaluator {
  private roleHierarchy: Record<string, string[]>;
  private rolePermissions: Record<string, string[]>;
  private expandedRolesCache: Map<string, Set<string>> = new Map();

  constructor(
    roleHierarchy?: Record<string, string[]>,
    rolePermissions?: Record<string, string[]>
  ) {
    this.roleHierarchy = roleHierarchy ?? DEFAULT_ROLE_HIERARCHY;
    this.rolePermissions = rolePermissions ?? DEFAULT_ROLE_PERMISSIONS;
  }

  /**
   * Check if the actor's roles satisfy the policy's subject role requirements.
   * Returns true if the actor has at least one role that matches or inherits
   * one of the required roles.
   */
  checkRoles(actor: Actor, policySubject: PolicySubject | undefined): boolean {
    // If no subject constraints, the policy applies to everyone
    if (!policySubject || !policySubject.roles || policySubject.roles.length === 0) {
      return true;
    }

    const requiredRoles = policySubject.roles;
    const actorExpandedRoles = this.expandRoles(actor.roles);

    // Check if any of the actor's expanded roles match any required role
    for (const required of requiredRoles) {
      if (this.roleMatches(actorExpandedRoles, required)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if the actor has a specific permission through their roles.
   */
  hasPermission(actor: Actor, permission: string): boolean {
    const allPermissions = this.getEffectivePermissions(actor.roles);
    return this.permissionMatches(allPermissions, permission);
  }

  /**
   * Get all effective permissions for a set of roles, including inherited ones.
   */
  getEffectivePermissions(roles: string[]): Set<string> {
    const permissions = new Set<string>();
    const expandedRoles = this.expandRoles(roles);

    for (const role of expandedRoles) {
      const baseRole = this.getBaseRole(role);
      const rolePerms = this.rolePermissions[baseRole];
      if (rolePerms) {
        for (const perm of rolePerms) {
          permissions.add(perm);

          // If it's a scoped role, prefix permissions with scope
          const scope = this.getScope(role);
          if (scope) {
            permissions.add(`${scope}:${perm}`);
          }
        }
      }
    }

    return permissions;
  }

  /**
   * Expand a set of roles to include all inherited roles through the hierarchy.
   * For example, 'admin' expands to ['admin', 'manager', 'user', 'viewer'].
   */
  expandRoles(roles: string[]): Set<string> {
    const cacheKey = roles.sort().join(',');
    const cached = this.expandedRolesCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    const expanded = new Set<string>();

    for (const role of roles) {
      this.expandRoleRecursive(role, expanded, new Set());
    }

    this.expandedRolesCache.set(cacheKey, expanded);
    return expanded;
  }

  /**
   * Recursively expand a role through the hierarchy.
   * Includes cycle detection to prevent infinite loops.
   */
  private expandRoleRecursive(role: string, result: Set<string>, visited: Set<string>): void {
    if (visited.has(role)) {
      return; // Cycle detection
    }

    visited.add(role);
    result.add(role);

    // Get the base role (without scope prefix) for hierarchy lookup
    const baseRole = this.getBaseRole(role);
    const scope = this.getScope(role);
    const inheritedRoles = this.roleHierarchy[baseRole];

    if (inheritedRoles) {
      for (const inherited of inheritedRoles) {
        // If original role was scoped, propagate the scope to inherited roles
        const inheritedFull = scope ? `${scope}:${inherited}` : inherited;
        this.expandRoleRecursive(inheritedFull, result, visited);
      }
    }
  }

  /**
   * Check if a set of expanded roles matches a required role.
   * Supports wildcard matching and scoped role matching.
   */
  private roleMatches(expandedRoles: Set<string>, requiredRole: string): boolean {
    // Direct match
    if (expandedRoles.has(requiredRole)) {
      return true;
    }

    // Check if any expanded role matches via wildcard or scope
    for (const role of expandedRoles) {
      // Wildcard in expanded role: admin matches any specific role
      if (role === '*' || role === 'admin') {
        // admin only matches via hierarchy, not via wildcard
      }

      // Scoped wildcard: org:* matches org:admin, org:user, etc.
      if (role.endsWith(':*')) {
        const scope = role.slice(0, -2);
        if (requiredRole.startsWith(scope + ':')) {
          return true;
        }
      }

      // Glob pattern matching for roles
      if (this.globMatch(role, requiredRole)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if a set of permissions matches a required permission.
   * Supports wildcard patterns.
   */
  private permissionMatches(permissions: Set<string>, required: string): boolean {
    if (permissions.has(required) || permissions.has('*')) {
      return true;
    }

    for (const perm of permissions) {
      if (this.globMatch(perm, required)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Simple glob matching: * matches any segment, ** matches everything.
   */
  private globMatch(pattern: string, value: string): boolean {
    if (pattern === value) return true;
    if (pattern === '*') return true;

    // Convert glob to regex
    const regexStr = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '<<DOUBLESTAR>>')
      .replace(/\*/g, '[^:]*')
      .replace(/<<DOUBLESTAR>>/g, '.*')
      .replace(/\?/g, '.');

    try {
      return new RegExp(`^${regexStr}$`).test(value);
    } catch {
      return pattern === value;
    }
  }

  /**
   * Extract the base role from a potentially scoped role.
   * "org:admin" -> "admin", "admin" -> "admin"
   */
  private getBaseRole(role: string): string {
    const colonIndex = role.lastIndexOf(':');
    if (colonIndex === -1) {
      return role;
    }
    return role.substring(colonIndex + 1);
  }

  /**
   * Extract the scope from a scoped role.
   * "org:admin" -> "org", "project:editor" -> "project", "admin" -> null
   */
  private getScope(role: string): string | null {
    const colonIndex = role.lastIndexOf(':');
    if (colonIndex === -1) {
      return null;
    }
    return role.substring(0, colonIndex);
  }

  /**
   * Update the role hierarchy at runtime.
   */
  updateHierarchy(hierarchy: Record<string, string[]>): void {
    this.roleHierarchy = { ...this.roleHierarchy, ...hierarchy };
    this.expandedRolesCache.clear(); // Invalidate cache
  }

  /**
   * Update role permissions at runtime.
   */
  updatePermissions(permissions: Record<string, string[]>): void {
    this.rolePermissions = { ...this.rolePermissions, ...permissions };
  }

  /**
   * Get the current role hierarchy for inspection.
   */
  getHierarchy(): Readonly<Record<string, string[]>> {
    return this.roleHierarchy;
  }
}

export const rbacEvaluator = new RBACEvaluator();
