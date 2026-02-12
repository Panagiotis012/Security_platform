import type { PolicyRequest, PolicySubject, Policy, ConditionNode } from '../models/policy-schema';
import type { EvaluationContext} from './conditions';
import { ConditionEvaluator, buildEvaluationContext } from './conditions';
import { RBACEvaluator } from './rbac';

/**
 * Result of ABAC evaluation for a single policy.
 */
export interface ABACResult {
  matches: boolean;
  subjectMatch: boolean;
  actionMatch: boolean;
  resourceMatch: boolean;
  conditionMatch: boolean;
  reason: string;
}

/**
 * ABACEvaluator handles Attribute-Based Access Control evaluation.
 * Evaluates attributes from subject (actor), resource, action, and environment.
 * Combines with RBAC results for hybrid evaluation.
 */
export class ABACEvaluator {
  private conditionEvaluator: ConditionEvaluator;
  private rbacEvaluator: RBACEvaluator;

  constructor(conditionEvaluator: ConditionEvaluator, rbacEvaluator: RBACEvaluator) {
    this.conditionEvaluator = conditionEvaluator;
    this.rbacEvaluator = rbacEvaluator;
  }

  /**
   * Evaluate whether a policy applies to and permits/denies the given request.
   * Checks subject, action, resource, and condition matching.
   */
  evaluatePolicy(policy: Policy, request: PolicyRequest): ABACResult {
    // Step 1: Check subject match (roles + subject attributes)
    const subjectMatch = this.evaluateSubject(policy.subjects, request);
    if (!subjectMatch.matches) {
      return {
        matches: false,
        subjectMatch: false,
        actionMatch: false,
        resourceMatch: false,
        conditionMatch: false,
        reason: subjectMatch.reason,
      };
    }

    // Step 2: Check action match
    const actionMatch = this.evaluateAction(policy.actions, request.action);
    if (!actionMatch) {
      return {
        matches: false,
        subjectMatch: true,
        actionMatch: false,
        resourceMatch: false,
        conditionMatch: false,
        reason: `Action "${request.action}" does not match policy actions`,
      };
    }

    // Step 3: Check resource match
    const resourceMatch = this.evaluateResource(policy.resources, request.resource);
    if (!resourceMatch) {
      return {
        matches: false,
        subjectMatch: true,
        actionMatch: true,
        resourceMatch: false,
        conditionMatch: false,
        reason: `Resource "${request.resource.type}:${request.resource.id}" does not match policy resources`,
      };
    }

    // Step 4: Check conditions
    const conditionMatch = this.evaluateConditions(policy.conditions, request);
    if (!conditionMatch.matches) {
      return {
        matches: false,
        subjectMatch: true,
        actionMatch: true,
        resourceMatch: true,
        conditionMatch: false,
        reason: conditionMatch.reason,
      };
    }

    return {
      matches: true,
      subjectMatch: true,
      actionMatch: true,
      resourceMatch: true,
      conditionMatch: true,
      reason: `Policy "${policy.name}" matches request`,
    };
  }

  /**
   * Evaluate subject matching: RBAC roles + attribute-based subject conditions.
   */
  private evaluateSubject(
    subjects: PolicySubject | undefined,
    request: PolicyRequest
  ): { matches: boolean; reason: string } {
    if (!subjects) {
      return { matches: true, reason: 'No subject constraints' };
    }

    // Check RBAC roles
    const roleMatch = this.rbacEvaluator.checkRoles(request.actor, subjects);
    if (!roleMatch && subjects.roles && subjects.roles.length > 0) {
      return {
        matches: false,
        reason: `Actor roles [${request.actor.roles.join(', ')}] do not satisfy required roles [${subjects.roles.join(', ')}]`,
      };
    }

    // Check subject attribute conditions
    if (subjects.attributes && Object.keys(subjects.attributes).length > 0) {
      const attrMatch = this.evaluateSubjectAttributes(
        subjects.attributes,
        request.actor.attributes ?? {}
      );
      if (!attrMatch) {
        return {
          matches: false,
          reason: 'Actor attributes do not match subject attribute requirements',
        };
      }
    }

    return { matches: true, reason: 'Subject matches' };
  }

  /**
   * Check if actor attributes satisfy the policy's subject attribute requirements.
   * Each required attribute must be present and equal in the actor's attributes.
   */
  private evaluateSubjectAttributes(
    required: Record<string, unknown>,
    actual: Record<string, unknown>
  ): boolean {
    for (const [key, expectedValue] of Object.entries(required)) {
      const actualValue = actual[key];

      if (actualValue === undefined) {
        return false;
      }

      // Array containment check
      if (Array.isArray(expectedValue)) {
        if (Array.isArray(actualValue)) {
          // All expected values must be in actual
          const actualStrings = actualValue.map(String);
          const hasAll = expectedValue.every((v) => actualStrings.includes(String(v)));
          if (!hasAll) return false;
        } else {
          // Actual is scalar, check if it's in expected array
          if (!expectedValue.map(String).includes(String(actualValue))) {
            return false;
          }
        }
      } else {
        // Scalar comparison
        if (String(actualValue) !== String(expectedValue)) {
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Evaluate if the request action matches any of the policy's action patterns.
   * Supports wildcard patterns: "resource:*", "*", "resource:read".
   */
  private evaluateAction(policyActions: string[], requestAction: string): boolean {
    for (const pattern of policyActions) {
      if (this.patternMatches(pattern, requestAction)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Evaluate if the request resource matches any of the policy's resource patterns.
   * Resource patterns use the format: "type:id" or "type:*" or "*".
   */
  private evaluateResource(
    policyResources: string[],
    resource: { type: string; id: string }
  ): boolean {
    const resourceString = `${resource.type}:${resource.id}`;

    for (const pattern of policyResources) {
      // Match against "type:id" combination
      if (this.patternMatches(pattern, resourceString)) {
        return true;
      }

      // Also match against just the type
      if (this.patternMatches(pattern, resource.type)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Evaluate condition tree if present on the policy.
   */
  private evaluateConditions(
    conditions: ConditionNode | undefined,
    request: PolicyRequest
  ): { matches: boolean; reason: string } {
    if (!conditions) {
      return { matches: true, reason: 'No conditions to evaluate' };
    }

    const context: EvaluationContext = buildEvaluationContext(request);
    const result = this.conditionEvaluator.evaluate(conditions, context);

    return {
      matches: result,
      reason: result ? 'All conditions satisfied' : 'One or more conditions not satisfied',
    };
  }

  /**
   * Pattern matching with wildcard support.
   * Supports: "*" (match all), "prefix:*" (prefix match), exact match,
   * and "?" for single character.
   */
  private patternMatches(pattern: string, value: string): boolean {
    // Exact match
    if (pattern === value) {
      return true;
    }

    // Universal wildcard
    if (pattern === '*') {
      return true;
    }

    // Convert pattern to regex for glob matching
    let regexStr = '^';
    for (let i = 0; i < pattern.length; i++) {
      const ch = pattern[i];
      switch (ch) {
        case '*':
          // Check for **
          if (i + 1 < pattern.length && pattern[i + 1] === '*') {
            regexStr += '.*';
            i++; // Skip next *
          } else {
            regexStr += '[^:]*'; // * matches within a segment (doesn't cross :)
          }
          break;
        case '?':
          regexStr += '[^:]';
          break;
        case '.':
        case '(':
        case ')':
        case '[':
        case ']':
        case '{':
        case '}':
        case '+':
        case '^':
        case '$':
        case '|':
        case '\\':
          regexStr += '\\' + ch;
          break;
        default:
          regexStr += ch;
      }
    }
    regexStr += '$';

    try {
      return new RegExp(regexStr).test(value);
    } catch {
      return pattern === value;
    }
  }
}

/**
 * Create an ABACEvaluator with default dependencies.
 */
export function createABACEvaluator(
  conditionEval?: ConditionEvaluator,
  rbacEval?: RBACEvaluator
): ABACEvaluator {
  const ce = conditionEval ?? new ConditionEvaluator();
  const re = rbacEval ?? new RBACEvaluator();
  return new ABACEvaluator(ce, re);
}
