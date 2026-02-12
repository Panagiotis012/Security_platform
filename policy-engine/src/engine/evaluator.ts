import { v4 as uuidv4 } from 'uuid';
import type {
  PolicyRequest,
  PolicyDecision,
  DecisionResult,
} from '../models/policy-schema';
import { ConditionEvaluator } from './conditions';
import { RBACEvaluator } from './rbac';
import { ABACEvaluator } from './abac';
import type { PolicyStore } from '../store/policy-store';
import config from '../../config/default';

/**
 * PolicyEvaluator is the core decision engine.
 *
 * It implements a deny-override combining algorithm:
 * 1. Load all applicable policies for the given action + resource.
 * 2. Evaluate each policy in priority order (higher priority first).
 * 3. First explicit DENY wins immediately.
 * 4. If no DENY and at least one ALLOW, the decision is ALLOW.
 * 5. If no policy matches at all, default to DENY (fail-closed).
 *
 * Evaluation is time-bounded to prevent slow policy evaluation from
 * blocking the request pipeline.
 */
export class PolicyEvaluator {
  private abacEvaluator: ABACEvaluator;
  private policyStore: PolicyStore;
  private maxEvaluationTimeMs: number;

  constructor(policyStore: PolicyStore, abacEvaluator?: ABACEvaluator) {
    const conditionEvaluator = new ConditionEvaluator();
    const rbacEvaluator = new RBACEvaluator();
    this.abacEvaluator = abacEvaluator ?? new ABACEvaluator(conditionEvaluator, rbacEvaluator);
    this.policyStore = policyStore;
    this.maxEvaluationTimeMs = config.authorization.maxEvaluationTimeMs;
  }

  /**
   * Evaluate a policy request and produce a decision.
   * FAIL-CLOSED: if no policy matches or an error occurs, the result is DENY.
   */
  async evaluate(request: PolicyRequest): Promise<PolicyDecision> {
    const startTime = performance.now();
    const correlationId = request.correlationId ?? uuidv4();

    try {
      // Step 1: Find all applicable policies
      const applicablePolicies = await this.policyStore.findApplicable(
        request.action,
        `${request.resource.type}:${request.resource.id}`
      );

      if (applicablePolicies.length === 0) {
        return this.buildDecision(
          'DENY',
          null,
          'No applicable policies found - default deny (fail-closed)',
          startTime,
          correlationId,
          []
        );
      }

      // Step 2: Sort by priority descending (higher priority first)
      const sortedPolicies = [...applicablePolicies].sort((a, b) => b.priority - a.priority);

      // Step 3: Evaluate each policy (deny-override combining algorithm)
      let hasAllow = false;
      let allowPolicyId: string | null = null;
      let allowReason = '';
      const matchedPolicyIds: string[] = [];

      for (const policy of sortedPolicies) {
        // Time budget check
        const elapsed = performance.now() - startTime;
        if (elapsed > this.maxEvaluationTimeMs) {
          return this.buildDecision(
            'DENY',
            null,
            `Evaluation time budget exceeded (${Math.round(elapsed)}ms > ${this.maxEvaluationTimeMs}ms) - default deny`,
            startTime,
            correlationId,
            matchedPolicyIds
          );
        }

        // Skip disabled policies
        if (!policy.enabled) {
          continue;
        }

        // Evaluate the policy using ABAC evaluator (which includes RBAC)
        const result = this.abacEvaluator.evaluatePolicy(policy, request);

        if (result.matches) {
          matchedPolicyIds.push(policy.id);

          if (policy.effect === 'DENY') {
            // First explicit DENY wins immediately
            return this.buildDecision(
              'DENY',
              policy.id,
              `Denied by policy "${policy.name}" (id: ${policy.id}): ${result.reason}`,
              startTime,
              correlationId,
              matchedPolicyIds
            );
          }

          if (policy.effect === 'ALLOW' && !hasAllow) {
            hasAllow = true;
            allowPolicyId = policy.id;
            allowReason = `Allowed by policy "${policy.name}" (id: ${policy.id}): ${result.reason}`;
          }
        }
      }

      // Step 4: If at least one ALLOW and no DENY, allow
      if (hasAllow) {
        return this.buildDecision(
          'ALLOW',
          allowPolicyId,
          allowReason,
          startTime,
          correlationId,
          matchedPolicyIds
        );
      }

      // Step 5: No policy matched - default DENY (fail-closed)
      return this.buildDecision(
        'DENY',
        null,
        'No matching policy produced an ALLOW decision - default deny (fail-closed)',
        startTime,
        correlationId,
        matchedPolicyIds
      );
    } catch (error) {
      // FAIL-CLOSED: any error results in DENY
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown evaluation error';
      return this.buildDecision(
        'DENY',
        null,
        `Evaluation error: ${errorMessage} - default deny (fail-closed)`,
        startTime,
        correlationId,
        []
      );
    }
  }

  /**
   * Build a PolicyDecision object with timing information.
   */
  private buildDecision(
    decision: DecisionResult,
    policyId: string | null,
    reason: string,
    startTime: number,
    correlationId: string,
    matchedPolicies: string[]
  ): PolicyDecision {
    const evaluationTimeMs = Math.round((performance.now() - startTime) * 1000) / 1000;

    return {
      decision,
      policyId,
      reason,
      timestamp: new Date().toISOString(),
      evaluationTimeMs,
      correlationId,
      matchedPolicies,
    };
  }
}
