import { InMemoryPolicyStore, type PolicyStore } from '../../policy-engine/src/store/policy-store';
import { PolicyEvaluator } from '../../policy-engine/src/engine/evaluator';

describe('Policy Engine (PDP) - Real Evaluations', () => {
  test('fail-closed: no applicable policies -> DENY', async () => {
    const store = new InMemoryPolicyStore();
    const evaluator = new PolicyEvaluator(store);

    const decision = await evaluator.evaluate({
      actor: { id: 'user-1', roles: ['user'], attributes: {} },
      action: 'resource:read',
      resource: { type: 'document', id: 'doc-1', attributes: {} },
      environment: { ip: '1.2.3.4' },
    });

    expect(decision.decision).toBe('DENY');
    expect(decision.reason.toLowerCase()).toContain('default deny');
  });

  test('allow when matching ALLOW policy exists', async () => {
    const store = new InMemoryPolicyStore();
    await store.create({
      name: 'Allow document reads for users',
      description: 'Basic read permission',
      effect: 'ALLOW',
      subjects: { roles: ['user'] },
      actions: ['resource:read'],
      resources: ['document:*'],
      priority: 10,
      enabled: true,
    });

    const evaluator = new PolicyEvaluator(store);
    const decision = await evaluator.evaluate({
      actor: { id: 'user-1', roles: ['user'], attributes: {} },
      action: 'resource:read',
      resource: { type: 'document', id: 'doc-1', attributes: {} },
      environment: {},
    });

    expect(decision.decision).toBe('ALLOW');
    expect(decision.policyId).toBeTruthy();
  });

  test('deny-override: explicit DENY wins immediately', async () => {
    const store = new InMemoryPolicyStore();

    const allow = await store.create({
      name: 'Allow document reads for users',
      effect: 'ALLOW',
      subjects: { roles: ['user'] },
      actions: ['resource:read'],
      resources: ['document:*'],
      priority: 10,
      enabled: true,
    });

    const deny = await store.create({
      name: 'Deny reads for sensitive docs',
      effect: 'DENY',
      subjects: { roles: ['user'] },
      actions: ['resource:read'],
      resources: ['document:sensitive-*'],
      priority: 100,
      enabled: true,
    });

    const evaluator = new PolicyEvaluator(store);
    const decision = await evaluator.evaluate({
      actor: { id: 'user-1', roles: ['user'], attributes: {} },
      action: 'resource:read',
      resource: { type: 'document', id: 'sensitive-123', attributes: {} },
      environment: {},
    });

    expect(decision.decision).toBe('DENY');
    expect(decision.policyId).toBe(deny.id);
    expect(decision.policyId).not.toBe(allow.id);
  });

  test('fail-closed: policy store errors -> DENY', async () => {
    const evaluator = new PolicyEvaluator({
      // Only implement what evaluator calls for this test
      // eslint-disable-next-line @typescript-eslint/require-await
      async findApplicable() {
        throw new Error('boom');
      },
    } as unknown as PolicyStore);

    const decision = await evaluator.evaluate({
      actor: { id: 'user-1', roles: ['user'], attributes: {} },
      action: 'resource:read',
      resource: { type: 'document', id: 'doc-1', attributes: {} },
      environment: {},
    });

    expect(decision.decision).toBe('DENY');
    expect(decision.reason.toLowerCase()).toContain('error');
  });
});
