import type { Request, Response } from 'express';
import { Router } from 'express';
import {
  PolicyRequestSchema,
  CreatePolicyInput,
  UpdatePolicyInput,
  PolicyListFiltersSchema,
  DecisionQuerySchema,
} from '../models/policy-schema';
import type { PolicyEvaluator } from '../engine/evaluator';
import type { PolicyStore} from '../store/policy-store';
import { PolicyStoreError } from '../store/policy-store';
import type { DecisionLogger } from '../store/decision-log';
import {
  adminAuth,
  validateBody,
} from './middleware';
import { createLogger } from '../utils/logger';

const logger = createLogger('routes');

/**
 * Create all API routes for the Policy Decision Point.
 */
export function createRoutes(
  evaluator: PolicyEvaluator,
  policyStore: PolicyStore,
  decisionLogger: DecisionLogger
): Router {
  const router = Router();

  // ─── POST /v1/evaluate - Main policy evaluation endpoint ──────────────

  router.post(
    '/v1/evaluate',
    validateBody(PolicyRequestSchema),
    async (req: Request, res: Response): Promise<void> => {
      try {
        const policyRequest = req.body;
        // Attach correlation ID from middleware
        policyRequest.correlationId = policyRequest.correlationId || req.correlationId;

        // Evaluate the request
        const decision = await evaluator.evaluate(policyRequest);

        // Log the decision (every ALLOW and DENY)
        try {
          await decisionLogger.log(policyRequest, decision);
        } catch (logErr) {
          // Decision logging failure should NOT affect the response
          logger.error('Failed to log decision', {
            correlationId: req.correlationId,
            error: logErr instanceof Error ? logErr.message : 'Unknown error',
          });
        }

        res.status(200).json({
          ...decision,
          correlationId: req.correlationId,
        });
      } catch (err) {
        logger.error('Evaluation endpoint error', {
          correlationId: req.correlationId,
          error: err instanceof Error ? err.message : 'Unknown error',
        });

        // FAIL-CLOSED: any error at the endpoint level also results in DENY
        res.status(200).json({
          decision: 'DENY',
          policyId: null,
          reason: 'Internal evaluation error - default deny (fail-closed)',
          timestamp: new Date().toISOString(),
          evaluationTimeMs: 0,
          correlationId: req.correlationId,
        });
      }
    }
  );

  // ─── POST /v1/policies - Create a new policy (admin only) ────────────

  router.post(
    '/v1/policies',
    adminAuth,
    validateBody(CreatePolicyInput),
    async (req: Request, res: Response): Promise<void> => {
      try {
        const policy = await policyStore.create(req.body);

        logger.info('Policy created via API', {
          correlationId: req.correlationId,
          policyId: policy.id,
          name: policy.name,
          adminUser: req.adminUser?.sub,
        });

        res.status(201).json(policy);
      } catch (err) {
        handleStoreError(err, req, res);
      }
    }
  );

  // ─── PUT /v1/policies/:id - Update a policy (admin only) ─────────────

  router.put(
    '/v1/policies/:id',
    adminAuth,
    validateBody(UpdatePolicyInput),
    async (req: Request, res: Response): Promise<void> => {
      try {
        const policy = await policyStore.update(req.params.id, req.body);

        logger.info('Policy updated via API', {
          correlationId: req.correlationId,
          policyId: policy.id,
          name: policy.name,
          version: policy.version,
          adminUser: req.adminUser?.sub,
        });

        res.status(200).json(policy);
      } catch (err) {
        handleStoreError(err, req, res);
      }
    }
  );

  // ─── DELETE /v1/policies/:id - Soft-delete a policy (admin only) ──────

  router.delete(
    '/v1/policies/:id',
    adminAuth,
    async (req: Request, res: Response): Promise<void> => {
      try {
        await policyStore.delete(req.params.id);

        logger.info('Policy deleted via API', {
          correlationId: req.correlationId,
          policyId: req.params.id,
          adminUser: req.adminUser?.sub,
        });

        res.status(204).send();
      } catch (err) {
        handleStoreError(err, req, res);
      }
    }
  );

  // ─── GET /v1/policies - List policies (admin only) ────────────────────

  router.get(
    '/v1/policies',
    adminAuth,
    async (req: Request, res: Response): Promise<void> => {
      try {
        // Parse and validate query parameters
        const filtersResult = PolicyListFiltersSchema.safeParse({
          effect: req.query.effect,
          enabled:
            req.query.enabled !== undefined
              ? req.query.enabled === 'true'
              : undefined,
          action: req.query.action,
          resource: req.query.resource,
          limit: req.query.limit ? parseInt(req.query.limit as string, 10) : undefined,
          offset: req.query.offset ? parseInt(req.query.offset as string, 10) : undefined,
        });

        if (!filtersResult.success) {
          res.status(400).json({
            error: 'Validation failed',
            message: 'Invalid query parameters',
            details: filtersResult.error.issues.map((i) => ({
              path: i.path.join('.'),
              message: i.message,
            })),
            correlationId: req.correlationId,
          });
          return;
        }

        const { policies, total } = await policyStore.list(filtersResult.data);

        res.status(200).json({
          policies,
          total,
          limit: filtersResult.data.limit,
          offset: filtersResult.data.offset,
        });
      } catch (err) {
        handleStoreError(err, req, res);
      }
    }
  );

  // ─── GET /v1/policies/:id - Get a single policy (admin only) ─────────

  router.get(
    '/v1/policies/:id',
    adminAuth,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const policy = await policyStore.findById(req.params.id);

        if (!policy) {
          res.status(404).json({
            error: 'Not found',
            message: `Policy "${req.params.id}" not found`,
            correlationId: req.correlationId,
          });
          return;
        }

        res.status(200).json(policy);
      } catch (err) {
        handleStoreError(err, req, res);
      }
    }
  );

  // ─── GET /v1/policies/:id/versions - Get policy version history ──────

  router.get(
    '/v1/policies/:id/versions',
    adminAuth,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const versions = await policyStore.getVersionHistory(req.params.id);

        if (versions.length === 0) {
          res.status(404).json({
            error: 'Not found',
            message: `No version history for policy "${req.params.id}"`,
            correlationId: req.correlationId,
          });
          return;
        }

        res.status(200).json({ versions });
      } catch (err) {
        handleStoreError(err, req, res);
      }
    }
  );

  // ─── GET /v1/decisions - Query decision logs (admin only) ─────────────

  router.get(
    '/v1/decisions',
    adminAuth,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const filtersResult = DecisionQuerySchema.safeParse({
          actorId: req.query.actorId,
          action: req.query.action,
          resourceType: req.query.resourceType,
          resourceId: req.query.resourceId,
          decision: req.query.decision,
          fromTime: req.query.fromTime,
          toTime: req.query.toTime,
          correlationId: req.query.correlationId,
          limit: req.query.limit ? parseInt(req.query.limit as string, 10) : undefined,
          offset: req.query.offset ? parseInt(req.query.offset as string, 10) : undefined,
        });

        if (!filtersResult.success) {
          res.status(400).json({
            error: 'Validation failed',
            message: 'Invalid query parameters',
            details: filtersResult.error.issues.map((i) => ({
              path: i.path.join('.'),
              message: i.message,
            })),
            correlationId: req.correlationId,
          });
          return;
        }

        const { entries, total } = await decisionLogger.query(filtersResult.data);

        res.status(200).json({
          entries,
          total,
          limit: filtersResult.data.limit,
          offset: filtersResult.data.offset,
        });
      } catch (err) {
        logger.error('Decision query error', {
          correlationId: req.correlationId,
          error: err instanceof Error ? err.message : 'Unknown error',
        });

        res.status(500).json({
          error: 'Internal server error',
          message: 'Failed to query decision logs',
          correlationId: req.correlationId,
        });
      }
    }
  );

  // ─── GET /v1/decisions/export - Export decision logs (admin only) ─────

  router.get(
    '/v1/decisions/export',
    adminAuth,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const filtersResult = DecisionQuerySchema.safeParse({
          actorId: req.query.actorId,
          action: req.query.action,
          resourceType: req.query.resourceType,
          resourceId: req.query.resourceId,
          decision: req.query.decision,
          fromTime: req.query.fromTime,
          toTime: req.query.toTime,
          limit: 10000,
          offset: 0,
        });

        if (!filtersResult.success) {
          res.status(400).json({
            error: 'Validation failed',
            message: 'Invalid query parameters',
            correlationId: req.correlationId,
          });
          return;
        }

        const entries = await decisionLogger.export(filtersResult.data);

        res.setHeader('Content-Type', 'application/json');
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="decisions-export-${new Date().toISOString()}.json"`
        );
        res.status(200).json({ entries, exportedAt: new Date().toISOString() });
      } catch (err) {
        logger.error('Decision export error', {
          correlationId: req.correlationId,
          error: err instanceof Error ? err.message : 'Unknown error',
        });

        res.status(500).json({
          error: 'Internal server error',
          message: 'Failed to export decision logs',
          correlationId: req.correlationId,
        });
      }
    }
  );

  // ─── GET /v1/decisions/stats - Decision log statistics ────────────────

  router.get(
    '/v1/decisions/stats',
    adminAuth,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const stats = await decisionLogger.getStats();
        res.status(200).json(stats);
      } catch (err) {
        logger.error('Decision stats error', {
          correlationId: req.correlationId,
          error: err instanceof Error ? err.message : 'Unknown error',
        });

        res.status(500).json({
          error: 'Internal server error',
          message: 'Failed to get decision statistics',
          correlationId: req.correlationId,
        });
      }
    }
  );

  return router;
}

// ─── Error handling helper ──────────────────────────────────────────────────

function handleStoreError(err: unknown, req: Request, res: Response): void {
  if (err instanceof PolicyStoreError) {
    switch (err.code) {
      case 'NOT_FOUND':
        res.status(404).json({
          error: 'Not found',
          message: err.message,
          correlationId: req.correlationId,
        });
        return;
      case 'CONFLICT':
        res.status(409).json({
          error: 'Conflict',
          message: err.message,
          correlationId: req.correlationId,
        });
        return;
      case 'VALIDATION':
        res.status(400).json({
          error: 'Validation failed',
          message: err.message,
          correlationId: req.correlationId,
        });
        return;
    }
  }

  logger.error('Store operation error', {
    correlationId: req.correlationId,
    error: err instanceof Error ? err.message : 'Unknown error',
  });

  res.status(500).json({
    error: 'Internal server error',
    message: 'An unexpected error occurred',
    correlationId: req.correlationId,
  });
}
