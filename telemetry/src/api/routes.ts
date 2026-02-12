// ─── Telemetry & Detection API Routes ───
// Exposes audit ingestion, querying, alert management, and detection metrics.

import type { Request, Response, NextFunction } from 'express';
import { Router } from 'express';
import winston from 'winston';
import type { AuditIngester } from '../audit/audit-ingester';
import type { AuditStore } from '../audit/audit-store';
import type { DetectionEngine } from '../detection/detection-engine';
import type { AlertManager } from '../alerting/alert-manager';
import type { ResponseHookExecutor, HookType } from '../alerting/response-hooks';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  defaultMeta: { service: 'api-routes' },
  transports: [new winston.transports.Console()],
});

const SOC_ROLES = ['admin', 'security-admin', 'incident-responder', 'security-analyst'] as const;
const SOC_PRIVILEGED_ROLES = ['admin', 'security-admin', 'incident-responder'] as const;

function parseCsvHeader(value: string | string[] | undefined): string[] {
  const raw = Array.isArray(value) ? value.join(',') : (value ?? '');
  return raw
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

export function requireGatewayPrincipal() {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = String(req.headers['x-authenticated-user'] ?? '').trim();
    if (!user) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    next();
  };
}

export function requireAnyRole(allowedRoles: readonly string[]) {
  const allowed = new Set(allowedRoles.map((r) => r.toLowerCase()));
  return (req: Request, res: Response, next: NextFunction): void => {
    const roles = parseCsvHeader(req.headers['x-authenticated-roles'] as string | string[] | undefined);
    const ok = roles.some((r) => allowed.has(r));
    if (!ok) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }
    next();
  };
}

export function createAuditRoutes(ingester: AuditIngester, store: AuditStore): Router {
  const router = Router();
  router.use('/v1/audit', requireGatewayPrincipal());

  // ─── POST /v1/audit/events ─── Ingest audit events (internal services only)
  router.post('/v1/audit/events', async (req: Request, res: Response) => {
    try {
      const body = req.body;

      // Support both single event and batch ingestion
      if (Array.isArray(body)) {
        const results = await ingester.ingestBatch(body);
        const successCount = results.filter((r) => r.success).length;
        const failureCount = results.length - successCount;

        return res.status(successCount > 0 ? 202 : 400).json({
          accepted: successCount,
          rejected: failureCount,
          results: results.map((r) => ({
            success: r.success,
            eventId: r.event?.id,
            error: r.error,
          })),
        });
      }

      const result = await ingester.ingest(body);
      if (result.success) {
        return res.status(202).json({
          accepted: 1,
          eventId: result.event!.id,
          riskScore: result.event!.riskScore,
        });
      }

      return res.status(400).json({
        accepted: 0,
        error: result.error,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.error('Audit ingestion error', { error: message });
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ─── GET /v1/audit/events ─── Query audit events (admin)
  router.get('/v1/audit/events', async (req: Request, res: Response) => {
    try {
      const filters = {
        actorId: req.query.actorId as string | undefined,
        actorType: req.query.actorType as 'user' | 'service' | 'system' | 'api-key' | undefined,
        action: req.query.action as string | undefined,
        actions: req.query.actions ? (req.query.actions as string).split(',') : undefined,
        resourceType: req.query.resourceType as string | undefined,
        resourceId: req.query.resourceId as string | undefined,
        decision: req.query.decision as 'ALLOW' | 'DENY' | 'CHALLENGE' | 'ERROR' | undefined,
        decisions: req.query.decisions ? (req.query.decisions as string).split(',') as ('ALLOW' | 'DENY' | 'CHALLENGE' | 'ERROR')[] : undefined,
        minRiskScore: req.query.minRiskScore ? parseFloat(req.query.minRiskScore as string) : undefined,
        maxRiskScore: req.query.maxRiskScore ? parseFloat(req.query.maxRiskScore as string) : undefined,
        fromTimestamp: req.query.from as string | undefined,
        toTimestamp: req.query.to as string | undefined,
        correlationId: req.query.correlationId as string | undefined,
        ip: req.query.ip as string | undefined,
        limit: req.query.limit ? parseInt(req.query.limit as string, 10) : 100,
        offset: req.query.offset ? parseInt(req.query.offset as string, 10) : 0,
      };

      const result = await store.query(filters);

      return res.status(200).json({
        events: result.events,
        total: result.total,
        limit: filters.limit,
        offset: filters.offset,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.error('Audit query error', { error: message });
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ─── GET /v1/audit/verify ─── Verify hash chain integrity
  router.get('/v1/audit/verify', requireAnyRole(SOC_ROLES), (req: Request, res: Response) => {
    try {
      const fromIndex = req.query.from ? parseInt(req.query.from as string, 10) : undefined;
      const toIndex = req.query.to ? parseInt(req.query.to as string, 10) : undefined;

      const result = store.verifyIntegrity(fromIndex, toIndex);
      const head = store.getChainHead();

      return res.status(200).json({
        integrity: result.valid ? 'VERIFIED' : 'BROKEN',
        valid: result.valid,
        brokenAtIndex: result.brokenAtIndex,
        chainHead: head
          ? {
              index: head.index,
              hash: head.hash,
              previousHash: head.previousHash,
              timestamp: head.timestamp,
            }
          : null,
        totalEvents: store.getCount(),
        verifiedAt: new Date().toISOString(),
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.error('Audit verify error', { error: message });
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ─── GET /v1/audit/export ─── Export audit events for compliance
  router.get('/v1/audit/export', requireAnyRole(SOC_ROLES), async (req: Request, res: Response) => {
    try {
      const from = req.query.from as string;
      const to = req.query.to as string;

      if (!from || !to) {
        return res.status(400).json({ error: 'Both "from" and "to" query parameters are required' });
      }

      const events = await store.exportRange(from, to);

      return res.status(200).json({
        events,
        count: events.length,
        exportedAt: new Date().toISOString(),
        range: { from, to },
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.error('Audit export error', { error: message });
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
}

export function createAlertRoutes(alertManager: AlertManager): Router {
  const router = Router();
  router.use('/v1/alerts', requireGatewayPrincipal(), requireAnyRole(SOC_ROLES));

  // ─── GET /v1/alerts ─── List alerts with filters
  router.get('/v1/alerts', (req: Request, res: Response) => {
    try {
      const filters = {
        state: req.query.state as 'OPEN' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED' | undefined,
        states: req.query.states ? (req.query.states as string).split(',') as ('OPEN' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED')[] : undefined,
        severity: req.query.severity as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | undefined,
        severities: req.query.severities ? (req.query.severities as string).split(',') as ('CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW')[] : undefined,
        detectionId: req.query.detectionId as string | undefined,
        fromTimestamp: req.query.from as string | undefined,
        toTimestamp: req.query.to as string | undefined,
        limit: req.query.limit ? parseInt(req.query.limit as string, 10) : 50,
        offset: req.query.offset ? parseInt(req.query.offset as string, 10) : 0,
      };

      const result = alertManager.queryAlerts(filters);

      return res.status(200).json({
        alerts: result.alerts,
        total: result.total,
        limit: filters.limit,
        offset: filters.offset,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.error('Alert query error', { error: message });
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ─── GET /v1/alerts/:id ─── Get a single alert
  router.get('/v1/alerts/:id', (req: Request, res: Response) => {
    const alert = alertManager.getAlert(req.params.id);
    if (!alert) {
      return res.status(404).json({ error: 'Alert not found' });
    }
    return res.status(200).json(alert);
  });

  // ─── POST /v1/alerts/:id/acknowledge ─── Acknowledge alert
  router.post('/v1/alerts/:id/acknowledge', (req: Request, res: Response) => {
    try {
      const userId = req.body.userId || req.headers['x-user-id'] as string;
      if (!userId) {
        return res.status(400).json({ error: 'userId is required' });
      }

      const result = alertManager.acknowledgeAlert(req.params.id, userId);
      if (!result.success) {
        return res.status(400).json({ error: result.error });
      }

      return res.status(200).json({
        success: true,
        alert: result.alert,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.error('Alert acknowledge error', { error: message });
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ─── POST /v1/alerts/:id/investigate ─── Move to investigating
  router.post('/v1/alerts/:id/investigate', (req: Request, res: Response) => {
    try {
      const userId = req.body.userId || req.headers['x-user-id'] as string;
      if (!userId) {
        return res.status(400).json({ error: 'userId is required' });
      }

      const result = alertManager.investigateAlert(req.params.id, userId);
      if (!result.success) {
        return res.status(400).json({ error: result.error });
      }

      return res.status(200).json({
        success: true,
        alert: result.alert,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.error('Alert investigate error', { error: message });
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ─── POST /v1/alerts/:id/resolve ─── Resolve alert
  router.post('/v1/alerts/:id/resolve', (req: Request, res: Response) => {
    try {
      const userId = req.body.userId || req.headers['x-user-id'] as string;
      const resolution = req.body.resolution as string;

      if (!userId) {
        return res.status(400).json({ error: 'userId is required' });
      }
      if (!resolution) {
        return res.status(400).json({ error: 'resolution is required' });
      }

      const result = alertManager.resolveAlert(req.params.id, userId, resolution);
      if (!result.success) {
        return res.status(400).json({ error: result.error });
      }

      return res.status(200).json({
        success: true,
        alert: result.alert,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.error('Alert resolve error', { error: message });
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
}

export function createDetectionRoutes(
  engine: DetectionEngine,
  alertManager: AlertManager,
  responseHookExecutor: ResponseHookExecutor,
  ingester: AuditIngester
): Router {
  const router = Router();
  router.use('/v1/detections', requireGatewayPrincipal(), requireAnyRole(SOC_ROLES));
  router.use('/v1/metrics', requireGatewayPrincipal(), requireAnyRole(SOC_ROLES));
  router.use('/v1/hooks', requireGatewayPrincipal(), requireAnyRole(SOC_PRIVILEGED_ROLES));

  // ─── GET /v1/detections ─── List active detections
  router.get('/v1/detections', (_req: Request, res: Response) => {
    try {
      const detections = engine.getDetections().map((d) => ({
        id: d.id,
        name: d.name,
        description: d.description,
        severity: d.severity,
        type: d.type,
        enabled: d.enabled,
        suppressionWindowSeconds: d.suppressionWindowSeconds,
        thresholds: d.thresholds,
      }));

      return res.status(200).json({
        detections,
        total: detections.length,
        engineRunning: engine.isRunning(),
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.error('Detection list error', { error: message });
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ─── PUT /v1/detections/:id/enabled ─── Enable/disable a detection
  router.put('/v1/detections/:id/enabled', (req: Request, res: Response) => {
    try {
      const { enabled } = req.body;
      if (typeof enabled !== 'boolean') {
        return res.status(400).json({ error: '"enabled" must be a boolean' });
      }

      const success = engine.setDetectionEnabled(req.params.id, enabled);
      if (!success) {
        return res.status(404).json({ error: 'Detection not found' });
      }

      return res.status(200).json({ success: true, detectionId: req.params.id, enabled });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.error('Detection toggle error', { error: message });
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ─── PUT /v1/detections/:id/thresholds ─── Update detection thresholds
  router.put('/v1/detections/:id/thresholds', (req: Request, res: Response) => {
    try {
      const thresholds = req.body;
      if (!thresholds || typeof thresholds !== 'object') {
        return res.status(400).json({ error: 'Request body must be an object of thresholds' });
      }

      const success = engine.updateThresholds(req.params.id, thresholds);
      if (!success) {
        return res.status(404).json({ error: 'Detection not found' });
      }

      return res.status(200).json({ success: true, detectionId: req.params.id, thresholds });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.error('Detection threshold update error', { error: message });
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ─── GET /v1/metrics ─── Detection metrics and stats
  router.get('/v1/metrics', (_req: Request, res: Response) => {
    try {
      const engineMetrics = engine.getEngineMetrics();
      const detectionMetrics = engine.getMetrics();
      const alertMetrics = alertManager.getMetrics();
      const hookMetrics = responseHookExecutor.getMetrics();
      const ingestionMetrics = ingester.getMetrics();

      return res.status(200).json({
        engine: engineMetrics,
        detections: detectionMetrics,
        alerts: alertMetrics,
        responseHooks: hookMetrics,
        ingestion: ingestionMetrics,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.error('Metrics error', { error: message });
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ─── POST /v1/hooks/execute ─── Manually trigger a response hook (admin)
  router.post('/v1/hooks/execute', async (req: Request, res: Response) => {
    try {
      const { hookType, context } = req.body;
      if (!hookType || !context) {
        return res.status(400).json({ error: 'hookType and context are required' });
      }

      const validHookTypes: HookType[] = [
        'BLOCK_IP', 'REVOKE_SESSIONS', 'REQUIRE_STEP_UP', 'THROTTLE_USER', 'ROTATE_CREDENTIALS',
      ];
      if (!validHookTypes.includes(hookType)) {
        return res.status(400).json({ error: `Invalid hookType. Must be one of: ${validHookTypes.join(', ')}` });
      }

      const result = await responseHookExecutor.executeHook(hookType, context);

      return res.status(200).json(result);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.error('Hook execution error', { error: message });
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ─── GET /v1/hooks/blocked-ips ─── List currently blocked IPs
  router.get('/v1/hooks/blocked-ips', (_req: Request, res: Response) => {
    try {
      const blockedIps = responseHookExecutor.getBlockedIps();
      return res.status(200).json({ blockedIps, count: blockedIps.length });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.error('Blocked IPs list error', { error: message });
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
}
