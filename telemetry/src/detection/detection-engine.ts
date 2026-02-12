// ─── Detection Engine ───
// Core engine that evaluates registered detection rules against a sliding window of audit events.
// Supports threshold-based, pattern-based, and statistical anomaly detections.
// Each detection has adjustable thresholds and suppression windows.

import winston from 'winston';
import config from '../../config/default';
import type { AuditEvent, AuditStore } from '../audit/audit-store';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  defaultMeta: { service: 'detection-engine' },
  transports: [new winston.transports.Console()],
});

// ─── Types ───

export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type DetectionType = 'threshold' | 'pattern' | 'statistical' | 'behavioral';

export interface Alert {
  id: string;
  detectionId: string;
  detectionName: string;
  severity: AlertSeverity;
  title: string;
  description: string;
  events: AuditEvent[];
  context: Record<string, unknown>;
  responseHooks: string[];
  timestamp: string;
}

export interface Detection {
  id: string;
  name: string;
  description: string;
  severity: AlertSeverity;
  type: DetectionType;
  enabled: boolean;
  /** Evaluate a window of events and return any alerts triggered */
  evaluate(events: AuditEvent[]): Alert[];
  /** Suppression window in seconds (same detection + same actor) */
  suppressionWindowSeconds: number;
  /** Adjustable thresholds specific to this detection */
  thresholds: Record<string, number>;
}

export interface DetectionMetrics {
  detectionId: string;
  detectionName: string;
  evaluations: number;
  alertsGenerated: number;
  lastEvaluation: string | null;
  lastAlertTime: string | null;
  averageEvalTimeMs: number;
}

// ─── Detection Engine ───

export class DetectionEngine {
  private detections: Map<string, Detection> = new Map();
  private metrics: Map<string, DetectionMetrics> = new Map();
  private store: AuditStore & { getEventsInWindow(windowMs: number): AuditEvent[] };
  private alertCallback: ((alerts: Alert[]) => void) | null = null;
  private running = false;
  private intervalHandle: ReturnType<typeof setInterval> | null = null;
  private evaluationCount = 0;
  private totalAlertsGenerated = 0;

  constructor(store: AuditStore & { getEventsInWindow(windowMs: number): AuditEvent[] }) {
    this.store = store;
    logger.info('DetectionEngine initialized');
  }

  /**
   * Register a detection rule with the engine.
   */
  registerDetection(detection: Detection): void {
    if (this.detections.has(detection.id)) {
      logger.warn('Detection already registered, overwriting', { id: detection.id });
    }

    this.detections.set(detection.id, detection);
    this.metrics.set(detection.id, {
      detectionId: detection.id,
      detectionName: detection.name,
      evaluations: 0,
      alertsGenerated: 0,
      lastEvaluation: null,
      lastAlertTime: null,
      averageEvalTimeMs: 0,
    });

    logger.info('Detection registered', {
      id: detection.id,
      name: detection.name,
      severity: detection.severity,
      type: detection.type,
      enabled: detection.enabled,
    });
  }

  /**
   * Unregister a detection rule.
   */
  unregisterDetection(detectionId: string): boolean {
    const removed = this.detections.delete(detectionId);
    if (removed) {
      logger.info('Detection unregistered', { id: detectionId });
    }
    return removed;
  }

  /**
   * Enable or disable a specific detection.
   */
  setDetectionEnabled(detectionId: string, enabled: boolean): boolean {
    const detection = this.detections.get(detectionId);
    if (!detection) return false;
    detection.enabled = enabled;
    logger.info('Detection enabled state changed', { id: detectionId, enabled });
    return true;
  }

  /**
   * Update thresholds for a specific detection at runtime.
   */
  updateThresholds(detectionId: string, thresholds: Record<string, number>): boolean {
    const detection = this.detections.get(detectionId);
    if (!detection) return false;
    detection.thresholds = { ...detection.thresholds, ...thresholds };
    logger.info('Detection thresholds updated', { id: detectionId, thresholds: detection.thresholds });
    return true;
  }

  /**
   * Set a callback function that receives alerts generated during evaluation.
   */
  onAlerts(callback: (alerts: Alert[]) => void): void {
    this.alertCallback = callback;
  }

  /**
   * Run a single evaluation cycle: fetch recent events and run all enabled detections.
   */
  evaluate(): Alert[] {
    const windowMs = config.detectionEngine.eventWindowMinutes * 60 * 1000;
    const events = this.store.getEventsInWindow(windowMs);

    if (events.length === 0) {
      return [];
    }

    // Cap events to prevent memory issues
    const cappedEvents = events.length > config.detectionEngine.maxEventsPerEvaluation
      ? events.slice(events.length - config.detectionEngine.maxEventsPerEvaluation)
      : events;

    const allAlerts: Alert[] = [];
    this.evaluationCount++;

    for (const [id, detection] of this.detections) {
      if (!detection.enabled) continue;

      const metric = this.metrics.get(id)!;
      const startTime = Date.now();

      try {
        const alerts = detection.evaluate(cappedEvents);
        const evalTime = Date.now() - startTime;

        metric.evaluations++;
        metric.lastEvaluation = new Date().toISOString();
        metric.averageEvalTimeMs =
          (metric.averageEvalTimeMs * (metric.evaluations - 1) + evalTime) / metric.evaluations;

        if (alerts.length > 0) {
          metric.alertsGenerated += alerts.length;
          metric.lastAlertTime = new Date().toISOString();
          allAlerts.push(...alerts);

          logger.warn('Detection triggered', {
            detectionId: id,
            detectionName: detection.name,
            alertCount: alerts.length,
            severity: detection.severity,
          });
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        logger.error('Detection evaluation error', {
          detectionId: id,
          error: message,
        });
      }
    }

    this.totalAlertsGenerated += allAlerts.length;

    // Deliver alerts to callback
    if (allAlerts.length > 0 && this.alertCallback) {
      try {
        this.alertCallback(allAlerts);
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        logger.error('Alert callback error', { error: message });
      }
    }

    return allAlerts;
  }

  /**
   * Start periodic evaluation.
   */
  start(): void {
    if (this.running) {
      logger.warn('DetectionEngine already running');
      return;
    }

    const intervalMs = config.detectionEngine.evaluationIntervalSeconds * 1000;
    this.running = true;

    this.intervalHandle = setInterval(() => {
      try {
        this.evaluate();
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        logger.error('Periodic evaluation failed', { error: message });
      }
    }, intervalMs);

    logger.info('DetectionEngine started', {
      intervalSeconds: config.detectionEngine.evaluationIntervalSeconds,
      registeredDetections: this.detections.size,
      enabledDetections: Array.from(this.detections.values()).filter((d) => d.enabled).length,
    });
  }

  /**
   * Stop periodic evaluation.
   */
  stop(): void {
    if (this.intervalHandle) {
      clearInterval(this.intervalHandle);
      this.intervalHandle = null;
    }
    this.running = false;
    logger.info('DetectionEngine stopped');
  }

  /**
   * Get all registered detections.
   */
  getDetections(): Detection[] {
    return Array.from(this.detections.values());
  }

  /**
   * Get metrics for all detections.
   */
  getMetrics(): DetectionMetrics[] {
    return Array.from(this.metrics.values());
  }

  /**
   * Get aggregate engine metrics.
   */
  getEngineMetrics(): {
    running: boolean;
    totalEvaluations: number;
    totalAlertsGenerated: number;
    registeredDetections: number;
    enabledDetections: number;
  } {
    return {
      running: this.running,
      totalEvaluations: this.evaluationCount,
      totalAlertsGenerated: this.totalAlertsGenerated,
      registeredDetections: this.detections.size,
      enabledDetections: Array.from(this.detections.values()).filter((d) => d.enabled).length,
    };
  }

  /**
   * Check if the engine is running.
   */
  isRunning(): boolean {
    return this.running;
  }
}
