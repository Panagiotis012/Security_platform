// ─── Alert Manager ───
// Manages the full lifecycle of security alerts: creation, routing, deduplication,
// acknowledgement, investigation, and resolution.
// Alert states: OPEN -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED

import { v4 as uuidv4 } from 'uuid';
import winston from 'winston';
import config from '../../config/default';
import type { Alert as DetectionAlert, AlertSeverity } from '../detection/detection-engine';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  defaultMeta: { service: 'alert-manager' },
  transports: [new winston.transports.Console()],
});

// ─── Alert Types ───

export type AlertState = 'OPEN' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED';

export interface ManagedAlert {
  id: string;
  detectionId: string;
  detectionName: string;
  severity: AlertSeverity;
  state: AlertState;
  title: string;
  description: string;
  eventCount: number;
  eventIds: string[];
  context: Record<string, unknown>;
  responseHooks: string[];
  createdAt: string;
  updatedAt: string;
  acknowledgedBy?: string;
  acknowledgedAt?: string;
  investigatedBy?: string;
  investigatedAt?: string;
  resolvedBy?: string;
  resolvedAt?: string;
  resolution?: string;
  duplicateCount: number;
  lastDuplicateAt?: string;
}

export interface AlertFilters {
  state?: AlertState;
  states?: AlertState[];
  severity?: AlertSeverity;
  severities?: AlertSeverity[];
  detectionId?: string;
  fromTimestamp?: string;
  toTimestamp?: string;
  limit?: number;
  offset?: number;
}

// ─── Alert Manager ───

export class AlertManager {
  private alerts: Map<string, ManagedAlert> = new Map();
  // Deduplication key: detectionId + primary actor/context identifier
  private deduplicationIndex: Map<string, string> = new Map();
  private webhookCallback: ((alert: ManagedAlert) => Promise<void>) | null = null;
  private totalCreated = 0;
  private totalDeduplicated = 0;
  private totalRouted = 0;

  constructor() {
    logger.info('AlertManager initialized');
  }

  /**
   * Set a webhook callback for alert routing.
   * In production, this would call external webhook endpoints.
   */
  onWebhook(callback: (alert: ManagedAlert) => Promise<void>): void {
    this.webhookCallback = callback;
  }

  /**
   * Process alerts from the detection engine.
   * Handles deduplication, creation, and routing.
   */
  async processDetectionAlerts(detectionAlerts: DetectionAlert[]): Promise<ManagedAlert[]> {
    const managedAlerts: ManagedAlert[] = [];

    for (const detAlert of detectionAlerts) {
      const managed = await this.createAlert(detAlert);
      if (managed) {
        managedAlerts.push(managed);
      }
    }

    return managedAlerts;
  }

  /**
   * Create a new alert or deduplicate against an existing one.
   */
  async createAlert(detAlert: DetectionAlert): Promise<ManagedAlert | null> {
    // Build deduplication key from detection ID + primary context identifier
    const deduplicationKey = this.buildDeduplicationKey(detAlert);
    const existingAlertId = this.deduplicationIndex.get(deduplicationKey);

    // Check if we should deduplicate
    if (existingAlertId) {
      const existingAlert = this.alerts.get(existingAlertId);
      if (existingAlert && existingAlert.state !== 'RESOLVED') {
        // Check suppression window
        const suppressionSeconds = config.suppression.perDetection[detAlert.detectionId]
          || config.suppression.defaultWindowSeconds;
        const suppressionCutoff = new Date(
          Date.now() - suppressionSeconds * 1000
        ).toISOString();

        if (existingAlert.updatedAt > suppressionCutoff) {
          // Within suppression window: update the existing alert
          existingAlert.duplicateCount++;
          existingAlert.lastDuplicateAt = new Date().toISOString();
          existingAlert.updatedAt = new Date().toISOString();
          existingAlert.eventCount += detAlert.events.length;

          // Add new event IDs (capped)
          const newEventIds = detAlert.events.map((e) => e.id);
          existingAlert.eventIds = [
            ...existingAlert.eventIds,
            ...newEventIds,
          ].slice(-200); // Keep last 200 event IDs

          this.totalDeduplicated++;

          logger.info('Alert deduplicated', {
            alertId: existingAlert.id,
            detectionId: detAlert.detectionId,
            duplicateCount: existingAlert.duplicateCount,
          });

          return null; // Deduplicated, no new alert
        }
      }
    }

    // Create new managed alert
    const managedAlert: ManagedAlert = {
      id: uuidv4(),
      detectionId: detAlert.detectionId,
      detectionName: detAlert.detectionName,
      severity: detAlert.severity,
      state: 'OPEN',
      title: detAlert.title,
      description: detAlert.description,
      eventCount: detAlert.events.length,
      eventIds: detAlert.events.map((e) => e.id),
      context: detAlert.context,
      responseHooks: detAlert.responseHooks,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      duplicateCount: 0,
    };

    this.alerts.set(managedAlert.id, managedAlert);
    this.deduplicationIndex.set(deduplicationKey, managedAlert.id);
    this.totalCreated++;

    logger.warn('New alert created', {
      alertId: managedAlert.id,
      severity: managedAlert.severity,
      detection: managedAlert.detectionName,
      title: managedAlert.title,
    });

    // Route the alert
    await this.routeAlert(managedAlert);

    return managedAlert;
  }

  /**
   * Route an alert to appropriate channels based on severity.
   */
  private async routeAlert(alert: ManagedAlert): Promise<void> {
    this.totalRouted++;

    const routingConfig = this.getRoutingConfig(alert.severity);

    for (const channel of routingConfig.channels) {
      try {
        switch (channel) {
          case 'webhook':
            if (this.webhookCallback) {
              await this.webhookCallback(alert);
              logger.info('Alert routed via webhook', {
                alertId: alert.id,
                severity: alert.severity,
              });
            } else {
              logger.warn('Webhook callback not configured, logging alert', {
                alertId: alert.id,
                severity: alert.severity,
              });
            }
            break;

          case 'log':
            // Always log alerts (this is the minimum routing)
            const logLevel = alert.severity === 'CRITICAL' ? 'error' : 'warn';
            logger.log(logLevel, `SECURITY ALERT [${alert.severity}]: ${alert.title}`, {
              alertId: alert.id,
              detectionId: alert.detectionId,
              description: alert.description,
              context: alert.context,
            });
            break;

          case 'queue':
            // In production, this would enqueue to a message broker (SQS, RabbitMQ, etc.)
            logger.info('Alert queued for async processing', {
              alertId: alert.id,
              severity: alert.severity,
            });
            break;
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        logger.error('Alert routing failed', {
          alertId: alert.id,
          channel,
          error: message,
        });
      }
    }
  }

  /**
   * Acknowledge an alert (SOC analyst has seen it).
   */
  acknowledgeAlert(
    alertId: string,
    userId: string
  ): { success: boolean; alert?: ManagedAlert; error?: string } {
    const alert = this.alerts.get(alertId);
    if (!alert) {
      return { success: false, error: 'Alert not found' };
    }

    if (alert.state !== 'OPEN') {
      return { success: false, error: `Cannot acknowledge alert in state "${alert.state}"` };
    }

    alert.state = 'ACKNOWLEDGED';
    alert.acknowledgedBy = userId;
    alert.acknowledgedAt = new Date().toISOString();
    alert.updatedAt = new Date().toISOString();

    logger.info('Alert acknowledged', {
      alertId,
      acknowledgedBy: userId,
    });

    return { success: true, alert };
  }

  /**
   * Move alert to INVESTIGATING state.
   */
  investigateAlert(
    alertId: string,
    userId: string
  ): { success: boolean; alert?: ManagedAlert; error?: string } {
    const alert = this.alerts.get(alertId);
    if (!alert) {
      return { success: false, error: 'Alert not found' };
    }

    if (alert.state !== 'ACKNOWLEDGED' && alert.state !== 'OPEN') {
      return { success: false, error: `Cannot investigate alert in state "${alert.state}"` };
    }

    alert.state = 'INVESTIGATING';
    alert.investigatedBy = userId;
    alert.investigatedAt = new Date().toISOString();
    alert.updatedAt = new Date().toISOString();

    logger.info('Alert under investigation', {
      alertId,
      investigatedBy: userId,
    });

    return { success: true, alert };
  }

  /**
   * Resolve an alert with a resolution note.
   */
  resolveAlert(
    alertId: string,
    userId: string,
    resolution: string
  ): { success: boolean; alert?: ManagedAlert; error?: string } {
    const alert = this.alerts.get(alertId);
    if (!alert) {
      return { success: false, error: 'Alert not found' };
    }

    if (alert.state === 'RESOLVED') {
      return { success: false, error: 'Alert is already resolved' };
    }

    alert.state = 'RESOLVED';
    alert.resolvedBy = userId;
    alert.resolvedAt = new Date().toISOString();
    alert.resolution = resolution;
    alert.updatedAt = new Date().toISOString();

    logger.info('Alert resolved', {
      alertId,
      resolvedBy: userId,
      resolution,
    });

    return { success: true, alert };
  }

  /**
   * Query alerts with filters.
   */
  queryAlerts(filters: AlertFilters): { alerts: ManagedAlert[]; total: number } {
    let results = Array.from(this.alerts.values());

    if (filters.state) {
      results = results.filter((a) => a.state === filters.state);
    }
    if (filters.states && filters.states.length > 0) {
      results = results.filter((a) => filters.states!.includes(a.state));
    }
    if (filters.severity) {
      results = results.filter((a) => a.severity === filters.severity);
    }
    if (filters.severities && filters.severities.length > 0) {
      results = results.filter((a) => filters.severities!.includes(a.severity));
    }
    if (filters.detectionId) {
      results = results.filter((a) => a.detectionId === filters.detectionId);
    }
    if (filters.fromTimestamp) {
      results = results.filter((a) => a.createdAt >= filters.fromTimestamp!);
    }
    if (filters.toTimestamp) {
      results = results.filter((a) => a.createdAt <= filters.toTimestamp!);
    }

    // Sort by creation time, newest first
    results.sort((a, b) => b.createdAt.localeCompare(a.createdAt));

    const total = results.length;
    const offset = filters.offset ?? 0;
    const limit = filters.limit ?? 50;
    const paged = results.slice(offset, offset + limit);

    return { alerts: paged, total };
  }

  /**
   * Get a single alert by ID.
   */
  getAlert(alertId: string): ManagedAlert | undefined {
    return this.alerts.get(alertId);
  }

  /**
   * Get alert manager metrics.
   */
  getMetrics(): {
    totalCreated: number;
    totalDeduplicated: number;
    totalRouted: number;
    openAlerts: number;
    acknowledgedAlerts: number;
    investigatingAlerts: number;
    resolvedAlerts: number;
    bySeverity: Record<AlertSeverity, number>;
  } {
    const allAlerts = Array.from(this.alerts.values());
    const bySeverity: Record<AlertSeverity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    };

    for (const alert of allAlerts) {
      if (alert.state !== 'RESOLVED') {
        bySeverity[alert.severity]++;
      }
    }

    return {
      totalCreated: this.totalCreated,
      totalDeduplicated: this.totalDeduplicated,
      totalRouted: this.totalRouted,
      openAlerts: allAlerts.filter((a) => a.state === 'OPEN').length,
      acknowledgedAlerts: allAlerts.filter((a) => a.state === 'ACKNOWLEDGED').length,
      investigatingAlerts: allAlerts.filter((a) => a.state === 'INVESTIGATING').length,
      resolvedAlerts: allAlerts.filter((a) => a.state === 'RESOLVED').length,
      bySeverity,
    };
  }

  // ─── Private helpers ───

  private buildDeduplicationKey(alert: DetectionAlert): string {
    // Primary actor or IP from context
    const primaryActor =
      (alert.context.actorId as string) ||
      (alert.context.userId as string) ||
      (alert.context.sourceIp as string) ||
      (alert.context.sessionId as string) ||
      (alert.context.ipRange as string) ||
      'global';

    return `${alert.detectionId}:${primaryActor}`;
  }

  private getRoutingConfig(severity: AlertSeverity) {
    switch (severity) {
      case 'CRITICAL':
        return config.alertRouting.critical;
      case 'HIGH':
        return config.alertRouting.high;
      case 'MEDIUM':
        return config.alertRouting.medium;
      case 'LOW':
        return config.alertRouting.low;
      default:
        return config.alertRouting.low;
    }
  }
}
