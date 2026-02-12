// ─── Mass Data Export / Exfiltration Detection ───
// Detects mass data export or exfiltration attempts.
// Trigger: user accesses >100 records in 5 minutes OR downloads >50MB.
// Severity: MEDIUM-HIGH (treated as HIGH in our severity system)
// Response: throttle access, alert SOC.

import { v4 as uuidv4 } from 'uuid';
import config from '../../../config/default';
import type { AuditEvent } from '../../audit/audit-store';
import type { Detection, Alert, AlertSeverity } from '../detection-engine';

const thresholds = config.detectionThresholds.massExport;

export const MassExportDetection: Detection = {
  id: 'mass-export',
  name: 'Mass Data Export Detection',
  description: 'Detects potential data exfiltration through excessive record access or large data downloads.',
  severity: 'HIGH' as AlertSeverity,
  type: 'threshold',
  enabled: true,
  suppressionWindowSeconds: config.suppression.perDetection['mass-export'] || 300,
  thresholds: {
    maxRecordsPerWindow: thresholds.maxRecordsPerWindow,
    maxBytesPerWindow: thresholds.maxBytesPerWindow,
    windowMinutes: thresholds.windowMinutes,
  },

  evaluate(events: AuditEvent[]): Alert[] {
    const alerts: Alert[] = [];
    const windowMs = this.thresholds.windowMinutes * 60 * 1000;
    const now = Date.now();
    const cutoff = new Date(now - windowMs).toISOString();

    // Filter to data access events within the window
    const dataAccessActions = [
      'data.read', 'data.list', 'data.export', 'data.download', 'data.bulk-read',
      'resource.read', 'resource.list', 'api.query', 'report.generate', 'report.export',
    ];

    const dataEvents = events.filter(
      (e) =>
        e.timestamp >= cutoff &&
        e.result.decision === 'ALLOW' &&
        dataAccessActions.some((action) => e.action.includes(action) || e.action === action)
    );

    if (dataEvents.length === 0) return alerts;

    // Group by actor
    const byActor = new Map<string, AuditEvent[]>();
    for (const event of dataEvents) {
      const key = event.actor.id;
      const existing = byActor.get(key) || [];
      existing.push(event);
      byActor.set(key, existing);
    }

    for (const [actorId, actorEvents] of byActor) {
      // Count distinct records accessed
      const recordsAccessed = new Set<string>();
      let totalBytes = 0;
      const resourceTypes = new Set<string>();

      for (const event of actorEvents) {
        // Each event with a unique resource ID counts as a record access
        recordsAccessed.add(`${event.resource.type}:${event.resource.id}`);
        resourceTypes.add(event.resource.type);

        // Extract bytes transferred from metadata if available
        const bytes = event.metadata?.bytesTransferred as number | undefined;
        if (bytes && typeof bytes === 'number') {
          totalBytes += bytes;
        }

        // Also check resource attributes for record counts (e.g., bulk reads)
        const recordCount = event.resource.attributes?.recordCount as number | undefined;
        if (recordCount && typeof recordCount === 'number') {
          // For bulk operations, add the record count to simulate individual accesses
          for (let i = 0; i < recordCount; i++) {
            recordsAccessed.add(`${event.resource.type}:${event.resource.id}:bulk:${i}`);
          }
        }

        const responseBytes = event.resource.attributes?.responseBytes as number | undefined;
        if (responseBytes && typeof responseBytes === 'number') {
          totalBytes += responseBytes;
        }
      }

      // Check thresholds
      const recordsExceeded = recordsAccessed.size > this.thresholds.maxRecordsPerWindow;
      const bytesExceeded = totalBytes > this.thresholds.maxBytesPerWindow;

      if (recordsExceeded || bytesExceeded) {
        const reasons: string[] = [];
        if (recordsExceeded) {
          reasons.push(`${recordsAccessed.size} records accessed (threshold: ${this.thresholds.maxRecordsPerWindow})`);
        }
        if (bytesExceeded) {
          const mbTransferred = (totalBytes / (1024 * 1024)).toFixed(1);
          const mbThreshold = (this.thresholds.maxBytesPerWindow / (1024 * 1024)).toFixed(1);
          reasons.push(`${mbTransferred}MB transferred (threshold: ${mbThreshold}MB)`);
        }

        alerts.push({
          id: uuidv4(),
          detectionId: this.id,
          detectionName: this.name,
          severity: this.severity,
          title: `Mass data export by user ${actorId}`,
          description: `Potential data exfiltration by user "${actorId}": ${reasons.join('; ')} in ${this.thresholds.windowMinutes} minutes across ${resourceTypes.size} resource type(s).`,
          events: actorEvents.slice(0, 50),
          context: {
            actorId,
            recordsAccessed: recordsAccessed.size,
            bytesTransferred: totalBytes,
            bytesTransferredMB: parseFloat((totalBytes / (1024 * 1024)).toFixed(2)),
            resourceTypes: Array.from(resourceTypes),
            eventCount: actorEvents.length,
            windowMinutes: this.thresholds.windowMinutes,
            recordsThresholdExceeded: recordsExceeded,
            bytesThresholdExceeded: bytesExceeded,
            sourceIps: [...new Set(actorEvents.map((e) => e.context.ip).filter(Boolean))],
          },
          responseHooks: ['THROTTLE_USER'],
          timestamp: new Date().toISOString(),
        });
      }
    }

    return alerts;
  },
};
