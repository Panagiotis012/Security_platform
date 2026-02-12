// ─── Anomalous Access Pattern Detection ───
// Detects anomalous access patterns by comparing current behavior to a user's baseline.
// Trigger: access at unusual hours, unusual resource types, unusual volume vs. rolling 7-day window.
// Severity: MEDIUM
// Response: increase monitoring, alert if combined with other signals.

import { v4 as uuidv4 } from 'uuid';
import config from '../../../config/default';
import type { AuditEvent } from '../../audit/audit-store';
import type { Detection, Alert, AlertSeverity } from '../detection-engine';

const thresholds = config.detectionThresholds.anomalousAccessPattern;

/**
 * In-memory user baseline tracker.
 * In production, this would be backed by a time-series database or Redis.
 */
interface UserBaseline {
  userId: string;
  /** Hourly access counts (0-23) over the baseline period */
  hourlyDistribution: number[];
  /** Total events in the baseline period */
  totalEvents: number;
  /** Average daily event count */
  avgDailyEvents: number;
  /** Standard deviation of daily event counts */
  stdDevDailyEvents: number;
  /** Set of resource types the user typically accesses */
  typicalResourceTypes: Set<string>;
  /** Set of actions the user typically performs */
  typicalActions: Set<string>;
  /** Set of IPs the user typically connects from */
  typicalIps: Set<string>;
  /** Last updated timestamp */
  lastUpdated: string;
}

// Static baseline cache (in production, use Redis or a database)
const userBaselines = new Map<string, UserBaseline>();

/**
 * Build or update a user's baseline from historical events.
 */
function updateBaseline(userId: string, historicalEvents: AuditEvent[]): UserBaseline {
  const hourlyDistribution = new Array(24).fill(0);
  const resourceTypes = new Set<string>();
  const actions = new Set<string>();
  const ips = new Set<string>();
  const dailyCounts = new Map<string, number>();

  for (const event of historicalEvents) {
    const date = new Date(event.timestamp);
    hourlyDistribution[date.getUTCHours()]++;
    resourceTypes.add(event.resource.type);
    actions.add(event.action);
    if (event.context.ip) ips.add(event.context.ip);

    const dayKey = date.toISOString().slice(0, 10);
    dailyCounts.set(dayKey, (dailyCounts.get(dayKey) || 0) + 1);
  }

  const dailyValues = Array.from(dailyCounts.values());
  const avgDaily = dailyValues.length > 0
    ? dailyValues.reduce((a, b) => a + b, 0) / dailyValues.length
    : 0;

  const variance = dailyValues.length > 0
    ? dailyValues.reduce((sum, v) => sum + Math.pow(v - avgDaily, 2), 0) / dailyValues.length
    : 0;
  const stdDev = Math.sqrt(variance);

  const baseline: UserBaseline = {
    userId,
    hourlyDistribution,
    totalEvents: historicalEvents.length,
    avgDailyEvents: avgDaily,
    stdDevDailyEvents: stdDev,
    typicalResourceTypes: resourceTypes,
    typicalActions: actions,
    typicalIps: ips,
    lastUpdated: new Date().toISOString(),
  };

  userBaselines.set(userId, baseline);
  return baseline;
}

export const AnomalousAccessPatternDetection: Detection = {
  id: 'anomalous-access',
  name: 'Anomalous Access Pattern Detection',
  description: 'Detects unusual access patterns by comparing current behavior to a user baseline (rolling 7-day window).',
  severity: 'MEDIUM' as AlertSeverity,
  type: 'statistical',
  enabled: true,
  suppressionWindowSeconds: config.suppression.perDetection['anomalous-access'] || 1800,
  thresholds: {
    baselineWindowDays: thresholds.baselineWindowDays,
    stdDevMultiplier: thresholds.stdDevMultiplier,
    unusualHoursStart: thresholds.unusualHoursStart,
    unusualHoursEnd: thresholds.unusualHoursEnd,
  },

  evaluate(events: AuditEvent[]): Alert[] {
    const alerts: Alert[] = [];

    if (events.length === 0) return alerts;

    // Separate baseline period events from recent events (last 30 min)
    const recentWindowMs = 30 * 60 * 1000;
    const recentCutoff = new Date(Date.now() - recentWindowMs).toISOString();
    const baselineCutoff = new Date(
      Date.now() - this.thresholds.baselineWindowDays * 24 * 60 * 60 * 1000
    ).toISOString();

    // Group all events by user
    const byUser = new Map<string, { baseline: AuditEvent[]; recent: AuditEvent[] }>();
    for (const event of events) {
      if (event.actor.type !== 'user') continue;
      const userId = event.actor.id;
      if (!byUser.has(userId)) {
        byUser.set(userId, { baseline: [], recent: [] });
      }
      const bucket = byUser.get(userId)!;
      if (event.timestamp >= recentCutoff) {
        bucket.recent.push(event);
      }
      if (event.timestamp >= baselineCutoff) {
        bucket.baseline.push(event);
      }
    }

    for (const [userId, { baseline: baselineEvents, recent: recentEvents }] of byUser) {
      if (recentEvents.length === 0) continue;

      // Build/update baseline
      const existingBaseline = userBaselines.get(userId);
      const baselineData = baselineEvents.length >= 10
        ? updateBaseline(userId, baselineEvents)
        : existingBaseline;

      if (!baselineData || baselineData.totalEvents < 10) {
        // Not enough data for a meaningful baseline; skip
        continue;
      }

      const anomalies: string[] = [];
      const anomalyDetails: Record<string, unknown> = {};

      // ─── Check 1: Unusual hours ───
      const unusualHourEvents = recentEvents.filter((e) => {
        const hour = new Date(e.timestamp).getUTCHours();
        return hour >= this.thresholds.unusualHoursStart && hour < this.thresholds.unusualHoursEnd;
      });

      if (unusualHourEvents.length > 0) {
        // Check if the user normally accesses during these hours
        const unusualHourBaseline = baselineData.hourlyDistribution
          .slice(this.thresholds.unusualHoursStart, this.thresholds.unusualHoursEnd)
          .reduce((a, b) => a + b, 0);

        const totalBaselineActivity = baselineData.hourlyDistribution.reduce((a, b) => a + b, 0);
        const unusualHourRatio = totalBaselineActivity > 0 ? unusualHourBaseline / totalBaselineActivity : 0;

        // If user rarely accesses during unusual hours (<5% of their activity), flag it
        if (unusualHourRatio < 0.05) {
          anomalies.push(`Activity during unusual hours (${this.thresholds.unusualHoursStart}:00-${this.thresholds.unusualHoursEnd}:00 UTC)`);
          anomalyDetails.unusualHourEvents = unusualHourEvents.length;
          anomalyDetails.unusualHourBaselineRatio = unusualHourRatio;
        }
      }

      // ─── Check 2: Unusual resource types ───
      const recentResourceTypes = new Set(recentEvents.map((e) => e.resource.type));
      const newResourceTypes = [...recentResourceTypes].filter(
        (rt) => !baselineData.typicalResourceTypes.has(rt)
      );

      if (newResourceTypes.length > 0) {
        anomalies.push(`Accessing ${newResourceTypes.length} new resource type(s): ${newResourceTypes.join(', ')}`);
        anomalyDetails.newResourceTypes = newResourceTypes;
      }

      // ─── Check 3: Unusual volume ───
      // Project recent 30-minute window to daily rate and compare
      const projectedDailyRate = recentEvents.length * (24 * 60 / 30); // extrapolate to daily
      const volumeThreshold = baselineData.avgDailyEvents +
        this.thresholds.stdDevMultiplier * baselineData.stdDevDailyEvents;

      if (
        baselineData.avgDailyEvents > 0 &&
        projectedDailyRate > volumeThreshold &&
        projectedDailyRate > baselineData.avgDailyEvents * 2 // At least 2x normal
      ) {
        anomalies.push(
          `Volume spike: ${recentEvents.length} events in 30 min (projected daily: ${Math.round(projectedDailyRate)}, baseline avg: ${Math.round(baselineData.avgDailyEvents)})`
        );
        anomalyDetails.projectedDailyRate = Math.round(projectedDailyRate);
        anomalyDetails.baselineAvgDaily = Math.round(baselineData.avgDailyEvents);
        anomalyDetails.baselineStdDev = Math.round(baselineData.stdDevDailyEvents);
      }

      // ─── Check 4: New IP address ───
      const recentIps = new Set(recentEvents.map((e) => e.context.ip).filter(Boolean) as string[]);
      const newIps = [...recentIps].filter((ip) => !baselineData.typicalIps.has(ip));

      if (newIps.length > 0 && baselineData.typicalIps.size > 0) {
        anomalies.push(`Access from ${newIps.length} new IP(s): ${newIps.join(', ')}`);
        anomalyDetails.newIps = newIps;
      }

      // ─── Generate alert if multiple anomalies or a strong single signal ───
      if (anomalies.length >= 2 || (anomalies.length === 1 && (newResourceTypes.length > 2 || unusualHourEvents.length > 3))) {
        alerts.push({
          id: uuidv4(),
          detectionId: this.id,
          detectionName: this.name,
          severity: this.severity,
          title: `Anomalous access pattern for user ${userId}`,
          description: `User "${userId}" exhibits ${anomalies.length} anomalous behavior(s): ${anomalies.join('; ')}`,
          events: recentEvents.slice(0, 30),
          context: {
            userId,
            anomalyCount: anomalies.length,
            anomalies,
            ...anomalyDetails,
            baselineTotalEvents: baselineData.totalEvents,
            baselineDays: this.thresholds.baselineWindowDays,
          },
          responseHooks: ['THROTTLE_USER'], // Increase monitoring; don't block
          timestamp: new Date().toISOString(),
        });
      }
    }

    return alerts;
  },
};
