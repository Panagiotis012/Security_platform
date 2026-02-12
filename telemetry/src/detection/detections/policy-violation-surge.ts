// ─── Policy Violation Surge Detection ───
// Detects a surge in policy violations (DENY decisions) that exceeds the normal rate.
// Trigger: >5x normal rate of DENY decisions in a 10-minute window.
// Could indicate misconfiguration, deployment issue, or active attack.
// Severity: MEDIUM-HIGH (treated as HIGH)
// Response: alert SOC and platform team.

import { v4 as uuidv4 } from 'uuid';
import config from '../../../config/default';
import type { AuditEvent } from '../../audit/audit-store';
import type { Detection, Alert, AlertSeverity } from '../detection-engine';

const thresholds = config.detectionThresholds.policyViolationSurge;

/**
 * Tracks the historical DENY rate for surge detection.
 * In production, this would be backed by a time-series database.
 */
interface DenyRateTracker {
  /** Rolling window of per-minute DENY counts */
  minuteCounts: { minute: string; count: number }[];
  /** Average DENY count per minute over the baseline period */
  avgDeniesPerMinute: number;
  /** Last computed timestamp */
  lastComputed: string;
}

// Static tracker instance
let denyRateTracker: DenyRateTracker = {
  minuteCounts: [],
  avgDeniesPerMinute: 0,
  lastComputed: '',
};

/**
 * Update the baseline deny rate from all events.
 */
function updateDenyBaseline(events: AuditEvent[]): void {
  const denyEvents = events.filter((e) => e.result.decision === 'DENY');

  if (denyEvents.length === 0) return;

  // Bucket denials by minute
  const byMinute = new Map<string, number>();
  for (const event of denyEvents) {
    const minuteKey = event.timestamp.slice(0, 16); // YYYY-MM-DDTHH:MM
    byMinute.set(minuteKey, (byMinute.get(minuteKey) || 0) + 1);
  }

  const minuteCounts = Array.from(byMinute.entries())
    .map(([minute, count]) => ({ minute, count }))
    .sort((a, b) => a.minute.localeCompare(b.minute));

  // Calculate average denials per minute
  const totalMinutes = minuteCounts.length;
  const totalDenies = minuteCounts.reduce((sum, mc) => sum + mc.count, 0);
  const avgPerMinute = totalMinutes > 0 ? totalDenies / totalMinutes : 0;

  denyRateTracker = {
    minuteCounts,
    avgDeniesPerMinute: avgPerMinute,
    lastComputed: new Date().toISOString(),
  };
}

export const PolicyViolationSurgeDetection: Detection = {
  id: 'policy-violation-surge',
  name: 'Policy Violation Surge Detection',
  description: 'Detects abnormal surges in policy DENY decisions that may indicate misconfiguration or active attack.',
  severity: 'HIGH' as AlertSeverity,
  type: 'statistical',
  enabled: true,
  suppressionWindowSeconds: config.suppression.perDetection['policy-violation-surge'] || 600,
  thresholds: {
    surgeMultiplier: thresholds.surgeMultiplier,
    windowMinutes: thresholds.windowMinutes,
    minBaselineCount: thresholds.minBaselineCount,
  },

  evaluate(events: AuditEvent[]): Alert[] {
    const alerts: Alert[] = [];
    const windowMs = this.thresholds.windowMinutes * 60 * 1000;
    const now = Date.now();
    const cutoff = new Date(now - windowMs).toISOString();

    // Update baseline from all available events
    updateDenyBaseline(events);

    // Filter to DENY events in the current window
    const recentDenies = events.filter(
      (e) => e.timestamp >= cutoff && e.result.decision === 'DENY'
    );

    if (recentDenies.length === 0) return alerts;

    // Calculate current deny rate per minute
    const windowMinutes = this.thresholds.windowMinutes;
    const currentDenyRate = recentDenies.length / windowMinutes;
    const baselineRate = denyRateTracker.avgDeniesPerMinute;

    // Need a minimum baseline to avoid false positives
    if (denyRateTracker.minuteCounts.length < this.thresholds.minBaselineCount) {
      return alerts;
    }

    // Check if the current rate exceeds the surge threshold
    const surgeThreshold = baselineRate * this.thresholds.surgeMultiplier;

    if (currentDenyRate > surgeThreshold && recentDenies.length >= this.thresholds.minBaselineCount) {
      // Analyze the surge: which policies, which actors, which resources
      const policyBreakdown = new Map<string, number>();
      const actorBreakdown = new Map<string, number>();
      const actionBreakdown = new Map<string, number>();
      const resourceTypeBreakdown = new Map<string, number>();

      for (const event of recentDenies) {
        const policyId = event.result.policyId || 'unknown';
        policyBreakdown.set(policyId, (policyBreakdown.get(policyId) || 0) + 1);
        actorBreakdown.set(event.actor.id, (actorBreakdown.get(event.actor.id) || 0) + 1);
        actionBreakdown.set(event.action, (actionBreakdown.get(event.action) || 0) + 1);
        resourceTypeBreakdown.set(event.resource.type, (resourceTypeBreakdown.get(event.resource.type) || 0) + 1);
      }

      // Sort breakdowns by count
      const topPolicies = Array.from(policyBreakdown.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);
      const topActors = Array.from(actorBreakdown.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);
      const topActions = Array.from(actionBreakdown.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

      // Determine likely cause
      const singlePolicyDominant = topPolicies.length > 0 &&
        topPolicies[0][1] > recentDenies.length * 0.7;
      const singleActorDominant = topActors.length > 0 &&
        topActors[0][1] > recentDenies.length * 0.7;

      let likelyCause = 'Unknown';
      if (singlePolicyDominant) {
        likelyCause = `Policy misconfiguration (policy "${topPolicies[0][0]}" responsible for ${Math.round(topPolicies[0][1] / recentDenies.length * 100)}% of denials)`;
      } else if (singleActorDominant) {
        likelyCause = `Single actor attack (actor "${topActors[0][0]}" responsible for ${Math.round(topActors[0][1] / recentDenies.length * 100)}% of denials)`;
      } else if (topActors.length > 5) {
        likelyCause = 'Broad attack or systemic issue affecting multiple users';
      }

      alerts.push({
        id: uuidv4(),
        detectionId: this.id,
        detectionName: this.name,
        severity: this.severity,
        title: `Policy violation surge: ${currentDenyRate.toFixed(1)}/min vs baseline ${baselineRate.toFixed(1)}/min`,
        description: `DENY decisions surged to ${currentDenyRate.toFixed(1)}/min (${this.thresholds.surgeMultiplier}x threshold: ${surgeThreshold.toFixed(1)}/min, baseline: ${baselineRate.toFixed(1)}/min) over the last ${windowMinutes} minutes. Total denials: ${recentDenies.length}. Likely cause: ${likelyCause}`,
        events: recentDenies.slice(0, 50),
        context: {
          currentDenyRate: parseFloat(currentDenyRate.toFixed(2)),
          baselineDenyRate: parseFloat(baselineRate.toFixed(2)),
          surgeMultiplier: this.thresholds.surgeMultiplier,
          totalDenials: recentDenies.length,
          windowMinutes,
          likelyCause,
          topPolicies: Object.fromEntries(topPolicies),
          topActors: Object.fromEntries(topActors),
          topActions: Object.fromEntries(topActions),
          topResourceTypes: Object.fromEntries(resourceTypeBreakdown),
          singlePolicyDominant,
          singleActorDominant,
        },
        responseHooks: [], // Alert only; automated response could worsen a misconfiguration
        timestamp: new Date().toISOString(),
      });
    }

    return alerts;
  },
};
