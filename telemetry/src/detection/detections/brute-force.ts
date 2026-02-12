// ─── Brute Force Detection ───
// Detects brute force login attempts.
// Trigger: >10 failed logins for the same actor or from the same IP in 5 minutes.
// Severity: HIGH
// Response: auto-block IP temporarily, require CAPTCHA, alert SOC.

import { v4 as uuidv4 } from 'uuid';
import config from '../../../config/default';
import type { AuditEvent } from '../../audit/audit-store';
import type { Detection, Alert, AlertSeverity } from '../detection-engine';

const thresholds = config.detectionThresholds.bruteForce;

export const BruteForceDetection: Detection = {
  id: 'brute-force',
  name: 'Brute Force Login Detection',
  description: 'Detects multiple failed login attempts from the same actor or IP address within a short time window.',
  severity: 'HIGH' as AlertSeverity,
  type: 'threshold',
  enabled: true,
  suppressionWindowSeconds: config.suppression.perDetection['brute-force'] || 600,
  thresholds: {
    maxFailedLogins: thresholds.maxFailedLogins,
    windowMinutes: thresholds.windowMinutes,
  },

  evaluate(events: AuditEvent[]): Alert[] {
    const alerts: Alert[] = [];
    const windowMs = this.thresholds.windowMinutes * 60 * 1000;
    const now = Date.now();
    const cutoff = new Date(now - windowMs).toISOString();

    // Filter to login failures within the window
    const loginFailures = events.filter(
      (e) =>
        e.timestamp >= cutoff &&
        (e.action === 'auth.login' || e.action === 'auth.authenticate' || e.action.includes('login')) &&
        e.result.decision === 'DENY'
    );

    if (loginFailures.length === 0) return alerts;

    // Group by actor ID
    const byActor = new Map<string, AuditEvent[]>();
    for (const event of loginFailures) {
      const key = event.actor.id;
      const existing = byActor.get(key) || [];
      existing.push(event);
      byActor.set(key, existing);
    }

    // Check each actor
    for (const [actorId, actorEvents] of byActor) {
      if (actorEvents.length > this.thresholds.maxFailedLogins) {
        const sourceIps = [...new Set(actorEvents.map((e) => e.context.ip).filter(Boolean))];
        alerts.push({
          id: uuidv4(),
          detectionId: this.id,
          detectionName: this.name,
          severity: this.severity,
          title: `Brute force attack detected for user ${actorId}`,
          description: `${actorEvents.length} failed login attempts for actor "${actorId}" in the last ${this.thresholds.windowMinutes} minutes from ${sourceIps.length} IP(s): ${sourceIps.join(', ')}`,
          events: actorEvents,
          context: {
            actorId,
            failedCount: actorEvents.length,
            sourceIps,
            windowMinutes: this.thresholds.windowMinutes,
          },
          responseHooks: ['BLOCK_IP', 'REQUIRE_STEP_UP'],
          timestamp: new Date().toISOString(),
        });
      }
    }

    // Group by source IP
    const byIp = new Map<string, AuditEvent[]>();
    for (const event of loginFailures) {
      if (!event.context.ip) continue;
      const key = event.context.ip;
      const existing = byIp.get(key) || [];
      existing.push(event);
      byIp.set(key, existing);
    }

    // Check each IP (only if not already covered by actor-based alert)
    const alertedActors = new Set(alerts.map((a) => (a.context.actorId as string)));
    for (const [ip, ipEvents] of byIp) {
      if (ipEvents.length > this.thresholds.maxFailedLogins) {
        const distinctActors = [...new Set(ipEvents.map((e) => e.actor.id))];
        // Skip if all actors from this IP are already alerted
        if (distinctActors.every((a) => alertedActors.has(a))) continue;

        alerts.push({
          id: uuidv4(),
          detectionId: this.id,
          detectionName: this.name,
          severity: this.severity,
          title: `Brute force attack detected from IP ${ip}`,
          description: `${ipEvents.length} failed login attempts from IP "${ip}" targeting ${distinctActors.length} account(s) in the last ${this.thresholds.windowMinutes} minutes.`,
          events: ipEvents,
          context: {
            sourceIp: ip,
            failedCount: ipEvents.length,
            targetedActors: distinctActors,
            windowMinutes: this.thresholds.windowMinutes,
          },
          responseHooks: ['BLOCK_IP'],
          timestamp: new Date().toISOString(),
        });
      }
    }

    return alerts;
  },
};
