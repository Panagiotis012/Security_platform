// ─── Credential Stuffing Detection ───
// Detects credential stuffing attacks: automated login attempts using stolen credential lists.
// Trigger: >20 different usernames with failures from the same IP range (/24) in 10 minutes.
// Severity: HIGH
// Response: block IP range, alert SOC.

import { v4 as uuidv4 } from 'uuid';
import config from '../../../config/default';
import type { AuditEvent } from '../../audit/audit-store';
import type { Detection, Alert, AlertSeverity } from '../detection-engine';

const thresholds = config.detectionThresholds.credentialStuffing;

/**
 * Extract the /24 subnet prefix from an IPv4 address.
 * Example: "192.168.1.100" -> "192.168.1"
 */
function getIpRangePrefix(ip: string): string {
  const parts = ip.split('.');
  if (parts.length === 4) {
    // IPv4 /24 prefix
    return parts.slice(0, 3).join('.');
  }
  // For IPv6 or unusual formats, use the first segment group
  const v6Parts = ip.split(':');
  if (v6Parts.length >= 4) {
    return v6Parts.slice(0, 4).join(':');
  }
  return ip;
}

export const CredentialStuffingDetection: Detection = {
  id: 'credential-stuffing',
  name: 'Credential Stuffing Detection',
  description: 'Detects automated credential stuffing attacks using stolen credential lists from the same IP range.',
  severity: 'HIGH' as AlertSeverity,
  type: 'pattern',
  enabled: true,
  suppressionWindowSeconds: config.suppression.perDetection['credential-stuffing'] || 900,
  thresholds: {
    maxDistinctUsernames: thresholds.maxDistinctUsernames,
    windowMinutes: thresholds.windowMinutes,
  },

  evaluate(events: AuditEvent[]): Alert[] {
    const alerts: Alert[] = [];
    const windowMs = this.thresholds.windowMinutes * 60 * 1000;
    const now = Date.now();
    const cutoff = new Date(now - windowMs).toISOString();

    // Filter to login failures within the window that have an IP
    const loginFailures = events.filter(
      (e) =>
        e.timestamp >= cutoff &&
        (e.action === 'auth.login' || e.action === 'auth.authenticate' || e.action.includes('login')) &&
        e.result.decision === 'DENY' &&
        e.context.ip
    );

    if (loginFailures.length === 0) return alerts;

    // Group by IP range prefix (/24 for IPv4)
    const byIpRange = new Map<string, AuditEvent[]>();
    for (const event of loginFailures) {
      const rangePrefix = getIpRangePrefix(event.context.ip!);
      const existing = byIpRange.get(rangePrefix) || [];
      existing.push(event);
      byIpRange.set(rangePrefix, existing);
    }

    // Check each IP range
    for (const [rangePrefix, rangeEvents] of byIpRange) {
      const distinctUsernames = new Set(rangeEvents.map((e) => e.actor.id));
      const distinctIps = new Set(rangeEvents.map((e) => e.context.ip));

      if (distinctUsernames.size > this.thresholds.maxDistinctUsernames) {
        // Additional signal: check for rapid, evenly-spaced requests (bot-like behavior)
        const timestamps = rangeEvents.map((e) => new Date(e.timestamp).getTime()).sort((a, b) => a - b);
        let evenlySpaced = false;
        if (timestamps.length >= 5) {
          const intervals: number[] = [];
          for (let i = 1; i < timestamps.length; i++) {
            intervals.push(timestamps[i] - timestamps[i - 1]);
          }
          const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
          const variance = intervals.reduce((sum, v) => sum + Math.pow(v - avgInterval, 2), 0) / intervals.length;
          const stdDev = Math.sqrt(variance);
          // If standard deviation is less than 20% of the mean, it is bot-like
          evenlySpaced = avgInterval > 0 && stdDev / avgInterval < 0.2;
        }

        alerts.push({
          id: uuidv4(),
          detectionId: this.id,
          detectionName: this.name,
          severity: this.severity,
          title: `Credential stuffing attack from IP range ${rangePrefix}.0/24`,
          description: `${distinctUsernames.size} distinct usernames attempted from IP range ${rangePrefix}.0/24 (${distinctIps.size} IPs) with ${rangeEvents.length} total failures in ${this.thresholds.windowMinutes} minutes.${evenlySpaced ? ' Bot-like request timing detected.' : ''}`,
          events: rangeEvents.slice(0, 50), // Cap event count in alert
          context: {
            ipRange: `${rangePrefix}.0/24`,
            distinctUsernames: distinctUsernames.size,
            distinctIps: Array.from(distinctIps),
            totalFailures: rangeEvents.length,
            botLikeTiming: evenlySpaced,
            windowMinutes: this.thresholds.windowMinutes,
            sampleUsernames: Array.from(distinctUsernames).slice(0, 10), // Sample for investigation
          },
          responseHooks: ['BLOCK_IP'],
          timestamp: new Date().toISOString(),
        });
      }
    }

    return alerts;
  },
};
