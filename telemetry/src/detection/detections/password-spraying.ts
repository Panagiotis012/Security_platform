// ─── Password Spraying Detection ───
// Detects password spraying attacks: trying a small number of passwords against many accounts.
// Trigger: failed logins across >10 accounts with low per-account attempts (<=3) in 15 minutes.
// This is distinct from brute force (many attempts on one account) and credential stuffing
// (many different credentials from one IP range).
// Severity: HIGH
// Response: temporary lockout pattern, alert SOC.

import { v4 as uuidv4 } from 'uuid';
import config from '../../../config/default';
import type { AuditEvent } from '../../audit/audit-store';
import type { Detection, Alert, AlertSeverity } from '../detection-engine';

const thresholds = config.detectionThresholds.passwordSpraying;

export const PasswordSprayingDetection: Detection = {
  id: 'password-spraying',
  name: 'Password Spraying Detection',
  description: 'Detects password spraying attacks where a small number of passwords are tried across many accounts.',
  severity: 'HIGH' as AlertSeverity,
  type: 'pattern',
  enabled: true,
  suppressionWindowSeconds: config.suppression.perDetection['password-spraying'] || 900,
  thresholds: {
    minAffectedAccounts: thresholds.minAffectedAccounts,
    maxPerAccountAttempts: thresholds.maxPerAccountAttempts,
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

    // Group by source IP to find spray patterns
    const byIp = new Map<string, AuditEvent[]>();
    for (const event of loginFailures) {
      const key = event.context.ip || 'unknown';
      const existing = byIp.get(key) || [];
      existing.push(event);
      byIp.set(key, existing);
    }

    for (const [ip, ipEvents] of byIp) {
      // Count attempts per account from this IP
      const attemptsPerAccount = new Map<string, number>();
      for (const event of ipEvents) {
        const current = attemptsPerAccount.get(event.actor.id) || 0;
        attemptsPerAccount.set(event.actor.id, current + 1);
      }

      // Password spraying signature: many accounts, few attempts per account
      const accountsWithLowAttempts = Array.from(attemptsPerAccount.entries()).filter(
        ([, count]) => count <= this.thresholds.maxPerAccountAttempts
      );

      if (accountsWithLowAttempts.length >= this.thresholds.minAffectedAccounts) {
        const affectedAccounts = accountsWithLowAttempts.map(([id]) => id);
        const totalAttempts = accountsWithLowAttempts.reduce((sum, [, count]) => sum + count, 0);
        const avgAttemptsPerAccount = totalAttempts / affectedAccounts.length;

        alerts.push({
          id: uuidv4(),
          detectionId: this.id,
          detectionName: this.name,
          severity: this.severity,
          title: `Password spraying attack detected from ${ip}`,
          description: `${affectedAccounts.length} accounts targeted with an average of ${avgAttemptsPerAccount.toFixed(1)} attempts each from IP "${ip}" in ${this.thresholds.windowMinutes} minutes. This pattern indicates password spraying.`,
          events: ipEvents.slice(0, 50),
          context: {
            sourceIp: ip,
            affectedAccountCount: affectedAccounts.length,
            totalAttempts,
            avgAttemptsPerAccount,
            sampleAccounts: affectedAccounts.slice(0, 20),
            windowMinutes: this.thresholds.windowMinutes,
          },
          responseHooks: ['BLOCK_IP', 'THROTTLE_USER'],
          timestamp: new Date().toISOString(),
        });
      }
    }

    // Also check across multiple IPs (distributed password spraying)
    // Group by targeted account and check if many accounts see low-count failures from diverse IPs
    const accountFailureIps = new Map<string, Set<string>>();
    const accountFailureCounts = new Map<string, number>();

    for (const event of loginFailures) {
      const actorId = event.actor.id;
      const ip = event.context.ip || 'unknown';
      if (!accountFailureIps.has(actorId)) {
        accountFailureIps.set(actorId, new Set());
      }
      accountFailureIps.get(actorId)!.add(ip);
      accountFailureCounts.set(actorId, (accountFailureCounts.get(actorId) || 0) + 1);
    }

    // Find accounts with low attempts from diverse IPs
    const distributedTargets = Array.from(accountFailureCounts.entries()).filter(
      ([actorId, count]) =>
        count <= this.thresholds.maxPerAccountAttempts &&
        (accountFailureIps.get(actorId)?.size ?? 0) >= 2 // Multiple IPs targeting this account
    );

    if (distributedTargets.length >= this.thresholds.minAffectedAccounts) {
      const allIps = new Set<string>();
      for (const [actorId] of distributedTargets) {
        const ips = accountFailureIps.get(actorId);
        if (ips) ips.forEach((ip) => allIps.add(ip));
      }

      alerts.push({
        id: uuidv4(),
        detectionId: this.id,
        detectionName: this.name,
        severity: this.severity,
        title: 'Distributed password spraying attack detected',
        description: `${distributedTargets.length} accounts targeted from ${allIps.size} different IPs with low per-account attempts. This indicates a coordinated distributed password spraying attack.`,
        events: loginFailures.slice(0, 50),
        context: {
          affectedAccountCount: distributedTargets.length,
          sourceIpCount: allIps.size,
          sampleIps: Array.from(allIps).slice(0, 20),
          sampleAccounts: distributedTargets.slice(0, 20).map(([id]) => id),
          distributed: true,
          windowMinutes: this.thresholds.windowMinutes,
        },
        responseHooks: ['BLOCK_IP', 'THROTTLE_USER'],
        timestamp: new Date().toISOString(),
      });
    }

    return alerts;
  },
};
