// ─── Token Replay Detection ───
// Detects token replay attacks: stolen or intercepted tokens used from unauthorized locations.
// Trigger: same token used from different IPs/devices, or revoked token usage attempt.
// Severity: CRITICAL
// Response: revoke all tokens for user, force re-auth, alert SOC.

import { v4 as uuidv4 } from 'uuid';
import config from '../../../config/default';
import type { AuditEvent } from '../../audit/audit-store';
import type { Detection, Alert, AlertSeverity } from '../detection-engine';

export const TokenReplayDetection: Detection = {
  id: 'token-replay',
  name: 'Token Replay Detection',
  description: 'Detects stolen or replayed tokens being used from unauthorized locations or after revocation.',
  severity: 'CRITICAL' as AlertSeverity,
  type: 'pattern',
  enabled: config.detectionThresholds.tokenReplay.enabled,
  suppressionWindowSeconds: config.suppression.perDetection['token-replay'] || 60,
  thresholds: {
    // No numeric threshold; this is pattern-based
    maxIpsPerSession: 2, // Allow at most 2 IPs per session (for legitimate roaming)
  },

  evaluate(events: AuditEvent[]): Alert[] {
    const alerts: Alert[] = [];

    // ─── Detection 1: Same session/token from different IPs or devices ───

    // Group events by session ID
    const bySession = new Map<string, AuditEvent[]>();
    for (const event of events) {
      if (!event.actor.sessionId) continue;
      const key = event.actor.sessionId;
      const existing = bySession.get(key) || [];
      existing.push(event);
      bySession.set(key, existing);
    }

    for (const [sessionId, sessionEvents] of bySession) {
      // Collect distinct IPs for this session
      const ips = new Set<string>();
      const devices = new Set<string>();
      for (const event of sessionEvents) {
        if (event.context.ip) ips.add(event.context.ip);
        if (event.actor.deviceId) devices.add(event.actor.deviceId);
      }

      // Token replay: same session from too many different IPs
      if (ips.size > this.thresholds.maxIpsPerSession) {
        const actorId = sessionEvents[0].actor.id;
        const ipList = Array.from(ips);

        // Check if the IPs are in different subnets (stronger signal)
        const subnets = new Set(ipList.map((ip) => ip.split('.').slice(0, 3).join('.')));
        const crossSubnet = subnets.size > 1;

        alerts.push({
          id: uuidv4(),
          detectionId: this.id,
          detectionName: this.name,
          severity: this.severity,
          title: `Token replay suspected: session ${sessionId.slice(0, 8)}... used from ${ips.size} IPs`,
          description: `Session "${sessionId.slice(0, 8)}..." for user "${actorId}" was used from ${ips.size} different IP addresses${crossSubnet ? ' across different subnets' : ''}: ${ipList.join(', ')}. This strongly indicates token theft or replay.`,
          events: sessionEvents.slice(0, 20),
          context: {
            sessionId,
            actorId,
            distinctIps: ipList,
            distinctDevices: Array.from(devices),
            crossSubnet,
            eventCount: sessionEvents.length,
          },
          responseHooks: ['REVOKE_SESSIONS', 'REQUIRE_STEP_UP'],
          timestamp: new Date().toISOString(),
        });
      }

      // Token replay: same session from different devices
      if (devices.size > 1) {
        const actorId = sessionEvents[0].actor.id;
        const deviceList = Array.from(devices);

        // Only alert if not already covered by IP-based detection
        if (ips.size <= this.thresholds.maxIpsPerSession) {
          alerts.push({
            id: uuidv4(),
            detectionId: this.id,
            detectionName: this.name,
            severity: this.severity,
            title: `Token replay suspected: session used from ${devices.size} devices`,
            description: `Session "${sessionId.slice(0, 8)}..." for user "${actorId}" was used from ${devices.size} different devices: ${deviceList.join(', ')}.`,
            events: sessionEvents.slice(0, 20),
            context: {
              sessionId,
              actorId,
              distinctDevices: deviceList,
              eventCount: sessionEvents.length,
            },
            responseHooks: ['REVOKE_SESSIONS', 'REQUIRE_STEP_UP'],
            timestamp: new Date().toISOString(),
          });
        }
      }
    }

    // ─── Detection 2: Revoked token usage ───
    // Look for events where a revoked or expired token was used
    const revokedTokenEvents = events.filter(
      (e) =>
        e.result.decision === 'DENY' &&
        (e.result.reason?.toLowerCase().includes('revoked') ||
          e.result.reason?.toLowerCase().includes('expired') ||
          e.result.reason?.toLowerCase().includes('invalid token') ||
          e.action === 'auth.token.validate.failed' ||
          e.action === 'auth.token.revoked-usage')
    );

    // Group revoked token events by actor
    const revokedByActor = new Map<string, AuditEvent[]>();
    for (const event of revokedTokenEvents) {
      const key = event.actor.id;
      const existing = revokedByActor.get(key) || [];
      existing.push(event);
      revokedByActor.set(key, existing);
    }

    for (const [actorId, actorEvents] of revokedByActor) {
      // Even a single revoked token usage attempt is suspicious
      if (actorEvents.length >= 1) {
        const sourceIps = [...new Set(actorEvents.map((e) => e.context.ip).filter(Boolean))];

        alerts.push({
          id: uuidv4(),
          detectionId: this.id,
          detectionName: this.name,
          severity: this.severity,
          title: `Revoked token usage attempt for user ${actorId}`,
          description: `${actorEvents.length} attempt(s) to use revoked/expired tokens for user "${actorId}" from IP(s): ${sourceIps.join(', ')}. This indicates token theft where the legitimate user has already revoked the token.`,
          events: actorEvents,
          context: {
            actorId,
            attemptCount: actorEvents.length,
            sourceIps,
            reasons: [...new Set(actorEvents.map((e) => e.result.reason).filter(Boolean))],
          },
          responseHooks: ['REVOKE_SESSIONS', 'BLOCK_IP', 'REQUIRE_STEP_UP'],
          timestamp: new Date().toISOString(),
        });
      }
    }

    return alerts;
  },
};
