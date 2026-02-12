// ─── Session Anomaly Detection ───
// Detects session anomalies: session used from new device/IP without re-auth,
// session cookie theft indicators, and session hijacking patterns.
// Severity: HIGH
// Response: invalidate session, require re-auth, alert.

import { v4 as uuidv4 } from 'uuid';
import config from '../../../config/default';
import type { AuditEvent } from '../../audit/audit-store';
import type { Detection, Alert, AlertSeverity } from '../detection-engine';

/**
 * Tracks session-to-context bindings for anomaly detection.
 * In production, this would be stored in Redis with TTL.
 */
interface SessionBinding {
  sessionId: string;
  userId: string;
  originalIp: string;
  originalDeviceId: string;
  originalUserAgent: string;
  firstSeen: string;
  lastSeen: string;
  ipHistory: Set<string>;
  deviceHistory: Set<string>;
  userAgentHistory: Set<string>;
}

// Static session binding cache
const sessionBindings = new Map<string, SessionBinding>();

/**
 * Update session binding from an authentication event.
 */
function updateSessionBinding(event: AuditEvent): SessionBinding {
  const sessionId = event.actor.sessionId!;
  const existing = sessionBindings.get(sessionId);

  if (existing) {
    existing.lastSeen = event.timestamp;
    if (event.context.ip) existing.ipHistory.add(event.context.ip);
    if (event.actor.deviceId) existing.deviceHistory.add(event.actor.deviceId);
    if (event.context.userAgent) existing.userAgentHistory.add(event.context.userAgent);
    return existing;
  }

  const binding: SessionBinding = {
    sessionId,
    userId: event.actor.id,
    originalIp: event.context.ip || '',
    originalDeviceId: event.actor.deviceId || '',
    originalUserAgent: event.context.userAgent || '',
    firstSeen: event.timestamp,
    lastSeen: event.timestamp,
    ipHistory: new Set(event.context.ip ? [event.context.ip] : []),
    deviceHistory: new Set(event.actor.deviceId ? [event.actor.deviceId] : []),
    userAgentHistory: new Set(event.context.userAgent ? [event.context.userAgent] : []),
  };

  sessionBindings.set(sessionId, binding);
  return binding;
}

export const SessionAnomalyDetection: Detection = {
  id: 'session-anomaly',
  name: 'Session Anomaly Detection',
  description: 'Detects session hijacking, cookie theft, and unauthorized session usage from new contexts.',
  severity: 'HIGH' as AlertSeverity,
  type: 'behavioral',
  enabled: config.detectionThresholds.sessionAnomaly.enabled,
  suppressionWindowSeconds: config.suppression.perDetection['session-anomaly'] || 300,
  thresholds: {
    maxIpsPerSession: 3,
    maxDevicesPerSession: 2,
  },

  evaluate(events: AuditEvent[]): Alert[] {
    const alerts: Alert[] = [];

    // Filter to events that have session IDs
    const sessionEvents = events.filter((e) => e.actor.sessionId);

    if (sessionEvents.length === 0) return alerts;

    // First pass: build/update session bindings from authentication events
    const authEvents = sessionEvents.filter(
      (e) =>
        (e.action.includes('auth') || e.action.includes('login') || e.action.includes('session.create')) &&
        e.result.decision === 'ALLOW'
    );
    for (const event of authEvents) {
      updateSessionBinding(event);
    }

    // Second pass: check all session events for anomalies
    // Group by session
    const bySession = new Map<string, AuditEvent[]>();
    for (const event of sessionEvents) {
      const key = event.actor.sessionId!;
      const existing = bySession.get(key) || [];
      existing.push(event);
      bySession.set(key, existing);
    }

    const alertedSessions = new Set<string>();

    for (const [sessionId, sessEvents] of bySession) {
      const binding = sessionBindings.get(sessionId);

      // ─── Detection 1: IP change without re-authentication ───
      if (binding && binding.originalIp) {
        const nonAuthEventsWithNewIp = sessEvents.filter(
          (e) =>
            e.context.ip &&
            e.context.ip !== binding.originalIp &&
            !e.action.includes('auth') &&
            !e.action.includes('login') &&
            e.result.decision === 'ALLOW'
        );

        if (nonAuthEventsWithNewIp.length > 0 && !alertedSessions.has(`${sessionId}:ip`)) {
          const newIps = [...new Set(nonAuthEventsWithNewIp.map((e) => e.context.ip))];

          // Check if any recent auth event established this new IP
          const recentAuth = authEvents.find(
            (e) =>
              e.actor.sessionId === sessionId &&
              newIps.includes(e.context.ip || '') &&
              e.timestamp > binding.firstSeen
          );

          if (!recentAuth) {
            alertedSessions.add(`${sessionId}:ip`);
            alerts.push({
              id: uuidv4(),
              detectionId: this.id,
              detectionName: this.name,
              severity: this.severity,
              title: `Session IP change without re-auth: ${sessionId.slice(0, 8)}...`,
              description: `Session "${sessionId.slice(0, 8)}..." for user "${binding.userId}" switched from IP "${binding.originalIp}" to ${newIps.join(', ')} without re-authentication. This may indicate session cookie theft.`,
              events: nonAuthEventsWithNewIp.slice(0, 10),
              context: {
                sessionId,
                userId: binding.userId,
                originalIp: binding.originalIp,
                newIps,
                originalDeviceId: binding.originalDeviceId,
                eventCount: nonAuthEventsWithNewIp.length,
              },
              responseHooks: ['REVOKE_SESSIONS', 'REQUIRE_STEP_UP'],
              timestamp: new Date().toISOString(),
            });
          }
        }
      }

      // ─── Detection 2: Device change within session ───
      if (binding && binding.originalDeviceId) {
        const eventsWithNewDevice = sessEvents.filter(
          (e) =>
            e.actor.deviceId &&
            e.actor.deviceId !== binding.originalDeviceId &&
            e.result.decision === 'ALLOW'
        );

        if (eventsWithNewDevice.length > 0 && !alertedSessions.has(`${sessionId}:device`)) {
          const newDevices = [...new Set(eventsWithNewDevice.map((e) => e.actor.deviceId))];
          alertedSessions.add(`${sessionId}:device`);

          alerts.push({
            id: uuidv4(),
            detectionId: this.id,
            detectionName: this.name,
            severity: this.severity,
            title: `Session device switch: ${sessionId.slice(0, 8)}...`,
            description: `Session "${sessionId.slice(0, 8)}..." for user "${binding.userId}" was originally on device "${binding.originalDeviceId}" but is now being used from device(s): ${newDevices.join(', ')}. Sessions should not transfer between devices.`,
            events: eventsWithNewDevice.slice(0, 10),
            context: {
              sessionId,
              userId: binding.userId,
              originalDeviceId: binding.originalDeviceId,
              newDevices,
            },
            responseHooks: ['REVOKE_SESSIONS', 'REQUIRE_STEP_UP'],
            timestamp: new Date().toISOString(),
          });
        }
      }

      // ─── Detection 3: User-Agent change (session cookie theft from different browser) ───
      if (binding && binding.originalUserAgent) {
        const eventsWithNewUA = sessEvents.filter(
          (e) =>
            e.context.userAgent &&
            e.context.userAgent !== binding.originalUserAgent &&
            e.result.decision === 'ALLOW'
        );

        if (eventsWithNewUA.length > 0 && !alertedSessions.has(`${sessionId}:ua`)) {
          const newUAs = [...new Set(eventsWithNewUA.map((e) => e.context.userAgent))];

          // Only alert if the UA change is significant (not just version bump)
          const originalBrowser = extractBrowserFamily(binding.originalUserAgent);
          const newBrowsers = newUAs.map((ua) => extractBrowserFamily(ua || ''));
          const differentBrowser = newBrowsers.some((b) => b !== originalBrowser);

          if (differentBrowser) {
            alertedSessions.add(`${sessionId}:ua`);

            alerts.push({
              id: uuidv4(),
              detectionId: this.id,
              detectionName: this.name,
              severity: this.severity,
              title: `Session user-agent change: ${sessionId.slice(0, 8)}...`,
              description: `Session "${sessionId.slice(0, 8)}..." for user "${binding.userId}" switched browser family from "${originalBrowser}" to "${newBrowsers.join(', ')}". This is a strong indicator of session token theft.`,
              events: eventsWithNewUA.slice(0, 10),
              context: {
                sessionId,
                userId: binding.userId,
                originalBrowser,
                newBrowsers,
                originalUserAgent: binding.originalUserAgent,
                newUserAgents: newUAs,
              },
              responseHooks: ['REVOKE_SESSIONS', 'REQUIRE_STEP_UP'],
              timestamp: new Date().toISOString(),
            });
          }
        }
      }

      // ─── Detection 4: Excessive IPs per session (lateral movement) ───
      const uniqueIps = new Set(sessEvents.map((e) => e.context.ip).filter(Boolean));
      if (uniqueIps.size > this.thresholds.maxIpsPerSession && !alertedSessions.has(`${sessionId}:many-ips`)) {
        alertedSessions.add(`${sessionId}:many-ips`);
        const userId = sessEvents[0]?.actor.id || 'unknown';

        alerts.push({
          id: uuidv4(),
          detectionId: this.id,
          detectionName: this.name,
          severity: this.severity,
          title: `Session used from ${uniqueIps.size} IPs: ${sessionId.slice(0, 8)}...`,
          description: `Session "${sessionId.slice(0, 8)}..." for user "${userId}" was used from ${uniqueIps.size} different IP addresses, exceeding the threshold of ${this.thresholds.maxIpsPerSession}. IPs: ${Array.from(uniqueIps).join(', ')}`,
          events: sessEvents.slice(0, 20),
          context: {
            sessionId,
            userId,
            uniqueIps: Array.from(uniqueIps),
            ipCount: uniqueIps.size,
            threshold: this.thresholds.maxIpsPerSession,
          },
          responseHooks: ['REVOKE_SESSIONS', 'REQUIRE_STEP_UP'],
          timestamp: new Date().toISOString(),
        });
      }
    }

    return alerts;
  },
};

/**
 * Extract the browser family from a user-agent string for comparison.
 */
function extractBrowserFamily(userAgent: string): string {
  const ua = userAgent.toLowerCase();
  if (ua.includes('firefox')) return 'Firefox';
  if (ua.includes('edg/') || ua.includes('edge/')) return 'Edge';
  if (ua.includes('chrome') && !ua.includes('edg')) return 'Chrome';
  if (ua.includes('safari') && !ua.includes('chrome')) return 'Safari';
  if (ua.includes('opera') || ua.includes('opr/')) return 'Opera';
  if (ua.includes('msie') || ua.includes('trident')) return 'IE';
  if (ua.includes('curl')) return 'curl';
  if (ua.includes('python')) return 'Python';
  if (ua.includes('java')) return 'Java';
  return 'Unknown';
}
