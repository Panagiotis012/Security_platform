// ─── Privilege Escalation Detection ───
// Detects privilege escalation attempts: user attempts actions above their role,
// repeated authorization denials for admin resources.
// Trigger: user attempts admin/elevated actions and receives repeated DENY decisions.
// Severity: HIGH
// Response: alert SOC, log for investigation.

import { v4 as uuidv4 } from 'uuid';
import config from '../../../config/default';
import type { AuditEvent } from '../../audit/audit-store';
import type { Detection, Alert, AlertSeverity } from '../detection-engine';

const thresholds = config.detectionThresholds.privilegeEscalation;

// Actions and resources considered elevated/admin-level
const ELEVATED_ACTIONS = [
  'admin.', 'role.assign', 'role.create', 'role.modify', 'role.delete',
  'policy.create', 'policy.modify', 'policy.delete',
  'user.create', 'user.delete', 'user.modify-role',
  'config.modify', 'config.delete',
  'secret.read', 'secret.create', 'secret.modify',
  'audit.delete', 'audit.modify',
  'key.create', 'key.rotate', 'key.delete',
  'service.deploy', 'service.destroy',
  'permission.grant', 'permission.revoke',
];

const SENSITIVE_RESOURCE_TYPES = [
  'admin-panel', 'admin-api', 'role', 'policy', 'permission',
  'secrets', 'credentials', 'keys', 'certificates',
  'audit-log', 'config', 'infrastructure',
];

function isElevatedAction(action: string): boolean {
  return ELEVATED_ACTIONS.some((ea) => action.includes(ea));
}

function isSensitiveResource(resourceType: string): boolean {
  return SENSITIVE_RESOURCE_TYPES.some((sr) => resourceType.includes(sr));
}

export const PrivilegeEscalationDetection: Detection = {
  id: 'privilege-escalation',
  name: 'Privilege Escalation Detection',
  description: 'Detects users attempting to access resources or perform actions beyond their authorized role.',
  severity: 'HIGH' as AlertSeverity,
  type: 'pattern',
  enabled: true,
  suppressionWindowSeconds: config.suppression.perDetection['privilege-escalation'] || 600,
  thresholds: {
    maxDeniedAdminAttempts: thresholds.maxDeniedAdminAttempts,
    windowMinutes: thresholds.windowMinutes,
  },

  evaluate(events: AuditEvent[]): Alert[] {
    const alerts: Alert[] = [];
    const windowMs = this.thresholds.windowMinutes * 60 * 1000;
    const now = Date.now();
    const cutoff = new Date(now - windowMs).toISOString();

    // Filter to denied events targeting elevated actions or sensitive resources within the window
    const escalationAttempts = events.filter(
      (e) =>
        e.timestamp >= cutoff &&
        e.result.decision === 'DENY' &&
        e.actor.type === 'user' && // Focus on user actors, not services
        (isElevatedAction(e.action) || isSensitiveResource(e.resource.type))
    );

    if (escalationAttempts.length === 0) return alerts;

    // Group by actor
    const byActor = new Map<string, AuditEvent[]>();
    for (const event of escalationAttempts) {
      const key = event.actor.id;
      const existing = byActor.get(key) || [];
      existing.push(event);
      byActor.set(key, existing);
    }

    for (const [actorId, actorEvents] of byActor) {
      if (actorEvents.length >= this.thresholds.maxDeniedAdminAttempts) {
        const attemptedActions = [...new Set(actorEvents.map((e) => e.action))];
        const targetedResources = [...new Set(actorEvents.map((e) => `${e.resource.type}:${e.resource.id}`))];
        const denyReasons = [...new Set(actorEvents.map((e) => e.result.reason).filter(Boolean))];
        const policyIds = [...new Set(actorEvents.map((e) => e.result.policyId).filter(Boolean))];

        // Determine if this looks like systematic probing vs. accidental access
        const isSystematic = attemptedActions.length >= 3 || targetedResources.length >= 3;

        alerts.push({
          id: uuidv4(),
          detectionId: this.id,
          detectionName: this.name,
          severity: this.severity,
          title: `Privilege escalation attempts by user ${actorId}`,
          description: `User "${actorId}" made ${actorEvents.length} denied attempts to access elevated resources/actions in ${this.thresholds.windowMinutes} minutes. ${isSystematic ? 'Pattern suggests systematic privilege probing.' : 'May indicate misconfigured permissions or attempted escalation.'} Attempted actions: ${attemptedActions.join(', ')}`,
          events: actorEvents,
          context: {
            actorId,
            deniedAttempts: actorEvents.length,
            attemptedActions,
            targetedResources: targetedResources.slice(0, 20),
            denyReasons,
            policyIds,
            isSystematicProbing: isSystematic,
            sourceIps: [...new Set(actorEvents.map((e) => e.context.ip).filter(Boolean))],
            windowMinutes: this.thresholds.windowMinutes,
          },
          responseHooks: [], // Alert SOC and log only; no automated response to avoid locking out legitimate users
          timestamp: new Date().toISOString(),
        });
      }
    }

    // ─── Additional check: role assignment attempts (even if some succeed) ───
    const roleAttempts = events.filter(
      (e) =>
        e.timestamp >= cutoff &&
        (e.action.includes('role.assign') || e.action.includes('permission.grant')) &&
        e.actor.type === 'user'
    );

    // Group self-assignment attempts (user tries to grant themselves elevated access)
    for (const event of roleAttempts) {
      if (
        event.actor.id === event.subject?.id &&
        event.result.decision === 'DENY'
      ) {
        alerts.push({
          id: uuidv4(),
          detectionId: this.id,
          detectionName: this.name,
          severity: this.severity,
          title: `Self-privilege escalation attempt by user ${event.actor.id}`,
          description: `User "${event.actor.id}" attempted to assign elevated roles/permissions to themselves. Action: "${event.action}", Resource: "${event.resource.type}:${event.resource.id}". Denied by policy ${event.result.policyId || 'unknown'}.`,
          events: [event],
          context: {
            actorId: event.actor.id,
            action: event.action,
            targetResource: `${event.resource.type}:${event.resource.id}`,
            selfAssignment: true,
            sourceIp: event.context.ip,
          },
          responseHooks: [],
          timestamp: new Date().toISOString(),
        });
      }
    }

    return alerts;
  },
};
