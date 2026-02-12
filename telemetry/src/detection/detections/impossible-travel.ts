// ─── Impossible Travel Detection ───
// Detects impossible travel: same user authenticates from locations >500km apart within <1 hour.
// Uses geoIP data from enriched audit events.
// Severity: HIGH
// Response: require step-up auth, alert SOC.

import { v4 as uuidv4 } from 'uuid';
import config from '../../../config/default';
import type { AuditEvent } from '../../audit/audit-store';
import type { Detection, Alert, AlertSeverity } from '../detection-engine';

const thresholds = config.detectionThresholds.impossibleTravel;

/**
 * Calculate the great-circle distance between two points on Earth using the Haversine formula.
 * Returns distance in kilometers.
 */
function haversineDistance(
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number
): number {
  const R = 6371; // Earth's radius in km
  const dLat = toRadians(lat2 - lat1);
  const dLon = toRadians(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRadians(lat1)) *
      Math.cos(toRadians(lat2)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

function toRadians(degrees: number): number {
  return degrees * (Math.PI / 180);
}

/**
 * Calculate required speed in km/h to travel between two points in the given time.
 */
function requiredSpeedKmH(distanceKm: number, timeMs: number): number {
  if (timeMs <= 0) return Infinity;
  const hours = timeMs / (1000 * 60 * 60);
  return distanceKm / hours;
}

export const ImpossibleTravelDetection: Detection = {
  id: 'impossible-travel',
  name: 'Impossible Travel Detection',
  description: 'Detects when a user authenticates from geographically distant locations in an impossibly short time.',
  severity: 'HIGH' as AlertSeverity,
  type: 'pattern',
  enabled: true,
  suppressionWindowSeconds: config.suppression.perDetection['impossible-travel'] || 3600,
  thresholds: {
    maxDistanceKm: thresholds.maxDistanceKm,
    minTimeHours: thresholds.minTimeHours,
  },

  evaluate(events: AuditEvent[]): Alert[] {
    const alerts: Alert[] = [];
    const maxTimeMs = this.thresholds.minTimeHours * 60 * 60 * 1000;

    // Filter to authentication events that have geoIP data
    const authEventsWithGeo = events.filter(
      (e) =>
        (e.action.includes('auth') || e.action.includes('login') || e.action.includes('session')) &&
        e.result.decision === 'ALLOW' &&
        e.context.geoLocation?.latitude !== undefined &&
        e.context.geoLocation?.longitude !== undefined
    );

    if (authEventsWithGeo.length < 2) return alerts;

    // Group by user
    const byUser = new Map<string, AuditEvent[]>();
    for (const event of authEventsWithGeo) {
      const key = event.actor.id;
      const existing = byUser.get(key) || [];
      existing.push(event);
      byUser.set(key, existing);
    }

    // Track which user pairs have already been alerted to avoid duplicates
    const alertedPairs = new Set<string>();

    for (const [userId, userEvents] of byUser) {
      if (userEvents.length < 2) continue;

      // Sort by timestamp
      const sorted = [...userEvents].sort(
        (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      );

      // Compare consecutive events
      for (let i = 0; i < sorted.length - 1; i++) {
        for (let j = i + 1; j < sorted.length; j++) {
          const event1 = sorted[i];
          const event2 = sorted[j];

          const time1 = new Date(event1.timestamp).getTime();
          const time2 = new Date(event2.timestamp).getTime();
          const timeDiff = time2 - time1;

          // Only check within our time window
          if (timeDiff > maxTimeMs) break;

          const lat1 = event1.context.geoLocation!.latitude!;
          const lon1 = event1.context.geoLocation!.longitude!;
          const lat2 = event2.context.geoLocation!.latitude!;
          const lon2 = event2.context.geoLocation!.longitude!;

          const distance = haversineDistance(lat1, lon1, lat2, lon2);

          if (distance > this.thresholds.maxDistanceKm) {
            const pairKey = `${userId}:${event1.id}:${event2.id}`;
            if (alertedPairs.has(pairKey)) continue;
            alertedPairs.add(pairKey);

            const speed = requiredSpeedKmH(distance, timeDiff);
            const timeMinutes = timeDiff / (1000 * 60);

            const location1 = [
              event1.context.geoLocation?.city,
              event1.context.geoLocation?.region,
              event1.context.geoLocation?.country,
            ].filter(Boolean).join(', ') || `${lat1},${lon1}`;

            const location2 = [
              event2.context.geoLocation?.city,
              event2.context.geoLocation?.region,
              event2.context.geoLocation?.country,
            ].filter(Boolean).join(', ') || `${lat2},${lon2}`;

            alerts.push({
              id: uuidv4(),
              detectionId: this.id,
              detectionName: this.name,
              severity: this.severity,
              title: `Impossible travel for user ${userId}`,
              description: `User "${userId}" authenticated from "${location1}" and "${location2}" (${Math.round(distance)} km apart) within ${Math.round(timeMinutes)} minutes. Required speed: ${Math.round(speed)} km/h. This is physically impossible and indicates credential compromise.`,
              events: [event1, event2],
              context: {
                userId,
                location1: {
                  ip: event1.context.ip,
                  city: event1.context.geoLocation?.city,
                  country: event1.context.geoLocation?.country,
                  latitude: lat1,
                  longitude: lon1,
                },
                location2: {
                  ip: event2.context.ip,
                  city: event2.context.geoLocation?.city,
                  country: event2.context.geoLocation?.country,
                  latitude: lat2,
                  longitude: lon2,
                },
                distanceKm: Math.round(distance),
                timeMinutes: Math.round(timeMinutes),
                requiredSpeedKmH: Math.round(speed),
              },
              responseHooks: ['REQUIRE_STEP_UP', 'REVOKE_SESSIONS'],
              timestamp: new Date().toISOString(),
            });

            // Only alert once per user per evaluation to avoid flood
            break;
          }
        }
      }
    }

    return alerts;
  },
};
