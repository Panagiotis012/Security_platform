import { v4 as uuidv4 } from 'uuid';
import type { AuditEvent } from '../../telemetry/src/audit/audit-store';
import { InMemoryAuditStore } from '../../telemetry/src/audit/audit-store';
import { DetectionEngine } from '../../telemetry/src/detection/detection-engine';
import { BruteForceDetection } from '../../telemetry/src/detection/detections/brute-force';
import { ImpossibleTravelDetection } from '../../telemetry/src/detection/detections/impossible-travel';

function makeEvent(partial: Partial<AuditEvent>): AuditEvent {
  const now = new Date().toISOString();
  return {
    id: uuidv4(),
    version: '2.0',
    timestamp: now,
    actor: { type: 'user', id: 'user-1' },
    subject: { type: 'auth', id: 'login' },
    action: 'auth.login',
    resource: { type: 'auth', id: 'login' },
    result: { decision: 'DENY' },
    context: { ip: '1.2.3.4', userAgent: 'jest' },
    ...partial,
  };
}

describe('Telemetry Detection Engine - Real Detections', () => {
  test('BruteForceDetection triggers when threshold exceeded in window', async () => {
    const store = new InMemoryAuditStore();

    // Create >10 failures for the same actor in the recent window.
    const now = Date.now();
    for (let i = 0; i < 12; i++) {
      await store.append(
        makeEvent({
          actor: { type: 'user', id: 'user-1' },
          result: { decision: 'DENY' },
          context: { ip: '1.2.3.4' },
          timestamp: new Date(now - i * 10_000).toISOString(),
        })
      );
    }

    const engine = new DetectionEngine(store);
    engine.registerDetection(BruteForceDetection);

    const alerts = engine.evaluate();
    expect(alerts.some((a) => a.detectionId === 'brute-force')).toBe(true);
  });

  test('ImpossibleTravelDetection triggers for far distance in short time', async () => {
    const store = new InMemoryAuditStore();
    const now = Date.now();

    await store.append(
      makeEvent({
        actor: { type: 'user', id: 'user-1' },
        action: 'auth.login',
        result: { decision: 'ALLOW' },
        context: {
          ip: '1.2.3.4',
          geoLocation: { latitude: 40.7128, longitude: -74.0060 }, // NYC
        },
        timestamp: new Date(now - 30 * 60_000).toISOString(),
      })
    );

    await store.append(
      makeEvent({
        actor: { type: 'user', id: 'user-1' },
        action: 'auth.login',
        result: { decision: 'ALLOW' },
        context: {
          ip: '9.9.9.9',
          geoLocation: { latitude: 51.5074, longitude: -0.1278 }, // London
        },
        timestamp: new Date(now).toISOString(),
      })
    );

    const engine = new DetectionEngine(store);
    engine.registerDetection(ImpossibleTravelDetection);

    const alerts = engine.evaluate();
    expect(alerts.some((a) => a.detectionId === 'impossible-travel')).toBe(true);
  });
});
