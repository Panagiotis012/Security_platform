import {
  signConvergenceTelemetryPayload,
  verifyConvergenceTelemetryPayload,
} from '../../gateway/src/internal/convergence-telemetry-signing';

describe('Convergence Telemetry Signing', () => {
  test('signs and verifies telemetry payloads', () => {
    const payload = {
      runId: 'run-1',
      peer: 'https://peer-a.example',
      healed: true,
      driftsDetected: 2,
    };
    const signed = signConvergenceTelemetryPayload(
      payload,
      'gateway-convergence-v1',
      '0123456789abcdef0123456789abcdef',
    );
    const verified = verifyConvergenceTelemetryPayload(
      payload,
      signed,
      { 'gateway-convergence-v1': '0123456789abcdef0123456789abcdef' },
    );
    expect(verified.ok).toBe(true);
  });

  test('rejects tampered payloads', () => {
    const payload = {
      runId: 'run-1',
      peer: 'https://peer-a.example',
      healed: true,
      driftsDetected: 2,
    };
    const signed = signConvergenceTelemetryPayload(
      payload,
      'gateway-convergence-v1',
      '0123456789abcdef0123456789abcdef',
    );
    const tampered = {
      ...payload,
      healed: false,
    };
    const verified = verifyConvergenceTelemetryPayload(
      tampered,
      signed,
      { 'gateway-convergence-v1': '0123456789abcdef0123456789abcdef' },
    );
    expect(verified.ok).toBe(false);
    if (!verified.ok) {
      expect(verified.reason).toBe('payload_hash_mismatch');
    }
  });
});
