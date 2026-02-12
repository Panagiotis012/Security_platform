describe('Telemetry config - alert routing', () => {
  const ORIGINAL_ENV = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV };

    delete process.env.ALERT_WEBHOOK_URL;
    delete process.env.ALERT_CRITICAL_WEBHOOK;
    delete process.env.ALERT_HIGH_WEBHOOK;
  });

  afterAll(() => {
    process.env = ORIGINAL_ENV;
  });

  it('disables webhook channel when no webhook URL is configured', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const cfg = require('../../telemetry/config/default').default;

    expect(cfg.alertRouting.critical.channels).toEqual(['log']);
    expect(cfg.alertRouting.critical.webhookUrl).toBe('');

    expect(cfg.alertRouting.high.channels).toEqual(['log']);
    expect(cfg.alertRouting.high.webhookUrl).toBe('');
  });

  it('uses ALERT_WEBHOOK_URL as a fallback for critical/high', () => {
    process.env.ALERT_WEBHOOK_URL = 'https://example.com/webhook';
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const cfg = require('../../telemetry/config/default').default;

    expect(cfg.alertRouting.critical.channels).toContain('webhook');
    expect(cfg.alertRouting.critical.webhookUrl).toBe('https://example.com/webhook');

    expect(cfg.alertRouting.high.channels).toContain('webhook');
    expect(cfg.alertRouting.high.webhookUrl).toBe('https://example.com/webhook');
  });

  it('prefers per-severity webhook URL overrides', () => {
    process.env.ALERT_WEBHOOK_URL = 'https://example.com/all';
    process.env.ALERT_CRITICAL_WEBHOOK = 'https://example.com/critical';
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const cfg = require('../../telemetry/config/default').default;

    expect(cfg.alertRouting.critical.webhookUrl).toBe('https://example.com/critical');
    expect(cfg.alertRouting.high.webhookUrl).toBe('https://example.com/all');
  });
});

