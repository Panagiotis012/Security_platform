// ─── Response Hook Executor ───
// Executes automated response actions triggered by detections.
// Each hook execution is itself logged as an audit event for full accountability.
// Hooks are configurable per detection and can be enabled/disabled independently.

import { v4 as uuidv4 } from 'uuid';
import http from 'http';
import https from 'https';
import fs from 'fs';
import winston from 'winston';
import config from '../../config/default';
import { computeInternalAuthHeaders, readSecret } from '@zerotrust/shared';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  defaultMeta: { service: 'response-hooks' },
  transports: [new winston.transports.Console()],
});

// ─── Hook Types ───

export type HookType =
  | 'BLOCK_IP'
  | 'REVOKE_SESSIONS'
  | 'REQUIRE_STEP_UP'
  | 'THROTTLE_USER'
  | 'ROTATE_CREDENTIALS';

export interface HookContext {
  alertId: string;
  detectionId: string;
  actorId?: string;
  sessionId?: string;
  ip?: string;
  ips?: string[];
  ipRange?: string;
  userId?: string;
  reason: string;
  [key: string]: unknown;
}

export interface HookResult {
  hookType: HookType;
  success: boolean;
  executionId: string;
  timestamp: string;
  details: Record<string, unknown>;
  error?: string;
}

export interface HookExecution {
  id: string;
  hookType: HookType;
  context: HookContext;
  result: HookResult;
  auditEventGenerated: boolean;
}

// ─── In-Memory State for Hooks ───

interface BlockedIpEntry {
  ip: string;
  blockedAt: string;
  expiresAt: string;
  reason: string;
  alertId: string;
}

interface StepUpFlag {
  userId: string;
  flaggedAt: string;
  expiresAt: string;
  reason: string;
  alertId: string;
}

interface ThrottledUser {
  userId: string;
  throttledAt: string;
  expiresAt: string;
  reducedRatePercent: number;
  reason: string;
  alertId: string;
}

// ─── Response Hook Executor ───

export class ResponseHookExecutor {
  /** Blocked IPs with TTL */
  private blockedIps: Map<string, BlockedIpEntry> = new Map();
  /** Users flagged for step-up authentication */
  private stepUpFlags: Map<string, StepUpFlag> = new Map();
  /** Throttled users */
  private throttledUsers: Map<string, ThrottledUser> = new Map();
  /** Revoked sessions */
  private revokedSessions: Set<string> = new Set();
  /** Credential rotation requests */
  private rotationRequests: Map<string, string> = new Map(); // userId -> requestId
  /** All hook executions for audit trail */
  private executions: HookExecution[] = [];
  /** Callback to generate audit events for hook executions */
  private auditCallback: ((hookExecution: HookExecution) => Promise<void>) | null = null;
  /** Shared secret for internal HMAC auth to other services. */
  private readonly internalSecret: string;
  /** Secret used by this caller identity (can differ from shared fallback). */
  private readonly internalCallerSecret: string;
  /** Caller ID used for internal service authentication. */
  private readonly internalCallerId: string;
  /** Key id for caller secret rotation. */
  private readonly internalCallerKeyId: string;
  /** HTTP client timeout for hook calls. */
  private readonly hookTimeoutMs: number;
  /** HTTPS agent used for intra-cluster calls (supports optional mTLS). */
  private readonly httpsAgent: https.Agent | undefined;

  constructor() {
    this.internalSecret = readSecret('INTERNAL_SHARED_SECRET');
    this.internalCallerId = (process.env['INTERNAL_AUTH_CALLER_ID'] ?? 'telemetry').trim() || 'telemetry';
    this.internalCallerSecret = readSecret('INTERNAL_AUTH_CALLER_SECRET', { defaultValue: this.internalSecret });
    this.internalCallerKeyId = (process.env['INTERNAL_AUTH_CALLER_KEY_ID'] ?? 'telemetry-v1').trim() || 'telemetry-v1';
    this.hookTimeoutMs = parseInt(process.env['HOOK_REQUEST_TIMEOUT_MS'] ?? '5000', 10);

    const tlsInsecure = ['true', '1', 'yes'].includes((process.env['HOOKS_TLS_INSECURE'] ?? '').toLowerCase());
    const caPath = process.env['INTERNAL_MTLS_CA_PATH'] ?? process.env['TELEMETRY_TLS_CA_PATH'] ?? '/certs/ca.crt';
    const certPath = process.env['TELEMETRY_TLS_CERT_PATH'] ?? '/certs/telemetry.crt';
    const keyPath = process.env['TELEMETRY_TLS_KEY_PATH'] ?? '/certs/telemetry.key';

    try {
      const agentOptions: https.AgentOptions = {
        keepAlive: true,
        maxSockets: 64,
        rejectUnauthorized: !tlsInsecure,
      };

      if (fs.existsSync(caPath)) {
        agentOptions.ca = fs.readFileSync(caPath);
      }
      if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
        agentOptions.cert = fs.readFileSync(certPath);
        agentOptions.key = fs.readFileSync(keyPath);
      }

      this.httpsAgent = new https.Agent(agentOptions);
    } catch {
      // If TLS material can't be loaded (dev/test), hook calls may still work over HTTP.
      this.httpsAgent = undefined;
    }

    // Start cleanup timer for expired entries
    this.startCleanupTimer();
    logger.info('ResponseHookExecutor initialized');
  }

  private async postInternalJson(
    baseUrl: string,
    path: string,
    body: Record<string, unknown>,
    audience?: string,
  ): Promise<{ statusCode: number; json: unknown; text: string }> {
    if (!baseUrl) {
      throw new Error('missing_service_url');
    }
    if (!this.internalSecret) {
      throw new Error('missing_INTERNAL_SHARED_SECRET');
    }

    const url = new URL(path, baseUrl);
    const method = 'POST';
    const requestPath = `${url.pathname}${url.search}`;
    const rawBody = Buffer.from(JSON.stringify(body), 'utf8');

    const internalHeaders = computeInternalAuthHeaders(
      { method, path: requestPath, rawBody },
      this.internalCallerSecret,
      undefined,
      undefined,
      this.internalCallerId,
      audience,
      this.internalCallerKeyId,
    );

    const headers: Record<string, string> = {
      ...internalHeaders,
      'content-type': 'application/json',
      'content-length': String(rawBody.length),
    };

    const isHttps = url.protocol === 'https:';
    const port = url.port ? parseInt(url.port, 10) : (isHttps ? 443 : 80);
    const requestOptions: https.RequestOptions = {
      protocol: url.protocol,
      hostname: url.hostname,
      port,
      method,
      path: requestPath,
      headers,
      timeout: this.hookTimeoutMs,
      ...(isHttps && this.httpsAgent ? { agent: this.httpsAgent } : {}),
    };

    return await new Promise((resolve, reject) => {
      const mod = isHttps ? https : http;
      const req = mod.request(requestOptions, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json: unknown = undefined;
          try {
            json = text ? JSON.parse(text) : undefined;
          } catch {
            // non-JSON response; keep as text
          }
          resolve({ statusCode: res.statusCode ?? 0, json, text });
        });
      });

      req.on('timeout', () => {
        req.destroy(new Error('hook_request_timeout'));
      });
      req.on('error', (err) => reject(err));

      req.write(rawBody);
      req.end();
    });
  }

  /**
   * Set a callback that will be called to generate audit events for each hook execution.
   */
  onAuditEvent(callback: (hookExecution: HookExecution) => Promise<void>): void {
    this.auditCallback = callback;
  }

  /**
   * Execute a response hook with the given context.
   */
  async executeHook(hookType: HookType, context: HookContext): Promise<HookResult> {
    const executionId = uuidv4();

    logger.info('Executing response hook', {
      hookType,
      executionId,
      alertId: context.alertId,
      detectionId: context.detectionId,
    });

    let result: HookResult;

    try {
      switch (hookType) {
        case 'BLOCK_IP':
          result = await this.executeBlockIp(executionId, context);
          break;
        case 'REVOKE_SESSIONS':
          result = await this.executeRevokeSessions(executionId, context);
          break;
        case 'REQUIRE_STEP_UP':
          result = await this.executeRequireStepUp(executionId, context);
          break;
        case 'THROTTLE_USER':
          result = await this.executeThrottleUser(executionId, context);
          break;
        case 'ROTATE_CREDENTIALS':
          result = await this.executeRotateCredentials(executionId, context);
          break;
        default:
          result = {
            hookType,
            success: false,
            executionId,
            timestamp: new Date().toISOString(),
            details: {},
            error: `Unknown hook type: ${hookType}`,
          };
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      result = {
        hookType,
        success: false,
        executionId,
        timestamp: new Date().toISOString(),
        details: {},
        error: message,
      };
      logger.error('Hook execution failed', {
        hookType,
        executionId,
        error: message,
      });
    }

    // Record the execution
    const execution: HookExecution = {
      id: executionId,
      hookType,
      context,
      result,
      auditEventGenerated: false,
    };
    this.executions.push(execution);

    // Generate audit event for the hook execution
    if (this.auditCallback) {
      try {
        await this.auditCallback(execution);
        execution.auditEventGenerated = true;
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        logger.error('Failed to generate audit event for hook execution', {
          executionId,
          error: message,
        });
      }
    }

    return result;
  }

  /**
   * Execute all response hooks specified in an alert.
   */
  async executeAlertHooks(
    alertId: string,
    detectionId: string,
    hooks: string[],
    context: Record<string, unknown>
  ): Promise<HookResult[]> {
    const results: HookResult[] = [];

    for (const hookTypeStr of hooks) {
      const hookType = hookTypeStr as HookType;
      const hookContext: HookContext = {
        alertId,
        detectionId,
        reason: `Automated response for detection ${detectionId}`,
        actorId: context.actorId as string | undefined,
        userId: context.userId as string | undefined,
        ip: context.sourceIp as string | undefined,
        ips: context.sourceIps as string[] | undefined,
        ipRange: context.ipRange as string | undefined,
        sessionId: context.sessionId as string | undefined,
        ...context,
      };

      const result = await this.executeHook(hookType, hookContext);
      results.push(result);
    }

    return results;
  }

  // ─── Individual Hook Implementations ───

  private async executeBlockIp(executionId: string, context: HookContext): Promise<HookResult> {
    const hookConfig = config.responseHooks.blockIp;

    if (!hookConfig.enabled) {
      return {
        hookType: 'BLOCK_IP',
        success: false,
        executionId,
        timestamp: new Date().toISOString(),
        details: { reason: 'BLOCK_IP hook is disabled' },
        error: 'Hook disabled',
      };
    }

    const ipsToBlock: string[] = [];
    if (context.ip) ipsToBlock.push(context.ip);
    if (context.ips) ipsToBlock.push(...context.ips);

    if (ipsToBlock.length === 0) {
      return {
        hookType: 'BLOCK_IP',
        success: false,
        executionId,
        timestamp: new Date().toISOString(),
        details: { reason: 'No IP address provided in context' },
        error: 'No IP to block',
      };
    }

    const durationMinutes = Math.min(hookConfig.defaultDurationMinutes, hookConfig.maxDurationMinutes);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + durationMinutes * 60 * 1000).toISOString();
    const blockedIpList: string[] = [];

    // Notify gateway to enforce the block immediately.
    try {
      const ttlSeconds = Math.max(1, Math.floor(durationMinutes * 60));
      const resp = await this.postInternalJson(
        hookConfig.gatewayServiceUrl,
        '/internal/block-ip',
        {
          ips: ipsToBlock,
          ttlSeconds,
          reason: context.reason,
          alertId: context.alertId,
        },
      );
      if (resp.statusCode < 200 || resp.statusCode >= 300) {
        throw new Error(`gateway_block_ip_failed:${resp.statusCode}:${resp.text || 'no_body'}`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error('Gateway BLOCK_IP hook failed', {
        executionId,
        alertId: context.alertId,
        error: message,
      });
      return {
        hookType: 'BLOCK_IP',
        success: false,
        executionId,
        timestamp: now.toISOString(),
        details: {
          ips: ipsToBlock,
          durationMinutes,
        },
        error: message,
      };
    }

    for (const ip of ipsToBlock) {
      const entry: BlockedIpEntry = {
        ip,
        blockedAt: now.toISOString(),
        expiresAt,
        reason: context.reason,
        alertId: context.alertId,
      };
      this.blockedIps.set(ip, entry);
      blockedIpList.push(ip);

      logger.warn('IP blocked', {
        ip,
        durationMinutes,
        alertId: context.alertId,
        executionId,
      });
    }

    return {
      hookType: 'BLOCK_IP',
      success: true,
      executionId,
      timestamp: now.toISOString(),
      details: {
        blockedIps: blockedIpList,
        durationMinutes,
        expiresAt,
        gatewayNotified: true,
      },
    };
  }

  private async executeRevokeSessions(executionId: string, context: HookContext): Promise<HookResult> {
    const hookConfig = config.responseHooks.revokeSessions;

    if (!hookConfig.enabled) {
      return {
        hookType: 'REVOKE_SESSIONS',
        success: false,
        executionId,
        timestamp: new Date().toISOString(),
        details: { reason: 'REVOKE_SESSIONS hook is disabled' },
        error: 'Hook disabled',
      };
    }

    const userId = context.userId || context.actorId;
    if (!userId) {
      return {
        hookType: 'REVOKE_SESSIONS',
        success: false,
        executionId,
        timestamp: new Date().toISOString(),
        details: { reason: 'No user ID provided' },
        error: 'No user ID',
      };
    }

    const now = new Date();

    let identityResponse: unknown = undefined;
    try {
      const resp = await this.postInternalJson(
        hookConfig.identityServiceUrl,
        '/internal/revoke-user',
        {
          userId,
          revokeSessions: true,
          revokeTokens: true,
          reason: context.reason,
          alertId: context.alertId,
        },
        process.env['HOOK_IDENTITY_INTERNAL_AUDIENCE'] ?? 'identity',
      );
      if (resp.statusCode < 200 || resp.statusCode >= 300) {
        throw new Error(`identity_revoke_user_failed:${resp.statusCode}:${resp.text || 'no_body'}`);
      }
      identityResponse = resp.json;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error('Identity REVOKE_SESSIONS hook failed', {
        userId,
        executionId,
        alertId: context.alertId,
        error: message,
      });
      return {
        hookType: 'REVOKE_SESSIONS',
        success: false,
        executionId,
        timestamp: now.toISOString(),
        details: { userId },
        error: message,
      };
    }

    // Record the revocation locally
    if (context.sessionId) {
      this.revokedSessions.add(context.sessionId);
    }

    logger.warn('Sessions revoked for user', {
      userId,
      alertId: context.alertId,
      executionId,
    });

    return {
      hookType: 'REVOKE_SESSIONS',
      success: true,
      executionId,
      timestamp: now.toISOString(),
      details: {
        userId,
        sessionId: context.sessionId,
        allSessionsRevoked: true,
        identityServiceNotified: true,
        identityResponse,
      },
    };
  }

  private async executeRequireStepUp(executionId: string, context: HookContext): Promise<HookResult> {
    const hookConfig = config.responseHooks.requireStepUp;

    if (!hookConfig.enabled) {
      return {
        hookType: 'REQUIRE_STEP_UP',
        success: false,
        executionId,
        timestamp: new Date().toISOString(),
        details: { reason: 'REQUIRE_STEP_UP hook is disabled' },
        error: 'Hook disabled',
      };
    }

    const userId = context.userId || context.actorId;
    if (!userId) {
      return {
        hookType: 'REQUIRE_STEP_UP',
        success: false,
        executionId,
        timestamp: new Date().toISOString(),
        details: { reason: 'No user ID provided' },
        error: 'No user ID',
      };
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + hookConfig.durationMinutes * 60 * 1000).toISOString();

    try {
      const ttlSeconds = Math.max(1, Math.floor(hookConfig.durationMinutes * 60));
      const resp = await this.postInternalJson(
        hookConfig.gatewayServiceUrl,
        '/internal/require-step-up',
        {
          userId,
          requiredLevel: hookConfig.requiredLevel,
          ttlSeconds,
          reason: context.reason,
          alertId: context.alertId,
        },
      );
      if (resp.statusCode < 200 || resp.statusCode >= 300) {
        throw new Error(`gateway_require_step_up_failed:${resp.statusCode}:${resp.text || 'no_body'}`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error('Gateway REQUIRE_STEP_UP hook failed', {
        userId,
        executionId,
        alertId: context.alertId,
        error: message,
      });
      return {
        hookType: 'REQUIRE_STEP_UP',
        success: false,
        executionId,
        timestamp: now.toISOString(),
        details: { userId },
        error: message,
      };
    }

    this.stepUpFlags.set(userId, {
      userId,
      flaggedAt: now.toISOString(),
      expiresAt,
      reason: context.reason,
      alertId: context.alertId,
    });

    logger.warn('Step-up authentication required for user', {
      userId,
      alertId: context.alertId,
      executionId,
    });

    return {
      hookType: 'REQUIRE_STEP_UP',
      success: true,
      executionId,
      timestamp: now.toISOString(),
      details: {
        userId,
        flaggedForStepUp: true,
        requiredLevel: hookConfig.requiredLevel,
        durationMinutes: hookConfig.durationMinutes,
        expiresAt,
        gatewayNotified: true,
      },
    };
  }

  private async executeThrottleUser(executionId: string, context: HookContext): Promise<HookResult> {
    const hookConfig = config.responseHooks.throttleUser;

    if (!hookConfig.enabled) {
      return {
        hookType: 'THROTTLE_USER',
        success: false,
        executionId,
        timestamp: new Date().toISOString(),
        details: { reason: 'THROTTLE_USER hook is disabled' },
        error: 'Hook disabled',
      };
    }

    const userId = context.userId || context.actorId;
    if (!userId) {
      return {
        hookType: 'THROTTLE_USER',
        success: false,
        executionId,
        timestamp: new Date().toISOString(),
        details: { reason: 'No user ID provided' },
        error: 'No user ID',
      };
    }

    const now = new Date();
    const expiresAt = new Date(
      now.getTime() + hookConfig.durationMinutes * 60 * 1000
    ).toISOString();

    try {
      const ttlSeconds = Math.max(1, Math.floor(hookConfig.durationMinutes * 60));
      const resp = await this.postInternalJson(
        hookConfig.gatewayServiceUrl,
        '/internal/throttle-user',
        {
          userId,
          reducedRatePercent: hookConfig.reducedRatePercent,
          ttlSeconds,
          reason: context.reason,
          alertId: context.alertId,
        },
      );
      if (resp.statusCode < 200 || resp.statusCode >= 300) {
        throw new Error(`gateway_throttle_user_failed:${resp.statusCode}:${resp.text || 'no_body'}`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error('Gateway THROTTLE_USER hook failed', {
        userId,
        executionId,
        alertId: context.alertId,
        error: message,
      });
      return {
        hookType: 'THROTTLE_USER',
        success: false,
        executionId,
        timestamp: now.toISOString(),
        details: { userId },
        error: message,
      };
    }

    this.throttledUsers.set(userId, {
      userId,
      throttledAt: now.toISOString(),
      expiresAt,
      reducedRatePercent: hookConfig.reducedRatePercent,
      reason: context.reason,
      alertId: context.alertId,
    });

    logger.warn('User throttled', {
      userId,
      reducedRatePercent: hookConfig.reducedRatePercent,
      durationMinutes: hookConfig.durationMinutes,
      alertId: context.alertId,
      executionId,
    });

    return {
      hookType: 'THROTTLE_USER',
      success: true,
      executionId,
      timestamp: new Date().toISOString(),
      details: {
        userId,
        reducedRatePercent: hookConfig.reducedRatePercent,
        durationMinutes: hookConfig.durationMinutes,
        expiresAt,
        gatewayNotified: true,
      },
    };
  }

  private async executeRotateCredentials(executionId: string, context: HookContext): Promise<HookResult> {
    const hookConfig = config.responseHooks.rotateCredentials;

    if (!hookConfig.enabled) {
      return {
        hookType: 'ROTATE_CREDENTIALS',
        success: false,
        executionId,
        timestamp: new Date().toISOString(),
        details: { reason: 'ROTATE_CREDENTIALS hook is disabled' },
        error: 'Hook disabled',
      };
    }

    const userId = context.userId || context.actorId;
    if (!userId) {
      return {
        hookType: 'ROTATE_CREDENTIALS',
        success: false,
        executionId,
        timestamp: new Date().toISOString(),
        details: { reason: 'No user ID provided' },
        error: 'No user ID',
      };
    }

    // In production: call identity service to initiate credential rotation
    // await fetch(`${hookConfig.identityServiceUrl}/v1/credentials/rotate`, {
    //   method: 'POST', body: JSON.stringify({ userId, forced: true }), ...
    // });

    const requestId = uuidv4();
    this.rotationRequests.set(userId, requestId);

    logger.warn('Credential rotation requested', {
      userId,
      requestId,
      alertId: context.alertId,
      executionId,
    });

    return {
      hookType: 'ROTATE_CREDENTIALS',
      success: true,
      executionId,
      timestamp: new Date().toISOString(),
      details: {
        userId,
        rotationRequestId: requestId,
        identityServiceNotified: false, // Would be true in production
      },
    };
  }

  // ─── Query Methods ───

  /**
   * Check if an IP is currently blocked.
   */
  isIpBlocked(ip: string): { blocked: boolean; entry?: BlockedIpEntry } {
    const entry = this.blockedIps.get(ip);
    if (!entry) return { blocked: false };

    // Check expiration
    if (new Date(entry.expiresAt) < new Date()) {
      this.blockedIps.delete(ip);
      return { blocked: false };
    }

    return { blocked: true, entry };
  }

  /**
   * Check if a user requires step-up authentication.
   */
  requiresStepUp(userId: string): boolean {
    const entry = this.stepUpFlags.get(userId);
    if (!entry) return false;
    if (new Date(entry.expiresAt) < new Date()) {
      this.stepUpFlags.delete(userId);
      return false;
    }
    return true;
  }

  /**
   * Clear step-up flag after user completes step-up.
   */
  clearStepUp(userId: string): void {
    this.stepUpFlags.delete(userId);
  }

  /**
   * Get all blocked IPs.
   */
  getBlockedIps(): BlockedIpEntry[] {
    return Array.from(this.blockedIps.values());
  }

  /**
   * Get all throttled users.
   */
  getThrottledUsers(): ThrottledUser[] {
    return Array.from(this.throttledUsers.values());
  }

  /**
   * Get all hook executions.
   */
  getExecutions(limit = 100): HookExecution[] {
    return this.executions.slice(-limit);
  }

  /**
   * Get hook execution metrics.
   */
  getMetrics(): {
    totalExecutions: number;
    successfulExecutions: number;
    failedExecutions: number;
    blockedIps: number;
    stepUpFlags: number;
    throttledUsers: number;
    byHookType: Record<string, { total: number; success: number; failed: number }>;
  } {
    const byHookType: Record<string, { total: number; success: number; failed: number }> = {};

    for (const exec of this.executions) {
      if (!byHookType[exec.hookType]) {
        byHookType[exec.hookType] = { total: 0, success: 0, failed: 0 };
      }
      byHookType[exec.hookType].total++;
      if (exec.result.success) {
        byHookType[exec.hookType].success++;
      } else {
        byHookType[exec.hookType].failed++;
      }
    }

    return {
      totalExecutions: this.executions.length,
      successfulExecutions: this.executions.filter((e) => e.result.success).length,
      failedExecutions: this.executions.filter((e) => !e.result.success).length,
      blockedIps: this.blockedIps.size,
      stepUpFlags: this.stepUpFlags.size,
      throttledUsers: this.throttledUsers.size,
      byHookType,
    };
  }

  // ─── Cleanup ───

  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  private startCleanupTimer(): void {
    // Clean up expired entries every 60 seconds
    this.cleanupTimer = setInterval(() => {
      const now = new Date();

      for (const [ip, entry] of this.blockedIps) {
        if (new Date(entry.expiresAt) < now) {
          this.blockedIps.delete(ip);
          logger.info('IP block expired', { ip });
        }
      }

      for (const [userId, entry] of this.throttledUsers) {
        if (new Date(entry.expiresAt) < now) {
          this.throttledUsers.delete(userId);
          logger.info('User throttle expired', { userId });
        }
      }

      for (const [userId, entry] of this.stepUpFlags) {
        if (new Date(entry.expiresAt) < now) {
          this.stepUpFlags.delete(userId);
          logger.info('Step-up requirement expired', { userId });
        }
      }
    }, 60_000);
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  /**
   * Stop the cleanup timer (for graceful shutdown).
   */
  stop(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }
}
