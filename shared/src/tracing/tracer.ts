/**
 * OpenTelemetry distributed tracing module for the Zero Trust security platform.
 *
 * Provides:
 *  - Automatic span creation for HTTP requests via Express middleware
 *  - W3C Trace Context propagation for distributed tracing
 *  - Security-aware span attributes (user ID, policy decision, correlation ID)
 *  - Integration with the existing correlation ID system
 *  - Helper functions for adding security events and error recording
 *  - Graceful shutdown and configuration via environment variables
 *
 * Usage:
 *   import { initializeTracing, tracingMiddleware, createSpan, addSecurityEvent } from '@zerotrust/shared';
 *
 *   // Initialize once at startup
 *   const tracingManager = await initializeTracing();
 *
 *   // Apply middleware early in the Express pipeline
 *   app.use(tracingMiddleware(tracingManager));
 *
 *   // Create child spans for specific operations
 *   app.get('/api/resource', async (req, res) => {
 *     const span = createSpan(req.traceSpan, 'fetch_resource', {
 *       resource_id: resourceId,
 *     });
 *     try {
 *       // ... fetch logic ...
 *       addSecurityEvent(span, {
 *         type: 'policy_evaluation',
 *         result: 'allow',
 *         policy_id: policyId,
 *       });
 *     } catch (error) {
 *       recordError(span, error as Error);
 *       throw error;
 *     } finally {
 *       span.end();
 *     }
 *   });
 */

import type {
  Context,
  Span,
  Tracer} from '@opentelemetry/api';
import {
  context,
  trace,
  SpanStatusCode
} from '@opentelemetry/api';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { W3CTraceContextPropagator } from '@opentelemetry/core';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Security context attributes to include in spans.
 */
export interface SecurityContext {
  /** ID of the authenticated user or workload. */
  authenticatedUser?: string;
  /** Result of policy evaluation (allow/deny/error). */
  policyDecision?: 'allow' | 'deny' | 'error';
  /** ID of the policy that was evaluated. */
  policyId?: string;
  /** Correlation ID for cross-service tracing. */
  correlationId?: string;
  /** Privilege level of the user (e.g., "admin", "user"). */
  privilegeLevel?: string;
  /** Tenant or organization ID if applicable. */
  tenantId?: string;
  /** Any additional custom attributes. */
  [key: string]: unknown;
}

/**
 * Security event to record in a span.
 */
export interface SecurityEvent {
  /** Type of security event (policy_evaluation, access_denied, mfa_required, etc.). */
  type: string;
  /** Outcome of the event (allow, deny, challenge, etc.). */
  result?: string;
  /** Optional message. */
  message?: string;
  /** Policy ID if applicable. */
  policyId?: string;
  /** Additional metadata. */
  [key: string]: unknown;
}

/**
 * Configuration options for the TracingManager.
 */
export interface TracingConfig {
  /** Service name to identify this service in traces. */
  serviceName: string;
  /** OpenTelemetry Collector OTLP/HTTP endpoint. */
  exporterEndpoint: string;
  /** Sampling rate (0.0 to 1.0). */
  samplingRate: number;
  /** Environment (dev, staging, production, etc.). */
  environment: string;
  /** Version of the service. */
  serviceVersion: string;
  /** Optional custom attributes to add to all spans. */
  globalAttributes?: Record<string, unknown>;
}

/**
 * Minimal subset of Express types to avoid hard dependency.
 */
export interface TracingRequest {
  headers: Record<string, string | string[] | undefined>;
  method: string;
  originalUrl: string;
  url: string;
  ip?: string;
  traceSpan?: Span;
  traceContext?: Context;
  correlationId?: string;
}

export interface TracingResponse {
  statusCode?: number;
  status(code: number): void;
  setHeader(name: string, value: string): void;
  on(event: string, listener: (...args: unknown[]) => void): void;
}

/**
 * Manages OpenTelemetry initialization and span creation.
 */
export class TracingManager {
  private sdk: NodeSDK | null = null;
  private tracer: Tracer | null = null;
  private config: TracingConfig;
  private initialized = false;

  constructor(config: TracingConfig) {
    this.config = config;
  }

  /**
   * Initialize the OpenTelemetry SDK and tracer.
   * Must be called exactly once at application startup.
   */
  public async initialize(): Promise<void> {
    if (this.initialized) {
      throw new Error('TracingManager already initialized');
    }

    try {
      // Create the OTLP exporter
      const exporter = new OTLPTraceExporter({
        url: this.config.exporterEndpoint,
      });

      // Initialize the Node SDK with the exporter
      this.sdk = new NodeSDK({
        traceExporter: exporter,
        instrumentations: [],
      });

      await this.sdk.start();

      // Get the tracer provider and create a tracer
      const tracerProvider = trace.getTracerProvider();
      this.tracer = tracerProvider.getTracer(this.config.serviceName, this.config.serviceVersion);

      this.initialized = true;
    } catch (error) {
      const message =
        error instanceof Error ? error.message : String(error);
      throw new Error(`Failed to initialize TracingManager: ${message}`);
    }
  }

  /**
   * Get the underlying Tracer instance.
   * Can only be called after initialization.
   */
  public getTracer(): Tracer {
    if (!this.tracer) {
      throw new Error('TracingManager not initialized');
    }
    return this.tracer;
  }

  /**
   * Get the current tracing configuration.
   */
  public getConfig(): TracingConfig {
    return this.config;
  }

  /**
   * Gracefully shut down the SDK, flushing all pending spans.
   * Should be called at application shutdown.
   */
  public async shutdown(): Promise<void> {
    if (!this.sdk) {
      return;
    }

    try {
      await this.sdk.shutdown();
      this.sdk = null;
      this.tracer = null;
      this.initialized = false;
    } catch (error) {
      const message =
        error instanceof Error ? error.message : String(error);
      console.error(`Error during TracingManager shutdown: ${message}`);
    }
  }
}

/**
 * Initialize the TracingManager from environment variables.
 *
 * Environment variables:
 *  - OTEL_SERVICE_NAME: Service name (default: "unknown-service")
 *  - OTEL_EXPORTER_OTLP_ENDPOINT: Collector endpoint (default: "http://localhost:4318")
 *  - OTEL_TRACE_SAMPLE_RATE: Sampling rate 0.0-1.0 (default: "1.0")
 *  - NODE_ENV: Environment (default: "development")
 *  - SERVICE_VERSION: Service version (default: "0.0.0")
 */
export async function initializeTracing(config?: Partial<TracingConfig>): Promise<TracingManager> {
  const finalConfig: TracingConfig = {
    serviceName: config?.serviceName ?? process.env.OTEL_SERVICE_NAME ?? 'unknown-service',
    exporterEndpoint:
      config?.exporterEndpoint ??
      process.env.OTEL_EXPORTER_OTLP_ENDPOINT ??
      'http://localhost:4318',
    samplingRate: config?.samplingRate ?? parseFloat(process.env.OTEL_TRACE_SAMPLE_RATE ?? '1.0'),
    environment: config?.environment ?? process.env.NODE_ENV ?? 'development',
    serviceVersion: config?.serviceVersion ?? process.env.SERVICE_VERSION ?? '0.0.0',
    globalAttributes: config?.globalAttributes,
  };

  const manager = new TracingManager(finalConfig);
  await manager.initialize();
  return manager;
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/**
 * Create a child span within a parent span or the current trace context.
 *
 * @param parentSpan Parent span or the current root span (can be undefined)
 * @param name Name of the new span
 * @param attributes Optional attributes to attach to the span
 * @returns The newly created span
 */
export function createSpan(
  parentSpan: Span | undefined,
  name: string,
  attributes?: Record<string, unknown>,
): Span {
  const tracer = trace.getTracer('default');
  let newSpan: Span;

  if (parentSpan) {
    // Create a child of the given parent
    newSpan = tracer.startSpan(name, {}, trace.setSpan(context.active(), parentSpan));
  } else {
    // Use the current context (may be a root span)
    newSpan = tracer.startSpan(name);
  }

  if (attributes) {
    Object.entries(attributes).forEach(([key, value]) => {
      newSpan.setAttribute(key, value as string | number | boolean);
    });
  }

  return newSpan;
}

/**
 * Add a security-relevant event to a span.
 *
 * @param span The span to add the event to
 * @param event The security event
 */
export function addSecurityEvent(span: Span, event: SecurityEvent): void {
  const eventName = `security.${event.type}`;
  const attributes: Record<string, string | number | boolean> = {};

  if (event.result) {
    attributes['security.result'] = event.result;
  }
  if (event.message) {
    attributes['security.message'] = event.message;
  }
  if (event.policyId) {
    attributes['security.policy_id'] = event.policyId;
  }

  // Add any additional attributes
  Object.entries(event).forEach(([key, value]) => {
    if (!['type', 'result', 'message', 'policyId'].includes(key)) {
      attributes[`security.${key}`] = value as string | number | boolean;
    }
  });

  span.addEvent(eventName, attributes);
}

/**
 * Record an error on a span and set the span status to error.
 *
 * @param span The span to record the error on
 * @param error The error to record
 */
export function recordError(span: Span, error: Error): void {
  span.recordException(error);
  span.setStatus({
    code: SpanStatusCode.ERROR,
    message: error.message,
  });
}

/**
 * Inject the current trace context into outgoing request headers.
 * Used when making calls to downstream services.
 *
 * @param span The current span
 * @param headers Headers object to inject trace context into
 */
export function injectTraceContext(span: Span, headers: Record<string, string>): void {
  const propagator = new W3CTraceContextPropagator();
  const ctx = trace.setSpan(context.active(), span);
  const carrier: Record<string, unknown> = {};
  propagator.inject(ctx, carrier, {
    set: (carrier: Record<string, unknown>, key: string, value: string) => {
      carrier[key] = value;
    },
  });
  Object.entries(carrier).forEach(([key, value]) => {
    headers[key] = String(value);
  });
}

/**
 * Extract trace context from incoming request headers.
 * Used to continue a trace from an upstream service.
 *
 * @param headers Request headers containing trace context
 * @returns The extracted context
 */
export function extractTraceContext(
  headers: Record<string, string | string[] | undefined>,
): Context {
  const propagator = new W3CTraceContextPropagator();
  const carrier: Record<string, unknown> = {};
  Object.entries(headers).forEach(([key, value]) => {
    carrier[key] = Array.isArray(value) ? value[0] : value;
  });
  return propagator.extract(context.active(), carrier, {
    get: (carrier: Record<string, unknown>, key: string) => {
      const value = carrier[key];
      return Array.isArray(value) ? value[0] : value;
    },
    keys: (carrier: Record<string, unknown>) => {
      return Object.keys(carrier);
    },
  });
}

// ---------------------------------------------------------------------------
// Express middleware
// ---------------------------------------------------------------------------

/**
 * Configuration options for the tracing middleware.
 */
export interface TracingMiddlewareOptions {
  /** If true, trace context from request headers is propagated. Default: true. */
  propagateIncoming?: boolean;
  /** If true, trace context is injected into response headers. Default: true. */
  propagateOutgoing?: boolean;
  /** Paths to skip tracing (e.g., health checks). Default: ['/health', '/ready']. */
  excludePaths?: string[];
  /** Custom attribute extractor function. */
  attributeExtractor?: (req: TracingRequest) => Record<string, unknown>;
  /** Custom security context extractor function. */
  securityContextExtractor?: (req: TracingRequest) => SecurityContext | undefined;
}

/**
 * Create Express middleware that automatically creates spans for incoming HTTP requests.
 *
 * The middleware:
 *  - Extracts or generates a trace context from request headers
 *  - Creates a root span for the request
 *  - Sets standard HTTP attributes (method, url, status_code, user_agent)
 *  - Sets security attributes from the security context
 *  - Attaches the span and context to the request for downstream handlers
 *  - Records response status and duration
 *  - Propagates trace context to downstream services via injectTraceContext()
 *
 * @param manager The TracingManager instance
 * @param options Configuration options
 * @returns Express middleware function
 */
export function tracingMiddleware(
  manager: TracingManager,
  options: TracingMiddlewareOptions = {},
): (req: TracingRequest, res: TracingResponse, next: (err?: unknown) => void) => void {
  const propagateIncoming = options.propagateIncoming ?? true;
  const propagateOutgoing = options.propagateOutgoing ?? true;
  const excludePaths = options.excludePaths ?? ['/health', '/ready'];
  const tracer = manager.getTracer();

  return (req: TracingRequest, res: TracingResponse, next: (err?: unknown) => void): void => {
    // Check if path should be excluded
    const pathToCheck = req.url.split('?')[0] ?? req.url;
    if (excludePaths.some((excludePath) => pathToCheck.startsWith(excludePath))) {
      next();
      return;
    }

    // Extract trace context from incoming headers or create a new one
    let spanContext: Context;
    if (propagateIncoming) {
      spanContext = extractTraceContext(req.headers);
    } else {
      spanContext = context.active();
    }

    // Create a span for this request
    const spanName = `${req.method} ${pathToCheck}`;
    const span = context.with(spanContext, () => {
      return tracer.startSpan(spanName);
    });

    // Collect HTTP attributes
    const httpAttributes: Record<string, unknown> = {
      'http.method': req.method,
      'http.url': req.url,
      'http.scheme': req.headers['x-forwarded-proto'] ?? 'http',
      'http.target': pathToCheck,
      'http.host': req.headers.host,
      'http.user_agent': req.headers['user-agent'],
      'http.client_ip': req.ip ?? req.headers['x-forwarded-for'],
    };

    // Set HTTP attributes
    Object.entries(httpAttributes).forEach(([key, value]) => {
      if (value !== undefined) {
        span.setAttribute(key, value as string | number | boolean);
      }
    });

    // Extract and set security context
    const securityCtx = options.securityContextExtractor?.(req) ?? extractSecurityContextFromRequest(req);
    if (securityCtx) {
      if (securityCtx.authenticatedUser) {
        span.setAttribute('security.authenticated_user', securityCtx.authenticatedUser);
      }
      if (securityCtx.policyDecision) {
        span.setAttribute('security.policy_decision', securityCtx.policyDecision);
      }
      if (securityCtx.policyId) {
        span.setAttribute('security.policy_id', securityCtx.policyId);
      }
      if (securityCtx.correlationId) {
        span.setAttribute('security.correlation_id', securityCtx.correlationId);
      }
      if (securityCtx.privilegeLevel) {
        span.setAttribute('security.privilege_level', securityCtx.privilegeLevel);
      }
      if (securityCtx.tenantId) {
        span.setAttribute('security.tenant_id', securityCtx.tenantId);
      }
    }

    // Apply custom attributes if provided
    if (options.attributeExtractor) {
      const customAttrs = options.attributeExtractor(req);
      Object.entries(customAttrs).forEach(([key, value]) => {
        span.setAttribute(key, value as string | number | boolean);
      });
    }

    // Attach span and context to the request for downstream handlers
    req.traceSpan = span;
    req.traceContext = trace.setSpan(spanContext, span);

    // Capture response status
    let statusCode: number | undefined;
    const originalStatus = res.status.bind(res);
    res.status = function (code: number) {
      statusCode = code;
      return originalStatus(code);
    };

    // Record response completion
    const startTime = Date.now();
    const responseListener = (): void => {
      const duration = Date.now() - startTime;

      // Set response status code
      if (statusCode !== undefined) {
        span.setAttribute('http.status_code', statusCode);

        // Set span status based on HTTP status code
        if (statusCode >= 400) {
          span.setStatus({
            code: SpanStatusCode.ERROR,
            message: `HTTP ${statusCode}`,
          });
        } else {
          span.setStatus({ code: SpanStatusCode.OK });
        }
      }

      // Set duration
      span.setAttribute('http.duration_ms', duration);

      // Inject trace context into response headers if enabled
      if (propagateOutgoing) {
        const responseHeaders: Record<string, string> = {};
        injectTraceContext(span, responseHeaders);
        Object.entries(responseHeaders).forEach(([key, value]) => {
          res.setHeader(key, value);
        });
      }

      span.end();
    };

    // Listen for response completion
    res.on('finish', responseListener);
    res.on('close', responseListener);

    // Continue to next middleware
    next();
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Extract security context from the request if available.
 * Looks for common patterns in Express request properties.
 */
function extractSecurityContextFromRequest(req: TracingRequest): SecurityContext | undefined {
  const context: SecurityContext = {};
  let hasAny = false;

  // Check for correlation ID (populated by correlationIdMiddleware)
  if ((req as unknown as { correlationId?: string }).correlationId) {
    context.correlationId = (req as unknown as { correlationId?: string }).correlationId;
    hasAny = true;
  }

  // Check for user (common pattern in Express auth middleware)
  const user = (req as unknown as { user?: { id?: string; privilegeLevel?: string } }).user;
  if (user) {
    if (user.id) {
      context.authenticatedUser = user.id;
      hasAny = true;
    }
    if (user.privilegeLevel) {
      context.privilegeLevel = user.privilegeLevel;
      hasAny = true;
    }
  }

  return hasAny ? context : undefined;
}
