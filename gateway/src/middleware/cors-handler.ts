import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { GatewayConfig} from '../../config/default';
import { getRouteConfig } from '../../config/default';
import { createSecurityLogger } from './request-logger';

/**
 * CORS handler middleware.
 *
 * DENY by default. No wildcard (*) with credentials. EVER.
 *
 * - Exact origin allowlist from configuration (global + per-route)
 * - Configurable methods/headers per route
 * - Preflight caching with configurable max-age
 * - All CORS violations are logged as security events
 *
 * Threat model:
 * - Cross-origin data theft via credentialed requests
 * - Origin spoofing (mitigated by browser enforcement; we validate server-side)
 * - Misconfigured wildcards leaking data
 */

export function createCorsMiddleware(config: GatewayConfig): RequestHandler {
  const securityLog = createSecurityLogger(config);

  // Build a Set of allowed origins for O(1) lookup
  const globalAllowedOrigins = new Set(
    config.cors.globalAllowedOrigins.map(o => o.toLowerCase())
  );

  return (req: Request, res: Response, next: NextFunction): void => {
    const correlationId = (req.headers['x-correlation-id'] as string) || 'unknown';
    const origin = req.headers['origin'];

    // No Origin header: same-origin request or non-browser client.
    // We do NOT add any CORS headers, which means cross-origin access is denied.
    if (!origin) {
      next();
      return;
    }

    const normalizedOrigin = origin.toLowerCase().trim();
    const routeConfig = getRouteConfig(config, req.path, req.method);

    // Build the effective allowed origins for this request
    const routeAllowedOrigins = routeConfig?.cors?.allowedOrigins
      ? new Set(routeConfig.cors.allowedOrigins.map(o => o.toLowerCase()))
      : null;

    const effectiveOrigins = routeAllowedOrigins || globalAllowedOrigins;

    // ── Origin validation ─────────────────────────────────────────────
    if (!effectiveOrigins.has(normalizedOrigin)) {
      securityLog.warn({
        event: 'cors_violation',
        correlationId,
        origin: normalizedOrigin,
        path: req.path,
        method: req.method,
        ip: req.ip,
        reason: 'Origin not in allowlist',
        allowedOrigins: Array.from(effectiveOrigins),
      });

      // Do NOT set any CORS headers — browser will block the response
      // Return 403 for preflight.
      if (req.method === 'OPTIONS') {
        res.status(403).json({ error: 'CORS: Origin not allowed' });
        return;
      }

      // SECURITY: CORS is not CSRF protection, but if a request includes an
      // Origin header and is not allowlisted, do not process state-changing
      // requests. Browsers can still send the request even if they can't read
      // the response.
      const safeMethods = new Set(['GET', 'HEAD']);
      if (!safeMethods.has(req.method.toUpperCase())) {
        res.status(403).json({ error: 'CORS: Origin not allowed' });
        return;
      }

      // For safe methods: allow the request but without CORS headers.
      next();
      return;
    }

    // ── CORS headers ──────────────────────────────────────────────────
    // NEVER use wildcard (*). Always echo back the specific allowed origin.
    res.setHeader('Access-Control-Allow-Origin', origin); // Preserve original casing
    res.setHeader('Vary', 'Origin');

    // Credentials
    const allowCredentials = routeConfig?.cors?.credentials ?? config.cors.globalCredentials;
    if (allowCredentials) {
      // SECURITY: Never combine credentials: true with wildcard origin
      // We already enforce exact origin matching above, so this is safe.
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }

    // Exposed headers
    const exposedHeaders = routeConfig?.cors?.exposedHeaders ?? config.cors.globalExposedHeaders;
    if (exposedHeaders.length > 0) {
      res.setHeader('Access-Control-Expose-Headers', exposedHeaders.join(', '));
    }

    // ── Preflight handling ────────────────────────────────────────────
    if (req.method === 'OPTIONS') {
      const requestedMethod = req.headers['access-control-request-method'];
      const requestedHeaders = req.headers['access-control-request-headers'];

      // Validate requested method
      const allowedMethods = routeConfig?.cors?.allowedMethods ?? config.cors.globalAllowedMethods;
      if (requestedMethod && !allowedMethods.includes(requestedMethod.toUpperCase())) {
        securityLog.warn({
          event: 'cors_preflight_method_denied',
          correlationId,
          origin: normalizedOrigin,
          requestedMethod,
          allowedMethods,
          path: req.path,
          ip: req.ip,
        });
        res.status(403).json({ error: 'CORS: Method not allowed' });
        return;
      }

      // Validate requested headers
      const allowedHeaders = routeConfig?.cors?.allowedHeaders ?? config.cors.globalAllowedHeaders;
      if (requestedHeaders) {
        const requested = requestedHeaders.split(',').map(h => h.trim().toLowerCase());
        const allowed = new Set(allowedHeaders.map(h => h.toLowerCase()));

        const disallowed = requested.filter(h => !allowed.has(h));
        if (disallowed.length > 0) {
          securityLog.warn({
            event: 'cors_preflight_header_denied',
            correlationId,
            origin: normalizedOrigin,
            disallowedHeaders: disallowed,
            allowedHeaders,
            path: req.path,
            ip: req.ip,
          });
          res.status(403).json({ error: 'CORS: Header not allowed' });
          return;
        }
      }

      res.setHeader('Access-Control-Allow-Methods', allowedMethods.join(', '));
      res.setHeader('Access-Control-Allow-Headers', allowedHeaders.join(', '));

      // Preflight cache
      const maxAge = routeConfig?.cors?.maxAge ?? config.cors.preflightCacheTtl;
      res.setHeader('Access-Control-Max-Age', String(maxAge));

      // Preflight complete — no further processing needed
      res.status(204).end();
      return;
    }

    next();
  };
}
