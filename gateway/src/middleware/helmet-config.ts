import helmet from 'helmet';
import type { RequestHandler } from 'express';

/**
 * Helmet security headers configuration.
 *
 * Applies defense-in-depth HTTP headers:
 * - HSTS: 2-year max-age, includeSubDomains, preload-eligible
 * - X-Content-Type-Options: nosniff
 * - X-Frame-Options: DENY (via CSP frame-ancestors)
 * - Referrer-Policy: strict-origin-when-cross-origin
 * - Content-Security-Policy: strict defaults
 * - Removes X-Powered-By
 */
export function createHelmetMiddleware(): RequestHandler {
  return helmet({
    // HSTS must be conditional on HTTPS. We set it in a separate middleware
    // that checks `req.secure` (which respects Express trust proxy settings).
    strictTransportSecurity: false,

    // Prevent MIME type sniffing
    xContentTypeOptions: true, // Sets X-Content-Type-Options: nosniff

    // Strict Content Security Policy
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'"],
        fontSrc: ["'self'"],
        connectSrc: ["'self'"],
        mediaSrc: ["'none'"],
        objectSrc: ["'none'"],
        frameSrc: ["'none'"],
        frameAncestors: ["'none'"], // Equivalent to X-Frame-Options: DENY
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: [],
        blockAllMixedContent: [],
      },
      reportOnly: false,
    },

    // Referrer Policy: send origin on cross-origin, full URL on same-origin
    referrerPolicy: {
      policy: 'strict-origin-when-cross-origin',
    },

    // Prevent framing (belt-and-suspenders with CSP frame-ancestors)
    frameguard: {
      action: 'deny',
    },

    // Do not expose X-Powered-By
    hidePoweredBy: true,

    // Prevent IE from executing downloads in site context
    ieNoOpen: true,

    // Disable DNS prefetching
    dnsPrefetchControl: {
      allow: false,
    },

    // Disable browser-side caching of responses by default.
    // Individual routes can override as needed.
    // This prevents sensitive data from being cached.
    // Note: noCache is deprecated in newer helmet; use custom headers if needed.

    // Cross-Origin policies
    crossOriginEmbedderPolicy: { policy: 'require-corp' },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },

    // Permission-Policy (formerly Feature-Policy)
    permittedCrossDomainPolicies: {
      permittedPolicies: 'none',
    },

    // X-XSS-Protection: 0 (modern CSP is the defense; the old header can cause issues)
    xssFilter: false,
  }) as RequestHandler;
}

/**
 * Conditional HSTS header.
 *
 * Never emit HSTS on plain HTTP (including misconfigured reverse proxies),
 * because that can brick local development and create confusing behavior.
 */
export function conditionalHsts(): RequestHandler {
  const value = 'max-age=63072000; includeSubDomains; preload';
  return (req, res, next) => {
    if (req.secure) {
      res.setHeader('Strict-Transport-Security', value);
    }
    next();
  };
}

/**
 * Additional cache-control header for API responses.
 * Prevents caching of sensitive API data.
 */
export function noCacheHeaders(): RequestHandler {
  return (_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
    next();
  };
}
