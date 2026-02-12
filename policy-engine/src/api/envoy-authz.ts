import type { Router, Request, Response } from 'express';
import { Router as createRouter } from 'express';
import http from 'http';
import https from 'https';
import type { TLSSocket } from 'tls';
import { createLogger } from '../utils/logger';

const logger = createLogger('envoy-authz');

type OpaDecision = {
  allow: boolean;
  reason?: string;
  headers?: Record<string, string>;
};

function headerValue(req: Request, name: string): string | undefined {
  const v = req.headers[name.toLowerCase()];
  if (typeof v === 'string') return v;
  if (Array.isArray(v) && typeof v[0] === 'string') return v[0];
  return undefined;
}

function parseJwtPayloadHeader(raw: string | undefined): Record<string, unknown> | undefined {
  if (!raw) return undefined;
  const b = raw.trim();
  if (!b) return undefined;

  try {
    // Envoy's `forward_payload_header` is base64 (URL-safe) JSON.
    const normalized = b.replace(/-/g, '+').replace(/_/g, '/');
    const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
    const json = Buffer.from(normalized + pad, 'base64').toString('utf8');
    const parsed = JSON.parse(json) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
    return parsed as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function peerCertCommonName(req: Request): string | undefined {
  const sock = ((): TLSSocket | undefined => {
    const candidate = req.socket as unknown;
    if (!candidate || typeof candidate !== 'object') return undefined;
    const tlsSock = candidate as TLSSocket;
    return typeof tlsSock.getPeerCertificate === 'function' ? tlsSock : undefined;
  })();
  try {
    const cert = sock?.getPeerCertificate?.();
    const cn = ((): unknown => {
      if (!cert || typeof cert !== 'object' || Array.isArray(cert)) return undefined;
      const subject = (cert as { subject?: unknown }).subject;
      if (!subject || typeof subject !== 'object' || Array.isArray(subject)) return undefined;
      return (subject as { CN?: unknown }).CN;
    })();
    return typeof cn === 'string' && cn.length > 0 ? cn : undefined;
  } catch {
    return undefined;
  }
}

function getOpaResult(json: unknown): unknown {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return undefined;
  return (json as { result?: unknown }).result;
}

function coerceStringRecord(value: unknown): Record<string, string> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function isPublicPath(path: string): boolean {
  return (
    path.startsWith('/auth/login') ||
    path.startsWith('/auth/callback') ||
    path.startsWith('/auth/token/refresh') ||
    path.startsWith('/auth/logout') ||
    path.startsWith('/auth/session') ||
    path.startsWith('/auth/step-up/') ||
    path.startsWith('/auth/webauthn/') ||
    path.startsWith('/health') ||
    path.startsWith('/healthz') ||
    path.startsWith('/ready') ||
    path.startsWith('/readyz') ||
    path.startsWith('/startupz') ||
    path === '/.well-known/jwks.json'
  );
}

async function postJson(urlStr: string, body: unknown, timeoutMs: number): Promise<{ statusCode: number; json: unknown; text: string }> {
  const url = new URL(urlStr);
  const mod = url.protocol === 'https:' ? https : http;
  const rawBody = Buffer.from(JSON.stringify(body), 'utf8');

  return await new Promise((resolve, reject) => {
    const req = mod.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port ? parseInt(url.port, 10) : (url.protocol === 'https:' ? 443 : 80),
        method: 'POST',
        path: `${url.pathname}${url.search}`,
        headers: {
          'content-type': 'application/json',
          'content-length': String(rawBody.length),
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json: unknown = undefined;
          try {
            json = text ? JSON.parse(text) : undefined;
          } catch {
            json = undefined;
          }
          resolve({ statusCode: res.statusCode ?? 0, json, text });
        });
      }
    );

    req.on('timeout', () => req.destroy(new Error('opa_timeout')));
    req.on('error', (err) => reject(err));
    req.write(rawBody);
    req.end();
  });
}

async function evaluateWithOpa(input: Record<string, unknown>, requestId: string | undefined): Promise<OpaDecision> {
  const opaUrl = process.env['OPA_URL'] ?? 'http://opa:8185';
  // Query the `result` rule under the package.
  const decisionPath = process.env['OPA_DECISION_PATH'] ?? '/v1/data/zerotrust/envoy/authz/result';
  const timeoutMs = parseInt(process.env['OPA_TIMEOUT_MS'] ?? '400', 10);
  const url = new URL(decisionPath, opaUrl).toString();

  const resp = await postJson(url, { input }, timeoutMs);
  if (resp.statusCode < 200 || resp.statusCode >= 300) {
    logger.warn('OPA non-2xx response', { statusCode: resp.statusCode, requestId });
    return { allow: false, reason: 'opa_error' };
  }

  // OPA returns { result: <value> }.
  const result = getOpaResult(resp.json);
  if (typeof result === 'boolean') {
    return { allow: result, reason: result ? 'allow' : 'deny' };
  }
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    return { allow: false, reason: 'invalid_opa_result' };
  }

  const obj = result as Record<string, unknown>;
  const allow = Boolean(obj['allow']);
  const reason = typeof obj['reason'] === 'string' ? obj['reason'] : (allow ? 'allow' : 'deny');
  const headers = coerceStringRecord(obj['headers']);
  return { allow, reason, headers };
}

export function createEnvoyAuthzRoutes(): Router {
  const router = createRouter();

  // Envoy's ext_authz HTTP service prefixes the original request path by default:
  //   path_prefix + original_path
  // So we accept both `/v1/envoy/authz` and `/v1/envoy/authz/...` (any method).
  router.all(/^\/v1\/envoy\/authz(?:\/.*)?$/, async (req: Request, res: Response) => {
    const requestId = headerValue(req, 'x-request-id') ?? headerValue(req, 'x-correlation-id');

    // If configured, pin the ext_authz caller identity to a specific mTLS client cert.
    const expectedCn = (process.env['PDP_EXT_AUTHZ_EXPECTED_CN'] ?? '').trim();
    if (expectedCn) {
      const cn = peerCertCommonName(req);
      if (cn !== expectedCn) {
        logger.warn('ext_authz caller CN mismatch', { expectedCn, cn, requestId });
        res.status(403).json({ denied: true, reason: 'invalid_client_cert' });
        return;
      }
    }

    const originalMethod =
      headerValue(req, 'x-zt-original-method') ??
      headerValue(req, 'x-envoy-original-method') ??
      req.method;

    const pathFromHeaders =
      headerValue(req, 'x-zt-original-path') ??
      headerValue(req, 'x-envoy-original-path');
    // If the proxy didn't provide an explicit original-path header, derive it
    // from Envoy's default behavior: `path_prefix + original_path`.
    const derivedPath = req.path.startsWith('/v1/envoy/authz')
      ? (req.path.slice('/v1/envoy/authz'.length) || '/')
      : undefined;
    const originalPath = pathFromHeaders ?? derivedPath;
    const originalHost =
      headerValue(req, 'x-zt-original-host') ??
      headerValue(req, 'x-envoy-original-host') ??
      headerValue(req, 'host');

    const jwtPayload = parseJwtPayloadHeader(headerValue(req, 'x-jwt-payload'));
    const stepUpLevel =
      typeof jwtPayload?.['step_up_level'] === 'number'
        ? jwtPayload['step_up_level']
        : typeof jwtPayload?.['step_up_level'] === 'string'
          ? parseInt(jwtPayload['step_up_level'], 10)
          : 0;

    const input: Record<string, unknown> = {
      method: originalMethod ?? 'UNKNOWN',
      path: originalPath ?? '/',
      host: originalHost ?? '',
      // Pass through minimal identity info; this payload is trusted because this
      // endpoint is intended to be mTLS-only behind Envoy.
      jwt: {
        ...(jwtPayload ?? {}),
        step_up_level: Number.isFinite(stepUpLevel) ? stepUpLevel : 0,
      },
      client: {
        x_forwarded_for: headerValue(req, 'x-forwarded-for') ?? '',
        downstream_remote_address: headerValue(req, 'x-zt-downstream-remote-address') ?? '',
      },
      now: new Date().toISOString(),
    };

    try {
      const decision = await evaluateWithOpa(input, requestId);
      if (decision.headers) {
        for (const [k, v] of Object.entries(decision.headers)) {
          if (typeof v === 'string' && v.length <= 1024) {
            res.setHeader(k, v);
          }
        }
      }

      if (!decision.allow) {
        res.status(403).json({ denied: true, reason: decision.reason ?? 'denied' });
        return;
      }

      res.status(200).json({ ok: true });
    } catch (err) {
      // Availability: keep explicitly public endpoints available even if OPA is down.
      // Security: everything else remains fail-closed.
      const p = originalPath ?? '/';
      const isPublic = isPublicPath(p);

      if (isPublic) {
        logger.warn('ext_authz bypass: OPA unavailable for public endpoint', {
          requestId,
          path: p,
          error: err instanceof Error ? err.message : String(err),
        });
        res.status(200).json({ ok: true, bypass: 'opa_unavailable_public' });
        return;
      }

      logger.error('ext_authz evaluation failed (fail-closed)', {
        requestId,
        error: err instanceof Error ? err.message : String(err),
      });
      res.status(403).json({ denied: true, reason: 'authz_error' });
    }
  });

  return router;
}
