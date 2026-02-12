import type { Request } from 'express';

export function extractClientIp(
  req: Request,
  maxDepth: number,
  trustedProxies: Set<string>
): string {
  const directIp = normalizeIp(req.socket.remoteAddress || '0.0.0.0');

  // SECURITY: Only honor X-Forwarded-For when the direct peer is a trusted proxy.
  // Otherwise any client can spoof it and bypass per-IP controls.
  const trustedByMtls = (() => {
    const expectedCn = (process.env['GATEWAY_TRUST_XFF_MTLS_CN'] ?? '').trim().toLowerCase();
    if (!expectedCn) return false;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const sock: any = req.socket;
    if (!sock || sock.authorized !== true) return false;
    const cert = sock?.getPeerCertificate?.();
    const cn = String(cert?.subject?.CN ?? '').trim().toLowerCase();
    return cn !== '' && cn === expectedCn;
  })();

  if (!trustedProxies.has(directIp) && !trustedByMtls) {
    return directIp;
  }

  const xForwardedFor = req.headers['x-forwarded-for'];
  if (!xForwardedFor) return directIp;

  const forwardedIps = (typeof xForwardedFor === 'string' ? xForwardedFor : xForwardedFor[0] || '')
    .split(',')
    .map((ip) => normalizeIp(ip))
    .filter(Boolean);

  if (forwardedIps.length === 0) {
    return directIp;
  }

  // Limit depth to prevent abuse
  if (forwardedIps.length > maxDepth) {
    // Too many hops — suspicious. Use the rightmost untrusted IP.
    // But cap at maxDepth from the right.
    const limited = forwardedIps.slice(-maxDepth);
    // Walk from right to left, skip trusted proxies, return first untrusted
    for (let i = limited.length - 1; i >= 0; i--) {
      const ip = limited[i];
      if (ip && !trustedProxies.has(ip)) {
        return ip;
      }
    }
    return limited[0] || directIp;
  }

  // Walk from right (closest to us) to left (closest to client)
  // Skip trusted proxies; the first untrusted IP is the client
  for (let i = forwardedIps.length - 1; i >= 0; i--) {
    const ip = forwardedIps[i];
    if (ip && !trustedProxies.has(ip)) {
      return ip;
    }
  }

  return forwardedIps[0] || directIp;
}

function normalizeIp(ip: string): string {
  const trimmed = (ip || '').trim().toLowerCase();
  if (trimmed.startsWith('::ffff:')) return trimmed.slice('::ffff:'.length);
  return trimmed;
}
