# Security Policy

## Supported Versions

This repository is a reference implementation. Security fixes are provided on the `main` branch.

## Reporting a Vulnerability

If you discover a security issue, do not open a public GitHub issue.

Send a private report including:
- A clear description of the issue and impact
- Reproduction steps or a proof-of-concept
- Affected components/paths
- Any suggested fix or mitigation

## Security Principles (Project Invariants)

- Fail closed by default (no matching policy => deny; PDP outage => deny)
- Defense in depth at the gateway (normalization before authz; deny-by-default CORS; rate limiting; WAF)
- Minimal error leakage (no stack traces to clients in production)
- Secrets never committed; production requires explicit secrets where applicable
- Internal plane APIs require gateway-originated authentication (HMAC internal auth + optional mTLS)
- Audit logging is append-only and tamper-evident; persistence modes are environment-dependent (dev file store vs real WORM in production)
