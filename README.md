# Security Platform (Zero Trust) - Reference Implementation

This repo is a multi-service TypeScript reference implementation of a "zero trust" security platform:

- `gateway/`: internal API gateway with normalization, deny-by-default CORS, adaptive rate limiting/WAF/IP reputation blocking, route-scoped edge response cache, JWT auth, and upstream proxying
- `identity/`: OIDC + PKCE login, sessions, step-up auth, JWT issuance, JWKS publishing
- `policy-engine/`: policy decision point plus Envoy `ext_authz` adapter that delegates to OPA (formal policy language)
- `telemetry/`: audit ingestion + tamper-evident storage + detection rules + alert management
- `supply-chain/`: SBOM/provenance/signing + admission gate + runtime hardening validator
- `shared/`: shared models/utilities (audit schema, canonicalization, hash chain, logging/PII redaction)

## Quickstart (Docker Compose)

This preset runs with defense-in-depth and production-like defaults:

- Public edge: **Envoy** on `https://localhost:8443` (and `http://localhost:8080` redirects to HTTPS)
- Internal-only: `gateway`, `identity`, `policy-engine`, `telemetry`, `supply-chain`
- Authz: Envoy `jwt_authn` + Envoy `ext_authz` -> `policy-engine` -> **OPA**
- Supply-chain signing keys: persisted in an **encrypted keystore** volume (for stable key IDs across restarts)

1. Generate dev certs (TLS + mTLS):

```bash
npm run generate:certs
```

2. Create/rotate local environment secrets (writes `deploy/docker/.env`):

```bash
npm run generate:env
```

3. Bring up the stack:

```bash
npm run docker:up
```

This compose preset runs services with `NODE_ENV=production`, so the stack will refuse to start if secrets are missing or weak (at minimum: `CSRF_SECRET`, `PDP_ADMIN_JWT_SECRET`, `INTERNAL_SHARED_SECRET`).

The supply-chain plane also requires `SUPPLY_CHAIN_KEYSTORE_MASTER_KEY` (32 bytes, hex) when keystore persistence is enabled (it is enabled by default in the docker preset).

### Production-Hardening Knobs

- Secrets can be provided via environment variables or via the common `*_FILE` convention (useful for Docker/Kubernetes secrets):
  - Example: set `INTERNAL_SHARED_SECRET_FILE=/run/secrets/internal_shared_secret` (and mount that file).
  - Supported across the platform for the main secrets: `INTERNAL_SHARED_SECRET`, `CSRF_SECRET`, `PDP_ADMIN_JWT_SECRET`, `REDIS_PASSWORD`, `SUPPLY_CHAIN_KEYSTORE_MASTER_KEY`, and OIDC client secrets.
- Startup guardrails fail fast on risky production flags:
  - `INTERNAL_AUTH_ENABLED=false` is rejected in production across planes.
  - `INTERNAL_AUTH_REQUIRE_NONCE=false`, `INTERNAL_AUTH_REQUIRE_CALLER=false`, `INTERNAL_AUTH_REQUIRE_KEY_ID=false`, and `INTERNAL_AUTH_REPLAY_PROTECTION_ENABLED=false` are rejected in production.
  - internal mTLS/TLS requirements are enforced in production.
  - gateway `TOKEN_ENFORCEMENT_FAIL_OPEN=true` is rejected in production.
  - identity dev token issuer requires an explicit production override (`ALLOW_DEV_TOKEN_ISSUER_IN_PRODUCTION=true`).
- Internal auth replay/confusion protection (nonce + caller + audience):
  - `X-Internal-Nonce` is included in signed internal requests.
  - `X-Internal-Caller` and `X-Internal-Audience` are signature-bound and can be enforced via allowlists.
  - `X-Internal-Key-Id` supports per-caller key rotation via keyrings (`INTERNAL_AUTH_KEYRING`).
  - duplicate nonces inside the skew window are rejected (`internal_replay_detected`).
  - distributed replay detection is enabled with Redis (`INTERNAL_AUTH_REPLAY_STORE=redis`).
  - tune local fallback cache size with `INTERNAL_AUTH_REPLAY_CACHE_MAX_ENTRIES` (default `50000`).
- Internal control-plane authorization for mutation APIs:
  - optional per-caller role enforcement for `POST`/`PUT`/`PATCH`/`DELETE` under `/internal/*`.
  - optional scoped API keys for mutation endpoints (`INTERNAL_CONTROL_PLANE_*`).
  - route-specific permissions (for example: `security_controls.write`, `edge_cache.write`, `upstream.write`, `abuse_intel.write`).
- Edge response cache (route opt-in):
  - only routes with `routes[*].edgeCache.enabled=true` are cached.
  - cache keys vary by route/path/query plus configurable headers (`EDGE_CACHE_VARY_HEADERS`).
  - authenticated traffic is not cached unless explicitly enabled per-route (`cacheAuthenticated=true`).
  - supports cache tags from origin responses (`EDGE_CACHE_TAG_HEADER`, default `cache-tag`) for targeted purges.
  - request coalescing reduces origin stampedes on hot-key misses (`EDGE_CACHE_REQUEST_COALESCING_*`).
  - stale-while-revalidate is supported (`EDGE_CACHE_STALE_WHILE_REVALIDATE_SECONDS`) for low-latency stale serves during origin refresh.
  - stale-if-error fallback can serve expired objects when origin refresh fails (`EDGE_CACHE_STALE_IF_ERROR_SECONDS`).
  - distributed cache state is enabled with Redis (`EDGE_CACHE_STORE=redis`), with internal purge endpoint:
    - `POST /internal/edge-cache/purge` (`key`, `routePath`, `tags`, or `all=true`).
  - route-version sync supports signed export/import bundles for multi-region soft purges (`EDGE_CACHE_VERSION_BUNDLE_*`).
  - invalidation event-log sync supports cursor-based signed export/import for deterministic purge/version replay (`EDGE_INVALIDATION_LOG_*`, `EDGE_INVALIDATION_BUNDLE_*`).
  - internal mutation endpoints support optional idempotency-key replay protection (`INTERNAL_MUTATION_IDEMPOTENCY_*`).
  - control-plane mutation audit stream supports signed cursor-based export/import for SOC replication (`CONTROL_PLANE_AUDIT_*`).
  - route policy supports runtime patching plus signed full-snapshot export/import for cross-region convergence (`ROUTE_POLICY_BUNDLE_*`).
  - upstream routing policy supports runtime patching plus signed full-snapshot export/import for cross-region convergence (`UPSTREAM_ROUTING_POLICY_BUNDLE_*`).
- WAF advanced controls:
  - supports custom regex rules via config/env (`waf.customRules` / `WAF_CUSTOM_RULES_JSON`).
  - supports managed rate-based rules (`waf.rateRules` / `WAF_RATE_RULES_JSON`) with `block`, `challenge`, or `log`.
  - supports per-rule-set actions: `block`, `log`, and `challenge`.
  - `challenge` action integrates with bot challenge flow (`bot_challenge_required` + challenge state).
  - managed rule lifecycle controls: `WAF_MANAGED_RULES_VERSION`, `WAF_ALLOWED_RULE_VERSIONS`, and per-rule rollout percentages.
- Edge access-control policies:
  - optional IP/CIDR allow/deny controls (`ACCESS_CONTROL_IP_ALLOWLIST`, `ACCESS_CONTROL_IP_DENYLIST`).
  - optional geo/ASN policy gates using trusted edge headers (`ACCESS_CONTROL_COUNTRY_*`, `ACCESS_CONTROL_ASN_*`).
  - route-scoped profile overrides via `routes[*].accessControlProfile` + `ACCESS_CONTROL_PROFILES_JSON`.
- Upstream failover pools:
  - each upstream can define weighted endpoints (`upstreams[*].pool.endpoints`).
  - optional endpoint priority enables active/passive failover (`upstreams[*].pool.endpoints[*].priority`).
  - optional latency-aware steering adapts endpoint weights from observed response latency (`upstreams[*].pool.steering.*`).
  - optional affinity-key steering keeps a caller consistently on one endpoint (`upstreams[*].pool.sessionAffinity.*`).
  - cookie-based affinity supports signed token rotation using current + previous secrets.
  - outlier ejection removes repeatedly failing endpoints for a cooldown window (`outlierEjection.*`).
  - optional active health probes can proactively eject unhealthy endpoints (`activeHealthChecks.*`).
  - enables active failover behavior within a single upstream logical service.
  - route-level canary rollout can gradually shift traffic to a secondary upstream using deterministic stickiness (`routes[*].canary.*`).
  - optional automatic canary rollback can suppress canary traffic when error-rate/latency thresholds are exceeded (`ROUTE_CANARY_AUTO_ROLLBACK_*`).
- Adaptive IP defense (edge abuse scoring -> temporary block):
  - scores `WAF 403`, `429`, `401`, and other `403` responses per source IP over a rolling window.
  - adds lightweight bot-fingerprint signals (automation UA/header anomalies) into adaptive scoring.
  - introduces L7 soft challenge before hard blocks (`bot_challenge_required`) with signed, IP/UA-bound challenge tokens.
  - blocks IPs when the score crosses `ADAPTIVE_DEFENSE_BLOCK_THRESHOLD`.
  - supports route/service-specific profiles via `routes[*].adaptiveProfile` and `ADAPTIVE_DEFENSE_PROFILES_JSON`.
  - uses Redis-backed distributed state by default (`ADAPTIVE_DEFENSE_STORE=redis`).
  - challenge state is also distributed (`ADAPTIVE_DEFENSE_CHALLENGE_STORE=redis`).
  - repeated invalid challenge-token attempts trigger temporary challenge backoff (`ADAPTIVE_DEFENSE_CHALLENGE_MAX_INVALID_ATTEMPTS`, `ADAPTIVE_DEFENSE_CHALLENGE_INVALID_ATTEMPT_*`).
  - signal weights, thresholds, challenge behavior, and profiles are configurable via `ADAPTIVE_DEFENSE_*` environment variables.
- Bot management:
  - suspicious automation can be challenged while high-confidence abuse is blocked.
  - successful challenge solves can mint a signed clearance cookie to reduce repeated challenges for real users.
  - clearance cookie is configurable and rotation-friendly (`BOT_MANAGEMENT_CLEARANCE_*`).
- Internal mTLS client pinning (defense-in-depth):
  - Planes accept only specific client certificate identities when `INTERNAL_MTLS_ALLOWED_CLIENT_CNS` is set (comma-separated CN allowlist).
  - The gateway can additionally restrict its control-plane endpoints via `GATEWAY_INTERNAL_MTLS_ALLOWED_CLIENT_CNS` (defaults in docker preset allow telemetry only).

4. Health checks (through Envoy):

- `https://localhost:8443/healthz`

### Abuse Intel Sharing (Region-to-Region)

Gateway internal APIs support abuse-intel exchange for distributed environments:

- `GET /internal/abuse-intel/export?limit=1000`
- `POST /internal/abuse-intel/import`
- `GET /internal/control-plane/audit/events?afterCursor=0&limit=1000` (internal mutation audit stream)
- `GET /internal/control-plane/audit/export?afterCursor=0&limit=1000` (signed mutation audit export)
- `POST /internal/control-plane/audit/import` (signed mutation audit import)
- `GET /internal/routes/policy` (current runtime route policy snapshot + revision)
- `PATCH /internal/routes/policy` (runtime route policy updates; supports `ifRevision` + `dryRun`)
- `GET /internal/routes/policy/export` (signed route policy snapshot export)
- `POST /internal/routes/policy/import` (signed route policy snapshot import)
- `GET /internal/routes/canary/metrics?routePath=/api` (runtime canary traffic/rollback metrics)
- `GET /internal/upstreams/policy` (current runtime upstream routing policy snapshot + revision)
- `PATCH /internal/upstreams/policy` (runtime upstream policy updates; supports `ifRevision` + `dryRun`)
- `GET /internal/upstreams/policy/export` (signed upstream policy snapshot export)
- `POST /internal/upstreams/policy/import` (signed upstream policy snapshot import)
- `POST /internal/edge-cache/purge` (target by `key`, `routePath`, `tags`, or `all=true`)
- `GET /internal/edge-cache/version?routePath=/public` (read soft-version token for a route)
- `POST /internal/edge-cache/version/bump` (soft purge by bumping a route version namespace)
- `GET /internal/edge-cache/version/export?limit=1000` (signed route-version bundle export)
- `POST /internal/edge-cache/version/import` (signed route-version bundle import)
- `GET /internal/edge-cache/invalidation/events?afterCursor=0&limit=1000` (event log stream by cursor)
- `GET /internal/edge-cache/invalidation/export?afterCursor=0&limit=1000` (signed invalidation bundle export)
- `POST /internal/edge-cache/invalidation/import` (signed invalidation bundle import + replay on local cache state)
- `GET /internal/upstreams/diagnostics` (pool endpoints, ejection state, EWMA latency, circuit status)
- `GET /internal/security-controls` (current WAF/Bot/Access control snapshot + revision)
- `PATCH /internal/security-controls` (runtime rollout updates for WAF/Bot/Access controls; supports `ifRevision` + `dryRun`)
- `GET /internal/security-controls/history` (signed change history, hash-chained)
- `GET /internal/security-controls/history/verify` (verifies history integrity/signatures)
- `GET /internal/security-controls/history/export?limit=1000` (signed history bundle export for cross-region sync)
- `POST /internal/security-controls/history/import` (signed history bundle import)
- `GET /internal/security-controls/history/:id` (fetch a specific change record)

These endpoints export/import active blocked-IP intelligence so regions can share bad-source fingerprints.
By default, exports are signed and imports require signed bundles:

- HMAC-signed bundle payloads (`keyId` + `signature`)
- source and key allowlists (`ADAPTIVE_DEFENSE_ABUSE_INTEL_ALLOWED_*`)
- replay detection for bundle IDs (`ADAPTIVE_DEFENSE_ABUSE_INTEL_REPLAY_*`)
- security-controls history is HMAC-signed and hash-chained (`SECURITY_CONTROLS_AUDIT_SECRET`, `SECURITY_CONTROLS_HISTORY_MAX_ENTRIES`)
- security-controls history can be persisted in Redis for multi-instance durability (`SECURITY_CONTROLS_HISTORY_STORE`, `SECURITY_CONTROLS_HISTORY_REDIS_*`)
- security-controls patching supports optimistic concurrency via revision preconditions (`ifRevision` body field or `If-Match` header)
- security-controls history export/import supports signed bundles with allowlists + replay protection (`SECURITY_CONTROLS_HISTORY_BUNDLE_*`)
- edge-cache route-version export/import supports signed bundles with allowlists + replay protection (`EDGE_CACHE_VERSION_BUNDLE_*`)
- edge-cache invalidation event-log export/import supports signed cursor bundles with allowlists + replay protection (`EDGE_INVALIDATION_BUNDLE_*`)
- control-plane mutation audit export/import supports signed cursor bundles with allowlists + replay protection (`CONTROL_PLANE_AUDIT_BUNDLE_*`)
- route policy export/import supports signed snapshot bundles with allowlists + replay protection (`ROUTE_POLICY_BUNDLE_*`)
- upstream routing policy export/import supports signed snapshot bundles with allowlists + replay protection (`UPSTREAM_ROUTING_POLICY_BUNDLE_*`)
- mutation endpoints support idempotency-key replay protection (`INTERNAL_MUTATION_IDEMPOTENCY_*`)
- optional regional convergence worker can continuously detect and auto-heal drift for security controls, edge-cache versions, edge invalidation events, control-plane audit cursors, route policy revisions, and upstream routing policy revisions from peer gateways (`CONTROL_PLANE_CONVERGENCE_*`)
  - optional convergence quorum guardrails require multi-peer agreement before applying route/upstream policy heals (`CONTROL_PLANE_CONVERGENCE_POLICY_QUORUM_*`)
  - convergence emits signed peer-result telemetry and appends it to control-plane audit trail (`CONTROL_PLANE_CONVERGENCE_AUDIT_*`)

Mutation endpoints (`POST`/`PUT`/`PATCH`/`DELETE` under `/internal/*`) accept `Idempotency-Key` (or `X-Idempotency-Key`) and reject duplicate replays with `409 idempotency_conflict`.

They are protected by internal auth + mTLS like other `/internal/*` endpoints.

## Public / Internet Deployment (Real TLS via Caddy)

The default compose preset (`deploy/docker/docker-compose.yml`) uses a self-signed local CA for `https://localhost:8443`.
For an internet-exposed deployment with real, publicly trusted TLS, use:

- `deploy/docker/docker-compose.public.yml` (Caddy terminates TLS on `:443` and forwards to Envoy over the internal Docker network)
- `deploy/docker/envoy/envoy.public.yaml` (Envoy HTTP listener with `xff_num_trusted_hops: 1`)

1. Set these in `deploy/docker/.env`:

- `PUBLIC_DOMAIN=your-domain.example`
- `ACME_EMAIL=you@your-domain.example`

2. Make sure your DNS `A/AAAA` records point to the host running Docker, and ports `80/tcp` and `443/tcp` are reachable from the internet.

Notes:
- If you publish an `AAAA` record, ensure IPv6 `80/443` reach the host too. If not, remove the `AAAA` record (ACME validation may prefer IPv6).
- If you have `CAA` records, ensure they allow your ACME CA (Caddy defaults to Let's Encrypt): add `issue "letsencrypt.org"` (or remove restrictive CAA).

3. Start the public stack:

```bash
npm run docker:public:up
```

If the host already has something listening on `80/443` (common when you already run nginx/Apache for other sites), `docker:public:up` will automatically start **without** Caddy and instead publish Envoy to `127.0.0.1:18080`. In that mode, configure your existing reverse proxy to forward:

- `https://<PUBLIC_DOMAIN>/*` -> `http://127.0.0.1:18080/*`

To force Caddy (and fail fast if ports are taken), run with:

```bash
FORCE_CADDY=1 npm run docker:public:up
```

If you're deploying on a host that only has Docker (no Node/openssl installed), you can instead run:

```bash
bash scripts/bootstrap-public-docker-only.sh
```

4. Verify:

- `https://<PUBLIC_DOMAIN>/healthz`

Important: Envoy JWT validation in `deploy/docker/envoy/envoy.public.yaml` is pinned to:

- `issuer: https://identity.zerotrust.local`
- `audience: https://api.zerotrust.local`

If you change `TOKEN_ISSUER` / `TOKEN_AUDIENCE`, update the Envoy config to match.

### Make HTTPS "Trusted" In Your Browser (macOS)

The Docker preset terminates TLS at Envoy using a local development CA (`certs/ca.crt`).
Browsers will show "Not secure" until you trust that CA.

Option A (CLI, adds to your login keychain):

```bash
./scripts/trust-dev-ca-macos.sh
```

Option B (GUI):

- Open **Keychain Access**
- Import `certs/ca.crt` into the **login** keychain
- Set it to **Always Trust**
- Restart Chrome/Safari

If you rotate certs with `npm run generate:certs -- --force`, you will need to trust the new CA again.
If you rotate only leaf certs with `npm run generate:certs -- --rotate-leaf`, you do NOT need to re-trust the CA.

Tip: `curl` with verification (no `-k`):

```bash
curl --cacert certs/ca.crt https://localhost:8443/healthz
```

### Deploying To A Cloud VM (Oracle / Any Linux VPS)

ACME validation requires inbound connectivity. In addition to DNS, ensure:

- Cloud firewall / security group allows `80/tcp` and `443/tcp` to the VM
- Host firewall allows `80/tcp` and `443/tcp` (if enabled)

#### Updating Docker Tools (Compose + buildx)

Some VMs have Docker Engine but are missing the `docker compose` plugin (v2) and/or `docker buildx`.
This repo includes a helper that installs the latest stable CLI plugins:

```bash
cd ~/Security_platform
sudo bash scripts/update-docker-cli-plugins.sh
```

If you prefer legacy `docker-compose` instead, install via apt:

```bash
sudo apt-get update
sudo apt-get install -y docker-compose
```

To copy this repo to a remote VM over SSH (excluding `certs/` and `deploy/docker/.env` by default):

```bash
DEPLOY_TARGET="ubuntu@<VM_PUBLIC_IP>" DEPLOY_DIR="~/Security_platform" bash scripts/ship-to-server.sh
```

Then SSH to the VM, set `PUBLIC_DOMAIN` + `ACME_EMAIL` in `deploy/docker/.env`, and run:

```bash
bash scripts/bootstrap-public-docker-only.sh
```

#### Auto-Start On Boot (systemd)

On a real server you should make the stack survive reboots. This repo includes a helper that installs a systemd unit which runs:

- `docker compose -f deploy/docker/docker-compose.public.yml up -d`
- by default with `--scale caddy=0` (assumes you already run nginx/Apache on `:80/:443`)

On the VM:

```bash
cd ~/Security_platform
sudo bash scripts/install-systemd-public.sh
```

The gateway routing is configured via `deploy/docker/gateway.config.json` (mounted into the gateway container).

#### Host Reverse Proxy (nginx)

If you deploy behind a host reverse proxy (common on VPS where ports `:80/:443` are already used),
proxy your public domain to Envoy on `http://127.0.0.1:18080`.

Example nginx config template:

- `deploy/nginx/security-platform-proxy.conf.example`

#### Observability UIs (Grafana / Prometheus / Alertmanager / Jaeger)

In the public preset, these UIs are bound to **localhost only** on the VM:

- Grafana: `127.0.0.1:3000`
- Prometheus: `127.0.0.1:9090`
- Alertmanager: `127.0.0.1:9093`
- Jaeger: `127.0.0.1:16686`

To access them safely from your laptop, use the provided SSH tunnel helper:

```bash
SSH_OPTS="-i /path/to/key -o IdentitiesOnly=yes" \
bash scripts/tunnel-observability.sh ubuntu@<VM_PUBLIC_IP>
```

Grafana login:

- User: `admin`
- Password: from `GRAFANA_PASSWORD` in `~/Security_platform/deploy/docker/.env` on the VM

If Grafana gets stuck on the loading logo, try:

- open in an incognito window (or disable extensions like ad blockers)
- hard refresh (Cmd+Shift+R) or clear site data for `http://127.0.0.1:3000`
- use a different local tunnel port to avoid conflicts:
  - `LOCAL_GRAFANA_PORT=13000 bash scripts/tunnel-observability.sh ubuntu@<VM_PUBLIC_IP>` then open `http://127.0.0.1:13000`

Grafana provisions dashboards into the **Security Platform** folder automatically from:

- `deploy/docker/provisioning/grafana/dashboards/`

Included dashboards:

- `Security Platform - Overview` (traffic + errors + latency + key security signals)
- `Security Platform - Status` (Prometheus scrape health + target up/down + public probe + TLS expiry)
- `Gateway - Security Signals` (WAF + normalization + rate limits + auth)
- `Host - Overview (node-exporter)` (CPU/memory/disk)

#### Fail2ban (SSH + nginx)

If you run this internet-exposed, you should add host-level brute force protection for SSH and basic nginx abuse protection.
On Ubuntu:

```bash
cd ~/Security_platform
sudo bash scripts/install-fail2ban-ubuntu.sh
sudo fail2ban-client status
```

#### Updating The VM Stack (Rebuild + Restart)

On the VM:

```bash
cd ~/Security_platform
RUN_SMOKE=1 bash scripts/vm-update-public.sh
```

If you also want to update `docker compose` + `docker buildx` plugins first:

```bash
cd ~/Security_platform
UPDATE_DOCKER_PLUGINS=1 RUN_SMOKE=1 bash scripts/vm-update-public.sh
```

#### Backups (Recommended)

This repo includes a production backup script that captures:

- `deploy/docker/.env` (secrets/config)
- `certs/` (internal mTLS CA + signing keys)
- critical Docker volumes (PDP store, audit log, SBOM store, keystore, Prometheus/Grafana state)

Manual backup (on the VM):

```bash
cd ~/Security_platform
bash scripts/backup-public.sh
```

Install a daily systemd timer (runs as root, stores backups under `/var/backups/security-platform` by default):

```bash
cd ~/Security_platform
sudo bash scripts/install-systemd-backup-public.sh
```

Restore and restore-drill helpers (run on the VM):

```bash
# Restore into the live volumes (dangerous; requires confirmation)
CONFIRM_RESTORE=1 BACKUP_DIR=backups/<UTC_TIMESTAMP> bash scripts/restore-public.sh

# Restore drill: restore into new volumes (safe, no impact to prod)
BACKUP_DIR=backups/<UTC_TIMESTAMP> bash scripts/restore-drill-public.sh
```

#### VM Troubleshooting (Doctor / Status / Logs)

On the VM:

```bash
cd ~/Security_platform
bash scripts/vm-doctor-public.sh
```

Quick status:

```bash
cd ~/Security_platform
bash scripts/vm-status-public.sh
```

Tail logs (defaults to core services, or pass service names):

```bash
cd ~/Security_platform
bash scripts/vm-logs-public.sh
bash scripts/vm-logs-public.sh envoy gateway
```

From your laptop (ship repo + backup + rebuild/restart remotely):

```bash
DEPLOY_TARGET="ubuntu@<VM_PUBLIC_IP>" \
SSH_OPTS="-i /path/to/key -o IdentitiesOnly=yes" \
bash scripts/deploy-public.sh
```

You can also use a single entrypoint wrapper for common ops from your laptop:

```bash
DEPLOY_TARGET="ubuntu@<VM_PUBLIC_IP>" \
SSH_OPTS="-i /path/to/key -o IdentitiesOnly=yes" \
bash scripts/public.sh doctor
```

Other commands: `status`, `logs`, `update`, `tunnel`, `smoke`, `deploy`.
Also useful: `backup`, `update-tools`, `upgrade`, `install-systemd`.

Tip: create a local `.public.env` (not committed) to avoid re-typing `DEPLOY_TARGET`/`SSH_OPTS`.
See: `.public.env.example`.
You can also create it via: `bash scripts/public.sh init`.

#### Backups (Volumes + Secrets)

The public stack uses Docker named volumes for state (policies, audit logs, SBOM storage, keystore, Prometheus TSDB, Grafana DB).

On the VM:

```bash
cd ~/Security_platform
bash scripts/backup-public.sh
```

This writes a timestamped backup into `backups/<UTC_TIMESTAMP>/` containing:

- `deploy-docker.env` (secrets/config)
- `certs.tgz` (internal CA + signing keys)
- `volume-*.tgz` (Docker volume snapshots)

Important: backups contain secrets. Copy them off-host and store securely.

#### Restore (Disaster Recovery)

Restore is destructive (overwrites `.env`, `certs/`, and volumes).

```bash
cd ~/Security_platform
CONFIRM_RESTORE=1 BACKUP_DIR=backups/<UTC_TIMESTAMP> bash scripts/restore-public.sh
```

You can also do a non-destructive **restore drill** that restores into new volumes (to validate backups without touching prod):

```bash
cd ~/Security_platform
BACKUP_DIR=backups/<UTC_TIMESTAMP> bash scripts/restore-drill-public.sh
```

5. End-to-end smoke test:

```bash
./scripts/smoke-edge.sh
```

By default this runs in secure mode (`DEV_TOKEN_ISSUER_ENABLED=false`) and validates denial/edge protections.
If you explicitly enable dev token issuance, the smoke test also validates step-up + signing flows.

In production mode, `DEV_TOKEN_ISSUER_ENABLED=true` is blocked unless you also set:

- `ALLOW_DEV_TOKEN_ISSUER_IN_PRODUCTION=true` (for short-lived controlled testing only)

6. Public go-live checks (smoke + regression + advanced attacks [+ optional soak]):

```bash
BASE_URL=https://<PUBLIC_DOMAIN> npm run public:go-live-check
```

Optional soak on public URL:

```bash
BASE_URL=https://<PUBLIC_DOMAIN> RUN_SOAK_SECONDS=1800 npm run public:go-live-check
```

For self-signed/non-public CA environments, set `CA_CERT_PATH` (or set `SMOKE_INSECURE_TLS=true` for local smoke runs).
If your deployment requires a publicly reachable JWKS endpoint, enforce it in smoke with `JWKS_EXPECT_PUBLIC=true`.

7. Policy tests (OPA/Rego):

```bash
npm run test:opa
```

7. Compose security regression tests (stack must already be running):

```bash
npm run test:e2e:compose
```

8. Advanced attack simulation suite (stack must already be running):

```bash
npm run test:e2e:attacks:advanced
```

This suite simulates higher-risk payloads (XSS/SQLi/CMDi/SSRF/traversal, header smuggling,
method override abuse, invalid JWT/CORS abuse, internal endpoint probing, and burst abuse).

9. Compose soak test (stack must already be running):

```bash
npm run test:e2e:soak:compose
```

Useful env vars for soak tuning:

- `SOAK_DURATION_SECONDS` (default `300`)
- `SOAK_INTERVAL_SECONDS` (default `1`)
- `REQUEST_TIMEOUT_SECONDS` (default `5`)
- `BASE_URL` (default `https://localhost:8443`)
- `SOAK_MAX_FAILURES` (default `5`)
- `SOAK_MAX_CONSECUTIVE_FAILURES` (default `3`)
- `SOAK_PROGRESS_EVERY_SECONDS` (default `60`)
- `SOAK_RUNTIME_CHECK_EVERY_SECONDS` (default `60`)

10. Long-run soak orchestration (multi-hour, chunked):

```bash
npm run test:e2e:soak:compose:long
```

Useful env vars for long-run mode:

- `LONGRUN_HOURS` (default `8`)
- `LONGRUN_TOTAL_SECONDS` (overrides `LONGRUN_HOURS` when set)
- `SOAK_CHUNK_SECONDS` (default `900`)
- `LONGRUN_RUN_COMPOSE_REGRESSION` (default `true`, runs `test:e2e:compose` after each chunk)
- `LONGRUN_KEEP_GOING_ON_FAILURE` (default `false`)

11. Full release gate (quality + security + OPA + compose regression):

```bash
npm run release:gate
```

Optional: include a soak step directly in release gate:

```bash
npm run release:gate -- --soak-seconds 1800
```

Optional: include advanced attack simulation in release gate:

```bash
npm run release:gate -- --advanced-attacks --soak-seconds 1800
```

If you want to prepare local compose prerequisites first:

```bash
npm run release:gate:prepare
```

If Docker is unavailable and you only want local gates:

```bash
npm run release:gate:quick
```

## Local Dev (Node)

Prereqs: Node >= 20.

```bash
npm install
npm run build
npm test
```

## Reproducible Builds

For production-like builds, generate and commit `package-lock.json` so Docker and CI can use `npm ci` deterministically:

```bash
bash scripts/generate-lockfile.sh
```

## Notes / Non-goals

- This repo intentionally uses in-memory stores in several places (rate limit buckets, policy store, audit store, SBOM/provenance stores). For real deployments, swap to Redis/DB/WORM storage.
- Telemetry supports a file-backed append-only audit log (`AUDIT_STORE=file`) for local single-node persistence, but it is not a true WORM store.
- "Perfect security" does not exist; treat this as a baseline and run threat modeling for your environment.
