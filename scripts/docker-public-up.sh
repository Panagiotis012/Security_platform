#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-deploy/docker/.env}"
COMPOSE_FILE="${COMPOSE_FILE:-deploy/docker/docker-compose.public.yml}"
SKIP_PUBLIC_DNS_CHECK="${SKIP_PUBLIC_DNS_CHECK:-0}"
DISABLE_CADDY="${DISABLE_CADDY:-0}"
FORCE_CADDY="${FORCE_CADDY:-0}"

# BuildKit is optional. Some hosts have Docker but not the buildx plugin; in that
# case BuildKit-enabled builds fail. Default to BuildKit only when buildx works.
buildx_ok="0"
if docker buildx version >/dev/null 2>&1; then
  buildx_ok="1"
fi

if [[ -z "${DOCKER_BUILDKIT+x}" ]]; then
  export DOCKER_BUILDKIT="$buildx_ok"
fi
if [[ -z "${COMPOSE_DOCKER_CLI_BUILD+x}" ]]; then
  export COMPOSE_DOCKER_CLI_BUILD="$DOCKER_BUILDKIT"
fi

if [[ "$DOCKER_BUILDKIT" == "1" && "$buildx_ok" != "1" ]]; then
  echo "NOTE: DOCKER_BUILDKIT=1 but docker buildx is not available; falling back to legacy builds (DOCKER_BUILDKIT=0)." >&2
  export DOCKER_BUILDKIT="0"
  export COMPOSE_DOCKER_CLI_BUILD="0"
fi

if docker compose version >/dev/null 2>&1; then
  compose() { docker compose "$@"; }
  COMPOSE_HINT="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  compose() { docker-compose "$@"; }
  COMPOSE_HINT="docker-compose"
else
  echo "ERROR: Docker Compose not found." >&2
  echo "Install docker compose + buildx plugins (recommended): sudo bash scripts/update-docker-cli-plugins.sh" >&2
  echo "Or install legacy docker-compose (Ubuntu): sudo apt-get update && sudo apt-get install -y docker-compose" >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: $ENV_FILE not found." >&2
  echo "Run: npm run generate:env  (or copy deploy/docker/.env.example -> deploy/docker/.env)" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker daemon is not available." >&2
  echo "Start Docker Desktop (macOS) or ensure dockerd is running, then retry." >&2
  exit 1
fi

COMPOSE_DIR="$(cd "$(dirname "$COMPOSE_FILE")" && pwd)"
COMPOSE_FILE_BASE="$(basename "$COMPOSE_FILE")"
ENV_FILE_ABS="$(cd "$(dirname "$ENV_FILE")" && pwd)/$(basename "$ENV_FILE")"

if [[ "$ENV_FILE_ABS" != "${COMPOSE_DIR}/.env" ]]; then
  echo "ERROR: For compatibility, ENV_FILE must be ${COMPOSE_DIR}/.env (got: ${ENV_FILE_ABS})." >&2
  echo "Either set ENV_FILE=${COMPOSE_DIR}/.env or copy your env file there." >&2
  exit 1
fi

require_env_key() {
  local key="$1"
  # Read the last occurrence, ignore comments/blank lines, and strip optional quotes.
  local raw
  raw="$(grep -E "^[[:space:]]*${key}=" "$ENV_FILE" | tail -n 1 | sed -E "s/^[[:space:]]*${key}=//" || true)"
  raw="${raw%$'\r'}"
  raw="${raw%\"}"
  raw="${raw#\"}"
  raw="${raw%\'}"
  raw="${raw#\'}"

  if [[ -z "${raw//[[:space:]]/}" ]]; then
    echo "ERROR: Missing required ${key} in $ENV_FILE (or the file was not saved)." >&2
    return 1
  fi
}

require_env_key "PUBLIC_DOMAIN"

read_env_key() {
  local key="$1"
  local raw
  raw="$(grep -E "^[[:space:]]*${key}=" "$ENV_FILE" | tail -n 1 | sed -E "s/^[[:space:]]*${key}=//" || true)"
  raw="${raw%$'\r'}"
  raw="${raw%\"}"
  raw="${raw#\"}"
  raw="${raw%\'}"
  raw="${raw#\'}"
  printf '%s' "$raw"
}

PUBLIC_DOMAIN="$(read_env_key PUBLIC_DOMAIN)"

# Keep Prometheus blackbox probe targets in sync with PUBLIC_DOMAIN.
# This file is mounted into the Prometheus container.
GENERATE_BLACKBOX_TARGETS="${GENERATE_BLACKBOX_TARGETS:-1}"
INCLUDE_JWKS_BLACKBOX_TARGET="${INCLUDE_JWKS_BLACKBOX_TARGET:-0}"
BLACKBOX_TARGETS_FILE="${COMPOSE_DIR}/prometheus-blackbox-targets.json"
if [[ "$GENERATE_BLACKBOX_TARGETS" == "1" ]]; then
  blackbox_targets=(
    "https://${PUBLIC_DOMAIN}/healthz"
  )

  # Some hardened deployments intentionally protect JWKS at the edge. Keep this
  # probe opt-in to avoid noisy false positives.
  if [[ "$INCLUDE_JWKS_BLACKBOX_TARGET" == "1" ]]; then
    blackbox_targets+=("https://${PUBLIC_DOMAIN}/.well-known/jwks.json")
  fi

  {
    echo "["
    echo "  {"
    echo '    "labels": { "probe": "public" },'
    echo '    "targets": ['
    for i in "${!blackbox_targets[@]}"; do
      target="${blackbox_targets[$i]}"
      comma=""
      if (( i < ${#blackbox_targets[@]} - 1 )); then
        comma=","
      fi
      printf '      "%s"%s\n' "${target}" "${comma}"
    done
    echo "    ]"
    echo "  }"
    echo "]"
  } >"${BLACKBOX_TARGETS_FILE}"
fi

# If the operator explicitly forces Caddy, respect it.
if [[ "$FORCE_CADDY" == "1" ]]; then
  DISABLE_CADDY="0"
fi

# Run from the compose directory so the default `.env` is loaded even on older Compose installs.
( cd "$COMPOSE_DIR" && compose -f "$COMPOSE_FILE_BASE" config -q )

# Determine whether we'll run with Caddy. This affects DNS preflight strictness:
# - When Caddy is enabled, we need correct A/AAAA/CAA for ACME validation.
# - When Caddy is disabled (common behind nginx/Apache), we still want A to match,
#   but AAAA/CAA are warnings (they can still affect clients / your external ACME).
ENFORCE_ACME_PREFLIGHT="0"
if [[ "$DISABLE_CADDY" != "1" ]]; then
  ENFORCE_ACME_PREFLIGHT="1"
fi

# Auto-disable Caddy when ports 80/443 are already occupied (unless FORCE_CADDY=1),
# and Caddy isn't already running.
if [[ "$ENFORCE_ACME_PREFLIGHT" == "1" ]]; then
  caddy_id="$( (cd "$COMPOSE_DIR" && compose -f "$COMPOSE_FILE_BASE" ps -q caddy 2>/dev/null) || true )"
  caddy_running="0"
  if [[ -n "${caddy_id//[[:space:]]/}" ]]; then
    if docker inspect -f '{{.State.Running}}' "$caddy_id" >/dev/null 2>&1; then
      if [[ "$(docker inspect -f '{{.State.Running}}' "$caddy_id" 2>/dev/null || true)" == "true" ]]; then
        caddy_running="1"
      fi
    fi
  fi

  if [[ "$caddy_running" != "1" ]]; then
    ports_in_use="0"
    if command -v ss >/dev/null 2>&1; then
      if ss -ltnH 2>/dev/null | awk '$4 ~ /:80$/ || $4 ~ /:443$/ {found=1} END{exit !found}'; then
        ports_in_use="1"
      fi
    elif command -v lsof >/dev/null 2>&1; then
      if lsof -nP -iTCP:80 -sTCP:LISTEN >/dev/null 2>&1 || lsof -nP -iTCP:443 -sTCP:LISTEN >/dev/null 2>&1; then
        ports_in_use="1"
      fi
    fi

    if [[ "$ports_in_use" == "1" ]]; then
      echo "NOTE: Ports 80/443 are already in use. Starting without Caddy (set FORCE_CADDY=1 to require Caddy)." >&2
      echo "NOTE: Configure your host reverse proxy to forward ${PUBLIC_DOMAIN} to http://127.0.0.1:18080" >&2
      DISABLE_CADDY="1"
      ENFORCE_ACME_PREFLIGHT="0"
    fi
  fi
fi

if [[ "$ENFORCE_ACME_PREFLIGHT" == "1" ]]; then
  require_env_key "ACME_EMAIL"
fi

if [[ "$SKIP_PUBLIC_DNS_CHECK" != "1" ]]; then
  if command -v dig >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
    dig_records() {
      local name="$1"
      local type="$2"

      dig_sanitize() { tr -d '\r' | sed '/^$/d' | sort -u; }

      # Prefer public resolvers to avoid being misled by stale local caches
      # (common on cloud VMs using provider DNS forwarders).
      local out_cf="" out_google="" any_ok="0"
      if out_cf="$(dig @"1.1.1.1" +time=2 +tries=1 +short "$name" "$type" 2>/dev/null)"; then
        any_ok="1"
      fi
      if out_google="$(dig @"8.8.8.8" +time=2 +tries=1 +short "$name" "$type" 2>/dev/null)"; then
        any_ok="1"
      fi

      # If at least one public resolver responded, use that answer (even if empty).
      # Do not fall back to the system resolver in this case, since it may be stale.
      if [[ "$any_ok" == "1" ]]; then
        printf '%s\n%s\n' "$out_cf" "$out_google" | dig_sanitize | paste -sd ' ' -
        return 0
      fi

      # Public resolvers unreachable: fall back to system resolver.
      dig +time=2 +tries=1 +short "$name" "$type" 2>/dev/null | dig_sanitize | paste -sd ' ' - || true
    }

    # This is a best-effort preflight to prevent confusing ACME failures.
    DNS_A="$(dig_records "$PUBLIC_DOMAIN" A)"
    DNS_AAAA="$(dig_records "$PUBLIC_DOMAIN" AAAA)"
    PUBLIC_IPV4="$(curl -4 -fsS https://api.ipify.org 2>/dev/null || true)"
    PUBLIC_IPV6="$(curl -6 -fsS https://api64.ipify.org 2>/dev/null || true)"

    HAVE_PUBLIC_IP="0"
    if [[ -n "$PUBLIC_IPV4" || -n "$PUBLIC_IPV6" ]]; then
      HAVE_PUBLIC_IP="1"
    fi

    if [[ "$HAVE_PUBLIC_IP" != "1" ]]; then
      echo "NOTE: Could not determine this host's public IP; skipping DNS preflight." >&2
	    else
	      if [[ -n "$DNS_A" && -n "$PUBLIC_IPV4" ]]; then
	        IPV4_MATCHED="0"
	        for ip in $DNS_A; do
          if [[ "$ip" == "$PUBLIC_IPV4" ]]; then IPV4_MATCHED="1"; fi
        done
        if [[ "$IPV4_MATCHED" != "1" ]]; then
          echo "ERROR: PUBLIC_DOMAIN ($PUBLIC_DOMAIN) A record does not match this host." >&2
          echo "  DNS A:     ${DNS_A:-<none>}" >&2
          echo "  Host IPv4: ${PUBLIC_IPV4:-<unknown>}" >&2
          exit 1
	        fi
	      fi
	
	      # If an AAAA record exists, ACME validation may use IPv6. Require it to match,
	      # or instruct the operator to remove AAAA until IPv6 routing/firewall is correct.
	      if [[ -n "$DNS_AAAA" ]]; then
        # Don't rely on the single outgoing address (it can change on some systems).
        # Instead, ensure every DNS AAAA record points to an IPv6 address assigned to this host.
        HOST_IPV6_CANDIDATES=""
        if command -v ip >/dev/null 2>&1; then
          HOST_IPV6_CANDIDATES+=" $(ip -6 addr show scope global 2>/dev/null | awk '/inet6 /{print $2}' | cut -d/ -f1 | tr '\n' ' ')"
        fi
        if command -v ifconfig >/dev/null 2>&1; then
          HOST_IPV6_CANDIDATES+=" $(ifconfig 2>/dev/null | awk '/inet6 /{print $2}' | sed 's/%.*//' | tr '\n' ' ')"
        fi
        if [[ -n "${PUBLIC_IPV6:-}" ]]; then
          HOST_IPV6_CANDIDATES+=" ${PUBLIC_IPV6}"
        fi

	        # Normalize: unique + lowercase + drop link-local/loopback.
	        mapfile -t HOST_IPV6_LIST < <(printf '%s\n' "$HOST_IPV6_CANDIDATES" | tr ' ' '\n' | tr 'A-F' 'a-f' | sed '/^$/d' | grep -Ev '^(fe80:|::1$)' | sort -u)
	        if [[ "${#HOST_IPV6_LIST[@]}" -eq 0 ]]; then
	          if [[ "$ENFORCE_ACME_PREFLIGHT" == "1" ]]; then
	            echo "ERROR: PUBLIC_DOMAIN ($PUBLIC_DOMAIN) has an AAAA record, but this host has no detected IPv6 addresses." >&2
	            echo "  DNS AAAA:  ${DNS_AAAA:-<none>}" >&2
	            echo "Remove the AAAA record (or fix IPv6) to avoid ACME validation failures." >&2
	            exit 1
	          else
	            echo "WARN: PUBLIC_DOMAIN ($PUBLIC_DOMAIN) has an AAAA record, but this host has no detected IPv6 addresses." >&2
	            echo "      Clients may attempt IPv6 and fail. Consider removing the AAAA record." >&2
	          fi
	        fi
	
	        BAD_AAAA=""
	        for dns_ip in $DNS_AAAA; do
          dns_ip="$(printf '%s' "$dns_ip" | tr 'A-F' 'a-f')"
          FOUND="0"
          for host_ip in "${HOST_IPV6_LIST[@]}"; do
            if [[ "$dns_ip" == "$host_ip" ]]; then
              FOUND="1"
              break
            fi
          done
          if [[ "$FOUND" != "1" ]]; then
            BAD_AAAA+="$dns_ip "
          fi
	        done
	        if [[ -n "${BAD_AAAA//[[:space:]]/}" ]]; then
	          if [[ "$ENFORCE_ACME_PREFLIGHT" == "1" ]]; then
	            echo "ERROR: PUBLIC_DOMAIN ($PUBLIC_DOMAIN) AAAA record does not match this host." >&2
	            echo "  DNS AAAA:   ${DNS_AAAA:-<none>}" >&2
	            echo "  Host IPv6:  ${HOST_IPV6_LIST[*]}" >&2
	            echo "Fix the AAAA record (or remove it) to avoid ACME validation failures." >&2
	            exit 1
	          else
	            echo "WARN: PUBLIC_DOMAIN ($PUBLIC_DOMAIN) AAAA record does not match this host." >&2
	            echo "      DNS AAAA:  ${DNS_AAAA:-<none>}" >&2
	            echo "      Host IPv6: ${HOST_IPV6_LIST[*]:-<none>}" >&2
	          fi
	        fi
	      fi
	
	      # CAA can block Let's Encrypt/ZeroSSL. If present, ensure it allows a supported CA.
      find_caa_records() {
        local name="$1"
        local caa
        caa="$(dig_records "$name" CAA || true)"
        if [[ -n "$caa" ]]; then
          printf '%s' "$caa"
          return 0
        fi
        if [[ "$name" == *.* ]]; then
          printf '%s' "$(find_caa_records "${name#*.}")"
        fi
      }

	      CAA_RECORDS="$(find_caa_records "$PUBLIC_DOMAIN" | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g' || true)"
	      if [[ -n "${CAA_RECORDS//[[:space:]]/}" ]]; then
	        # Only enforce when issue/issuewild exists. Ignore iodef-only setups.
	        if echo "$CAA_RECORDS" | grep -Eq 'issue(wild)?[[:space:]]+\"' ; then
	          if ! echo "$CAA_RECORDS" | grep -Eqi 'issue(wild)?[[:space:]]+\"(letsencrypt\.org|zerossl\.com)\"' ; then
	            if [[ "$ENFORCE_ACME_PREFLIGHT" == "1" ]]; then
	              echo "ERROR: CAA records for $PUBLIC_DOMAIN do not allow Let's Encrypt or ZeroSSL." >&2
	              echo "  CAA: ${CAA_RECORDS}" >&2
	              echo "Add: CAA 0 issue \"letsencrypt.org\"  (or remove restrictive CAA records), then retry." >&2
	              exit 1
	            else
	              echo "WARN: CAA records for $PUBLIC_DOMAIN do not allow Let's Encrypt or ZeroSSL." >&2
	              echo "      This does not block the stack when Caddy is disabled, but it may block external ACME issuance." >&2
	              echo "      CAA: ${CAA_RECORDS}" >&2
	            fi
	          fi
	        fi
	      fi
	    fi
  else
    echo "NOTE: dig/curl not found; skipping PUBLIC_DOMAIN DNS preflight." >&2
  fi
fi

scale_args=()

if [[ "$DISABLE_CADDY" == "1" ]]; then
  scale_args+=(--scale caddy=0)
fi

( cd "$COMPOSE_DIR" && compose -f "$COMPOSE_FILE_BASE" up -d --build "${scale_args[@]}" )

# Best-effort reload of Prometheus config/rules so changes to prometheus.yml or
# /etc/prometheus/rules are applied without a container restart.
if command -v curl >/dev/null 2>&1; then
  if curl -fsS -X POST http://127.0.0.1:9090/-/reload >/dev/null 2>&1; then
    echo "OK: Prometheus config reloaded (/ -/reload)"
  else
    echo "NOTE: Prometheus reload endpoint unavailable. If you changed prometheus.yml/rules, run:" >&2
    echo "      (cd ${COMPOSE_DIR} && ${COMPOSE_HINT} -f ${COMPOSE_FILE_BASE} restart prometheus)" >&2
  fi
fi

echo "Public stack is starting."
echo "Next checks:"
echo "  - HTTPS: https://<PUBLIC_DOMAIN>/healthz"
echo "  - Caddy logs: (cd $(dirname "$COMPOSE_FILE") && ${COMPOSE_HINT} -f ${COMPOSE_FILE_BASE} logs -f caddy)"
echo "  - Envoy logs: (cd $(dirname "$COMPOSE_FILE") && ${COMPOSE_HINT} -f ${COMPOSE_FILE_BASE} logs -f envoy)"
