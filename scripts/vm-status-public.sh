#!/usr/bin/env bash
set -euo pipefail

# Quick status for the public stack (run ON the VM).
#
# Usage:
#   cd ~/Security_platform
#   bash scripts/vm-status-public.sh

ENV_FILE="${ENV_FILE:-deploy/docker/.env}"
COMPOSE_FILE="${COMPOSE_FILE:-deploy/docker/docker-compose.public.yml}"

# Optional: systemd unit names (if you installed them via scripts/install-systemd-*.sh)
STACK_SYSTEMD_UNIT="${STACK_SYSTEMD_UNIT:-security-platform-public.service}"
BACKUP_SYSTEMD_TIMER="${BACKUP_SYSTEMD_TIMER:-security-platform-public-backup.timer}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

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

PUBLIC_DOMAIN=""
if [[ -f "$ENV_FILE" ]]; then
  PUBLIC_DOMAIN="$(read_env_key PUBLIC_DOMAIN)"
fi

compose_hint=""
compose() { docker compose "$@"; }
if docker compose version >/dev/null 2>&1; then
  compose() { docker compose "$@"; }
  compose_hint="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  compose() { docker-compose "$@"; }
  compose_hint="docker-compose"
else
  compose_hint="(compose missing)"
fi

compose_dir="$(cd "$(dirname "$COMPOSE_FILE")" && pwd)"
compose_base="$(basename "$COMPOSE_FILE")"

echo "Public stack status"
echo "  Repo:         $REPO_ROOT"
echo "  Env file:     $ENV_FILE"
echo "  Compose file: $COMPOSE_FILE"
if [[ -n "${PUBLIC_DOMAIN//[[:space:]]/}" ]]; then
  echo "  Domain:       https://${PUBLIC_DOMAIN}"
else
  echo "  Domain:       <missing PUBLIC_DOMAIN>"
fi

echo ""
echo "Docker tooling:"
docker --version 2>/dev/null || true
docker compose version 2>/dev/null || true
docker buildx version 2>/dev/null || true

if command -v systemctl >/dev/null 2>&1; then
  echo ""
  echo "systemd (optional):"
  if systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "$STACK_SYSTEMD_UNIT"; then
    echo "  ${STACK_SYSTEMD_UNIT}: enabled=$(systemctl is-enabled \"$STACK_SYSTEMD_UNIT\" 2>/dev/null || echo unknown) active=$(systemctl is-active \"$STACK_SYSTEMD_UNIT\" 2>/dev/null || echo unknown)"
  else
    echo "  ${STACK_SYSTEMD_UNIT}: not installed"
  fi
  if systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "$BACKUP_SYSTEMD_TIMER"; then
    echo "  ${BACKUP_SYSTEMD_TIMER}: enabled=$(systemctl is-enabled \"$BACKUP_SYSTEMD_TIMER\" 2>/dev/null || echo unknown) active=$(systemctl is-active \"$BACKUP_SYSTEMD_TIMER\" 2>/dev/null || echo unknown)"
  else
    echo "  ${BACKUP_SYSTEMD_TIMER}: not installed"
  fi
fi

echo ""
echo "Backups (best-effort):"
if [[ -d "/var/backups/security-platform" ]]; then
  last_bkp="$(ls -1 "/var/backups/security-platform" 2>/dev/null | sort | tail -n 1 || true)"
  if [[ -n "${last_bkp//[[:space:]]/}" ]]; then
    echo "  /var/backups/security-platform (latest): ${last_bkp}"
  else
    echo "  /var/backups/security-platform: empty"
  fi
fi
if [[ -d "${REPO_ROOT}/backups" ]]; then
  last_bkp="$(ls -1 "${REPO_ROOT}/backups" 2>/dev/null | sort | tail -n 1 || true)"
  if [[ -n "${last_bkp//[[:space:]]/}" ]]; then
    echo "  ${REPO_ROOT}/backups (latest): ${last_bkp}"
  else
    echo "  ${REPO_ROOT}/backups: empty"
  fi
fi

echo ""
echo "Public checks (best-effort, from Prometheus):"
if command -v curl >/dev/null 2>&1 && curl -fsS "http://127.0.0.1:9090/-/ready" >/dev/null 2>&1; then
  if command -v python3 >/dev/null 2>&1; then
    # Probe status
    probes_json="$(
      curl -fsS -G "http://127.0.0.1:9090/api/v1/query" --data-urlencode 'query=min(probe_success{job="blackbox"})' 2>/dev/null || true
    )"
    if [[ -n "${probes_json//[[:space:]]/}" ]]; then
      python3 - <<'PY' <<<"$probes_json" || true
import json
import sys

try:
    data = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)

res = (data.get("data") or {}).get("result") or []
if not res:
    print("  Public probes: <no data>")
    raise SystemExit(0)

val = (res[0].get("value") or [None, None])[1]
print(f"  Public probes (min success): {val}")
PY
    fi

    # TLS expiry (earliest)
    tls_json="$(
      curl -fsS -G "http://127.0.0.1:9090/api/v1/query" --data-urlencode 'query=min((probe_ssl_earliest_cert_expiry{job="blackbox"} - time()) / 86400)' 2>/dev/null || true
    )"
    if [[ -n "${tls_json//[[:space:]]/}" ]]; then
      python3 - <<'PY' <<<"$tls_json" || true
import json
import sys

try:
    data = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)

res = (data.get("data") or {}).get("result") or []
if not res:
    print("  TLS expiry (days): <no data>")
    raise SystemExit(0)

val = (res[0].get("value") or [None, None])[1]
print(f"  TLS expiry (earliest, days): {val}")
PY
    fi
  fi
else
  echo "  Prometheus not ready on localhost."
fi

echo ""
echo "Endpoints (expected):"
echo "  Edge (host -> Envoy):   http://127.0.0.1:18080/healthz"
if [[ -n "${PUBLIC_DOMAIN//[[:space:]]/}" ]]; then
  echo "  Public HTTPS:           https://${PUBLIC_DOMAIN}/healthz"
fi
echo "  Grafana (localhost):    http://127.0.0.1:3000"
echo "  Prometheus (localhost): http://127.0.0.1:9090"
echo "  Alertmanager (local):   http://127.0.0.1:9093"
echo "  Jaeger UI (localhost):  http://127.0.0.1:16686"
echo ""
echo "Grafana login:"
echo "  User: admin"
echo "  Pass: (stored in ${ENV_FILE} as GRAFANA_PASSWORD)"
echo ""

if [[ "$compose_hint" != "(compose missing)" ]]; then
  echo "Docker Compose (${compose_hint})"
  ( cd "$compose_dir" && compose -f "$compose_base" ps ) || true
else
  echo "Docker Compose: missing"
  echo "Install plugins: sudo bash scripts/update-docker-cli-plugins.sh"
fi
