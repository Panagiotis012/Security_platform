#!/usr/bin/env bash
set -euo pipefail

# Quick production diagnostics for the public stack.
# Run this ON the VM to identify common issues (Docker tooling, DNS, ports, health).
#
# Usage:
#   cd ~/Security_platform
#   bash scripts/vm-doctor-public.sh
#
# Optional:
#   ENV_FILE=deploy/docker/.env COMPOSE_FILE=deploy/docker/docker-compose.public.yml bash scripts/vm-doctor-public.sh

ENV_FILE="${ENV_FILE:-deploy/docker/.env}"
COMPOSE_FILE="${COMPOSE_FILE:-deploy/docker/docker-compose.public.yml}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$REPO_ROOT"

fatal=0

ok() { printf 'OK: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
err() { printf 'ERROR: %s\n' "$*" >&2; fatal=1; }

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

if [[ "$(uname -s)" != "Linux" ]]; then
  warn "This script is intended for Linux VMs (detected: $(uname -s))."
fi

if [[ ! -f "$ENV_FILE" ]]; then
  err "Missing env file: $ENV_FILE"
else
  ok "Found env file: $ENV_FILE"
fi

if [[ ! -f "$COMPOSE_FILE" ]]; then
  err "Missing compose file: $COMPOSE_FILE"
else
  ok "Found compose file: $COMPOSE_FILE"
fi

BLACKBOX_TARGETS_FILE="${BLACKBOX_TARGETS_FILE:-deploy/docker/prometheus-blackbox-targets.json}"
if [[ -f "$BLACKBOX_TARGETS_FILE" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$BLACKBOX_TARGETS_FILE" <<'PY' || true
import json
import sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    print(f"WARN: Blackbox targets file is not valid JSON: {path}", file=sys.stderr)
    raise SystemExit(0)

if data == []:
    print(f"WARN: Blackbox targets file is empty ({path}). Public probe metrics/alerts will be missing.", file=sys.stderr)
    raise SystemExit(0)
PY
  fi
else
  warn "Missing blackbox targets file (optional): $BLACKBOX_TARGETS_FILE"
fi

compose_hint=""
compose() {
  err "Docker Compose not found (need docker compose plugin or docker-compose)."
  return 127
}

if command -v docker >/dev/null 2>&1; then
  ok "docker found"
else
  err "docker not found on PATH"
fi

if docker info >/dev/null 2>&1; then
  ok "docker daemon reachable"
else
  err "docker daemon not reachable (is dockerd running? is your user in the docker group?)"
fi

if docker compose version >/dev/null 2>&1; then
  compose() { docker compose "$@"; }
  compose_hint="docker compose"
  ok "docker compose plugin available"
elif command -v docker-compose >/dev/null 2>&1; then
  compose() { docker-compose "$@"; }
  compose_hint="docker-compose"
  warn "Using legacy docker-compose (some compose features may be unsupported). Consider: sudo bash scripts/update-docker-cli-plugins.sh"
else
  err "Docker Compose missing. Install compose/buildx plugins: sudo bash scripts/update-docker-cli-plugins.sh"
fi

if docker buildx version >/dev/null 2>&1; then
  ok "docker buildx available"
else
  warn "docker buildx not available (BuildKit builds may fail). Install: sudo bash scripts/update-docker-cli-plugins.sh"
fi

if [[ -f /var/run/reboot-required ]]; then
  warn "Host indicates a reboot is required (/var/run/reboot-required exists)."
fi

df_line="$(df -h / 2>/dev/null | tail -n 1 || true)"
if [[ -n "${df_line//[[:space:]]/}" ]]; then
  use_pct="$(printf '%s\n' "$df_line" | awk '{print $5}' | tr -d '%')"
  if [[ "$use_pct" =~ ^[0-9]+$ ]] && (( use_pct >= 85 )); then
    warn "Disk usage on / is high: ${df_line}"
  else
    ok "Disk usage looks OK: ${df_line}"
  fi
fi

PUBLIC_DOMAIN=""
if [[ -f "$ENV_FILE" ]]; then
  PUBLIC_DOMAIN="$(read_env_key PUBLIC_DOMAIN)"
fi
if [[ -z "${PUBLIC_DOMAIN//[[:space:]]/}" ]]; then
  err "PUBLIC_DOMAIN is missing/blank in $ENV_FILE"
else
  ok "PUBLIC_DOMAIN=${PUBLIC_DOMAIN}"
fi

ports_in_use="unknown"
if command -v ss >/dev/null 2>&1; then
  ports_in_use="0"
  if ss -ltnH 2>/dev/null | awk '$4 ~ /:80$/ || $4 ~ /:443$/ {found=1} END{exit !found}'; then
    ports_in_use="1"
  fi
  if [[ "$ports_in_use" == "1" ]]; then
    warn "Ports 80/443 are in use (expected if nginx/Apache runs on the host)."
  else
    ok "Ports 80/443 appear free."
  fi
fi

if [[ -n "${PUBLIC_DOMAIN//[[:space:]]/}" && "$fatal" == "0" ]]; then
  if command -v dig >/dev/null 2>&1; then
    dns_a="$(dig @1.1.1.1 +time=2 +tries=1 +short "$PUBLIC_DOMAIN" A 2>/dev/null | tr -d '\r' | sed '/^$/d' | sort -u | paste -sd ' ' - || true)"
    dns_aaaa="$(dig @1.1.1.1 +time=2 +tries=1 +short "$PUBLIC_DOMAIN" AAAA 2>/dev/null | tr -d '\r' | sed '/^$/d' | sort -u | paste -sd ' ' - || true)"
    [[ -n "$dns_a" ]] && ok "DNS A: ${dns_a}" || warn "DNS A: <none>"
    [[ -n "$dns_aaaa" ]] && ok "DNS AAAA: ${dns_aaaa}" || ok "DNS AAAA: <none>"
  else
    warn "dig not installed; install: sudo apt-get update && sudo apt-get install -y dnsutils"
  fi

  if command -v curl >/dev/null 2>&1; then
    host_ipv4="$(curl -4 -fsS https://api.ipify.org 2>/dev/null || true)"
    if [[ -n "${host_ipv4//[[:space:]]/}" ]]; then
      ok "Host public IPv4: ${host_ipv4}"
    else
      warn "Unable to determine public IPv4 (ipify)."
    fi
  else
    warn "curl not installed; DNS/IP checks are limited."
  fi
fi

if [[ -n "${compose_hint//[[:space:]]/}" && -f "$COMPOSE_FILE" ]]; then
  compose_dir="$(cd "$(dirname "$COMPOSE_FILE")" && pwd)"
  compose_base="$(basename "$COMPOSE_FILE")"

  if ( cd "$compose_dir" && compose -f "$compose_base" config -q ) >/dev/null 2>&1; then
    ok "compose config is valid (${compose_hint} -f ${compose_base})"
  else
    err "compose config is invalid. Run: (cd $compose_dir && ${compose_hint} -f ${compose_base} config)"
  fi

  echo ""
  echo "==> Stack status (${compose_hint}):"
  ( cd "$compose_dir" && compose -f "$compose_base" ps ) || true
fi

if command -v curl >/dev/null 2>&1; then
  if curl -fsS http://127.0.0.1:18080/healthz >/dev/null 2>&1; then
    ok "Local Envoy listener (127.0.0.1:18080) /healthz OK"
  else
    warn "Local Envoy listener (127.0.0.1:18080) /healthz failed. If you terminate TLS on the host, ensure nginx proxies to http://127.0.0.1:18080"
  fi

  if [[ -n "${PUBLIC_DOMAIN//[[:space:]]/}" ]]; then
    if curl -fsS "https://${PUBLIC_DOMAIN}/healthz" >/dev/null 2>&1; then
      ok "Public HTTPS /healthz OK (https://${PUBLIC_DOMAIN}/healthz)"
    else
      warn "Public HTTPS /healthz failed from this VM. Check DNS, firewall, and host reverse proxy."
    fi
  fi

  if curl -fsS http://127.0.0.1:9090/-/ready >/dev/null 2>&1; then
    ok "Prometheus ready (127.0.0.1:9090)"

    # Best-effort: summarize Prometheus scrape health. This catches silent failures
    # where the stack is up, but a target is failing (bad TLS, wrong port, etc).
    if command -v python3 >/dev/null 2>&1; then
      targets_json="$(curl -fsS http://127.0.0.1:9090/api/v1/targets?state=active 2>/dev/null || true)"
      if [[ -n "${targets_json//[[:space:]]/}" ]]; then
        tmp_targets="$(mktemp)"
        printf '%s' "$targets_json" >"$tmp_targets"
        python3 - "$tmp_targets" <<'PY' || true
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    print("WARN: Unable to parse Prometheus targets JSON; skipping target health summary.", file=sys.stderr)
    raise SystemExit(0)

targets = (data.get("data") or {}).get("activeTargets") or []
bad = [t for t in targets if (t.get("health") or "") != "up"]

if not targets:
    print("WARN: Prometheus returned 0 active targets.", file=sys.stderr)
    raise SystemExit(0)

if not bad:
    print(f"OK: Prometheus targets all up ({len(targets)}/{len(targets)})")
    raise SystemExit(0)

print(f"WARN: Prometheus targets down ({len(bad)}/{len(targets)})", file=sys.stderr)
for t in bad[:15]:
    labels = t.get("labels") or {}
    job = labels.get("job", "?")
    inst = labels.get("instance", "?")
    last_err = (t.get("lastError") or "").strip()
    if last_err:
        print(f"  - {job} {inst}: {last_err}", file=sys.stderr)
    else:
        print(f"  - {job} {inst}: health={t.get('health')}", file=sys.stderr)
PY
        rm -f "$tmp_targets"
      fi
    fi

    # Best-effort: ensure blackbox probes are actually working. This catches
    # misconfigured DNS/proxy/TLS that won't show up as "service down" internally.
    if command -v python3 >/dev/null 2>&1; then
      bb_probe_json="$(
        curl -fsS -G "http://127.0.0.1:9090/api/v1/query" \
          --data-urlencode 'query=probe_success{job="blackbox"}' 2>/dev/null || true
      )"
      if [[ -n "${bb_probe_json//[[:space:]]/}" ]]; then
        tmp_bb="$(mktemp)"
        printf '%s' "$bb_probe_json" >"$tmp_bb"
        python3 - "$tmp_bb" <<'PY' || true
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    print("WARN: Unable to parse blackbox probe_success query JSON.", file=sys.stderr)
    raise SystemExit(0)

result = (data.get("data") or {}).get("result") or []
if not result:
    print("WARN: No blackbox probe metrics (probe_success). If this is a new install, ensure deploy/docker/prometheus-blackbox-targets.json is populated.", file=sys.stderr)
    raise SystemExit(0)

bad = []
for r in result:
    metric = r.get("metric") or {}
    inst = metric.get("instance") or "unknown"
    try:
        val = float((r.get("value") or [None, "nan"])[1])
    except Exception:
        val = float("nan")
    if val < 1:
        bad.append(inst)

if bad:
    print(f"WARN: Blackbox probes failing ({len(bad)}/{len(result)}): " + ", ".join(bad[:10]), file=sys.stderr)
else:
    print(f"OK: Blackbox probes OK ({len(result)}/{len(result)})")
PY
        rm -f "$tmp_bb"
      fi

      bb_tls_json="$(
        curl -fsS -G "http://127.0.0.1:9090/api/v1/query" \
          --data-urlencode 'query=probe_ssl_earliest_cert_expiry{job="blackbox"}' 2>/dev/null || true
      )"
      if [[ -n "${bb_tls_json//[[:space:]]/}" ]]; then
        tmp_tls="$(mktemp)"
        printf '%s' "$bb_tls_json" >"$tmp_tls"
        python3 - "$tmp_tls" <<'PY' || true
import json
import sys
import time

now = time.time()

try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    print("WARN: Unable to parse blackbox TLS expiry query JSON.", file=sys.stderr)
    raise SystemExit(0)

result = (data.get("data") or {}).get("result") or []
if not result:
    # Not fatal: some probes (like pure HTTP) won't expose TLS metrics.
    print("WARN: No blackbox TLS expiry metrics found (probe_ssl_earliest_cert_expiry).", file=sys.stderr)
    raise SystemExit(0)

days = []
for r in result:
    metric = r.get("metric") or {}
    inst = metric.get("instance") or "unknown"
    try:
        expiry = float((r.get("value") or [None, "nan"])[1])
    except Exception:
        continue
    days_left = (expiry - now) / 86400.0
    days.append((days_left, inst))

if not days:
    print("WARN: TLS expiry metrics present but could not compute remaining days.", file=sys.stderr)
    raise SystemExit(0)

days.sort()
min_days, min_inst = days[0]
if min_days < 14:
    print(f"WARN: TLS cert expires soon: {min_inst} in {min_days:.1f} day(s).", file=sys.stderr)
else:
    print(f"OK: TLS expiry (earliest): {min_inst} in {min_days:.1f} day(s).")
PY
        rm -f "$tmp_tls"
      fi
    fi
  else
    warn "Prometheus not ready (127.0.0.1:9090)"
  fi

  if curl -fsS http://127.0.0.1:3000/api/health >/dev/null 2>&1; then
    ok "Grafana healthy (127.0.0.1:3000)"
  else
    warn "Grafana health check failed (127.0.0.1:3000)"
  fi

  if curl -fsS http://127.0.0.1:9093/-/ready >/dev/null 2>&1; then
    ok "Alertmanager ready (127.0.0.1:9093)"
  else
    warn "Alertmanager not ready (127.0.0.1:9093)"
  fi
fi

if command -v fail2ban-client >/dev/null 2>&1; then
  if sudo -n true >/dev/null 2>&1; then
    if sudo fail2ban-client status >/dev/null 2>&1; then
      ok "fail2ban running"
    else
      warn "fail2ban-client present but status failed"
    fi
  else
    warn "fail2ban-client present; run: sudo fail2ban-client status"
  fi
else
  warn "fail2ban not installed (recommended for internet-exposed SSH/nginx). Run: sudo bash scripts/install-fail2ban-ubuntu.sh"
fi

echo ""
if [[ "$fatal" == "1" ]]; then
  echo "Doctor result: FAIL" >&2
  exit 1
fi

echo "Doctor result: OK"
exit 0
