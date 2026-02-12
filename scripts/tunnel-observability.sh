#!/usr/bin/env bash
set -euo pipefail

# Open SSH tunnels for the localhost-only observability UIs on a VM.
#
# Exposes locally:
#  - Grafana      http://127.0.0.1:3000
#  - Prometheus   http://127.0.0.1:9090
#  - Alertmanager http://127.0.0.1:9093
#  - Jaeger       http://127.0.0.1:16686
#
# Usage:
#   bash scripts/tunnel-observability.sh ubuntu@158.180.52.90
#
# With custom SSH options (key, etc):
#   SSH_OPTS="-i ~/.ssh/my.key -o IdentitiesOnly=yes" \
#   bash scripts/tunnel-observability.sh ubuntu@158.180.52.90
#
# Optional local port overrides:
#   LOCAL_GRAFANA_PORT=13000 LOCAL_PROM_PORT=19090 bash scripts/tunnel-observability.sh ubuntu@...

DEPLOY_TARGET="${DEPLOY_TARGET:-${1:-}}"
SSH_OPTS="${SSH_OPTS:-}"

LOCAL_GRAFANA_PORT="${LOCAL_GRAFANA_PORT:-3000}"
LOCAL_PROM_PORT="${LOCAL_PROM_PORT:-9090}"
LOCAL_ALERTMANAGER_PORT="${LOCAL_ALERTMANAGER_PORT:-9093}"
LOCAL_JAEGER_PORT="${LOCAL_JAEGER_PORT:-16686}"

if [[ -z "${DEPLOY_TARGET//[[:space:]]/}" ]]; then
  echo "ERROR: missing target. Example: bash scripts/tunnel-observability.sh ubuntu@158.180.52.90" >&2
  exit 1
fi

ssh_cmd=(ssh -N -T -o ExitOnForwardFailure=yes -o ServerAliveInterval=60 -o ServerAliveCountMax=3)
if [[ -n "$SSH_OPTS" ]]; then
  # shellcheck disable=SC2206
  ssh_cmd+=($SSH_OPTS)
fi

echo "Tunnels:"
echo "  Grafana:      http://127.0.0.1:${LOCAL_GRAFANA_PORT}"
echo "  Prometheus:   http://127.0.0.1:${LOCAL_PROM_PORT}"
echo "  Alertmanager: http://127.0.0.1:${LOCAL_ALERTMANAGER_PORT}"
echo "  Jaeger:       http://127.0.0.1:${LOCAL_JAEGER_PORT}"
echo ""
echo "Keeping SSH session open... (Ctrl+C to stop)"

exec "${ssh_cmd[@]}" \
  -L "${LOCAL_GRAFANA_PORT}:127.0.0.1:3000" \
  -L "${LOCAL_PROM_PORT}:127.0.0.1:9090" \
  -L "${LOCAL_ALERTMANAGER_PORT}:127.0.0.1:9093" \
  -L "${LOCAL_JAEGER_PORT}:127.0.0.1:16686" \
  "$DEPLOY_TARGET"

