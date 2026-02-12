#!/usr/bin/env bash
set -euo pipefail

# Tail logs for the public stack (run ON the VM).
#
# Usage:
#   cd ~/Security_platform
#   bash scripts/vm-logs-public.sh             # defaults (edge + core)
#   bash scripts/vm-logs-public.sh envoy       # specific service(s)
#   bash scripts/vm-logs-public.sh prometheus grafana

COMPOSE_FILE="${COMPOSE_FILE:-deploy/docker/docker-compose.public.yml}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

compose_hint=""
compose() { docker compose "$@"; }
if docker compose version >/dev/null 2>&1; then
  compose() { docker compose "$@"; }
  compose_hint="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  compose() { docker-compose "$@"; }
  compose_hint="docker-compose"
else
  echo "ERROR: Docker Compose not found. Install: sudo bash scripts/update-docker-cli-plugins.sh" >&2
  exit 1
fi

compose_dir="$(cd "$(dirname "$COMPOSE_FILE")" && pwd)"
compose_base="$(basename "$COMPOSE_FILE")"

services=("$@")
if [[ "${#services[@]}" -eq 0 ]]; then
  services=(envoy gateway identity policy-engine telemetry supply-chain)
fi

echo "Tailing logs (${compose_hint}): ${services[*]}"
echo "Compose: $COMPOSE_FILE"
echo "Ctrl+C to stop"

( cd "$compose_dir" && compose -f "$compose_base" logs -f --tail=200 "${services[@]}" )

