#!/usr/bin/env bash
set -euo pipefail

# Install a systemd unit that starts the public docker compose stack on boot.
#
# This is intended for servers/VPS where you run:
#   - nginx (or another reverse proxy) on :80/:443
#   - Envoy published on 127.0.0.1:18080 (compose does this by default)
#
# Usage (on the server):
#   cd ~/Security_platform
#   sudo bash scripts/install-systemd-public.sh
#
# Optional:
#   SERVICE_NAME=security-platform-public
#   DISABLE_CADDY=1   (default: 1)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SERVICE_NAME="${SERVICE_NAME:-security-platform-public}"
UNIT_PATH="${UNIT_PATH:-/etc/systemd/system/${SERVICE_NAME}.service}"

COMPOSE_DIR="${COMPOSE_DIR:-${REPO_ROOT}/deploy/docker}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.public.yml}"

# Most real servers already have nginx/Apache on :80/:443.
DISABLE_CADDY="${DISABLE_CADDY:-1}"

if [[ "$(id -u)" != "0" ]]; then
  echo "ERROR: must run as root (use: sudo bash $0)" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found on PATH" >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose plugin not available." >&2
  echo "Install it, then retry:" >&2
  echo "  sudo mkdir -p /usr/local/lib/docker/cli-plugins" >&2
  exit 1
fi

if [[ ! -d "$COMPOSE_DIR" ]]; then
  echo "ERROR: compose dir not found: $COMPOSE_DIR" >&2
  exit 1
fi
if [[ ! -f "${COMPOSE_DIR}/${COMPOSE_FILE}" ]]; then
  echo "ERROR: compose file not found: ${COMPOSE_DIR}/${COMPOSE_FILE}" >&2
  exit 1
fi
if [[ ! -f "${COMPOSE_DIR}/.env" ]]; then
  echo "ERROR: env file not found: ${COMPOSE_DIR}/.env" >&2
  echo "Run: cp deploy/docker/.env.example deploy/docker/.env && edit it, or run bootstrap." >&2
  exit 1
fi

scale_flags=""
if [[ "$DISABLE_CADDY" == "1" ]]; then
  scale_flags="--scale caddy=0"
fi

cat >"$UNIT_PATH" <<EOF
[Unit]
Description=Security Platform (Public) - Docker Compose
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${COMPOSE_DIR}
ExecStart=/usr/bin/docker compose -f ${COMPOSE_FILE} up -d --remove-orphans ${scale_flags}
ExecStop=/usr/bin/docker compose -f ${COMPOSE_FILE} down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

echo "Installed: $UNIT_PATH"
systemctl --no-pager status "$SERVICE_NAME" || true

