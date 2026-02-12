#!/usr/bin/env bash
set -euo pipefail

# Install a systemd timer that runs secure backups of the public deployment.
#
# Usage (on the server):
#   cd ~/Security_platform
#   sudo bash scripts/install-systemd-backup-public.sh
#
# Optional:
#   SERVICE_NAME=security-platform-public-backup
#   BACKUP_ROOT=/var/backups/security-platform
#   BACKUP_RETENTION_DAYS=14

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SERVICE_NAME="${SERVICE_NAME:-security-platform-public-backup}"
SERVICE_PATH="${SERVICE_PATH:-/etc/systemd/system/${SERVICE_NAME}.service}"
TIMER_PATH="${TIMER_PATH:-/etc/systemd/system/${SERVICE_NAME}.timer}"

BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/security-platform}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"

if [[ "$(id -u)" != "0" ]]; then
  echo "ERROR: must run as root (use: sudo bash $0)" >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "ERROR: systemctl not found; is this a systemd host?" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found on PATH" >&2
  exit 1
fi

mkdir -p "$BACKUP_ROOT"
chmod 700 "$BACKUP_ROOT" || true

cat >"$SERVICE_PATH" <<EOF
[Unit]
Description=Security Platform (Public) - Backup
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=${REPO_ROOT}
Environment=BACKUP_ROOT=${BACKUP_ROOT}
Environment=BACKUP_RETENTION_DAYS=${BACKUP_RETENTION_DAYS}
ExecStart=/usr/bin/bash ${REPO_ROOT}/scripts/backup-public.sh
Nice=10

[Install]
WantedBy=multi-user.target
EOF

cat >"$TIMER_PATH" <<'EOF'
[Unit]
Description=Security Platform (Public) - Daily Backup Timer

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.timer"

echo "Installed:"
echo "  - ${SERVICE_PATH}"
echo "  - ${TIMER_PATH}"
echo ""
systemctl --no-pager status "${SERVICE_NAME}.timer" || true
