#!/usr/bin/env bash
set -euo pipefail

# User-friendly public deploy helper:
#  - rsync repo to the VM (safe excludes by default)
#  - create a backup on the VM
#  - restart the systemd unit (if installed)
#
# Usage (from your laptop):
#   DEPLOY_TARGET="ubuntu@203.0.113.10" \
#   SSH_OPTS="-i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes" \
#   bash scripts/deploy-public.sh
#
# Optional:
#   DEPLOY_DIR="~/Security_platform"
#   SYSTEMD_UNIT="security-platform-public.service"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DEPLOY_TARGET="${DEPLOY_TARGET:-}"
DEPLOY_DIR="${DEPLOY_DIR:-~/Security_platform}"
SSH_OPTS="${SSH_OPTS:-}"
SYSTEMD_UNIT="${SYSTEMD_UNIT:-security-platform-public.service}"
REMOTE_VM_UPDATE="${REMOTE_VM_UPDATE:-1}"
REMOTE_RUN_SMOKE="${REMOTE_RUN_SMOKE:-0}"
REMOTE_UPDATE_DOCKER_PLUGINS="${REMOTE_UPDATE_DOCKER_PLUGINS:-0}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"

if [[ -z "${DEPLOY_TARGET//[[:space:]]/}" ]]; then
  echo "ERROR: DEPLOY_TARGET is required (e.g., ubuntu@158.180.52.90)." >&2
  exit 1
fi

echo "==> Shipping repo to ${DEPLOY_TARGET}:${DEPLOY_DIR}"
DEPLOY_TARGET="$DEPLOY_TARGET" DEPLOY_DIR="$DEPLOY_DIR" SSH_OPTS="$SSH_OPTS" bash "${REPO_ROOT}/scripts/ship-to-server.sh"

ssh_cmd=(ssh)
if [[ -n "$SSH_OPTS" ]]; then
  # shellcheck disable=SC2206
  ssh_cmd+=($SSH_OPTS)
fi

echo "==> Updating on VM..."

remote_cmd="set -euo pipefail; cd ${DEPLOY_DIR}; BACKUP_RETENTION_DAYS=${BACKUP_RETENTION_DAYS} bash scripts/backup-public.sh >/dev/null;"

if [[ "$REMOTE_UPDATE_DOCKER_PLUGINS" == "1" ]]; then
  # Use sudo -n to avoid hanging for password prompts in non-interactive SSH.
  remote_cmd+=" sudo -n bash scripts/update-docker-cli-plugins.sh || echo 'NOTE: docker CLI plugin update requires sudo (run: sudo bash scripts/update-docker-cli-plugins.sh)' >&2;"
fi

if [[ "$REMOTE_VM_UPDATE" == "1" ]]; then
  remote_cmd+=" BACKUP_BEFORE_UPDATE=0 RUN_SMOKE=${REMOTE_RUN_SMOKE} bash scripts/vm-update-public.sh;"
else
  remote_cmd+=" if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files --no-legend 2>/dev/null | awk '{print \\$1}' | grep -qx ${SYSTEMD_UNIT}; then sudo systemctl restart ${SYSTEMD_UNIT}; else echo 'NOTE: systemd unit not installed; run: sudo bash scripts/install-systemd-public.sh' >&2; fi;"
fi

remote_cmd+=" echo OK"

"${ssh_cmd[@]}" "$DEPLOY_TARGET" "$remote_cmd"
