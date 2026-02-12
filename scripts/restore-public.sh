#!/usr/bin/env bash
set -euo pipefail

# Restore a backup created by scripts/backup-public.sh.
#
# This is destructive: it overwrites deploy/docker/.env, certs/, and the Docker
# named volumes listed in the backup manifest.
#
# Usage (on the server):
#   cd ~/Security_platform
#   CONFIRM_RESTORE=1 BACKUP_DIR=backups/<UTC_TIMESTAMP> bash scripts/restore-public.sh
#
# Optional env:
#   STOP_STACK=1                  (default 1)
#   START_STACK=0                 (default 0)
#   SYSTEMD_UNIT=security-platform-public.service
#   COMPOSE_FILE=deploy/docker/docker-compose.public.yml

umask 077

if [[ "${CONFIRM_RESTORE:-0}" != "1" ]]; then
  echo "ERROR: Refusing to restore without CONFIRM_RESTORE=1" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BACKUP_DIR="${BACKUP_DIR:-${1:-}}"
if [[ -z "${BACKUP_DIR//[[:space:]]/}" ]]; then
  echo "ERROR: BACKUP_DIR is required (or pass it as the first argument)." >&2
  exit 1
fi

if [[ ! -d "$BACKUP_DIR" ]]; then
  echo "ERROR: BACKUP_DIR does not exist: $BACKUP_DIR" >&2
  exit 1
fi

MANIFEST="${BACKUP_DIR%/}/manifest.txt"
if [[ ! -f "$MANIFEST" ]]; then
  echo "ERROR: Backup manifest not found: $MANIFEST" >&2
  exit 1
fi

STOP_STACK="${STOP_STACK:-1}"
START_STACK="${START_STACK:-0}"
SYSTEMD_UNIT="${SYSTEMD_UNIT:-security-platform-public.service}"

COMPOSE_FILE="${COMPOSE_FILE:-${REPO_ROOT}/deploy/docker/docker-compose.public.yml}"
COMPOSE_DIR="$(cd "$(dirname "${COMPOSE_FILE}")" && pwd)"
COMPOSE_FILE_BASE="$(basename "${COMPOSE_FILE}")"
ENV_FILE="${COMPOSE_DIR}/.env"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found on PATH" >&2
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  compose() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
  compose() { docker-compose "$@"; }
else
  echo "ERROR: Docker Compose not found (need docker compose plugin or docker-compose)." >&2
  exit 1
fi

ts="$(date -u +%Y%m%dT%H%M%SZ)"

stop_stack() {
  if [[ "$STOP_STACK" != "1" ]]; then
    return 0
  fi

  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | awk '{print $1}' | grep -qx "$SYSTEMD_UNIT"; then
    echo "==> Stopping systemd unit: $SYSTEMD_UNIT"
    systemctl stop "$SYSTEMD_UNIT" || true
    return 0
  fi

  echo "==> Stopping compose stack..."
  ( cd "$COMPOSE_DIR" && compose -f "$COMPOSE_FILE_BASE" down ) || true
}

start_stack() {
  if [[ "$START_STACK" != "1" ]]; then
    return 0
  fi

  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | awk '{print $1}' | grep -qx "$SYSTEMD_UNIT"; then
    echo "==> Starting systemd unit: $SYSTEMD_UNIT"
    systemctl start "$SYSTEMD_UNIT"
    return 0
  fi

  echo "==> Starting compose stack..."
  ( cd "$COMPOSE_DIR" && compose -f "$COMPOSE_FILE_BASE" up -d --build )
}

echo "==> Restore source: $BACKUP_DIR"
stop_stack

# ---------------------------------------------------------------------------
# Restore deploy/docker/.env
# ---------------------------------------------------------------------------

if [[ -f "${BACKUP_DIR%/}/deploy-docker.env" ]]; then
  echo "==> Restoring deploy/docker/.env"
  if [[ -f "$ENV_FILE" ]]; then
    cp -f "$ENV_FILE" "${ENV_FILE}.bak.${ts}"
    chmod 600 "${ENV_FILE}.bak.${ts}" || true
  fi
  cp -f "${BACKUP_DIR%/}/deploy-docker.env" "$ENV_FILE"
  chmod 600 "$ENV_FILE" || true
else
  echo "WARN: deploy-docker.env not found in backup; skipping env restore." >&2
fi

# ---------------------------------------------------------------------------
# Restore certs/
# ---------------------------------------------------------------------------

if [[ -f "${BACKUP_DIR%/}/certs.tgz" ]]; then
  echo "==> Restoring certs/"
  if [[ -d "${REPO_ROOT}/certs" ]]; then
    mv "${REPO_ROOT}/certs" "${REPO_ROOT}/certs.bak.${ts}"
  fi
  mkdir -p "${REPO_ROOT}/certs"
  tar --numeric-owner -xzf "${BACKUP_DIR%/}/certs.tgz" -C "${REPO_ROOT}"
else
  echo "WARN: certs.tgz not found in backup; skipping certs restore." >&2
fi

# ---------------------------------------------------------------------------
# Restore Docker volumes
# ---------------------------------------------------------------------------

restore_volume() {
  local logical="$1"
  local vol_name="$2"
  local archive="${BACKUP_DIR%/}/volume-${logical}.tgz"

  if [[ -z "${vol_name//[[:space:]]/}" ]]; then
    echo "WARN: Missing volume name for '${logical}' in manifest; skipping." >&2
    return 0
  fi
  if [[ ! -f "$archive" ]]; then
    echo "WARN: Missing archive for '${logical}': ${archive}; skipping." >&2
    return 0
  fi

  echo "==> Restoring volume '${logical}' (${vol_name})"
  docker volume create "$vol_name" >/dev/null

  docker run --rm \
    -v "${vol_name}:/volume:rw" \
    -v "${BACKUP_DIR%/}:/backup:ro" \
    alpine@sha256:a4f4213abb84c497377b8544c81b3564f313746700372ec4fe84653e4fb03805 \
    sh -ec "
      rm -rf /volume/* /volume/.[!.]* /volume/..?* 2>/dev/null || true
      tar -xzf \"/backup/volume-${logical}.tgz\" -C /volume
    "
}

echo "==> Restoring volumes from manifest..."
while IFS='=' read -r key value; do
  key="${key%$'\r'}"
  value="${value%$'\r'}"

  case "$key" in
    ""|"timestamp"|"repo_root"|"compose_file"|sha256.*) continue ;;
  esac

  restore_volume "$key" "$value"
done <"$MANIFEST"

echo ""
echo "==> Restore complete."
echo "    Start stack: START_STACK=1 CONFIRM_RESTORE=1 BACKUP_DIR=\"$BACKUP_DIR\" bash scripts/restore-public.sh"

start_stack
