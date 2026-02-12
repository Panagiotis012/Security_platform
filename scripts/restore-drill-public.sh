#!/usr/bin/env bash
set -euo pipefail

# Restore drill: extract a backup into *new* Docker volumes (no impact to prod).
#
# This validates that:
#  - the archives are readable
#  - the volumes can be created
#  - tar extraction succeeds
#
# Usage (on the server):
#   cd ~/Security_platform
#   BACKUP_DIR=backups/<UTC_TIMESTAMP> bash scripts/restore-drill-public.sh
#
# Optional env:
#   DRILL_PREFIX=restore-drill-<name>

umask 077

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

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found on PATH" >&2
  exit 1
fi

ts="$(date -u +%Y%m%dT%H%M%SZ)"
DRILL_PREFIX="${DRILL_PREFIX:-restore-drill-${ts}}"

restore_volume_drill() {
  local logical="$1"
  local new_vol="${DRILL_PREFIX}-${logical}"
  local archive="${BACKUP_DIR%/}/volume-${logical}.tgz"

  if [[ ! -f "$archive" ]]; then
    echo "WARN: Missing archive for '${logical}': ${archive}; skipping." >&2
    return 0
  fi

  echo "==> Drill restore '${logical}' -> ${new_vol}"
  docker volume create "$new_vol" >/dev/null

  docker run --rm \
    -v "${new_vol}:/volume:rw" \
    -v "${BACKUP_DIR%/}:/backup:ro" \
    alpine@sha256:a4f4213abb84c497377b8544c81b3564f313746700372ec4fe84653e4fb03805 \
    sh -ec "
      tar -xzf \"/backup/volume-${logical}.tgz\" -C /volume
      cd /volume
      echo '    top-level:'
      ls -la | head -n 50 || true
      echo '    size:'
      du -sh . || true
    "

  echo "${logical}=${new_vol}"
}

echo "==> Restore drill prefix: $DRILL_PREFIX"
echo "==> Creating drill volumes and extracting archives..."
echo ""

	while IFS='=' read -r key _value; do
	  key="${key%$'\r'}"
	  case "$key" in
	    ""|"timestamp"|"repo_root"|"compose_file"|sha256.*) continue ;;
	  esac
	  restore_volume_drill "$key"
	done <"$MANIFEST"

echo ""
echo "==> Restore drill complete."
echo "    To clean up: docker volume rm $(docker volume ls -q | grep -E \"^${DRILL_PREFIX}-\" || true)"
