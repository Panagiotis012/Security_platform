#!/usr/bin/env bash
set -euo pipefail

# Backup critical production state for the public deployment:
#   - deploy/docker/.env (secrets/config)
#   - certs/            (internal mTLS CA + signing keys)
#   - Docker named volumes (audit logs, policy store, SBOM store, keystore, monitoring state)
#
# This script is safe to run while the stack is up.
#
# Usage (on the server):
#   cd ~/Security_platform
#   bash scripts/backup-public.sh
#
# Optional env:
#   BACKUP_ROOT=/var/backups/security-platform
#   BACKUP_DIR=/path/to/exact/output-dir
#   COMPOSE_FILE=deploy/docker/docker-compose.public.yml
#
# NOTE: Backups contain secrets. Store them securely off-host.

umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

COMPOSE_FILE="${COMPOSE_FILE:-${REPO_ROOT}/deploy/docker/docker-compose.public.yml}"
COMPOSE_DIR="$(cd "$(dirname "${COMPOSE_FILE}")" && pwd)"
COMPOSE_FILE_BASE="$(basename "${COMPOSE_FILE}")"
ENV_FILE="${COMPOSE_DIR}/.env"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_ROOT="${BACKUP_ROOT:-${REPO_ROOT}/backups}"
OUT_DIR="${BACKUP_DIR:-${BACKUP_ROOT}/${TS}}"

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

hash_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  else
    shasum -a 256 "$path" | awk '{print $1}'
  fi
}

mkdir -p "${OUT_DIR}"
chmod 700 "${OUT_DIR}" || true

echo "==> Backup dir: ${OUT_DIR}"

manifest="${OUT_DIR}/manifest.txt"
{
  echo "timestamp=${TS}"
  echo "repo_root=${REPO_ROOT}"
  echo "compose_file=${COMPOSE_FILE}"
  echo ""
} >"${manifest}"

if [[ -f "${ENV_FILE}" ]]; then
  echo "==> Backing up deploy/docker/.env"
  cp -f "${ENV_FILE}" "${OUT_DIR}/deploy-docker.env"
  chmod 600 "${OUT_DIR}/deploy-docker.env" || true
  echo "sha256.deploy-docker.env=$(hash_file "${OUT_DIR}/deploy-docker.env")" >>"${manifest}"
else
  echo "WARN: ${ENV_FILE} not found; skipping env backup." >&2
fi

if [[ -d "${REPO_ROOT}/certs" ]]; then
  echo "==> Backing up certs/ (includes signing keys)"
  tar --numeric-owner -czf "${OUT_DIR}/certs.tgz" -C "${REPO_ROOT}" certs
  echo "sha256.certs.tgz=$(hash_file "${OUT_DIR}/certs.tgz")" >>"${manifest}"
else
  echo "WARN: ${REPO_ROOT}/certs not found; skipping certs backup." >&2
fi

container_id_for() {
  local svc="$1"
  ( cd "${COMPOSE_DIR}" && compose -f "${COMPOSE_FILE_BASE}" ps -a -q "${svc}" 2>/dev/null | head -n 1 ) || true
}

volume_from_mount() {
  local cid="$1"
  local dst="$2"
  docker inspect -f "{{range .Mounts}}{{if eq .Destination \"${dst}\"}}{{.Name}}{{end}}{{end}}" "$cid" 2>/dev/null || true
}

volume_by_suffix() {
  local suffix="$1"
  docker volume ls -q 2>/dev/null | grep -E "_${suffix}$" | head -n 1 || true
}

backup_volume() {
  local logical="$1"
  local vol_name="$2"
  local out_path="${OUT_DIR}/volume-${logical}.tgz"
  local out_base
  out_base="$(basename "${out_path}")"

  if [[ -z "${vol_name//[[:space:]]/}" ]]; then
    echo "WARN: Could not determine Docker volume for '${logical}'; skipping." >&2
    return 0
  fi

  echo "==> Backing up volume '${logical}' (${vol_name})"
  docker run --rm \
    -v "${vol_name}:/volume:ro" \
    -v "${OUT_DIR}:/backup" \
    alpine@sha256:a4f4213abb84c497377b8544c81b3564f313746700372ec4fe84653e4fb03805 \
    sh -c "cd /volume && tar --numeric-owner -czf \"/backup/${out_base}\" ."

  local sha
  sha="$(hash_file "${out_path}")"
  echo "    sha256=${sha}"
  echo "sha256.volume-${logical}.tgz=${sha}" >>"${manifest}"
}

# logical|service|destination
items=(
  "pdp-data|policy-engine|/data/pdp"
  "audit-logs|telemetry|/data/audit"
  "sbom-store|supply-chain|/data/sbom"
  "supply-chain-keystore|supply-chain|/data/keys"
  "prometheus-data|prometheus|/prometheus"
  "grafana-data|grafana|/var/lib/grafana"
  "alertmanager-data|alertmanager|/alertmanager"
  # Caddy volumes may exist even when Caddy is scaled to 0; use volume-init (exited) to resolve.
  "caddy-data|volume-init|/caddy-data"
  "caddy-config|volume-init|/caddy-config"
)

for item in "${items[@]}"; do
  IFS='|' read -r logical svc dst <<<"${item}"
  cid="$(container_id_for "${svc}")"
  vol=""
  if [[ -n "${cid//[[:space:]]/}" ]]; then
    vol="$(volume_from_mount "${cid}" "${dst}")"
  fi
  if [[ -z "${vol//[[:space:]]/}" ]]; then
    vol="$(volume_by_suffix "${logical}")"
  fi
  echo "${logical}=${vol}" >>"${manifest}"
  backup_volume "${logical}" "${vol}"
done

echo ""
echo "==> Backup complete: ${OUT_DIR}"
echo "    Manifest: ${manifest}"

BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-}"
if [[ -n "${BACKUP_RETENTION_DAYS//[[:space:]]/}" ]]; then
  if [[ "$BACKUP_RETENTION_DAYS" =~ ^[0-9]+$ ]]; then
    if [[ "$BACKUP_RETENTION_DAYS" == "0" ]]; then
      echo "NOTE: BACKUP_RETENTION_DAYS=0; skipping prune."
    else
      echo "==> Pruning backups older than ${BACKUP_RETENTION_DAYS} day(s) from: ${BACKUP_ROOT}"
      # Only prune directories that match the timestamp naming convention.
      find "${BACKUP_ROOT}" -mindepth 1 -maxdepth 1 -type d -name '20????????T??????Z' -mtime +"${BACKUP_RETENTION_DAYS}" -exec rm -rf {} + 2>/dev/null || true
    fi
  else
    echo "WARN: BACKUP_RETENTION_DAYS is not an integer; skipping prune." >&2
  fi
fi
