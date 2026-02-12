#!/usr/bin/env bash
set -euo pipefail

# Sync this repo to a remote host over SSH (rsync).
#
# Defaults are intentionally safe for production:
#  - excludes secrets and private keys by default (deploy/docker/.env, certs/)
#  - excludes node_modules/ and other local-only artifacts
#
# Usage:
#   DEPLOY_TARGET="ubuntu@1.2.3.4" DEPLOY_DIR="~/Security_platform" bash scripts/ship-to-server.sh
#
# Optional:
#   SSH_OPTS="-i ~/.ssh/id_rsa"     (or any ssh args)
#   INCLUDE_SECRETS=1              (also sync deploy/docker/.env)
#   INCLUDE_CERTS=1                (also sync certs/)
#   DELETE=1                       (delete remote files that don't exist locally)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DEPLOY_TARGET="${DEPLOY_TARGET:-}"
DEPLOY_DIR="${DEPLOY_DIR:-~/Security_platform}"
SSH_OPTS="${SSH_OPTS:-}"

INCLUDE_SECRETS="${INCLUDE_SECRETS:-0}"
INCLUDE_CERTS="${INCLUDE_CERTS:-0}"
DELETE="${DELETE:-0}"

if [[ -z "$DEPLOY_TARGET" ]]; then
  echo "ERROR: DEPLOY_TARGET is required (e.g., ubuntu@203.0.113.10)." >&2
  exit 1
fi

if ! command -v rsync >/dev/null 2>&1; then
  echo "ERROR: rsync not found." >&2
  exit 1
fi

ssh_cmd=(ssh)
if [[ -n "$SSH_OPTS" ]]; then
  # shellcheck disable=SC2206
  ssh_cmd+=($SSH_OPTS)
fi

echo "==> Ensuring remote dir exists: ${DEPLOY_TARGET}:${DEPLOY_DIR}"
"${ssh_cmd[@]}" "$DEPLOY_TARGET" "mkdir -p ${DEPLOY_DIR}"

rsync_args=(
  -az
  --exclude ".DS_Store"
  --exclude ".public.env"
  --exclude "node_modules"
  --exclude "dist"
  --exclude "coverage"
)

if [[ "$INCLUDE_SECRETS" != "1" ]]; then
  rsync_args+=(--exclude "deploy/docker/.env")
fi
if [[ "$INCLUDE_CERTS" != "1" ]]; then
  rsync_args+=(--exclude "certs")
fi

if [[ "$DELETE" == "1" ]]; then
  rsync_args+=(--delete)
fi

echo "==> Syncing repo (excludes: node_modules/, certs/, deploy/docker/.env by default)"
rsync "${rsync_args[@]}" -e "${ssh_cmd[*]}" "${REPO_ROOT}/" "${DEPLOY_TARGET}:${DEPLOY_DIR}/"

echo "==> Done."
