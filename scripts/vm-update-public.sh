#!/usr/bin/env bash
set -euo pipefail

# User-friendly updater to run ON the VM.
#
# What it can do:
#  - optionally update Docker CLI plugins (docker compose + buildx)
#  - create a backup before making changes (default: enabled)
#  - rebuild + restart the public stack
#  - optionally run the public smoke test
#
# Usage:
#   cd ~/Security_platform
#   bash scripts/vm-update-public.sh
#
# With tool updates + smoke test:
#   UPDATE_DOCKER_PLUGINS=1 RUN_SMOKE=1 bash scripts/vm-update-public.sh
#
# To skip the pre-update backup (not recommended):
#   BACKUP_BEFORE_UPDATE=0 bash scripts/vm-update-public.sh
#
# Optional:
#   ENV_FILE=deploy/docker/.env
#   COMPOSE_FILE=deploy/docker/docker-compose.public.yml

ENV_FILE="${ENV_FILE:-deploy/docker/.env}"
COMPOSE_FILE="${COMPOSE_FILE:-deploy/docker/docker-compose.public.yml}"
UPDATE_DOCKER_PLUGINS="${UPDATE_DOCKER_PLUGINS:-0}"
RUN_SMOKE="${RUN_SMOKE:-0}"
BACKUP_BEFORE_UPDATE="${BACKUP_BEFORE_UPDATE:-1}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"

if [[ "$UPDATE_DOCKER_PLUGINS" == "1" ]]; then
  echo "==> Updating Docker CLI plugins (compose + buildx)..."
  if [[ "$(id -u)" -eq 0 ]]; then
    if ! bash scripts/update-docker-cli-plugins.sh; then
      echo "WARN: Docker CLI plugin update failed; continuing with stack update." >&2
    fi
  else
    if ! sudo bash scripts/update-docker-cli-plugins.sh; then
      echo "WARN: Docker CLI plugin update failed; continuing with stack update." >&2
    fi
  fi
fi

if [[ "$BACKUP_BEFORE_UPDATE" == "1" ]]; then
  echo "==> Creating a backup before updating..."
  if ! BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS}" bash scripts/backup-public.sh >/dev/null; then
    echo "WARN: Backup failed; continuing with stack update." >&2
  fi
fi

echo "==> Updating public stack (build + restart)..."
ENV_FILE="$ENV_FILE" COMPOSE_FILE="$COMPOSE_FILE" bash scripts/docker-public-up.sh

if [[ "$RUN_SMOKE" == "1" ]]; then
  public_domain="$(
    grep -E "^[[:space:]]*PUBLIC_DOMAIN=" "$ENV_FILE" | tail -n 1 | sed -E 's/^[[:space:]]*PUBLIC_DOMAIN=//' | tr -d '\r' | sed -E 's/^\"|\"$//g'
  )"
  if [[ -n "${public_domain//[[:space:]]/}" ]]; then
    echo "==> Smoke testing: https://${public_domain}"
    bash scripts/smoke-public.sh "https://${public_domain}"
  else
    echo "NOTE: PUBLIC_DOMAIN not found in $ENV_FILE; skipping smoke test." >&2
  fi
fi

echo "OK"
