#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-deploy/docker/.env}"
COMPOSE_FILE="${COMPOSE_FILE:-deploy/docker/docker-compose.public.yml}"

if docker compose version >/dev/null 2>&1; then
  compose() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
  compose() { docker-compose "$@"; }
else
  echo "ERROR: Docker Compose not found." >&2
  exit 1
fi

COMPOSE_DIR="$(cd "$(dirname "$COMPOSE_FILE")" && pwd)"
COMPOSE_FILE_BASE="$(basename "$COMPOSE_FILE")"
ENV_FILE_ABS="$(cd "$(dirname "$ENV_FILE")" && pwd)/$(basename "$ENV_FILE")"

if [[ "$ENV_FILE_ABS" != "${COMPOSE_DIR}/.env" ]]; then
  echo "ERROR: For compatibility, ENV_FILE must be ${COMPOSE_DIR}/.env (got: ${ENV_FILE_ABS})." >&2
  exit 1
fi

( cd "$COMPOSE_DIR" && compose -f "$COMPOSE_FILE_BASE" down )
