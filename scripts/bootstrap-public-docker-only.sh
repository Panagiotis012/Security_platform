#!/usr/bin/env bash
set -euo pipefail

# Bootstrap a public deployment on a host that has Docker but may not have Node/openssl installed.
# It will:
#  1) generate internal mTLS certs/keys (self-signed CA) for service-to-service auth
#  2) generate strong secrets in deploy/docker/.env (idempotent; use FORCE=1 to rotate)
#  3) start the public compose stack (Caddy + Envoy + internal services)
#
# NOTE: External/public TLS is handled by Caddy via ACME (Let's Encrypt/ZeroSSL).
#       You must have PUBLIC_DOMAIN + ACME_EMAIL set, and ports 80/443 reachable.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ENV_FILE="${ENV_FILE:-deploy/docker/.env}"
COMPOSE_FILE="${COMPOSE_FILE:-deploy/docker/docker-compose.public.yml}"
FORCE="${FORCE:-0}"

cd "$REPO_ROOT"

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker daemon is not available." >&2
  exit 1
fi

uid="$(id -u)"
gid="$(id -g)"

env_force_args=()
cert_force_args=()
if [[ "$FORCE" == "1" ]]; then
  env_force_args+=(--force)
  cert_force_args+=(--force)
fi

echo "==> Generating/refreshing deploy/docker/.env (secrets + HOST_UID/HOST_GID)..."
docker run --rm \
  -u "${uid}:${gid}" \
  -v "${REPO_ROOT}:/work" \
  -w /work \
  node:20-alpine@sha256:09e2b3d9726018aecf269bd35325f46bf75046a643a66d28360ec71132750ec8 \
  node scripts/generate-dev-env.mjs "${env_force_args[@]}"

echo "==> Generating internal mTLS certs/keys (certs/)..."
docker run --rm \
  -e HOST_UID="${uid}" \
  -e HOST_GID="${gid}" \
  -v "${REPO_ROOT}:/work" \
  -w /work \
  alpine@sha256:a4f4213abb84c497377b8544c81b3564f313746700372ec4fe84653e4fb03805 \
  sh -c "apk add --no-cache bash openssl >/dev/null && bash scripts/generate-certs.sh ${cert_force_args[*]} && chown -R ${uid}:${gid} /work/certs || true"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: ${ENV_FILE} was not created." >&2
  exit 1
fi

if ! grep -Eq '^[[:space:]]*PUBLIC_DOMAIN=[^#[:space:]]+' "$ENV_FILE" || ! grep -Eq '^[[:space:]]*ACME_EMAIL=[^#[:space:]]+' "$ENV_FILE"; then
  cat >&2 <<EOF
ERROR: Missing required PUBLIC_DOMAIN and/or ACME_EMAIL in ${ENV_FILE}.

Set at least:
  PUBLIC_DOMAIN=api.example.com
  ACME_EMAIL=you@example.com

Then re-run:
  ENV_FILE=${ENV_FILE} COMPOSE_FILE=${COMPOSE_FILE} bash scripts/bootstrap-public-docker-only.sh
EOF
  exit 1
fi

echo "==> Starting public stack..."
ENV_FILE="$ENV_FILE" COMPOSE_FILE="$COMPOSE_FILE" bash scripts/docker-public-up.sh
