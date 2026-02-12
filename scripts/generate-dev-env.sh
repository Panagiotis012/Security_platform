#!/usr/bin/env bash
set -euo pipefail

# Generates strong local secrets for the Docker Compose stack and writes them to
# `deploy/docker/.env`. This is meant for local/dev only.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT_DIR}/deploy/docker/.env"
EXAMPLE_FILE="${ROOT_DIR}/deploy/docker/.env.example"

if [[ ! -f "${ENV_FILE}" ]]; then
  cp "${EXAMPLE_FILE}" "${ENV_FILE}"
fi

gen_secret() {
  openssl rand -hex 32
}

get_val() {
  local key="$1"
  if grep -q "^${key}=" "${ENV_FILE}"; then
    grep -E "^${key}=" "${ENV_FILE}" | tail -n 1 | cut -d= -f2-
  else
    echo ""
  fi
}

set_kv() {
  local key="$1"
  local val="$2"
  if grep -q "^${key}=" "${ENV_FILE}"; then
    perl -pi -e "s|^${key}=.*|${key}=${val}|" "${ENV_FILE}"
  else
    printf "\n%s=%s\n" "${key}" "${val}" >> "${ENV_FILE}"
  fi
}

maybe_replace() {
  local key="$1"
  local current
  current="$(get_val "${key}")"
  if [[ -z "${current}" ]] || [[ "${current,,}" == *"change-me"* ]] || [[ ${#current} -lt 32 ]]; then
    set_kv "${key}" "$(gen_secret)"
  fi
}

maybe_replace "CSRF_SECRET"
maybe_replace "PDP_ADMIN_JWT_SECRET"
maybe_replace "INTERNAL_SHARED_SECRET"

echo "Updated dev secrets in ${ENV_FILE}:"
echo "  CSRF_SECRET=***"
echo "  PDP_ADMIN_JWT_SECRET=***"
echo "  INTERNAL_SHARED_SECRET=***"

