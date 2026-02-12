#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT_DIR}/deploy/docker/.env"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "node is required" >&2
  exit 1
fi

wait_for_200() {
  local url="$1"
  local max_seconds="${2:-60}"
  local start
  start="$(date +%s)"

  while true; do
    # Suppress errors; we only care about the HTTP code while waiting.
    local code
    code="$(curl -sk -o /dev/null -w '%{http_code}' "${url}" || true)"
    if [[ "${code}" == "200" ]]; then
      return 0
    fi

    local now
    now="$(date +%s)"
    if (( now - start >= max_seconds )); then
      echo "Timed out waiting for ${url} (last status: ${code})." >&2
      return 1
    fi
    sleep 0.5
  done
}

read_env_value() {
  local key="$1"
  local val
  val="$(grep -E "^${key}=" "${ENV_FILE}" | sed -E "s/^${key}=//" | head -n 1 || true)"
  # Strip optional surrounding quotes.
  val="${val%\"}"
  val="${val#\"}"
  printf '%s' "${val}"
}

is_enabled() {
  local raw="${1:-}"
  raw="$(printf '%s' "${raw}" | tr '[:upper:]' '[:lower:]')"
  [[ "${raw}" == "true" || "${raw}" == "1" || "${raw}" == "yes" ]]
}

echo "Waiting for edge to be ready (https://localhost:8443/healthz)..."
wait_for_200 "https://localhost:8443/healthz" 90

dev_token_enabled="${DEV_TOKEN_ISSUER_ENABLED:-}"
if [[ -z "${dev_token_enabled}" ]]; then
  dev_token_enabled="$(read_env_value 'DEV_TOKEN_ISSUER_ENABLED')"
fi

if ! is_enabled "${dev_token_enabled}"; then
  echo "Dev token issuer is disabled; running secure-mode smoke checks..."

  denied_issue_status="$(
    curl -sk -o /dev/null -w '%{http_code}' \
      -H 'content-type: application/json' \
      -d '{"sub":"dev-admin","roles":["admin"],"step_up_level":0}' \
      https://localhost:8443/auth/dev/issue-token \
    || true
  )"
  if [[ "${denied_issue_status}" == "200" ]]; then
    echo "/auth/dev/issue-token unexpectedly succeeded while disabled" >&2
    exit 1
  fi

  keys_status="$(
    curl -sk -o /dev/null -w '%{http_code}' \
      https://localhost:8443/v1/keys \
    || true
  )"
  if [[ "${keys_status}" != "401" && "${keys_status}" != "403" ]]; then
    echo "Expected /v1/keys without JWT to be denied (401/403), got ${keys_status}" >&2
    exit 1
  fi

  internal_status="$(
    curl -sk -o /dev/null -w '%{http_code}' \
      -H 'content-type: application/json' \
      -d '{"ip":"203.0.113.77"}' \
      https://localhost:8443/internal/block-ip \
    || true
  )"
  if [[ "${internal_status}" != "401" && "${internal_status}" != "403" ]]; then
    echo "Expected /internal/block-ip to be denied (401/403), got ${internal_status}" >&2
    exit 1
  fi

  echo "Smoke test OK (secure mode)"
  exit 0
fi

secret="${DEV_TOKEN_ISSUER_SECRET:-}"
if [[ -z "${secret}" ]]; then
  secret="$(read_env_value 'DEV_TOKEN_ISSUER_SECRET')"
fi
if [[ -z "${secret}" ]]; then
  echo "DEV_TOKEN_ISSUER_SECRET missing (set env var or populate ${ENV_FILE})" >&2
  exit 1
fi

echo "Issuing dev admin token via Envoy -> Gateway -> Identity..."
issue_body_file="$(mktemp)"
issue_code="$(
  curl -skS -o "${issue_body_file}" -w '%{http_code}' \
    -H 'content-type: application/json' \
    -H "x-dev-issuer-secret: ${secret}" \
    -d '{"sub":"dev-admin","roles":["admin"],"scopes":["openid","profile","email"],"step_up_level":0}' \
    https://localhost:8443/auth/dev/issue-token \
  || true
)"
if [[ "${issue_code}" != "200" ]]; then
  echo "Dev token issuance failed (HTTP ${issue_code}). Body:" >&2
  cat "${issue_body_file}" >&2 || true
  rm -f "${issue_body_file}"
  exit 1
fi
admin_token="$(
  node -e "const fs=require('fs');const raw=fs.readFileSync(process.argv[1],'utf8');if(!raw.trim()){console.error('empty_response');process.exit(1);}let j;try{j=JSON.parse(raw);}catch(e){console.error('non_json_response');console.error(raw);process.exit(1);}if(!j.access_token){console.error(j);process.exit(1);}process.stdout.write(j.access_token);" \
    "${issue_body_file}"
)"
rm -f "${issue_body_file}"

echo "Fetching signing key id from /v1/keys (requires JWT)..."
keys_body_file="$(mktemp)"
keys_code="$(
  curl -skS -o "${keys_body_file}" -w '%{http_code}' \
    -H "authorization: Bearer ${admin_token}" \
    https://localhost:8443/v1/keys \
  || true
)"
if [[ "${keys_code}" != "200" ]]; then
  echo "/v1/keys failed (HTTP ${keys_code}). Body:" >&2
  cat "${keys_body_file}" >&2 || true
  rm -f "${keys_body_file}"
  exit 1
fi
key_id="$(
  node -e "const fs=require('fs');const raw=fs.readFileSync(process.argv[1],'utf8');let j;try{j=JSON.parse(raw);}catch(e){console.error(raw);process.exit(1);}const k=j?.keys?.[0]?.keyId;if(!k){console.error(j);process.exit(1);}process.stdout.write(k);" \
    "${keys_body_file}"
)"
rm -f "${keys_body_file}"

echo "Verifying step-up enforcement on /v1/sign (expect 403 + x-zt-step-up-required)..."
hdr_file="$(mktemp)"
status_code="$(
  curl -sk -o /dev/null -D "${hdr_file}" \
    -w '%{http_code}' \
    -H 'content-type: application/json' \
    -H "authorization: Bearer ${admin_token}" \
    -d "{\"artifactDigest\":\"sha256:demo\",\"keyId\":\"${key_id}\"}" \
    https://localhost:8443/v1/sign
)"
step_up_required="$(grep -i -E '^x-zt-step-up-required:' "${hdr_file}" | head -n 1 | awk '{print $2}' | tr -d $'\r' || true)"
required_level="$(grep -i -E '^x-zt-required-step-up-level:' "${hdr_file}" | head -n 1 | awk '{print $2}' | tr -d $'\r' || true)"
rm -f "${hdr_file}"

if [[ "${status_code}" != 403 || "${step_up_required}" != "true" || "${required_level}" != "2" ]]; then
  echo "Expected 403 + x-zt-step-up-required: true + x-zt-required-step-up-level: 2, got ${status_code} + ${step_up_required:-<missing>} + ${required_level:-<missing>}" >&2
  exit 1
fi

echo "Issuing step-up token (level 2) and signing (expect 201)..."
issue2_body_file="$(mktemp)"
issue2_code="$(
  curl -skS -o "${issue2_body_file}" -w '%{http_code}' \
    -H 'content-type: application/json' \
    -H "x-dev-issuer-secret: ${secret}" \
    -d '{"sub":"dev-admin","roles":["admin"],"scopes":["openid","profile","email"],"step_up_level":2}' \
    https://localhost:8443/auth/dev/issue-token \
  || true
)"
if [[ "${issue2_code}" != "200" ]]; then
  echo "Dev step-up token issuance failed (HTTP ${issue2_code}). Body:" >&2
  cat "${issue2_body_file}" >&2 || true
  rm -f "${issue2_body_file}"
  exit 1
fi
admin_stepup_token="$(
  node -e "const fs=require('fs');const raw=fs.readFileSync(process.argv[1],'utf8');if(!raw.trim()){console.error('empty_response');process.exit(1);}let j;try{j=JSON.parse(raw);}catch(e){console.error('non_json_response');console.error(raw);process.exit(1);}if(!j.access_token){console.error(j);process.exit(1);}process.stdout.write(j.access_token);" \
    "${issue2_body_file}"
)"
rm -f "${issue2_body_file}"

sign_status="$(
  curl -sk -o /dev/null \
    -w '%{http_code}' \
    -H 'content-type: application/json' \
    -H "authorization: Bearer ${admin_stepup_token}" \
    -d "{\"artifactDigest\":\"sha256:demo\",\"keyId\":\"${key_id}\"}" \
    https://localhost:8443/v1/sign
)"
if [[ "${sign_status}" != 201 ]]; then
  echo "Expected 201, got ${sign_status}" >&2
  exit 1
fi

echo "Smoke test OK"
