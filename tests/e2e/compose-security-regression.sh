#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://localhost:8443}"
CA_CERT_PATH="${CA_CERT_PATH:-}"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

curl_tls_args=()
if [[ -n "${CA_CERT_PATH}" ]]; then
  curl_tls_args=(--cacert "${CA_CERT_PATH}")
else
  curl_tls_args=(-k)
fi

request_status() {
  local method="$1"
  local path="$2"
  local body="${3:-}"

  if [[ -n "${body}" ]]; then
    curl -sS "${curl_tls_args[@]}" \
      -o /dev/null \
      -w '%{http_code}' \
      -X "${method}" \
      -H 'content-type: application/json' \
      -d "${body}" \
      "${BASE_URL}${path}" || true
  else
    curl -sS "${curl_tls_args[@]}" \
      -o /dev/null \
      -w '%{http_code}' \
      -X "${method}" \
      "${BASE_URL}${path}" || true
  fi
}

expect_one_of() {
  local actual="$1"
  local name="$2"
  shift 2
  local allowed=("$@")
  local ok=1
  for v in "${allowed[@]}"; do
    if [[ "${actual}" == "${v}" ]]; then
      ok=0
      break
    fi
  done

  if [[ "${ok}" -ne 0 ]]; then
    echo "[FAIL] ${name}: got HTTP ${actual}, expected one of: ${allowed[*]}" >&2
    exit 1
  fi
  echo "[PASS] ${name}: HTTP ${actual}"
}

echo "Running compose security regression checks against ${BASE_URL}"

health_status="$(request_status GET /healthz)"
expect_one_of "${health_status}" "Health endpoint" 200

keys_status="$(request_status GET /v1/keys)"
expect_one_of "${keys_status}" "Protected API without JWT" 401 403

internal_status="$(request_status POST /internal/block-ip '{"ip":"203.0.113.77"}')"
expect_one_of "${internal_status}" "Internal control-plane endpoint exposed at edge" 401 403

dev_issuer_status="$(request_status POST /auth/dev/issue-token '{"sub":"dev-admin","roles":["admin"],"step_up_level":0}')"
if [[ "${dev_issuer_status}" == "200" ]]; then
  echo "[FAIL] Dev token issuer unexpectedly succeeded at edge (HTTP 200)" >&2
  exit 1
fi
echo "[PASS] Dev token issuer is not openly usable: HTTP ${dev_issuer_status}"

trace_status="$(request_status TRACE /auth/login)"
if [[ "${trace_status}" =~ ^2 ]]; then
  echo "[FAIL] TRACE unexpectedly succeeded (HTTP ${trace_status})" >&2
  exit 1
fi
echo "[PASS] TRACE rejected: HTTP ${trace_status}"

smuggle_status="$(
  curl -sS "${curl_tls_args[@]}" \
    -o /dev/null \
    -w '%{http_code}' \
    -X POST \
    -H 'Content-Type: application/json' \
    -H 'Content-Length: 16' \
    -H 'Transfer-Encoding: chunked' \
    -d '{"a":"b"}' \
    "${BASE_URL}/auth/login" || true
)"
if [[ "${smuggle_status}" =~ ^2 ]]; then
  echo "[FAIL] CL+TE ambiguity request unexpectedly succeeded (HTTP ${smuggle_status})" >&2
  exit 1
fi
echo "[PASS] CL+TE ambiguity request rejected: HTTP ${smuggle_status}"

echo "Compose security regression checks passed"
