#!/usr/bin/env bash
set -euo pipefail

# Minimal production-safe smoke test for a public deployment.
# It does NOT require auth tokens. It verifies:
#   - edge is healthy,
#   - protected endpoints are not open,
#   - malicious request patterns are not accepted (non-2xx),
#   - core transport hardening headers are present.
#
# Usage:
#   ./scripts/smoke-public.sh https://api.example.com
#
# Or:
#   BASE_URL=https://api.example.com ./scripts/smoke-public.sh

BASE_URL="${1:-${BASE_URL:-}}"
if [[ -z "${BASE_URL}" ]]; then
  echo "Usage: $0 https://api.example.com" >&2
  exit 2
fi
BASE_URL="${BASE_URL%/}"
CA_CERT_PATH="${CA_CERT_PATH:-}"
SMOKE_INSECURE_TLS="${SMOKE_INSECURE_TLS:-false}"
JWKS_EXPECT_PUBLIC="${JWKS_EXPECT_PUBLIC:-false}"

if ! command -v curl >/dev/null 2>&1; then
  echo "ERROR: curl is required" >&2
  exit 2
fi

is_enabled() {
  local raw="${1:-}"
  raw="$(printf '%s' "${raw}" | tr '[:upper:]' '[:lower:]')"
  [[ "${raw}" == "1" || "${raw}" == "true" || "${raw}" == "yes" ]]
}

curl_tls_args=()
if [[ -n "${CA_CERT_PATH}" ]]; then
  curl_tls_args=(--cacert "${CA_CERT_PATH}")
elif is_enabled "${SMOKE_INSECURE_TLS}" || [[ "${BASE_URL}" =~ ^https://(localhost|127\.0\.0\.1)(:|/|$) ]]; then
  curl_tls_args=(-k)
fi

curl_common_headers=(
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
  -H 'Accept: application/json,text/html,*/*;q=0.8'
  -H 'Accept-Language: en-US,en;q=0.9'
)

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

pass() {
  echo "OK: $*"
}

code_for() {
  local method="$1"
  local url="$2"
  shift 2
  curl -sS "${curl_tls_args[@]}" -o /dev/null -w '%{http_code}' -X "${method}" "${curl_common_headers[@]}" "$@" "${url}" || true
}

header_for() {
  local header_lc="$1"
  local url="$2"
  # Print the first matching header value (lowercased key match).
  curl -sS "${curl_tls_args[@]}" -D - -o /dev/null "${curl_common_headers[@]}" "$url" \
    | tr -d '\r' \
    | awk -F': ' -v h="$header_lc" 'tolower($1)==h {print $2; exit}'
}

echo "Target: ${BASE_URL}"

# 1) Health check should be publicly reachable.
health_body="$(curl -fsS "${curl_tls_args[@]}" "${curl_common_headers[@]}" "${BASE_URL}/healthz" || true)"
if [[ -z "${health_body}" ]]; then
  fail "/healthz returned empty body (or request failed)"
fi
if ! printf '%s' "${health_body}" | grep -q '"status":"healthy"'; then
  fail "/healthz did not look healthy. Body: ${health_body}"
fi
pass "/healthz is healthy"

# 2) JWKS may be public or protected depending on deployment hardening profile.
# If JWKS_EXPECT_PUBLIC=true, enforce 200.
jwks_code="$(code_for GET "${BASE_URL}/.well-known/jwks.json")"
if is_enabled "${JWKS_EXPECT_PUBLIC}"; then
  if [[ "${jwks_code}" != "200" ]]; then
    fail "/.well-known/jwks.json expected 200 (JWKS_EXPECT_PUBLIC=true), got ${jwks_code}"
  fi
  pass "/.well-known/jwks.json is public (200)"
elif [[ "${jwks_code}" == "200" ]]; then
  pass "/.well-known/jwks.json is public (200)"
elif [[ "${jwks_code}" == "401" || "${jwks_code}" == "403" ]]; then
  pass "/.well-known/jwks.json is edge-protected (${jwks_code})"
else
  fail "/.well-known/jwks.json expected 200/401/403, got ${jwks_code}"
fi

# 3) A protected endpoint must NOT be accessible without JWT.
keys_code="$(code_for GET "${BASE_URL}/v1/keys")"
if [[ "${keys_code}" != "401" && "${keys_code}" != "403" ]]; then
  fail "/v1/keys expected 401/403 without JWT, got ${keys_code}"
fi
pass "/v1/keys is protected (${keys_code})"

# 4) Malicious query patterns should never be accepted (2xx) on auth surface.
waf_code="$(code_for GET "${BASE_URL}/auth/login?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&next=javascript:alert(1)")"
if [[ "${waf_code}" =~ ^2 ]]; then
  fail "Malicious XSS-like request unexpectedly accepted (HTTP ${waf_code})"
fi
pass "Malicious XSS-like request not accepted (${waf_code})"

# 5) Method normalization: TRACE should not be accepted.
trace_code="$(code_for TRACE "${BASE_URL}/auth/login")"
if [[ "${trace_code}" =~ ^2 ]]; then
  fail "TRACE /auth/login unexpectedly returned ${trace_code}"
fi
pass "TRACE is not accepted (${trace_code})"

# 6) TLS security headers should exist (HSTS at minimum).
hsts="$(header_for 'strict-transport-security' "${BASE_URL}/healthz")"
if [[ -z "${hsts}" ]]; then
  fail "Missing Strict-Transport-Security header"
fi
pass "HSTS present (${hsts})"

echo "Smoke test OK"
