#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://localhost:8443}"
CA_CERT_PATH="${CA_CERT_PATH:-}"
ATTACK_TIMEOUT_SECONDS="${ATTACK_TIMEOUT_SECONDS:-10}"
ATTACK_BURST_REQUESTS="${ATTACK_BURST_REQUESTS:-80}"

ATTACK_REPORT_DIR="${ATTACK_REPORT_DIR:-artifacts/attacks}"
ATTACK_REPORT_BASENAME="${ATTACK_REPORT_BASENAME:-advanced-attacks-$(date -u +%Y%m%dT%H%M%SZ)}"
ATTACK_REPORT_CSV="${ATTACK_REPORT_CSV:-${ATTACK_REPORT_DIR}/${ATTACK_REPORT_BASENAME}.csv}"
ATTACK_REPORT_LOG="${ATTACK_REPORT_LOG:-${ATTACK_REPORT_DIR}/${ATTACK_REPORT_BASENAME}.log}"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if [[ ! "${ATTACK_TIMEOUT_SECONDS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "ATTACK_TIMEOUT_SECONDS must be a positive integer." >&2
  exit 1
fi

if [[ ! "${ATTACK_BURST_REQUESTS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "ATTACK_BURST_REQUESTS must be a positive integer." >&2
  exit 1
fi

mkdir -p "${ATTACK_REPORT_DIR}"
: > "${ATTACK_REPORT_LOG}"
echo "name,status,expectation,result" > "${ATTACK_REPORT_CSV}"

curl_tls_args=()
if [[ -n "${CA_CERT_PATH}" ]]; then
  curl_tls_args=(--cacert "${CA_CERT_PATH}")
else
  curl_tls_args=(-k)
fi

total_checks=0
passed_checks=0
failed_checks=0

log_line() {
  local level="$1"
  shift
  local message="$*"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  printf '%s [%s] %s\n' "${ts}" "${level}" "${message}" | tee -a "${ATTACK_REPORT_LOG}"
}

curl_status() {
  local method="$1"
  local path="$2"
  local body=""
  if [[ "$#" -ge 3 ]]; then
    body="$3"
    shift 3
  else
    shift 2
  fi

  local cmd=(curl -sS "${curl_tls_args[@]}" -m "${ATTACK_TIMEOUT_SECONDS}" -o /dev/null -w '%{http_code}' -X "${method}")
  cmd+=(-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36')
  cmd+=(-H 'Accept: application/json, text/plain, */*')
  cmd+=(-H 'Accept-Language: en-US,en;q=0.9')
  if [[ -n "${body}" ]]; then
    cmd+=(-H 'content-type: application/json' -d "${body}")
  fi
  if [[ "$#" -gt 0 ]]; then
    cmd+=("$@")
  fi
  cmd+=("${BASE_URL}${path}")

  "${cmd[@]}" || true
}

record_result() {
  local name="$1"
  local status="$2"
  local expectation="$3"
  local result="$4"

  total_checks=$((total_checks + 1))
  if [[ "${result}" == "PASS" ]]; then
    passed_checks=$((passed_checks + 1))
    log_line "INFO" "[PASS] ${name}: HTTP ${status} (${expectation})"
  else
    failed_checks=$((failed_checks + 1))
    log_line "ERROR" "[FAIL] ${name}: HTTP ${status} (${expectation})"
  fi
  printf '%s,%s,%s,%s\n' "${name}" "${status}" "${expectation}" "${result}" >> "${ATTACK_REPORT_CSV}"
}

expect_one_of() {
  local name="$1"
  local status="$2"
  local expectation="$3"
  shift 3
  local allowed=("$@")
  local ok=0
  local candidate

  for candidate in "${allowed[@]}"; do
    if [[ "${status}" == "${candidate}" ]]; then
      ok=1
      break
    fi
  done

  if [[ "${ok}" -eq 1 ]]; then
    record_result "${name}" "${status}" "${expectation}" "PASS"
  else
    record_result "${name}" "${status}" "${expectation}" "FAIL"
  fi
}

expect_not_2xx() {
  local name="$1"
  local status="$2"
  local expectation="$3"

  if [[ "${status}" =~ ^2 ]]; then
    record_result "${name}" "${status}" "${expectation}" "FAIL"
  else
    record_result "${name}" "${status}" "${expectation}" "PASS"
  fi
}

log_line "INFO" "Running advanced attack suite against ${BASE_URL}"
log_line "INFO" "report_csv=${ATTACK_REPORT_CSV}"
log_line "INFO" "report_log=${ATTACK_REPORT_LOG}"

health_status="$(curl_status GET /healthz)"
expect_one_of "health_ready" "${health_status}" "service should be healthy" 200

xss_status="$(curl_status GET '/auth/login?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&next=javascript:alert(1)')"
expect_one_of "xss_query_block" "${xss_status}" "XSS payload should be blocked" 403

sqli_status="$(curl_status GET '/auth/login?id=1%20UNION%20SELECT%20username,password%20FROM%20users--&sleep=sleep(1)')"
expect_one_of "sqli_union_block" "${sqli_status}" "SQLi payload should be blocked" 403

cmdi_status="$(curl_status GET '/auth/login?cmd=%24%28cat%20/etc/passwd%29|bash')"
expect_one_of "cmdi_subshell_block" "${cmdi_status}" "command injection payload should be blocked" 403

ssrf_status="$(curl_status GET '/auth/login?target=http://169.254.169.254/latest/meta-data/&fallback=file:///etc/passwd')"
expect_one_of "ssrf_metadata_block" "${ssrf_status}" "SSRF metadata target should be blocked" 403

traversal_status="$(curl_status GET '/auth/login?file=..%2F..%2Fetc%2Fpasswd&path=/etc/passwd')"
expect_one_of "traversal_query_block" "${traversal_status}" "traversal payload should be blocked" 400 403

double_encoded_status="$(curl_status GET '/auth/..%252fetc%252fpasswd')"
expect_one_of "double_encoded_path_block" "${double_encoded_status}" "double-encoded path should be rejected" 400 403

method_override_status="$(
  curl_status POST '/auth/login' '{"username":"a","password":"b"}' \
    -H 'X-HTTP-Method-Override: TRACE'
)"
expect_one_of "method_override_header_block" "${method_override_status}" "method override header should be rejected" 400 403

clte_status="$(
  curl -sS "${curl_tls_args[@]}" \
    -m "${ATTACK_TIMEOUT_SECONDS}" \
    -o /dev/null \
    -w '%{http_code}' \
    -X POST \
    -H 'Content-Type: application/json' \
    -H 'Content-Length: 16' \
    -H 'Transfer-Encoding: chunked' \
    -d '{"a":"b"}' \
    "${BASE_URL}/auth/login" || true
)"
expect_one_of "cl_te_smuggling_block" "${clte_status}" "CL+TE smuggling should be rejected" 400

jwt_none_token='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGVzIjpbImFkbWluIl19.'
jwt_tamper_status="$(curl_status GET '/v1/keys' '' -H "Authorization: Bearer ${jwt_none_token}")"
expect_one_of "jwt_alg_none_reject" "${jwt_tamper_status}" "tampered JWT should be rejected" 401 403

cors_evil_status="$(
  curl -sS "${curl_tls_args[@]}" \
    -m "${ATTACK_TIMEOUT_SECONDS}" \
    -o /dev/null \
    -w '%{http_code}' \
    -X OPTIONS \
    -H 'Origin: https://evil.example' \
    -H 'Access-Control-Request-Method: POST' \
    -H 'Access-Control-Request-Headers: content-type,authorization' \
    "${BASE_URL}/auth/login" || true
)"
expect_one_of "cors_evil_origin_block" "${cors_evil_status}" "evil CORS origin should be denied" 403

internal_probe_status="$(curl_status POST '/internal/security-controls' '{"waf":{"enabled":false}}')"
expect_one_of "internal_control_plane_probe_block" "${internal_probe_status}" "internal control plane should not be exposed" 401 403

dev_issuer_status="$(curl_status POST '/auth/dev/issue-token' '{"sub":"attacker","roles":["admin"],"step_up_level":2}')"
if [[ "${dev_issuer_status}" == "200" ]]; then
  record_result "dev_issuer_public_abuse" "${dev_issuer_status}" "dev issuer should not be openly usable" "FAIL"
else
  record_result "dev_issuer_public_abuse" "${dev_issuer_status}" "dev issuer should not be openly usable" "PASS"
fi

burst_blocked=0
burst_2xx=0
for i in $(seq 1 "${ATTACK_BURST_REQUESTS}"); do
  code="$(curl_status GET "/auth/login?burst=${i}")"
  if [[ "${code}" == "429" || "${code}" == "403" ]]; then
    burst_blocked=$((burst_blocked + 1))
  fi
  if [[ "${code}" =~ ^2 ]]; then
    burst_2xx=$((burst_2xx + 1))
  fi
done

if (( burst_blocked > 0 && burst_2xx == 0 )); then
  record_result "burst_abuse_mitigation" "blocked=${burst_blocked}" "burst attack should trigger blocking/challenge and avoid 2xx" "PASS"
else
  record_result "burst_abuse_mitigation" "blocked=${burst_blocked};2xx=${burst_2xx}" "burst attack should trigger blocking/challenge and avoid 2xx" "FAIL"
fi

echo
echo "Advanced attack suite summary:"
echo "  Total checks: ${total_checks}"
echo "  Passed: ${passed_checks}"
echo "  Failed: ${failed_checks}"
echo "  CSV report: ${ATTACK_REPORT_CSV}"
echo "  Log report: ${ATTACK_REPORT_LOG}"

if (( failed_checks > 0 )); then
  exit 1
fi

exit 0
