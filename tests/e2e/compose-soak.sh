#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE_URL="${BASE_URL:-https://localhost:8443}"
CA_CERT_PATH="${CA_CERT_PATH:-}"

SOAK_DURATION_SECONDS="${SOAK_DURATION_SECONDS:-300}"
SOAK_INTERVAL_SECONDS="${SOAK_INTERVAL_SECONDS:-1}"
REQUEST_TIMEOUT_SECONDS="${REQUEST_TIMEOUT_SECONDS:-5}"
SOAK_PROGRESS_EVERY_SECONDS="${SOAK_PROGRESS_EVERY_SECONDS:-60}"
SOAK_RUNTIME_CHECK_EVERY_SECONDS="${SOAK_RUNTIME_CHECK_EVERY_SECONDS:-60}"
SOAK_SMUGGLING_EVERY_ITERATIONS="${SOAK_SMUGGLING_EVERY_ITERATIONS:-10}"
SOAK_MAX_FAILURES="${SOAK_MAX_FAILURES:-5}"
SOAK_MAX_CONSECUTIVE_FAILURES="${SOAK_MAX_CONSECUTIVE_FAILURES:-3}"
SOAK_FAIL_FAST="${SOAK_FAIL_FAST:-true}"
SOAK_CAPTURE_FAILURE_CONTEXT="${SOAK_CAPTURE_FAILURE_CONTEXT:-true}"

SOAK_REPORT_DIR="${SOAK_REPORT_DIR:-${ROOT_DIR}/artifacts/soak}"
SOAK_REPORT_BASENAME="${SOAK_REPORT_BASENAME:-}"
SOAK_REPORT_FILE="${SOAK_REPORT_FILE:-}"
SOAK_LOG_FILE="${SOAK_LOG_FILE:-}"

COMPOSE_FILE="${ROOT_DIR}/deploy/docker/docker-compose.yml"
COMPOSE_ENV="${ROOT_DIR}/deploy/docker/.env"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

if ! command -v awk >/dev/null 2>&1; then
  echo "awk is required" >&2
  exit 1
fi

if ! command -v sort >/dev/null 2>&1; then
  echo "sort is required" >&2
  exit 1
fi

is_positive_int() {
  local value="$1"
  [[ "${value}" =~ ^[1-9][0-9]*$ ]]
}

is_non_negative_int() {
  local value="$1"
  [[ "${value}" =~ ^[0-9]+$ ]]
}

is_enabled() {
  local raw="${1:-}"
  raw="$(printf '%s' "${raw}" | tr '[:upper:]' '[:lower:]')"
  [[ "${raw}" == "true" || "${raw}" == "1" || "${raw}" == "yes" ]]
}

if ! is_positive_int "${SOAK_DURATION_SECONDS}"; then
  echo "SOAK_DURATION_SECONDS must be a positive integer (seconds)." >&2
  exit 1
fi

if ! is_positive_int "${SOAK_INTERVAL_SECONDS}"; then
  echo "SOAK_INTERVAL_SECONDS must be a positive integer (seconds)." >&2
  exit 1
fi

if ! is_positive_int "${REQUEST_TIMEOUT_SECONDS}"; then
  echo "REQUEST_TIMEOUT_SECONDS must be a positive integer (seconds)." >&2
  exit 1
fi

if ! is_non_negative_int "${SOAK_PROGRESS_EVERY_SECONDS}"; then
  echo "SOAK_PROGRESS_EVERY_SECONDS must be a non-negative integer (seconds)." >&2
  exit 1
fi

if ! is_non_negative_int "${SOAK_RUNTIME_CHECK_EVERY_SECONDS}"; then
  echo "SOAK_RUNTIME_CHECK_EVERY_SECONDS must be a non-negative integer (seconds)." >&2
  exit 1
fi

if ! is_non_negative_int "${SOAK_SMUGGLING_EVERY_ITERATIONS}"; then
  echo "SOAK_SMUGGLING_EVERY_ITERATIONS must be a non-negative integer." >&2
  exit 1
fi

if ! is_non_negative_int "${SOAK_MAX_FAILURES}"; then
  echo "SOAK_MAX_FAILURES must be a non-negative integer." >&2
  exit 1
fi

if ! is_non_negative_int "${SOAK_MAX_CONSECUTIVE_FAILURES}"; then
  echo "SOAK_MAX_CONSECUTIVE_FAILURES must be a non-negative integer." >&2
  exit 1
fi

mkdir -p "${SOAK_REPORT_DIR}"

artifact_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "${SOAK_REPORT_BASENAME}" ]]; then
  SOAK_REPORT_BASENAME="compose-soak-${artifact_stamp}"
fi

if [[ -z "${SOAK_REPORT_FILE}" ]]; then
  SOAK_REPORT_FILE="${SOAK_REPORT_DIR}/${SOAK_REPORT_BASENAME}.json"
fi

if [[ -z "${SOAK_LOG_FILE}" ]]; then
  SOAK_LOG_FILE="${SOAK_REPORT_DIR}/${SOAK_REPORT_BASENAME}.log"
fi

curl_tls_args=()
if [[ -n "${CA_CERT_PATH}" ]]; then
  curl_tls_args=(--cacert "${CA_CERT_PATH}")
else
  curl_tls_args=(-k)
fi

start_snapshot="$(mktemp)"
current_snapshot="$(mktemp)"
end_snapshot="$(mktemp)"
health_latency_samples="$(mktemp)"
failure_details_file="${SOAK_REPORT_DIR}/${SOAK_REPORT_BASENAME}.failures.log"

cleanup() {
  rm -f "${start_snapshot}" "${current_snapshot}" "${end_snapshot}" "${health_latency_samples}"
}
trap cleanup EXIT

: > "${SOAK_LOG_FILE}"
: > "${health_latency_samples}"
: > "${failure_details_file}"

log_line() {
  local level="$1"
  shift
  local message="$*"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  printf '%s [%s] %s\n' "${ts}" "${level}" "${message}" | tee -a "${SOAK_LOG_FILE}"
}

compose_cmd() {
  docker compose --env-file "${COMPOSE_ENV}" -f "${COMPOSE_FILE}" "$@"
}

collect_container_snapshot() {
  local out_file="$1"
  local ids

  : > "${out_file}"
  ids="$(compose_cmd ps -q || true)"
  if [[ -z "${ids}" ]]; then
    return 1
  fi

  while IFS= read -r id; do
    [[ -z "${id}" ]] && continue
    local inspect_line
    inspect_line="$(docker inspect --format '{{.Id}}|{{.Name}}|{{.RestartCount}}|{{.State.Status}}' "${id}" 2>/dev/null || true)"
    if [[ -z "${inspect_line}" ]]; then
      continue
    fi
    printf '%s\n' "${inspect_line}" | awk -F'|' '{name=$2; sub(/^\//, "", name); print $1 "|" name "|" $3 "|" $4}' >> "${out_file}"
  done <<EOF
${ids}
EOF

  [[ -s "${out_file}" ]]
}

check_one_of() {
  local status="$1"
  local allowed_csv="$2"
  local allowed_item

  IFS=',' read -r -a allowed_values <<< "${allowed_csv}"
  for allowed_item in "${allowed_values[@]}"; do
    if [[ "${status}" == "${allowed_item}" ]]; then
      return 0
    fi
  done
  return 1
}

request_status_latency() {
  local method="$1"
  local path="$2"
  local body="${3:-}"

  if [[ -n "${body}" ]]; then
    curl -sS "${curl_tls_args[@]}" \
      -m "${REQUEST_TIMEOUT_SECONDS}" \
      -o /dev/null \
      -w '%{http_code} %{time_total}' \
      -X "${method}" \
      -H 'content-type: application/json' \
      -d "${body}" \
      "${BASE_URL}${path}" || true
  else
    curl -sS "${curl_tls_args[@]}" \
      -m "${REQUEST_TIMEOUT_SECONDS}" \
      -o /dev/null \
      -w '%{http_code} %{time_total}' \
      -X "${method}" \
      "${BASE_URL}${path}" || true
  fi
}

wait_for_edge_health() {
  local attempts=60
  local i=0

  while (( i < attempts )); do
    local result status
    result="$(request_status_latency GET /healthz)"
    status="$(printf '%s\n' "${result}" | awk '{print $1}')"
    if [[ "${status}" == "200" ]]; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done

  return 1
}

capture_failure_context() {
  if ! is_enabled "${SOAK_CAPTURE_FAILURE_CONTEXT}"; then
    return
  fi
  if [[ "${failure_context_captured}" -eq 1 ]]; then
    return
  fi
  failure_context_captured=1
  log_line "INFO" "Capturing docker failure context into ${SOAK_LOG_FILE}"
  {
    echo
    echo "----- docker compose ps -----"
    compose_cmd ps || true
    echo
    echo "----- docker compose logs (tail=200) -----"
    compose_cmd logs --no-color --tail 200 || true
    echo
  } >> "${SOAK_LOG_FILE}" 2>&1
}

budget_fail_fast=false
if is_enabled "${SOAK_FAIL_FAST}"; then
  budget_fail_fast=true
fi

total_checks=0
passed_checks=0
failed_checks=0
consecutive_failed_checks=0
max_observed_consecutive_failures=0
budget_exceeded=0
abort_requested=0
abort_reason=""

health_pass=0
health_fail=0
protected_pass=0
protected_fail=0
internal_pass=0
internal_fail=0
trace_pass=0
trace_fail=0
smuggling_pass=0
smuggling_fail=0

failure_context_captured=0
periodic_runtime_issue_detected=0

record_check_success() {
  local name="$1"
  local latency="${2:-0}"

  total_checks=$((total_checks + 1))
  passed_checks=$((passed_checks + 1))
  consecutive_failed_checks=0

  case "${name}" in
    healthz)
      health_pass=$((health_pass + 1))
      printf '%s\n' "${latency}" >> "${health_latency_samples}"
      ;;
    protected_no_jwt) protected_pass=$((protected_pass + 1)) ;;
    internal_control_plane_edge) internal_pass=$((internal_pass + 1)) ;;
    trace_rejected) trace_pass=$((trace_pass + 1)) ;;
    cl_te_smuggling) smuggling_pass=$((smuggling_pass + 1)) ;;
  esac
}

record_check_failure() {
  local name="$1"
  local details="$2"

  total_checks=$((total_checks + 1))
  failed_checks=$((failed_checks + 1))
  consecutive_failed_checks=$((consecutive_failed_checks + 1))

  if (( consecutive_failed_checks > max_observed_consecutive_failures )); then
    max_observed_consecutive_failures="${consecutive_failed_checks}"
  fi

  case "${name}" in
    healthz) health_fail=$((health_fail + 1)) ;;
    protected_no_jwt) protected_fail=$((protected_fail + 1)) ;;
    internal_control_plane_edge) internal_fail=$((internal_fail + 1)) ;;
    trace_rejected) trace_fail=$((trace_fail + 1)) ;;
    cl_te_smuggling) smuggling_fail=$((smuggling_fail + 1)) ;;
  esac

  log_line "ERROR" "[FAIL] ${name}: ${details}"
  printf '%s\n' "${name}: ${details}" >> "${failure_details_file}"
}

evaluate_failure_budget() {
  local reasons=()

  if (( failed_checks > SOAK_MAX_FAILURES )); then
    reasons+=("failed_checks=${failed_checks} exceeded SOAK_MAX_FAILURES=${SOAK_MAX_FAILURES}")
  fi

  if (( SOAK_MAX_CONSECUTIVE_FAILURES > 0 )) && (( consecutive_failed_checks >= SOAK_MAX_CONSECUTIVE_FAILURES )); then
    reasons+=("consecutive_failed_checks=${consecutive_failed_checks} reached SOAK_MAX_CONSECUTIVE_FAILURES=${SOAK_MAX_CONSECUTIVE_FAILURES}")
  fi

  if (( ${#reasons[@]} > 0 )); then
    budget_exceeded=1
    if [[ "${abort_reason}" == "" ]]; then
      abort_reason="${reasons[*]}"
    fi
    if [[ "${budget_fail_fast}" == "true" ]]; then
      abort_requested=1
    fi
  fi
}

run_expected_check() {
  local name="$1"
  local method="$2"
  local path="$3"
  local expected_csv="$4"
  local body="${5:-}"
  local result status latency

  result="$(request_status_latency "${method}" "${path}" "${body}")"
  status="$(printf '%s\n' "${result}" | awk '{print $1}')"
  latency="$(printf '%s\n' "${result}" | awk '{print $2}')"

  status="${status:-000}"
  latency="${latency:-0}"

  if check_one_of "${status}" "${expected_csv}"; then
    record_check_success "${name}" "${latency}"
  else
    record_check_failure "${name}" "expected ${expected_csv}, got ${status} (latency=${latency}s)"
  fi

  evaluate_failure_budget
}

run_not_2xx_check() {
  local name="$1"
  local method="$2"
  local path="$3"
  local body="${4:-}"
  local result status latency

  result="$(request_status_latency "${method}" "${path}" "${body}")"
  status="$(printf '%s\n' "${result}" | awk '{print $1}')"
  latency="$(printf '%s\n' "${result}" | awk '{print $2}')"

  status="${status:-000}"
  latency="${latency:-0}"

  if [[ "${status}" =~ ^2 ]]; then
    record_check_failure "${name}" "expected non-2xx, got ${status} (latency=${latency}s)"
  else
    record_check_success "${name}" "${latency}"
  fi

  evaluate_failure_budget
}

run_smuggling_check() {
  local status
  status="$(
    curl -sS "${curl_tls_args[@]}" \
      -m "${REQUEST_TIMEOUT_SECONDS}" \
      -o /dev/null \
      -w '%{http_code}' \
      -X POST \
      -H 'Content-Type: application/json' \
      -H 'Content-Length: 16' \
      -H 'Transfer-Encoding: chunked' \
      -d '{"a":"b"}' \
      "${BASE_URL}/auth/login" || true
  )"
  status="${status:-000}"

  if [[ "${status}" =~ ^2 ]]; then
    record_check_failure "cl_te_smuggling" "expected non-2xx, got ${status}"
  else
    record_check_success "cl_te_smuggling" "0"
  fi

  evaluate_failure_budget
}

compare_container_snapshots() {
  local baseline_file="$1"
  local comparison_file="$2"
  local context_label="$3"
  local local_restarts=0
  local local_state_failures=0

  while IFS='|' read -r container_id container_name start_restart_count start_status; do
    [[ -z "${container_id}" ]] && continue

    local after_line
    after_line="$(grep "^${container_id}|" "${comparison_file}" || true)"
    if [[ -z "${after_line}" ]]; then
      local_state_failures=$((local_state_failures + 1))
      log_line "ERROR" "[FAIL] ${context_label}: container_missing ${container_name}"
      continue
    fi

    local end_restart_count end_status
    end_restart_count="$(printf '%s\n' "${after_line}" | cut -d'|' -f3)"
    end_status="$(printf '%s\n' "${after_line}" | cut -d'|' -f4)"

    if [[ "${end_restart_count}" =~ ^[0-9]+$ && "${start_restart_count}" =~ ^[0-9]+$ ]]; then
      if (( end_restart_count > start_restart_count )); then
        local_restarts=$((local_restarts + 1))
        log_line "ERROR" "[FAIL] ${context_label}: container_restarted ${container_name} (${start_restart_count} -> ${end_restart_count})"
      fi
    fi

    if [[ "${end_status}" != "running" ]]; then
      local_state_failures=$((local_state_failures + 1))
      log_line "ERROR" "[FAIL] ${context_label}: container_not_running ${container_name} (status=${end_status})"
    fi
  done < "${baseline_file}"

  printf '%s|%s\n' "${local_restarts}" "${local_state_failures}"
}

runtime_health_check() {
  if ! collect_container_snapshot "${current_snapshot}"; then
    record_check_failure "runtime_snapshot" "could not collect compose container snapshot during soak"
    periodic_runtime_issue_detected=1
    evaluate_failure_budget
    return 1
  fi

  local snapshot_result runtime_restarts runtime_state_failures
  snapshot_result="$(compare_container_snapshots "${start_snapshot}" "${current_snapshot}" "periodic_runtime_check")"
  runtime_restarts="$(printf '%s\n' "${snapshot_result}" | cut -d'|' -f1)"
  runtime_state_failures="$(printf '%s\n' "${snapshot_result}" | cut -d'|' -f2)"

  if (( runtime_restarts > 0 || runtime_state_failures > 0 )); then
    periodic_runtime_issue_detected=1
    if [[ "${budget_fail_fast}" == "true" ]]; then
      abort_requested=1
      abort_reason="runtime issue detected during periodic check"
    fi
    return 1
  fi
  return 0
}

percentile_from_file() {
  local input_file="$1"
  local percentile="$2"
  local count rank value

  count="$(wc -l < "${input_file}" | tr -d ' ')"
  if [[ -z "${count}" || "${count}" == "0" ]]; then
    printf '0'
    return
  fi

  rank="$(awk -v c="${count}" -v p="${percentile}" 'BEGIN { r=int((p*c + 99) / 100); if (r < 1) r = 1; if (r > c) r = c; print r }')"
  value="$(sort -n "${input_file}" | awk -v target="${rank}" 'NR==target {printf "%.6f", $1; exit}')"
  printf '%s' "${value:-0}"
}

print_progress() {
  local now_epoch="$1"
  local elapsed remaining
  elapsed=$((now_epoch - start_epoch))
  remaining=$((end_epoch - now_epoch))
  if (( remaining < 0 )); then
    remaining=0
  fi
  log_line "INFO" "progress elapsed=${elapsed}s remaining=${remaining}s iterations=${iteration} total_checks=${total_checks} failed_checks=${failed_checks} consecutive_failed_checks=${consecutive_failed_checks}"
}

start_timestamp_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
log_line "INFO" "Running compose soak test against ${BASE_URL}"
log_line "INFO" "duration=${SOAK_DURATION_SECONDS}s interval=${SOAK_INTERVAL_SECONDS}s timeout=${REQUEST_TIMEOUT_SECONDS}s fail_fast=${SOAK_FAIL_FAST} max_failures=${SOAK_MAX_FAILURES} max_consecutive=${SOAK_MAX_CONSECUTIVE_FAILURES}"
log_line "INFO" "report_file=${SOAK_REPORT_FILE} log_file=${SOAK_LOG_FILE}"

if ! wait_for_edge_health; then
  log_line "ERROR" "Edge is not healthy at ${BASE_URL}/healthz"
  capture_failure_context
  exit 1
fi

if ! collect_container_snapshot "${start_snapshot}"; then
  log_line "ERROR" "Could not collect initial compose container snapshot"
  capture_failure_context
  exit 1
fi

start_epoch="$(date +%s)"
end_epoch=$((start_epoch + SOAK_DURATION_SECONDS))
iteration=0

next_progress_epoch=0
if (( SOAK_PROGRESS_EVERY_SECONDS > 0 )); then
  next_progress_epoch=$((start_epoch + SOAK_PROGRESS_EVERY_SECONDS))
fi

next_runtime_check_epoch=0
if (( SOAK_RUNTIME_CHECK_EVERY_SECONDS > 0 )); then
  next_runtime_check_epoch=$((start_epoch + SOAK_RUNTIME_CHECK_EVERY_SECONDS))
fi

while true; do
  now_epoch="$(date +%s)"
  if (( now_epoch >= end_epoch )); then
    break
  fi

  if (( abort_requested == 1 )); then
    break
  fi

  iteration=$((iteration + 1))
  run_expected_check "healthz" GET /healthz "200"
  run_expected_check "protected_no_jwt" GET /v1/keys "401,403"
  run_expected_check "internal_control_plane_edge" POST /internal/block-ip "401,403" '{"ip":"203.0.113.77"}'
  run_not_2xx_check "trace_rejected" TRACE /auth/login

  if (( SOAK_SMUGGLING_EVERY_ITERATIONS > 0 )) && (( iteration % SOAK_SMUGGLING_EVERY_ITERATIONS == 0 )); then
    run_smuggling_check
  fi

  if (( abort_requested == 1 )); then
    break
  fi

  now_epoch="$(date +%s)"
  if (( SOAK_RUNTIME_CHECK_EVERY_SECONDS > 0 )) && (( now_epoch >= next_runtime_check_epoch )); then
    runtime_health_check || true
    next_runtime_check_epoch=$((now_epoch + SOAK_RUNTIME_CHECK_EVERY_SECONDS))
  fi

  if (( SOAK_PROGRESS_EVERY_SECONDS > 0 )) && (( now_epoch >= next_progress_epoch )); then
    print_progress "${now_epoch}"
    next_progress_epoch=$((now_epoch + SOAK_PROGRESS_EVERY_SECONDS))
  fi

  if (( abort_requested == 1 )); then
    break
  fi

  now_epoch="$(date +%s)"
  remaining_seconds=$((end_epoch - now_epoch))
  if (( remaining_seconds <= 0 )); then
    break
  fi

  sleep_for="${SOAK_INTERVAL_SECONDS}"
  if (( sleep_for > remaining_seconds )); then
    sleep_for="${remaining_seconds}"
  fi
  sleep "${sleep_for}"
done

if ! collect_container_snapshot "${end_snapshot}"; then
  log_line "ERROR" "Could not collect final compose container snapshot"
  capture_failure_context
  exit 1
fi

final_snapshot_result="$(compare_container_snapshots "${start_snapshot}" "${end_snapshot}" "final_runtime_check")"
restart_detections="$(printf '%s\n' "${final_snapshot_result}" | cut -d'|' -f1)"
container_state_failures="$(printf '%s\n' "${final_snapshot_result}" | cut -d'|' -f2)"

if (( failed_checks > SOAK_MAX_FAILURES )); then
  budget_exceeded=1
fi
if (( SOAK_MAX_CONSECUTIVE_FAILURES > 0 )) && (( max_observed_consecutive_failures >= SOAK_MAX_CONSECUTIVE_FAILURES )); then
  budget_exceeded=1
fi

elapsed_seconds=$(( $(date +%s) - start_epoch ))
finished_timestamp_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

health_samples="$(wc -l < "${health_latency_samples}" | tr -d ' ')"
health_min="0"
health_avg="0"
health_max="0"
health_p50="0"
health_p95="0"
health_p99="0"

if [[ -n "${health_samples}" && "${health_samples}" != "0" ]]; then
  health_min="$(awk 'NR==1 || $1 < min {min=$1} END {printf "%.6f", min}' "${health_latency_samples}")"
  health_max="$(awk 'NR==1 || $1 > max {max=$1} END {printf "%.6f", max}' "${health_latency_samples}")"
  health_avg="$(awk '{sum+=$1} END {if (NR > 0) printf "%.6f", sum/NR; else printf "0"}' "${health_latency_samples}")"
  health_p50="$(percentile_from_file "${health_latency_samples}" 50)"
  health_p95="$(percentile_from_file "${health_latency_samples}" 95)"
  health_p99="$(percentile_from_file "${health_latency_samples}" 99)"
fi

overall_failure=0
if (( budget_exceeded == 1 || restart_detections > 0 || container_state_failures > 0 || periodic_runtime_issue_detected > 0 )); then
  overall_failure=1
fi

if (( overall_failure == 1 )); then
  capture_failure_context
fi

overall_status="PASS"
if (( overall_failure == 1 )); then
  overall_status="FAIL"
fi

log_line "INFO" "Soak summary: elapsed=${elapsed_seconds}s iterations=${iteration} checks=${total_checks} passed=${passed_checks} failed=${failed_checks} restarts=${restart_detections} container_state_failures=${container_state_failures} budget_exceeded=${budget_exceeded} status=${overall_status}"

fail_fast_json="false"
if [[ "${budget_fail_fast}" == "true" ]]; then
  fail_fast_json="true"
fi

cat > "${SOAK_REPORT_FILE}" <<EOF
{
  "status": "${overall_status}",
  "startedAt": "${start_timestamp_utc}",
  "finishedAt": "${finished_timestamp_utc}",
  "baseUrl": "${BASE_URL}",
  "durationSeconds": ${SOAK_DURATION_SECONDS},
  "elapsedSeconds": ${elapsed_seconds},
  "iterationCount": ${iteration},
  "checks": {
    "total": ${total_checks},
    "passed": ${passed_checks},
    "failed": ${failed_checks},
    "maxObservedConsecutiveFailures": ${max_observed_consecutive_failures},
    "byName": {
      "healthz": { "passed": ${health_pass}, "failed": ${health_fail} },
      "protectedNoJwt": { "passed": ${protected_pass}, "failed": ${protected_fail} },
      "internalControlPlaneEdge": { "passed": ${internal_pass}, "failed": ${internal_fail} },
      "traceRejected": { "passed": ${trace_pass}, "failed": ${trace_fail} },
      "clTeSmuggling": { "passed": ${smuggling_pass}, "failed": ${smuggling_fail} }
    }
  },
  "failureBudget": {
    "maxFailures": ${SOAK_MAX_FAILURES},
    "maxConsecutiveFailures": ${SOAK_MAX_CONSECUTIVE_FAILURES},
    "failFast": ${fail_fast_json},
    "budgetExceeded": $(if (( budget_exceeded == 1 )); then echo true; else echo false; fi),
    "abortRequested": $(if (( abort_requested == 1 )); then echo true; else echo false; fi),
    "abortReason": "$(printf '%s' "${abort_reason}")"
  },
  "healthLatencySeconds": {
    "samples": ${health_samples:-0},
    "min": ${health_min},
    "avg": ${health_avg},
    "max": ${health_max},
    "p50": ${health_p50},
    "p95": ${health_p95},
    "p99": ${health_p99}
  },
  "containers": {
    "restartsDetected": ${restart_detections},
    "stateFailures": ${container_state_failures},
    "periodicRuntimeIssueDetected": $(if (( periodic_runtime_issue_detected == 1 )); then echo true; else echo false; fi)
  },
  "artifacts": {
    "logFile": "${SOAK_LOG_FILE}",
    "failureDetailsFile": "${failure_details_file}"
  }
}
EOF

echo
echo "Soak summary:"
echo "  Status: ${overall_status}"
echo "  Elapsed: ${elapsed_seconds}s"
echo "  Iterations: ${iteration}"
echo "  Checks: ${total_checks}"
echo "  Passed checks: ${passed_checks}"
echo "  Failed checks: ${failed_checks}"
echo "  Max consecutive failures observed: ${max_observed_consecutive_failures}"
echo "  Failure budget (max/consecutive): ${SOAK_MAX_FAILURES}/${SOAK_MAX_CONSECUTIVE_FAILURES}"
echo "  Health latency (s) min/avg/max/p95: ${health_min}/${health_avg}/${health_max}/${health_p95}"
echo "  Container restarts detected: ${restart_detections}"
echo "  Container state failures: ${container_state_failures}"
echo "  Report: ${SOAK_REPORT_FILE}"
echo "  Log: ${SOAK_LOG_FILE}"

if (( overall_failure == 1 )); then
  exit 1
fi

exit 0
