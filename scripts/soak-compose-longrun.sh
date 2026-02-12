#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${BASE_URL:-https://localhost:8443}"
CA_CERT_PATH="${CA_CERT_PATH:-}"

LONGRUN_HOURS="${LONGRUN_HOURS:-8}"
LONGRUN_TOTAL_SECONDS="${LONGRUN_TOTAL_SECONDS:-}"
SOAK_CHUNK_SECONDS="${SOAK_CHUNK_SECONDS:-900}"
SOAK_PAUSE_BETWEEN_CHUNKS_SECONDS="${SOAK_PAUSE_BETWEEN_CHUNKS_SECONDS:-5}"
LONGRUN_RUN_COMPOSE_REGRESSION="${LONGRUN_RUN_COMPOSE_REGRESSION:-true}"
LONGRUN_KEEP_GOING_ON_FAILURE="${LONGRUN_KEEP_GOING_ON_FAILURE:-false}"

SOAK_INTERVAL_SECONDS="${SOAK_INTERVAL_SECONDS:-1}"
REQUEST_TIMEOUT_SECONDS="${REQUEST_TIMEOUT_SECONDS:-5}"
SOAK_PROGRESS_EVERY_SECONDS="${SOAK_PROGRESS_EVERY_SECONDS:-60}"
SOAK_RUNTIME_CHECK_EVERY_SECONDS="${SOAK_RUNTIME_CHECK_EVERY_SECONDS:-60}"
SOAK_SMUGGLING_EVERY_ITERATIONS="${SOAK_SMUGGLING_EVERY_ITERATIONS:-10}"
SOAK_MAX_FAILURES="${SOAK_MAX_FAILURES:-5}"
SOAK_MAX_CONSECUTIVE_FAILURES="${SOAK_MAX_CONSECUTIVE_FAILURES:-3}"
SOAK_FAIL_FAST="${SOAK_FAIL_FAST:-true}"
SOAK_CAPTURE_FAILURE_CONTEXT="${SOAK_CAPTURE_FAILURE_CONTEXT:-true}"

LONGRUN_REPORT_DIR="${LONGRUN_REPORT_DIR:-${ROOT_DIR}/artifacts/soak}"
RUN_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_ID="${RUN_ID:-longrun-${RUN_STAMP}}"

MASTER_LOG_FILE="${LONGRUN_REPORT_DIR}/${RUN_ID}.log"
MASTER_CSV_FILE="${LONGRUN_REPORT_DIR}/${RUN_ID}.chunks.csv"
MASTER_REPORT_FILE="${LONGRUN_REPORT_DIR}/${RUN_ID}.summary.json"

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

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if ! is_positive_int "${LONGRUN_HOURS}"; then
  echo "LONGRUN_HOURS must be a positive integer." >&2
  exit 1
fi

if [[ -n "${LONGRUN_TOTAL_SECONDS}" ]] && ! is_positive_int "${LONGRUN_TOTAL_SECONDS}"; then
  echo "LONGRUN_TOTAL_SECONDS must be a positive integer when provided." >&2
  exit 1
fi

if ! is_positive_int "${SOAK_CHUNK_SECONDS}"; then
  echo "SOAK_CHUNK_SECONDS must be a positive integer." >&2
  exit 1
fi

if ! is_non_negative_int "${SOAK_PAUSE_BETWEEN_CHUNKS_SECONDS}"; then
  echo "SOAK_PAUSE_BETWEEN_CHUNKS_SECONDS must be a non-negative integer." >&2
  exit 1
fi

if [[ -z "${LONGRUN_TOTAL_SECONDS}" ]]; then
  LONGRUN_TOTAL_SECONDS=$((LONGRUN_HOURS * 3600))
fi

mkdir -p "${LONGRUN_REPORT_DIR}"
: > "${MASTER_LOG_FILE}"

log_line() {
  local level="$1"
  shift
  local message="$*"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  printf '%s [%s] %s\n' "${ts}" "${level}" "${message}" | tee -a "${MASTER_LOG_FILE}"
}

wait_for_edge_health() {
  local attempts=120
  local i=0
  while (( i < attempts )); do
    local code
    if [[ -n "${CA_CERT_PATH}" ]]; then
      code="$(curl --silent --show-error --cacert "${CA_CERT_PATH}" -o /dev/null -w '%{http_code}' "${BASE_URL}/healthz" || true)"
    else
      code="$(curl --silent --show-error -k -o /dev/null -w '%{http_code}' "${BASE_URL}/healthz" || true)"
    fi
    if [[ "${code}" == "200" ]]; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  return 1
}

run_started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
log_line "INFO" "Starting long-run compose soak (run_id=${RUN_ID})"
log_line "INFO" "base_url=${BASE_URL} total_seconds=${LONGRUN_TOTAL_SECONDS} chunk_seconds=${SOAK_CHUNK_SECONDS} run_regression=${LONGRUN_RUN_COMPOSE_REGRESSION} keep_going_on_failure=${LONGRUN_KEEP_GOING_ON_FAILURE}"
log_line "INFO" "master_report=${MASTER_REPORT_FILE} master_csv=${MASTER_CSV_FILE}"

if ! wait_for_edge_health; then
  log_line "ERROR" "Edge is not healthy at ${BASE_URL}/healthz"
  exit 1
fi

printf 'chunk_index,chunk_seconds,soak_status,regression_status,chunk_report,chunk_log\n' > "${MASTER_CSV_FILE}"

remaining_seconds="${LONGRUN_TOTAL_SECONDS}"
chunk_index=0
completed_seconds=0
passed_chunks=0
failed_chunks=0
aborted_early=0

while (( remaining_seconds > 0 )); do
  chunk_index=$((chunk_index + 1))
  chunk_seconds="${SOAK_CHUNK_SECONDS}"
  if (( chunk_seconds > remaining_seconds )); then
    chunk_seconds="${remaining_seconds}"
  fi

  chunk_base="${RUN_ID}-chunk-${chunk_index}"
  chunk_report="${LONGRUN_REPORT_DIR}/${chunk_base}.json"
  chunk_log="${LONGRUN_REPORT_DIR}/${chunk_base}.log"
  chunk_failed=0
  soak_status="PASS"
  regression_status="SKIP"

  log_line "INFO" "Chunk ${chunk_index} starting (duration=${chunk_seconds}s)"

  set +e
  BASE_URL="${BASE_URL}" \
  CA_CERT_PATH="${CA_CERT_PATH}" \
  SOAK_DURATION_SECONDS="${chunk_seconds}" \
  SOAK_INTERVAL_SECONDS="${SOAK_INTERVAL_SECONDS}" \
  REQUEST_TIMEOUT_SECONDS="${REQUEST_TIMEOUT_SECONDS}" \
  SOAK_PROGRESS_EVERY_SECONDS="${SOAK_PROGRESS_EVERY_SECONDS}" \
  SOAK_RUNTIME_CHECK_EVERY_SECONDS="${SOAK_RUNTIME_CHECK_EVERY_SECONDS}" \
  SOAK_SMUGGLING_EVERY_ITERATIONS="${SOAK_SMUGGLING_EVERY_ITERATIONS}" \
  SOAK_MAX_FAILURES="${SOAK_MAX_FAILURES}" \
  SOAK_MAX_CONSECUTIVE_FAILURES="${SOAK_MAX_CONSECUTIVE_FAILURES}" \
  SOAK_FAIL_FAST="${SOAK_FAIL_FAST}" \
  SOAK_CAPTURE_FAILURE_CONTEXT="${SOAK_CAPTURE_FAILURE_CONTEXT}" \
  SOAK_REPORT_FILE="${chunk_report}" \
  SOAK_LOG_FILE="${chunk_log}" \
  bash "${ROOT_DIR}/tests/e2e/compose-soak.sh"
  soak_rc=$?
  set -e

  if (( soak_rc != 0 )); then
    soak_status="FAIL"
    chunk_failed=1
    log_line "ERROR" "Chunk ${chunk_index} soak failed (rc=${soak_rc})"
  else
    log_line "INFO" "Chunk ${chunk_index} soak passed"
  fi

  if is_enabled "${LONGRUN_RUN_COMPOSE_REGRESSION}"; then
    set +e
    BASE_URL="${BASE_URL}" CA_CERT_PATH="${CA_CERT_PATH}" npm run test:e2e:compose
    regression_rc=$?
    set -e

    if (( regression_rc != 0 )); then
      regression_status="FAIL"
      chunk_failed=1
      log_line "ERROR" "Chunk ${chunk_index} compose regression failed (rc=${regression_rc})"
    else
      regression_status="PASS"
      log_line "INFO" "Chunk ${chunk_index} compose regression passed"
    fi
  fi

  printf '%s,%s,%s,%s,%s,%s\n' \
    "${chunk_index}" \
    "${chunk_seconds}" \
    "${soak_status}" \
    "${regression_status}" \
    "${chunk_report}" \
    "${chunk_log}" >> "${MASTER_CSV_FILE}"

  if (( chunk_failed == 1 )); then
    failed_chunks=$((failed_chunks + 1))
    if ! is_enabled "${LONGRUN_KEEP_GOING_ON_FAILURE}"; then
      aborted_early=1
      break
    fi
  else
    passed_chunks=$((passed_chunks + 1))
  fi

  remaining_seconds=$((remaining_seconds - chunk_seconds))
  completed_seconds=$((completed_seconds + chunk_seconds))

  if (( remaining_seconds > 0 )) && (( SOAK_PAUSE_BETWEEN_CHUNKS_SECONDS > 0 )); then
    log_line "INFO" "Sleeping ${SOAK_PAUSE_BETWEEN_CHUNKS_SECONDS}s before next chunk"
    sleep "${SOAK_PAUSE_BETWEEN_CHUNKS_SECONDS}"
  fi
done

if (( remaining_seconds < 0 )); then
  remaining_seconds=0
fi

if (( aborted_early == 1 )); then
  completed_seconds=$((completed_seconds + chunk_seconds))
fi

run_finished_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
overall_status="PASS"
if (( failed_chunks > 0 )); then
  overall_status="FAIL"
fi

cat > "${MASTER_REPORT_FILE}" <<EOF
{
  "runId": "${RUN_ID}",
  "status": "${overall_status}",
  "startedAt": "${run_started_at}",
  "finishedAt": "${run_finished_at}",
  "baseUrl": "${BASE_URL}",
  "requestedTotalSeconds": ${LONGRUN_TOTAL_SECONDS},
  "completedSeconds": ${completed_seconds},
  "remainingSeconds": ${remaining_seconds},
  "chunkSeconds": ${SOAK_CHUNK_SECONDS},
  "chunkCount": ${chunk_index},
  "passedChunks": ${passed_chunks},
  "failedChunks": ${failed_chunks},
  "abortedEarly": $(if (( aborted_early == 1 )); then echo true; else echo false; fi),
  "runComposeRegressionEachChunk": $(if is_enabled "${LONGRUN_RUN_COMPOSE_REGRESSION}"; then echo true; else echo false; fi),
  "keepGoingOnFailure": $(if is_enabled "${LONGRUN_KEEP_GOING_ON_FAILURE}"; then echo true; else echo false; fi),
  "artifacts": {
    "masterLogFile": "${MASTER_LOG_FILE}",
    "masterCsvFile": "${MASTER_CSV_FILE}"
  }
}
EOF

log_line "INFO" "Long-run summary: status=${overall_status} chunks=${chunk_index} passed_chunks=${passed_chunks} failed_chunks=${failed_chunks} completed_seconds=${completed_seconds} remaining_seconds=${remaining_seconds}"
log_line "INFO" "Summary report: ${MASTER_REPORT_FILE}"

echo
echo "Long-run soak summary:"
echo "  Status: ${overall_status}"
echo "  Run ID: ${RUN_ID}"
echo "  Chunk count: ${chunk_index}"
echo "  Passed chunks: ${passed_chunks}"
echo "  Failed chunks: ${failed_chunks}"
echo "  Completed seconds: ${completed_seconds}"
echo "  Remaining seconds: ${remaining_seconds}"
echo "  Summary report: ${MASTER_REPORT_FILE}"
echo "  Chunk table: ${MASTER_CSV_FILE}"
echo "  Master log: ${MASTER_LOG_FILE}"

if (( failed_chunks > 0 )); then
  exit 1
fi

exit 0
