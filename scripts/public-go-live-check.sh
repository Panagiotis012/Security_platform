#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-${BASE_URL:-}}"
CA_CERT_PATH="${CA_CERT_PATH:-}"

RUN_SMOKE="${RUN_SMOKE:-true}"
RUN_BASIC_REGRESSION="${RUN_BASIC_REGRESSION:-true}"
RUN_ADVANCED_ATTACKS="${RUN_ADVANCED_ATTACKS:-true}"
RUN_SOAK_SECONDS="${RUN_SOAK_SECONDS:-0}"

if [[ -z "${BASE_URL}" ]]; then
  echo "Usage: $0 https://api.example.com" >&2
  echo "Or set BASE_URL in the environment." >&2
  exit 2
fi
BASE_URL="${BASE_URL%/}"

is_enabled() {
  local raw="${1:-}"
  raw="$(printf '%s' "${raw}" | tr '[:upper:]' '[:lower:]')"
  [[ "${raw}" == "true" || "${raw}" == "1" || "${raw}" == "yes" ]]
}

if [[ ! "${RUN_SOAK_SECONDS}" =~ ^[0-9]+$ ]]; then
  echo "RUN_SOAK_SECONDS must be a non-negative integer." >&2
  exit 2
fi

echo "Go-live checks for: ${BASE_URL}"

if is_enabled "${RUN_SMOKE}"; then
  echo
  echo "==> Public Smoke"
  CA_CERT_PATH="${CA_CERT_PATH}" bash scripts/smoke-public.sh "${BASE_URL}"
fi

if is_enabled "${RUN_BASIC_REGRESSION}"; then
  echo
  echo "==> Basic Security Regression"
  BASE_URL="${BASE_URL}" CA_CERT_PATH="${CA_CERT_PATH}" bash tests/e2e/compose-security-regression.sh
fi

if is_enabled "${RUN_ADVANCED_ATTACKS}"; then
  echo
  echo "==> Advanced Attack Simulation"
  BASE_URL="${BASE_URL}" CA_CERT_PATH="${CA_CERT_PATH}" bash tests/e2e/compose-advanced-attacks.sh
fi

if (( RUN_SOAK_SECONDS > 0 )); then
  echo
  echo "==> Soak (${RUN_SOAK_SECONDS}s)"
  BASE_URL="${BASE_URL}" CA_CERT_PATH="${CA_CERT_PATH}" SOAK_DURATION_SECONDS="${RUN_SOAK_SECONDS}" npm run test:e2e:soak:compose
fi

echo
echo "Go-live checks completed successfully."
