#!/usr/bin/env bash
set -u
set -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

SKIP_DOCKER=0
PREPARE_DEV=0
KEEP_STACK=0
SOAK_SECONDS=0
ADVANCED_ATTACKS=0
COMPOSE_FILE="deploy/docker/docker-compose.yml"
COMPOSE_ENV="deploy/docker/.env"

passed_steps=()
failed_steps=()
skipped_steps=()
compose_started=0

usage() {
  cat <<'EOF'
Usage: bash scripts/release-gate.sh [--skip-docker] [--prepare-dev] [--keep-stack] [--soak-seconds N]

Options:
  --skip-docker  Run only local quality/security gates and skip Docker-based gates.
  --prepare-dev  Generate local certs and docker env before Docker-based gates.
  --keep-stack   Keep Docker stack running after completion (for debugging).
  --advanced-attacks  Run advanced attack simulation against compose edge.
  --soak-seconds N  Run compose soak test for N seconds after compose regression.
  -h, --help     Show this help.
EOF
}

is_positive_int() {
  [[ "${1:-}" =~ ^[1-9][0-9]*$ ]]
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --skip-docker)
      SKIP_DOCKER=1
      shift
      ;;
    --prepare-dev)
      PREPARE_DEV=1
      shift
      ;;
    --keep-stack)
      KEEP_STACK=1
      shift
      ;;
    --advanced-attacks)
      ADVANCED_ATTACKS=1
      shift
      ;;
    --soak-seconds)
      if [[ "$#" -lt 2 ]]; then
        echo "Missing value for --soak-seconds" >&2
        usage
        exit 1
      fi
      if ! is_positive_int "$2"; then
        echo "--soak-seconds expects a positive integer." >&2
        usage
        exit 1
      fi
      SOAK_SECONDS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

run_step() {
  local name="$1"
  shift

  echo
  echo "==> ${name}"
  "$@"
  local rc=$?
  if [[ "${rc}" -eq 0 ]]; then
    echo "[PASS] ${name}"
    passed_steps+=("${name}")
    return 0
  fi

  echo "[FAIL] ${name} (exit ${rc})" >&2
  failed_steps+=("${name}")
  return 1
}

skip_step() {
  local name="$1"
  local reason="$2"

  echo
  echo "==> ${name}"
  echo "[SKIP] ${name} (${reason})"
  skipped_steps+=("${name} (${reason})")
}

docker_daemon_ready() {
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

docker_compose_up_with_build() {
  docker compose --env-file "${COMPOSE_ENV}" -f "${COMPOSE_FILE}" up -d --build
}

wait_for_edge_health() {
  if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required for edge health checks" >&2
    return 1
  fi

  local attempts=120
  local sleep_seconds=2
  local url="https://localhost:8443/healthz"

  for ((i = 1; i <= attempts; i++)); do
    if curl -ksSf "${url}" >/dev/null; then
      return 0
    fi
    sleep "${sleep_seconds}"
  done

  echo "Edge did not become healthy in time (${url})" >&2
  docker compose --env-file "${COMPOSE_ENV}" -f "${COMPOSE_FILE}" ps || true
  docker compose --env-file "${COMPOSE_ENV}" -f "${COMPOSE_FILE}" logs --no-color --tail 200 || true
  return 1
}

teardown_stack() {
  if [[ "${compose_started}" -eq 1 && "${KEEP_STACK}" -eq 0 ]]; then
    echo
    echo "==> Docker Compose Down"
    if npm run docker:down; then
      echo "[PASS] Docker Compose Down"
    else
      echo "[WARN] Docker Compose Down failed" >&2
    fi
  fi
}

trap teardown_stack EXIT

echo "Running release gate from ${ROOT_DIR}"

run_step "Lint" npm run lint || true
run_step "Typecheck" npm run typecheck || true
run_step "Security + Integration Tests" npm test || true
run_step "Security Static Checks" npm run security:static || true
run_step "Dependency Audit" npm run security:audit || true

if [[ "${SKIP_DOCKER}" -eq 1 ]]; then
  skip_step "OPA Policy Tests" "--skip-docker"
  skip_step "Compose Security Regression" "--skip-docker"
  if [[ "${ADVANCED_ATTACKS}" -eq 1 ]]; then
    skip_step "Compose Advanced Attacks" "--skip-docker"
  fi
  if [[ "${SOAK_SECONDS}" -gt 0 ]]; then
    skip_step "Compose Soak (${SOAK_SECONDS}s)" "--skip-docker"
  fi
else
  if ! docker_daemon_ready; then
    echo
    echo "==> Docker Daemon"
    echo "[FAIL] Docker daemon is not available. Start Docker Desktop/daemon and rerun." >&2
    failed_steps+=("Docker Daemon")
    skip_step "OPA Policy Tests" "docker unavailable"
    skip_step "Compose Security Regression" "docker unavailable"
    if [[ "${ADVANCED_ATTACKS}" -eq 1 ]]; then
      skip_step "Compose Advanced Attacks" "docker unavailable"
    fi
    if [[ "${SOAK_SECONDS}" -gt 0 ]]; then
      skip_step "Compose Soak (${SOAK_SECONDS}s)" "docker unavailable"
    fi
  else
    if [[ "${PREPARE_DEV}" -eq 1 ]]; then
      run_step "Generate Dev Certs" npm run generate:certs || true
      run_step "Generate Dev Env" npm run generate:env || true
    fi

    run_step "OPA Policy Tests" npm run test:opa || true

    if [[ ! -f "${COMPOSE_ENV}" ]]; then
      echo
      echo "==> Compose Prerequisites"
      echo "[FAIL] Missing ${COMPOSE_ENV}. Run: npm run generate:env" >&2
      failed_steps+=("Compose Prerequisites")
      skip_step "Compose Security Regression" "missing ${COMPOSE_ENV}"
      if [[ "${ADVANCED_ATTACKS}" -eq 1 ]]; then
        skip_step "Compose Advanced Attacks" "missing ${COMPOSE_ENV}"
      fi
      if [[ "${SOAK_SECONDS}" -gt 0 ]]; then
        skip_step "Compose Soak (${SOAK_SECONDS}s)" "missing ${COMPOSE_ENV}"
      fi
    elif [[ ! -f "certs/ca.crt" || ! -f "certs/envoy.crt" ]]; then
      echo
      echo "==> Compose Prerequisites"
      echo "[FAIL] Missing local certs. Run: npm run generate:certs" >&2
      failed_steps+=("Compose Prerequisites")
      skip_step "Compose Security Regression" "missing local certs"
      if [[ "${ADVANCED_ATTACKS}" -eq 1 ]]; then
        skip_step "Compose Advanced Attacks" "missing local certs"
      fi
      if [[ "${SOAK_SECONDS}" -gt 0 ]]; then
        skip_step "Compose Soak (${SOAK_SECONDS}s)" "missing local certs"
      fi
    else
      if run_step "Docker Compose Up" docker_compose_up_with_build; then
        compose_started=1
        run_step "Wait For Edge Health" wait_for_edge_health || true
        run_step "Compose Security Regression" npm run test:e2e:compose || true
        if [[ "${ADVANCED_ATTACKS}" -eq 1 ]]; then
          run_step "Compose Advanced Attacks" npm run test:e2e:attacks:advanced || true
        fi
        if [[ "${SOAK_SECONDS}" -gt 0 ]]; then
          run_step "Compose Soak (${SOAK_SECONDS}s)" env SOAK_DURATION_SECONDS="${SOAK_SECONDS}" npm run test:e2e:soak:compose || true
        fi
      else
        skip_step "Wait For Edge Health" "compose failed to start"
        skip_step "Compose Security Regression" "compose failed to start"
        if [[ "${ADVANCED_ATTACKS}" -eq 1 ]]; then
          skip_step "Compose Advanced Attacks" "compose failed to start"
        fi
        if [[ "${SOAK_SECONDS}" -gt 0 ]]; then
          skip_step "Compose Soak (${SOAK_SECONDS}s)" "compose failed to start"
        fi
      fi
    fi
  fi
fi

echo
echo "Release gate summary:"
echo "  Passed: ${#passed_steps[@]}"
for step in "${passed_steps[@]}"; do
  echo "    - ${step}"
done

echo "  Failed: ${#failed_steps[@]}"
for step in "${failed_steps[@]}"; do
  echo "    - ${step}"
done

echo "  Skipped: ${#skipped_steps[@]}"
for step in "${skipped_steps[@]}"; do
  echo "    - ${step}"
done

if [[ "${#failed_steps[@]}" -gt 0 ]]; then
  exit 1
fi

exit 0
