#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to run OPA policy tests" >&2
  exit 1
fi

echo "Running OPA policy tests..."
docker run --rm \
  -v "${ROOT_DIR}/deploy/docker/opa:/policies:ro" \
  openpolicyagent/opa@sha256:92044e8f8e2d1ca6a62d8f40007f4d2045893fc46b18f3a5392f196f0b37880b \
  test /policies -v
