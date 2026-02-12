#!/usr/bin/env bash
set -euo pipefail

# Generates/updates the root lockfile for npm workspaces.
# Commit `package-lock.json` for reproducible builds (`npm ci`, deterministic Docker builds).
#
# Note: This requires network access to resolve and download dependencies.

cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "==> Generating root package-lock.json for workspaces..."
npm install --package-lock-only

echo "==> Done. You should commit package-lock.json."

