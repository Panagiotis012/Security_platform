#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

failed=0

echo "==> Security static checks"

echo "-> Checking for private key material outside approved locations..."
if rg -n --hidden \
  --glob '!node_modules/**' \
  --glob '!.git/**' \
  --glob '!dist/**' \
  --glob '!certs/**' \
  --glob '!**/*.log' \
  -- '-----BEGIN (RSA |EC |OPENSSH |)?PRIVATE KEY-----' .; then
  echo "ERROR: Potential private key material found outside certs/." >&2
  failed=1
fi

echo "-> Checking for mutable container image tags in Docker Compose..."
if rg -n --multiline '^\s*image:\s*[^\s@]+:[^\s]+' deploy/docker/docker-compose*.yml; then
  echo "ERROR: Mutable image tags detected. Pin images by digest (@sha256:...)." >&2
  failed=1
fi

echo "-> Checking for insecure production defaults..."
if rg -n 'DEV_TOKEN_ISSUER_ENABLED:\s*"\$\{DEV_TOKEN_ISSUER_ENABLED:-true\}"|DEV_TOKEN_ISSUER_ENABLED=true' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: Dev token issuer must default to disabled." >&2
  failed=1
fi

if rg -n 'ALLOW_DEV_TOKEN_ISSUER_IN_PRODUCTION=true' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: Production override for dev token issuer must default to false." >&2
  failed=1
fi

if rg -n 'INTERNAL_AUTH_REQUIRE_NONCE:\s*"\$\{INTERNAL_AUTH_REQUIRE_NONCE:-false\}"|INTERNAL_AUTH_REQUIRE_NONCE=false' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: INTERNAL_AUTH_REQUIRE_NONCE must default to true." >&2
  failed=1
fi

if rg -n 'INTERNAL_AUTH_REQUIRE_CALLER:\s*"\$\{INTERNAL_AUTH_REQUIRE_CALLER:-false\}"|INTERNAL_AUTH_REQUIRE_CALLER=false' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: INTERNAL_AUTH_REQUIRE_CALLER must default to true." >&2
  failed=1
fi

if rg -n 'INTERNAL_AUTH_REQUIRE_KEY_ID:\s*"\$\{INTERNAL_AUTH_REQUIRE_KEY_ID:-false\}"|INTERNAL_AUTH_REQUIRE_KEY_ID=false' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: INTERNAL_AUTH_REQUIRE_KEY_ID must default to true." >&2
  failed=1
fi

if rg -n 'INTERNAL_AUTH_REPLAY_PROTECTION_ENABLED:\s*"\$\{INTERNAL_AUTH_REPLAY_PROTECTION_ENABLED:-false\}"|INTERNAL_AUTH_REPLAY_PROTECTION_ENABLED=false' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: INTERNAL_AUTH_REPLAY_PROTECTION_ENABLED must default to true." >&2
  failed=1
fi

if rg -n 'INTERNAL_AUTH_REPLAY_STORE:\s*"\$\{INTERNAL_AUTH_REPLAY_STORE:-memory\}"|INTERNAL_AUTH_REPLAY_STORE=memory' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: INTERNAL_AUTH_REPLAY_STORE must default to redis for distributed replay protection." >&2
  failed=1
fi

if rg -n 'INTERNAL_AUTH_REPLAY_REDIS_REQUIRED:\s*"\$\{INTERNAL_AUTH_REPLAY_REDIS_REQUIRED:-false\}"|INTERNAL_AUTH_REPLAY_REDIS_REQUIRED=false' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: INTERNAL_AUTH_REPLAY_REDIS_REQUIRED must default to true in hardened presets." >&2
  failed=1
fi

if rg -n 'EDGE_CACHE_ENABLED:\s*"\$\{EDGE_CACHE_ENABLED:-false\}"|EDGE_CACHE_ENABLED=false' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: EDGE_CACHE_ENABLED must default to true." >&2
  failed=1
fi

if rg -n 'EDGE_CACHE_STORE:\s*"\$\{EDGE_CACHE_STORE:-memory\}"|EDGE_CACHE_STORE=memory' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: EDGE_CACHE_STORE must default to redis for distributed cache consistency." >&2
  failed=1
fi

if rg -n 'EDGE_CACHE_REDIS_REQUIRED:\s*"\$\{EDGE_CACHE_REDIS_REQUIRED:-false\}"|EDGE_CACHE_REDIS_REQUIRED=false' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: EDGE_CACHE_REDIS_REQUIRED must default to true in hardened presets." >&2
  failed=1
fi

if rg -n 'EDGE_CACHE_CACHE_AUTHENTICATED:\s*"\$\{EDGE_CACHE_CACHE_AUTHENTICATED:-true\}"|EDGE_CACHE_CACHE_AUTHENTICATED=true' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: EDGE_CACHE_CACHE_AUTHENTICATED must default to false." >&2
  failed=1
fi

if rg -n 'WAF_ENABLED:\s*"\$\{WAF_ENABLED:-false\}"|WAF_ENABLED=false' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: WAF_ENABLED must default to true." >&2
  failed=1
fi

if rg -n 'ADAPTIVE_DEFENSE_ENABLED:\s*"\$\{ADAPTIVE_DEFENSE_ENABLED:-false\}"|ADAPTIVE_DEFENSE_ENABLED=false' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: ADAPTIVE_DEFENSE_ENABLED must default to true." >&2
  failed=1
fi

if rg -n 'ADAPTIVE_DEFENSE_STORE:\s*"\$\{ADAPTIVE_DEFENSE_STORE:-memory\}"|ADAPTIVE_DEFENSE_STORE=memory' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: ADAPTIVE_DEFENSE_STORE must default to redis for distributed edge scoring." >&2
  failed=1
fi

if rg -n 'ADAPTIVE_DEFENSE_REDIS_REQUIRED:\s*"\$\{ADAPTIVE_DEFENSE_REDIS_REQUIRED:-false\}"|ADAPTIVE_DEFENSE_REDIS_REQUIRED=false' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: ADAPTIVE_DEFENSE_REDIS_REQUIRED must default to true in hardened presets." >&2
  failed=1
fi

if rg -n 'ADAPTIVE_DEFENSE_CHALLENGE_ENABLED:\s*"\$\{ADAPTIVE_DEFENSE_CHALLENGE_ENABLED:-false\}"|ADAPTIVE_DEFENSE_CHALLENGE_ENABLED=false' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: ADAPTIVE_DEFENSE_CHALLENGE_ENABLED must default to true." >&2
  failed=1
fi

if rg -n 'ADAPTIVE_DEFENSE_CHALLENGE_STORE:\s*"\$\{ADAPTIVE_DEFENSE_CHALLENGE_STORE:-memory\}"|ADAPTIVE_DEFENSE_CHALLENGE_STORE=memory' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: ADAPTIVE_DEFENSE_CHALLENGE_STORE must default to redis." >&2
  failed=1
fi

if rg -n 'ADAPTIVE_DEFENSE_CHALLENGE_REDIS_REQUIRED:\s*"\$\{ADAPTIVE_DEFENSE_CHALLENGE_REDIS_REQUIRED:-false\}"|ADAPTIVE_DEFENSE_CHALLENGE_REDIS_REQUIRED=false' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: ADAPTIVE_DEFENSE_CHALLENGE_REDIS_REQUIRED must default to true in hardened presets." >&2
  failed=1
fi

if rg -n 'ADAPTIVE_DEFENSE_ABUSE_INTEL_ENABLED:\s*"\$\{ADAPTIVE_DEFENSE_ABUSE_INTEL_ENABLED:-false\}"|ADAPTIVE_DEFENSE_ABUSE_INTEL_ENABLED=false' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: ADAPTIVE_DEFENSE_ABUSE_INTEL_ENABLED must default to true." >&2
  failed=1
fi

if rg -n 'ADAPTIVE_DEFENSE_ABUSE_INTEL_SIGN_EXPORTS:\s*"\$\{ADAPTIVE_DEFENSE_ABUSE_INTEL_SIGN_EXPORTS:-false\}"|ADAPTIVE_DEFENSE_ABUSE_INTEL_SIGN_EXPORTS=false' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: ADAPTIVE_DEFENSE_ABUSE_INTEL_SIGN_EXPORTS must default to true." >&2
  failed=1
fi

if rg -n 'ADAPTIVE_DEFENSE_ABUSE_INTEL_REQUIRE_SIGNED_IMPORTS:\s*"\$\{ADAPTIVE_DEFENSE_ABUSE_INTEL_REQUIRE_SIGNED_IMPORTS:-false\}"|ADAPTIVE_DEFENSE_ABUSE_INTEL_REQUIRE_SIGNED_IMPORTS=false' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: ADAPTIVE_DEFENSE_ABUSE_INTEL_REQUIRE_SIGNED_IMPORTS must default to true." >&2
  failed=1
fi

if rg -n 'ADAPTIVE_DEFENSE_ABUSE_INTEL_REPLAY_PROTECTION_ENABLED:\s*"\$\{ADAPTIVE_DEFENSE_ABUSE_INTEL_REPLAY_PROTECTION_ENABLED:-false\}"|ADAPTIVE_DEFENSE_ABUSE_INTEL_REPLAY_PROTECTION_ENABLED=false' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: ADAPTIVE_DEFENSE_ABUSE_INTEL_REPLAY_PROTECTION_ENABLED must default to true." >&2
  failed=1
fi

if rg -n 'ADAPTIVE_DEFENSE_ABUSE_INTEL_REPLAY_STORE:\s*"\$\{ADAPTIVE_DEFENSE_ABUSE_INTEL_REPLAY_STORE:-memory\}"|ADAPTIVE_DEFENSE_ABUSE_INTEL_REPLAY_STORE=memory' \
  deploy/docker/.env.example \
  deploy/docker/docker-compose*.yml \
  .github/workflows/*.yml; then
  echo "ERROR: ADAPTIVE_DEFENSE_ABUSE_INTEL_REPLAY_STORE must default to redis for distributed replay protection." >&2
  failed=1
fi

if [[ "${failed}" -ne 0 ]]; then
  echo "Security static checks failed." >&2
  exit 1
fi

echo "Security static checks passed."
