#!/usr/bin/env bash
set -euo pipefail

# Install/upgrade Docker CLI plugins (docker compose + docker buildx) on Linux.
#
# Why: Some VMs have Docker Engine but are missing the Compose/buildx plugins.
# This script installs the latest stable releases from GitHub into:
#   /usr/local/lib/docker/cli-plugins/
#
# Usage (on the VM):
#   sudo bash scripts/update-docker-cli-plugins.sh
#
# Optional:
#   PLUGIN_DIR=/custom/path sudo bash scripts/update-docker-cli-plugins.sh

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ERROR: This script is for Linux hosts only." >&2
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: Run as root (use sudo)." >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "ERROR: curl is required." >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required." >&2
  exit 1
fi

arch="$(uname -m)"
compose_arch=""
buildx_arch=""
case "$arch" in
  x86_64|amd64)
    compose_arch="x86_64"
    buildx_arch="amd64"
    ;;
  aarch64|arm64)
    compose_arch="aarch64"
    buildx_arch="arm64"
    ;;
  *)
    echo "ERROR: Unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

PLUGIN_DIR="${PLUGIN_DIR:-/usr/local/lib/docker/cli-plugins}"
mkdir -p "$PLUGIN_DIR"

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

fetch_latest_release_json() {
  local repo="$1"
  local url="https://api.github.com/repos/${repo}/releases/latest"
  local auth_args=()
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    auth_args+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  fi
  # GitHub API can rate limit anonymous requests. We keep this script dependency-light
  # (no jq) and fail with a helpful message if the response isn't valid JSON.
  curl -fsSL --retry 5 --retry-delay 1 \
    -H "Accept: application/vnd.github+json" \
    -H "User-Agent: security-platform" \
    "${auth_args[@]}" \
    "$url"
}

resolve_latest_tag_via_redirect() {
  local repo="$1"
  local effective_url=""
  # Avoid GitHub API rate limits by following the /releases/latest redirect.
  # Example:
  #   https://github.com/docker/compose/releases/latest
  # -> https://github.com/docker/compose/releases/tag/v2.27.0
  effective_url="$(
    curl -fsSLI -o /dev/null -w '%{url_effective}' -L "https://github.com/${repo}/releases/latest" || true
  )"
  if [[ -z "${effective_url//[[:space:]]/}" ]]; then
    return 1
  fi
  local tag="${effective_url##*/}"
  tag="${tag%%\?*}"
  if [[ -z "${tag//[[:space:]]/}" || "$tag" == "latest" ]]; then
    return 1
  fi
  printf '%s\n' "$tag"
}

asset_url_by_name() {
  local want_name="$1"
  python3 -c 'import json,sys
want = sys.argv[1]
raw = sys.stdin.read()
if not raw.strip():
  sys.stderr.write("ERROR: GitHub API response was empty (network issue or blocked access).\n")
  raise SystemExit(3)
try:
  data = json.loads(raw)
except json.JSONDecodeError:
  sys.stderr.write("ERROR: GitHub API response was not valid JSON. First bytes:\n")
  sys.stderr.write(raw[:200] + "\n")
  raise SystemExit(3)
for a in data.get("assets", []):
  if a.get("name") == want:
    print(a.get("browser_download_url", ""))
    raise SystemExit(0)
raise SystemExit(2)
' "$want_name"
}

tag_name() {
  python3 -c 'import json,sys
raw = sys.stdin.read()
if not raw.strip():
  sys.stderr.write("ERROR: GitHub API response was empty (network issue or blocked access).\n")
  raise SystemExit(3)
try:
  data = json.loads(raw)
except json.JSONDecodeError:
  sys.stderr.write("ERROR: GitHub API response was not valid JSON. First bytes:\n")
  sys.stderr.write(raw[:200] + "\n")
  raise SystemExit(3)
print(data.get("tag_name",""))
'
}

echo "==> Installing to: $PLUGIN_DIR"

# ---------------------------------------------------------------------------
# docker compose (v2 plugin)
# ---------------------------------------------------------------------------

echo "==> Resolving docker compose release..."
compose_asset="docker-compose-linux-${compose_arch}"
compose_url=""
compose_tag=""
if compose_json="$(fetch_latest_release_json docker/compose 2>/dev/null)"; then
  compose_url="$(asset_url_by_name "$compose_asset" <<<"$compose_json" 2>/dev/null || true)"
  compose_tag="$(tag_name <<<"$compose_json" 2>/dev/null || true)"
fi

if [[ -z "${compose_url//[[:space:]]/}" ]]; then
  compose_tag="$(resolve_latest_tag_via_redirect docker/compose || true)"
  if [[ -z "${compose_tag//[[:space:]]/}" ]]; then
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
      echo "NOTE: GITHUB_TOKEN is set, but the GitHub API response was not usable and the redirect fallback failed." >&2
    else
      echo "NOTE: If this fails due to GitHub API rate limits, set GITHUB_TOKEN (a GitHub PAT) and retry:" >&2
      echo "      GITHUB_TOKEN=... sudo bash scripts/update-docker-cli-plugins.sh" >&2
    fi
    echo "ERROR: Could not resolve latest docker/compose tag (API and redirect fallback failed)." >&2
    exit 1
  fi
  compose_url="https://github.com/docker/compose/releases/download/${compose_tag}/${compose_asset}"
fi

echo "==> Downloading docker compose ($compose_asset)"
curl -fsSL --retry 5 --retry-delay 1 -o "${tmpdir}/docker-compose" "$compose_url"
chmod 0755 "${tmpdir}/docker-compose"
install -m 0755 "${tmpdir}/docker-compose" "${PLUGIN_DIR}/docker-compose"

# ---------------------------------------------------------------------------
# docker buildx (plugin)
# ---------------------------------------------------------------------------

echo "==> Resolving docker buildx release..."
buildx_tag=""
buildx_url=""
buildx_asset=""
if buildx_json="$(fetch_latest_release_json docker/buildx 2>/dev/null)"; then
  buildx_tag="$(tag_name <<<"$buildx_json" 2>/dev/null || true)"
  if [[ -n "${buildx_tag//[[:space:]]/}" ]]; then
    buildx_asset="buildx-${buildx_tag}.linux-${buildx_arch}"
    buildx_url="$(asset_url_by_name "$buildx_asset" <<<"$buildx_json" 2>/dev/null || true)"
  fi
fi

if [[ -z "${buildx_url//[[:space:]]/}" ]]; then
  buildx_tag="$(resolve_latest_tag_via_redirect docker/buildx || true)"
  if [[ -z "${buildx_tag//[[:space:]]/}" ]]; then
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
      echo "NOTE: GITHUB_TOKEN is set, but the GitHub API response was not usable and the redirect fallback failed." >&2
    else
      echo "NOTE: If this fails due to GitHub API rate limits, set GITHUB_TOKEN (a GitHub PAT) and retry:" >&2
      echo "      GITHUB_TOKEN=... sudo bash scripts/update-docker-cli-plugins.sh" >&2
    fi
    echo "ERROR: Could not resolve latest docker/buildx tag (API and redirect fallback failed)." >&2
    exit 1
  fi
  buildx_asset="buildx-${buildx_tag}.linux-${buildx_arch}"
  buildx_url="https://github.com/docker/buildx/releases/download/${buildx_tag}/${buildx_asset}"
fi

echo "==> Downloading docker buildx ($buildx_asset)"
curl -fsSL --retry 5 --retry-delay 1 -o "${tmpdir}/docker-buildx" "$buildx_url"
chmod 0755 "${tmpdir}/docker-buildx"
install -m 0755 "${tmpdir}/docker-buildx" "${PLUGIN_DIR}/docker-buildx"

echo ""
echo "==> Installed plugins:"
docker compose version || true
docker buildx version || true
