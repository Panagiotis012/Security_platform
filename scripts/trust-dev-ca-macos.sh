#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA_CERT="${ROOT_DIR}/certs/ca.crt"

SYSTEM_KEYCHAIN="/Library/Keychains/System.keychain"
LOGIN_KEYCHAIN="${HOME}/Library/Keychains/login.keychain-db"

usage() {
  cat <<EOF
Usage: $(basename "$0") [--system] [--remove]

Trusts the local development CA used by the Security Platform so browsers stop
showing "Not secure" for https://localhost:8443.

Defaults to adding the CA to your login keychain. Use --system to add it to the
system keychain (may require admin rights).

Options:
  --system   Install into the system keychain (more global)
  --remove   Remove the CA from the selected keychain
EOF
}

SYSTEM=0
REMOVE=0

for arg in "$@"; do
  case "$arg" in
    --system) SYSTEM=1 ;;
    --remove) REMOVE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: ${arg}" >&2; usage; exit 1 ;;
  esac
done

if [[ ! -f "${CA_CERT}" ]]; then
  echo "Missing ${CA_CERT}" >&2
  echo "Run: npm run generate:certs" >&2
  exit 1
fi

KEYCHAIN="${LOGIN_KEYCHAIN}"
if [[ "${SYSTEM}" == "1" ]]; then
  KEYCHAIN="${SYSTEM_KEYCHAIN}"
fi

# Extract CN for remove/find operations (best-effort).
CA_CN="$(
  openssl x509 -in "${CA_CERT}" -noout -subject 2>/dev/null \
    | sed -nE 's/.*CN[[:space:]]*=[[:space:]]*([^,]+).*/\1/p' \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
    | head -n 1 \
    || true
)"
if [[ -z "${CA_CN}" ]]; then
  CA_CN="SecurityPlatform Dev CA"
fi

if [[ "${REMOVE}" == "1" ]]; then
  echo "Removing '${CA_CN}' from ${KEYCHAIN} (if present)..."
  security delete-certificate -c "${CA_CN}" "${KEYCHAIN}" >/dev/null 2>&1 || true
  echo "Done."
  exit 0
fi

echo "Adding '${CA_CN}' as a trusted root in ${KEYCHAIN}..."
echo "If prompted, allow access and restart Chrome afterwards."

# Replace any existing entry so trust settings are applied deterministically.
security delete-certificate -c "${CA_CN}" "${KEYCHAIN}" >/dev/null 2>&1 || true
security add-trusted-cert -d -r trustRoot -k "${KEYCHAIN}" "${CA_CERT}"

echo "Done. Chrome/Safari should now show a lock icon for https://localhost:8443."
