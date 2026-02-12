#!/usr/bin/env bash
# ============================================================================
# Generate self-signed TLS certificates for local development
# NEVER use these in production — use proper CA-signed certificates
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="${PROJECT_ROOT}/certs"
KEYS_DIR="${CERTS_DIR}/keys"

FORCE_CA=0
FORCE_LEAF=0
for arg in "$@"; do
  case "$arg" in
    --force)
      FORCE_CA=1
      FORCE_LEAF=1
      ;;
    --rotate-leaf)
      FORCE_LEAF=1
      ;;
    -h|--help)
      cat <<EOF
Usage: $(basename "$0") [--force] [--rotate-leaf]

Generates a local development CA + TLS/mTLS certs used by the Docker Compose preset.

By default this script is idempotent and will NOT regenerate existing certs/keys.
Use --force to rotate EVERYTHING (CA + all leaf certs/keys) (you will need to re-trust the CA).
Use --rotate-leaf to rotate only leaf certs/keys while keeping the existing CA (no re-trust needed).
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: ${arg}" >&2
      exit 1
      ;;
  esac
done

echo "==> Generating development certificates in ${CERTS_DIR}"

mkdir -p "${CERTS_DIR}" "${KEYS_DIR}"

cert_has_dns_san() {
  local cert_path="$1"
  local expected_dns="$2"
  openssl x509 -in "${cert_path}" -noout -ext subjectAltName 2>/dev/null | grep -q "DNS:${expected_dns}"
}

# --- Root CA ---
if [[ "${FORCE_CA}" == "1" || ! -f "${CERTS_DIR}/ca.key" || ! -f "${CERTS_DIR}/ca.crt" ]]; then
  echo "==> Creating Root CA..."
  openssl genrsa -out "${CERTS_DIR}/ca.key" 4096
  openssl req -new -x509 -days 365 -key "${CERTS_DIR}/ca.key" \
    -out "${CERTS_DIR}/ca.crt" \
    -subj "/C=US/ST=Security/L=Platform/O=SecurityPlatform/OU=DevCA/CN=SecurityPlatform Dev CA"
else
  echo "==> Root CA already exists; reusing ${CERTS_DIR}/ca.crt (use --force to rotate)"
fi

# --- Gateway TLS certificate ---
if [[ "${FORCE_LEAF}" == "1" || ! -f "${CERTS_DIR}/gateway.key" || ! -f "${CERTS_DIR}/gateway.crt" ]]; then
  echo "==> Creating Gateway TLS certificate..."
  openssl genrsa -out "${CERTS_DIR}/gateway.key" 2048

  cat > "${CERTS_DIR}/gateway.cnf" <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
C = US
ST = Security
L = Platform
O = SecurityPlatform
OU = Gateway
CN = localhost

[v3_req]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = localhost
DNS.2 = gateway
DNS.3 = *.security-platform.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

  openssl req -new -key "${CERTS_DIR}/gateway.key" \
    -out "${CERTS_DIR}/gateway.csr" \
    -config "${CERTS_DIR}/gateway.cnf"

  openssl x509 -req -days 365 \
    -in "${CERTS_DIR}/gateway.csr" \
    -CA "${CERTS_DIR}/ca.crt" \
    -CAkey "${CERTS_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERTS_DIR}/gateway.crt" \
    -extensions v3_req \
    -extfile "${CERTS_DIR}/gateway.cnf"
else
  echo "==> Gateway TLS certificate already exists; skipping (use --force or --rotate-leaf to rotate)"
fi

# --- Envoy TLS certificate (edge proxy) ---
if [[ "${FORCE_LEAF}" == "1" || ! -f "${CERTS_DIR}/envoy.key" || ! -f "${CERTS_DIR}/envoy.crt" ]]; then
  echo "==> Creating Envoy TLS certificate..."
  openssl genrsa -out "${CERTS_DIR}/envoy.key" 2048

  cat > "${CERTS_DIR}/envoy.cnf" <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
C = US
ST = Security
L = Platform
O = SecurityPlatform
OU = Envoy
CN = localhost

[v3_req]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = localhost
DNS.2 = envoy
DNS.3 = *.security-platform.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

  openssl req -new -key "${CERTS_DIR}/envoy.key" \
    -out "${CERTS_DIR}/envoy.csr" \
    -config "${CERTS_DIR}/envoy.cnf"

  openssl x509 -req -days 365 \
    -in "${CERTS_DIR}/envoy.csr" \
    -CA "${CERTS_DIR}/ca.crt" \
    -CAkey "${CERTS_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERTS_DIR}/envoy.crt" \
    -extensions v3_req \
    -extfile "${CERTS_DIR}/envoy.cnf"
else
  echo "==> Envoy TLS certificate already exists; skipping (use --force or --rotate-leaf to rotate)"
fi

# --- Gateway mTLS client certificate (gateway -> internal planes) ---
needs_upgrade_gateway_client=0
if [[ -f "${CERTS_DIR}/gateway-client.crt" ]] && ! cert_has_dns_san "${CERTS_DIR}/gateway-client.crt" "gateway"; then
  needs_upgrade_gateway_client=1
fi

if [[ "${FORCE_LEAF}" == "1" || ! -f "${CERTS_DIR}/gateway-client.key" || ! -f "${CERTS_DIR}/gateway-client.crt" || "${needs_upgrade_gateway_client}" == "1" ]]; then
  if [[ "${needs_upgrade_gateway_client}" == "1" && "${FORCE_LEAF}" != "1" ]]; then
    echo "==> Upgrading gateway-client cert (missing SAN); regenerating with DNS:gateway"
  else
    echo "==> Creating mTLS client certificate for gateway..."
  fi
  openssl genrsa -out "${CERTS_DIR}/gateway-client.key" 2048

  cat > "${CERTS_DIR}/gateway-client.cnf" <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
C = US
ST = Security
L = Platform
O = SecurityPlatform
OU = GatewayClient
CN = gateway

[v3_req]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth

[alt_names]
DNS.1 = gateway
EOF

  openssl req -new -key "${CERTS_DIR}/gateway-client.key" \
    -out "${CERTS_DIR}/gateway-client.csr" \
    -config "${CERTS_DIR}/gateway-client.cnf"

  openssl x509 -req -days 365 \
    -in "${CERTS_DIR}/gateway-client.csr" \
    -CA "${CERTS_DIR}/ca.crt" \
    -CAkey "${CERTS_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERTS_DIR}/gateway-client.crt" \
    -extensions v3_req \
    -extfile "${CERTS_DIR}/gateway-client.cnf"
else
  echo "==> Gateway mTLS client cert already exists; skipping (use --force or --rotate-leaf to rotate)"
fi

# --- Envoy mTLS client certificate (envoy -> gateway / PDP) ---
needs_upgrade_envoy_client=0
if [[ -f "${CERTS_DIR}/envoy-client.crt" ]] && ! cert_has_dns_san "${CERTS_DIR}/envoy-client.crt" "envoy"; then
  needs_upgrade_envoy_client=1
fi

if [[ "${FORCE_LEAF}" == "1" || ! -f "${CERTS_DIR}/envoy-client.key" || ! -f "${CERTS_DIR}/envoy-client.crt" || "${needs_upgrade_envoy_client}" == "1" ]]; then
  if [[ "${needs_upgrade_envoy_client}" == "1" && "${FORCE_LEAF}" != "1" ]]; then
    echo "==> Upgrading envoy-client cert (missing SAN); regenerating with DNS:envoy"
  else
    echo "==> Creating mTLS client certificate for Envoy..."
  fi
  openssl genrsa -out "${CERTS_DIR}/envoy-client.key" 2048

  cat > "${CERTS_DIR}/envoy-client.cnf" <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
C = US
ST = Security
L = Platform
O = SecurityPlatform
OU = EnvoyClient
CN = envoy

[v3_req]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth

[alt_names]
DNS.1 = envoy
EOF

  openssl req -new -key "${CERTS_DIR}/envoy-client.key" \
    -out "${CERTS_DIR}/envoy-client.csr" \
    -config "${CERTS_DIR}/envoy-client.cnf"

  openssl x509 -req -days 365 \
    -in "${CERTS_DIR}/envoy-client.csr" \
    -CA "${CERTS_DIR}/ca.crt" \
    -CAkey "${CERTS_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERTS_DIR}/envoy-client.crt" \
    -extensions v3_req \
    -extfile "${CERTS_DIR}/envoy-client.cnf"
else
  echo "==> Envoy mTLS client cert already exists; skipping (use --force or --rotate-leaf to rotate)"
fi

# --- mTLS client certificates (service-to-service) ---
for SERVICE in identity policy-engine telemetry supply-chain; do
  needs_upgrade=0
  if [[ -f "${CERTS_DIR}/${SERVICE}.crt" ]] && ! cert_has_dns_san "${CERTS_DIR}/${SERVICE}.crt" "${SERVICE}"; then
    needs_upgrade=1
  fi

  if [[ "${FORCE_LEAF}" == "1" || ! -f "${CERTS_DIR}/${SERVICE}.key" || ! -f "${CERTS_DIR}/${SERVICE}.crt" || "${needs_upgrade}" == "1" ]]; then
    if [[ "${needs_upgrade}" == "1" && "${FORCE_LEAF}" != "1" ]]; then
      echo "==> Upgrading ${SERVICE} cert (missing SAN); regenerating with DNS:${SERVICE}"
    else
      echo "==> Creating mTLS certificate for ${SERVICE}..."
    fi

    openssl genrsa -out "${CERTS_DIR}/${SERVICE}.key" 2048

    cat > "${CERTS_DIR}/${SERVICE}.cnf" <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
C = US
ST = Security
L = Platform
O = SecurityPlatform
OU = ${SERVICE}
CN = ${SERVICE}

[v3_req]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth

[alt_names]
DNS.1 = ${SERVICE}
EOF

    openssl req -new -key "${CERTS_DIR}/${SERVICE}.key" \
      -out "${CERTS_DIR}/${SERVICE}.csr" \
      -config "${CERTS_DIR}/${SERVICE}.cnf"
    openssl x509 -req -days 365 \
      -in "${CERTS_DIR}/${SERVICE}.csr" \
      -CA "${CERTS_DIR}/ca.crt" \
      -CAkey "${CERTS_DIR}/ca.key" \
      -CAcreateserial \
      -out "${CERTS_DIR}/${SERVICE}.crt" \
      -extensions v3_req \
      -extfile "${CERTS_DIR}/${SERVICE}.cnf"
  else
    echo "==> ${SERVICE} cert already exists; skipping (use --force or --rotate-leaf to rotate)"
  fi
done

# --- Token signing key (RS256) ---
if [[ "${FORCE_LEAF}" == "1" || ! -f "${KEYS_DIR}/token-signing.key" || ! -f "${KEYS_DIR}/token-signing.pub" ]]; then
  echo "==> Creating token signing key pair..."
  openssl genrsa -out "${KEYS_DIR}/token-signing.key" 2048
  openssl rsa -in "${KEYS_DIR}/token-signing.key" -pubout -out "${KEYS_DIR}/token-signing.pub"
else
  echo "==> Token signing key pair already exists; skipping (use --force or --rotate-leaf to rotate)"
fi

# --- Artifact signing key (EC P-256) ---
if [[ "${FORCE_LEAF}" == "1" || ! -f "${KEYS_DIR}/artifact-signing.key" || ! -f "${KEYS_DIR}/artifact-signing.pub" ]]; then
  echo "==> Creating artifact signing key pair..."
  openssl ecparam -genkey -name prime256v1 -out "${KEYS_DIR}/artifact-signing.key"
  openssl ec -in "${KEYS_DIR}/artifact-signing.key" -pubout -out "${KEYS_DIR}/artifact-signing.pub"
else
  echo "==> Artifact signing key pair already exists; skipping (use --force or --rotate-leaf to rotate)"
fi

# --- Cleanup CSR files ---
rm -f "${CERTS_DIR}"/*.csr "${CERTS_DIR}"/*.cnf "${CERTS_DIR}"/*.srl

# --- Set restrictive permissions ---
# Keep the CA private key owner-only. Service keys must be readable by the
# non-root container user; we rely on group-read with `group_add: ["${HOST_GID}"]`.
chmod 600 "${CERTS_DIR}/ca.key"
find "${CERTS_DIR}" -maxdepth 1 -type f -name '*.key' ! -name 'ca.key' -exec chmod 640 {} +
find "${KEYS_DIR}" -maxdepth 1 -type f -name '*.key' -exec chmod 640 {} +
chmod 644 "${CERTS_DIR}"/*.crt "${KEYS_DIR}"/*.pub

echo ""
echo "==> Development certificates generated successfully!"
echo "    CA:         ${CERTS_DIR}/ca.crt"
echo "    Gateway:    ${CERTS_DIR}/gateway.crt / gateway.key"
echo "    Envoy:      ${CERTS_DIR}/envoy.crt / envoy.key"
echo "    Gateway mTLS client: ${CERTS_DIR}/gateway-client.crt / gateway-client.key"
echo "    Envoy mTLS client:   ${CERTS_DIR}/envoy-client.crt / envoy-client.key"
echo "    Token key:  ${KEYS_DIR}/token-signing.key / .pub"
echo "    Artifact:   ${KEYS_DIR}/artifact-signing.key / .pub"
echo ""
echo "WARNING: These are self-signed certificates for development only."
echo "         Use proper CA-signed certificates in production."
