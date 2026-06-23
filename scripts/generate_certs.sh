#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

CERT_ROOT="certs"
CA_DIR="${CERT_ROOT}/ca"
SERVER_DIR="${CERT_ROOT}/server"
MONGO_DIR="${CERT_ROOT}/mongodb"
TMP_DIR="${CERT_ROOT}/.openssl-tmp"

fail() {
  printf '[ERRORE] %s\n' "$1" >&2
  exit 1
}

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

command -v openssl >/dev/null 2>&1 || fail "OpenSSL non è disponibile."
printf '[INFO] OpenSSL rilevato: %s\n' "$(openssl version)"

mkdir -p "${CA_DIR}"
mkdir -p "${SERVER_DIR}"
mkdir -p "${MONGO_DIR}"
mkdir -p "${CERT_ROOT}/devices/D-001"
mkdir -p "${CERT_ROOT}/devices/D-002"
mkdir -p "${CERT_ROOT}/devices/D-SOC"
mkdir -p "${TMP_DIR}"

find "${CA_DIR}" "${SERVER_DIR}" "${MONGO_DIR}" -type f ! -name '.gitkeep' -delete
umask 077

cat > "${TMP_DIR}/ca.cnf" <<'EOF'
[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca

[dn]
O = Maritime_Zero_Trust
CN = Maritime_Root_CA

[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:1
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

cat > "${TMP_DIR}/envoy.cnf" <<'EOF'
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
O = Maritime_Zero_Trust
OU = Policy_Enforcement_Point
CN = pep_gateway

[v3_req]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = pep_gateway
DNS.2 = envoy-gateway
DNS.3 = localhost
IP.1 = 127.0.0.1
IP.2 = 172.20.2.7
IP.3 = 172.20.3.7
EOF

cat > "${TMP_DIR}/mongodb-server.cnf" <<'EOF'
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
O = Maritime_Zero_Trust
OU = Database
CN = db_primary

[v3_req]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = db_primary
DNS.2 = mongo-primary
DNS.3 = localhost
IP.1 = 127.0.0.1
IP.2 = 172.20.3.5
EOF

cat > "${TMP_DIR}/api-client.cnf" <<'EOF'
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
O = Maritime_Zero_Trust
OU = Backend
CN = api_backend

[v3_req]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = DNS:api_backend
EOF

cat > "${TMP_DIR}/healthcheck-client.cnf" <<'EOF'
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
O = Maritime_Zero_Trust
OU = Database
CN = mongodb-healthcheck

[v3_req]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = DNS:mongodb-healthcheck
EOF

printf '[INFO] Generazione della CA radice...\n'
openssl req -new -x509 -newkey rsa:4096 -sha256 -nodes -days 3650 -config "${TMP_DIR}/ca.cnf" -keyout "${CA_DIR}/ca.key" -out "${CA_DIR}/ca.crt"

issue_certificate() {
  local label="$1"
  local config="$2"
  local key="$3"
  local csr="$4"
  local crt="$5"

  printf '[INFO] Generazione del certificato %s...\n' "${label}"
  openssl req -new -newkey rsa:3072 -sha256 -nodes -config "${config}" -keyout "${key}" -out "${csr}"
  openssl x509 -req -sha256 -days 825 -in "${csr}" -CA "${CA_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" -CAserial "${TMP_DIR}/ca.srl" -CAcreateserial -extfile "${config}" -extensions v3_req -out "${crt}"
  rm -f "${csr}"
}

issue_certificate "Envoy" "${TMP_DIR}/envoy.cnf" "${SERVER_DIR}/server.key" "${SERVER_DIR}/server.csr" "${SERVER_DIR}/server.crt"
issue_certificate "MongoDB server" "${TMP_DIR}/mongodb-server.cnf" "${MONGO_DIR}/mongodb-server.key" "${MONGO_DIR}/mongodb-server.csr" "${MONGO_DIR}/mongodb-server.crt"
issue_certificate "API client" "${TMP_DIR}/api-client.cnf" "${MONGO_DIR}/api-client.key" "${MONGO_DIR}/api-client.csr" "${MONGO_DIR}/api-client.crt"
issue_certificate "MongoDB healthcheck client" "${TMP_DIR}/healthcheck-client.cnf" "${MONGO_DIR}/healthcheck-client.key" "${MONGO_DIR}/healthcheck-client.csr" "${MONGO_DIR}/healthcheck-client.crt"

cat "${MONGO_DIR}/mongodb-server.crt" "${MONGO_DIR}/mongodb-server.key" > "${MONGO_DIR}/mongodb-server.pem"
cat "${MONGO_DIR}/api-client.crt" "${MONGO_DIR}/api-client.key" > "${MONGO_DIR}/api-client.pem"
cat "${MONGO_DIR}/healthcheck-client.crt" "${MONGO_DIR}/healthcheck-client.key" > "${MONGO_DIR}/healthcheck-client.pem"

chmod 600 "${CA_DIR}/ca.key" "${SERVER_DIR}/server.key" "${MONGO_DIR}/mongodb-server.key" "${MONGO_DIR}/api-client.key" "${MONGO_DIR}/healthcheck-client.key" "${MONGO_DIR}/mongodb-server.pem" "${MONGO_DIR}/api-client.pem" "${MONGO_DIR}/healthcheck-client.pem" 2>/dev/null || true
chmod 644 "${CA_DIR}/ca.crt" "${SERVER_DIR}/server.crt" "${MONGO_DIR}/mongodb-server.crt" "${MONGO_DIR}/api-client.crt" "${MONGO_DIR}/healthcheck-client.crt" 2>/dev/null || true

printf '[INFO] Verifica della catena di certificazione...\n'
openssl verify -CAfile "${CA_DIR}/ca.crt" "${SERVER_DIR}/server.crt"
openssl verify -CAfile "${CA_DIR}/ca.crt" "${MONGO_DIR}/mongodb-server.crt"
openssl verify -CAfile "${CA_DIR}/ca.crt" "${MONGO_DIR}/api-client.crt"
openssl verify -CAfile "${CA_DIR}/ca.crt" "${MONGO_DIR}/healthcheck-client.crt"

openssl x509 -in "${SERVER_DIR}/server.crt" -noout -checkhost pep_gateway >/dev/null || fail "SAN pep_gateway assente nel certificato Envoy."
openssl x509 -in "${MONGO_DIR}/mongodb-server.crt" -noout -checkhost db_primary >/dev/null || fail "SAN db_primary assente nel certificato MongoDB."

printf '\n[OK] Certificati infrastrutturali generati correttamente.\n'
printf '[INFO] Passaggio successivo: bash scripts/provision_tpm_devices.sh\n'
