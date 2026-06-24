#!/usr/bin/env bash

# =============================================================================
# GENERAZIONE CERTIFICATI PER COPPIE UTENTE-HARDWARE
# =============================================================================
#
# Legge configs/identity/identity_bindings.conf e genera:
# - una chiave TPM distinta per ogni coppia utente/dispositivo;
# - una CSR distinta;
# - un certificato X.509 client distinto;
# - un SAN SPIFFE che identifica inequivocabilmente la coppia.
#
# La CA firma le CSR sull'host. La chiave privata della CA non entra mai
# nei container client.
# =============================================================================

set -Eeuo pipefail
export MSYS_NO_PATHCONV=1

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

BINDINGS_FILE="${BINDINGS_FILE:-configs/identity/identity_bindings.conf}"
CA_CERT="${CA_CERT:-certs/ca/ca.crt}"
CA_KEY="${CA_KEY:-certs/ca/ca.key}"
CERT_DAYS="${CERT_DAYS:-365}"
FORCE_REPROVISION="${FORCE_REPROVISION:-0}"

MANIFEST_FILE="certs/devices/identity-certificates.tsv"
MANIFEST_TMP="${MANIFEST_FILE}.tmp"

declare -A SEEN_PAIR=()
declare -A SEEN_HANDLE=()

log() {
  printf '[%s] %s\n' "$1" "$2"
}

fail() {
  log ERROR "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || \
    fail "Comando non trovato: $1"
}

trim() {
  local value="$1"

  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"

  printf '%s' "${value}"
}

validate_identifier() {
  local label="$1"
  local value="$2"

  [[ "${value}" =~ ^[A-Za-z0-9._-]+$ ]] || \
    fail "${label} non valido: ${value}"
}

expected_service_for_device() {
  case "$1" in
    D-001) printf '%s' "client_d001_tpm" ;;
    D-002) printf '%s' "client_d002_tpm" ;;
    D-SOC) printf '%s' "client_dsoc_tpm" ;;
    *) return 1 ;;
  esac
}

expected_network_for_device() {
  case "$1" in
    D-001) printf '%s' "vpn_net" ;;
    D-002) printf '%s' "satellite_net" ;;
    D-SOC) printf '%s' "corporate_net" ;;
    *) return 1 ;;
  esac
}

swtpm_service_for_device() {
  case "$1" in
    D-001) printf '%s' "swtpm_d001" ;;
    D-002) printf '%s' "swtpm_d002" ;;
    D-SOC) printf '%s' "swtpm_dsoc" ;;
    *) return 1 ;;
  esac
}

wait_for_swtpm() {
  local service="$1"
  local attempt

  for attempt in $(seq 1 40); do
    if docker compose --profile testing exec -T "${service}" \
      bash -lc "timeout 2 bash -c '</dev/tcp/127.0.0.1/2321'" \
      >/dev/null 2>&1; then
      log OK "${service} pronto"
      return 0
    fi

    sleep 1
  done

  fail "${service} non disponibile sulla porta 2321"
}

validate_binding() {
  local user_id="$1"
  local device_id="$2"
  local client_service="$3"
  local tpm_handle="$4"
  local device_location="$5"
  local network_name="$6"

  local expected_service
  local expected_network
  local pair_key

  validate_identifier "USER_ID" "${user_id}"
  validate_identifier "DEVICE_ID" "${device_id}"
  validate_identifier "CLIENT_SERVICE" "${client_service}"
  validate_identifier "NETWORK_NAME" "${network_name}"

  [[ -n "${device_location}" ]] || \
    fail "DEVICE_LOCATION vuota per ${user_id}/${device_id}"

  [[ "${tpm_handle}" =~ ^0x81[0-9A-Fa-f]{6}$ ]] || \
    fail "Handle TPM non valido per ${user_id}/${device_id}: ${tpm_handle}"

  expected_service="$(expected_service_for_device "${device_id}")" || \
    fail "Dispositivo non riconosciuto: ${device_id}"

  expected_network="$(expected_network_for_device "${device_id}")"

  [[ "${client_service}" == "${expected_service}" ]] || \
    fail "${device_id} deve usare ${expected_service}, non ${client_service}"

  [[ "${network_name}" == "${expected_network}" ]] || \
    fail "${device_id} deve appartenere a ${expected_network}, non ${network_name}"

  pair_key="${user_id}|${device_id}"

  [[ -z "${SEEN_PAIR[${pair_key}]:-}" ]] || \
    fail "Coppia duplicata nella matrice: ${pair_key}"

  [[ -z "${SEEN_HANDLE[${tpm_handle}]:-}" ]] || \
    fail "Handle duplicato nella matrice: ${tpm_handle}"

  SEEN_PAIR["${pair_key}"]=1
  SEEN_HANDLE["${tpm_handle}"]=1
}

sign_identity_csr() {
  local user_id="$1"
  local device_id="$2"
  local tpm_handle="$3"
  local device_location="$4"
  local network_name="$5"

  local identity_dir="certs/devices/${device_id}/identities/${user_id}"
  local csr_file="${identity_dir}/identity.csr"
  local cert_file="${identity_dir}/identity.crt"
  local public_key_file="${identity_dir}/identity_tpm_public.pem"
  local ca_copy="${identity_dir}/ca.crt"
  local extension_file="${identity_dir}/identity.ext"

  local spiffe_uri="spiffe://maritime.local/users/${user_id}/devices/${device_id}"
  local serial_hex
  local cert_pub_hash
  local tpm_pub_hash
  local fingerprint

  [[ -s "${csr_file}" ]] || \
    fail "CSR mancante: ${csr_file}"

  [[ -s "${public_key_file}" ]] || \
    fail "Chiave pubblica mancante: ${public_key_file}"

  openssl req \
    -in "${csr_file}" \
    -noout \
    -verify >/dev/null

  cat > "${extension_file}" <<EXTENSIONS
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=URI:${spiffe_uri}
EXTENSIONS

  serial_hex="$(openssl rand -hex 16)"

  openssl x509 -req \
    -days "${CERT_DAYS}" \
    -sha256 \
    -in "${csr_file}" \
    -CA "${CA_CERT}" \
    -CAkey "${CA_KEY}" \
    -set_serial "0x${serial_hex}" \
    -extfile "${extension_file}" \
    -out "${cert_file}"

  cp "${CA_CERT}" "${ca_copy}"

  openssl verify \
    -CAfile "${CA_CERT}" \
    -purpose sslclient \
    "${cert_file}" >/dev/null

  cert_pub_hash="$(
    openssl x509 -in "${cert_file}" -pubkey -noout |
      openssl pkey -pubin -outform DER 2>/dev/null |
      openssl dgst -sha256 -r |
      awk '{print $1}'
  )"

  tpm_pub_hash="$(
    openssl pkey -pubin -in "${public_key_file}" -outform DER 2>/dev/null |
      openssl dgst -sha256 -r |
      awk '{print $1}'
  )"

  [[ "${cert_pub_hash}" == "${tpm_pub_hash}" ]] || \
    fail "Il certificato ${user_id}/${device_id} non corrisponde alla chiave TPM"

  openssl x509 -in "${cert_file}" -noout -subject |
    grep -Fq "OU = ${user_id}" || \
    fail "OU utente errata nel certificato ${user_id}/${device_id}"

  openssl x509 -in "${cert_file}" -noout -subject |
    grep -Fq "CN = ${device_id}" || \
    fail "CN dispositivo errato nel certificato ${user_id}/${device_id}"

  openssl x509 -in "${cert_file}" -noout -ext subjectAltName |
    grep -Fq "URI:${spiffe_uri}" || \
    fail "SAN SPIFFE errato nel certificato ${user_id}/${device_id}"

  fingerprint="$(
    openssl x509 \
      -in "${cert_file}" \
      -noout \
      -fingerprint \
      -sha256 |
      cut -d= -f2
  )"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${user_id}" \
    "${device_id}" \
    "${tpm_handle}" \
    "${network_name}" \
    "${cert_file}" \
    "${spiffe_uri}" \
    "${fingerprint}" \
    >> "${MANIFEST_TMP}"

  rm -f "${csr_file}" "${extension_file}"

  chmod 0644 \
    "${cert_file}" \
    "${public_key_file}" \
    "${ca_copy}" \
    2>/dev/null || true

  log OK "Certificato generato: ${cert_file}"
}

provision_identity() {
  local user_id="$1"
  local device_id="$2"
  local client_service="$3"
  local tpm_handle="$4"
  local device_location="$5"
  local network_name="$6"

  log STEP "Provisioning ${user_id} su ${device_id} con handle ${tpm_handle}"

  docker compose --profile testing run --rm --no-deps -T \
    -e "USER_ID=${user_id}" \
    -e "DEVICE_ID=${device_id}" \
    -e "DEVICE_LOCATION=${device_location}" \
    -e "TPM_HANDLE=${tpm_handle}" \
    -e "FORCE_REPROVISION=${FORCE_REPROVISION}" \
    "${client_service}" \
    /scripts/provision_device_tpm.sh </dev/null

  sign_identity_csr \
    "${user_id}" \
    "${device_id}" \
    "${tpm_handle}" \
    "${device_location}" \
    "${network_name}"
}

require_command docker
require_command openssl
require_command awk
require_command grep

[[ -s "${BINDINGS_FILE}" ]] || \
  fail "Matrice identità mancante: ${BINDINGS_FILE}"

[[ -s "${CA_CERT}" ]] || \
  fail "Certificato CA mancante: ${CA_CERT}"

[[ -s "${CA_KEY}" ]] || \
  fail "Chiave privata CA mancante: ${CA_KEY}"

docker compose version >/dev/null 2>&1 || \
  fail "Docker Compose non disponibile"

docker compose --profile testing config -q

# Prima validazione completa della matrice, senza modificare il TPM.
binding_count=0

while IFS='|' read -r raw_user raw_device raw_service raw_handle raw_location raw_network; do
  user_id="$(trim "${raw_user:-}")"
  device_id="$(trim "${raw_device:-}")"
  client_service="$(trim "${raw_service:-}")"
  tpm_handle="$(trim "${raw_handle:-}")"
  device_location="$(trim "${raw_location:-}")"
  network_name="$(trim "${raw_network:-}")"

  [[ -z "${user_id}" ]] && continue
  [[ "${user_id}" == \#* ]] && continue

  [[ -n "${network_name}" ]] || \
    fail "Riga incompleta nella matrice: ${raw_user}|${raw_device}|..."

  validate_binding \
    "${user_id}" \
    "${device_id}" \
    "${client_service}" \
    "${tpm_handle}" \
    "${device_location}" \
    "${network_name}"

  binding_count=$((binding_count + 1))
done < "${BINDINGS_FILE}"

[[ "${binding_count}" -gt 0 ]] || \
  fail "La matrice non contiene identità valide"

log OK "Matrice validata: ${binding_count} identità distinte"

log STEP "Build delle immagini client TPM"

docker compose --profile testing build \
  client_d001_tpm \
  client_d002_tpm \
  client_dsoc_tpm

log STEP "Avvio degli emulatori SWTPM"

docker compose --profile testing up -d \
  swtpm_d001 \
  swtpm_d002 \
  swtpm_dsoc

wait_for_swtpm swtpm_d001
wait_for_swtpm swtpm_d002
wait_for_swtpm swtpm_dsoc

for service in swtpm_d001 swtpm_d002 swtpm_dsoc; do
  docker compose --profile testing exec -T "${service}" \
    bash -lc "tpm2_flushcontext -t 2>/dev/null || true; tpm2_flushcontext -s 2>/dev/null || true; tpm2_flushcontext -l 2>/dev/null || true" \
    >/dev/null 2>&1 || true
done

log STEP "Rimozione dei client demo eventualmente gia' avviati"

docker compose --profile testing rm -sf \
  client_d001_tpm \
  client_d002_tpm \
  client_dsoc_tpm \
  >/dev/null 2>&1 || true

mkdir -p "$(dirname -- "${MANIFEST_FILE}")"

printf 'user_id\tdevice_id\ttpm_handle\tnetwork\tcertificate\tspiffe_uri\tsha256_fingerprint\n' \
  > "${MANIFEST_TMP}"

# Secondo passaggio: provisioning e firma.
generated_count=0

while IFS='|' read -r raw_user raw_device raw_service raw_handle raw_location raw_network; do
  user_id="$(trim "${raw_user:-}")"
  device_id="$(trim "${raw_device:-}")"
  client_service="$(trim "${raw_service:-}")"
  tpm_handle="$(trim "${raw_handle:-}")"
  device_location="$(trim "${raw_location:-}")"
  network_name="$(trim "${raw_network:-}")"

  [[ -z "${user_id}" ]] && continue
  [[ "${user_id}" == \#* ]] && continue

  provision_identity \
    "${user_id}" \
    "${device_id}" \
    "${client_service}" \
    "${tpm_handle}" \
    "${device_location}" \
    "${network_name}"

  generated_count=$((generated_count + 1))
done < "${BINDINGS_FILE}"

[[ "${generated_count}" -eq "${binding_count}" ]] || \
  fail "Generate ${generated_count} identità su ${binding_count} previste"

mv -f "${MANIFEST_TMP}" "${MANIFEST_FILE}"
chmod 0644 "${MANIFEST_FILE}" 2>/dev/null || true

log OK "Generate ${generated_count} identità utente-hardware TPM-backed"
log INFO "Manifest: ${MANIFEST_FILE}"
log INFO "Le chiavi private non sono state esportate dal TPM"
