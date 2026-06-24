#!/usr/bin/env bash

# Interrompe lo script al primo errore e impedisce l'uso di variabili non definite.
set -Eeuo pipefail

# Disabilita la conversione automatica degli argomenti MSYS2. I percorsi passati
# a OpenSSL sono relativi; il percorso Linux del comando eseguito nel container
# deve invece rimanere invariato.
export MSYS2_ARG_CONV_EXCL='*'

# Individua la directory principale del progetto.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

TMP_DIR="certs/.tpm-provision-tmp"
mkdir -p "${TMP_DIR}"

fail() {
  printf '[ERRORE] %s\n' "$1" >&2
  exit 1
}

# Arresta i TPM temporanei e rimuove i file di configurazione provvisori.
cleanup() {
  docker compose --profile testing stop \
    swtpm_d001 swtpm_d002 swtpm_dsoc >/dev/null 2>&1 || true
  rm -rf "${TMP_DIR}"
  rm -f certs/ca/ca.srl
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || fail "Docker non e disponibile."
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 non e disponibile."
command -v openssl >/dev/null 2>&1 || fail "OpenSSL non e disponibile."

[[ -r certs/ca/ca.crt && -r certs/ca/ca.key ]] || \
  fail "CA assente. Eseguire prima: bash scripts/generate_certs.sh"

printf '[INFO] Avvio dei TPM software...\n'
docker compose --profile testing up -d --build \
  swtpm_d001 swtpm_d002 swtpm_dsoc

# Attende che i container TPM raggiungano lo stato healthy.
for service in swtpm_d001 swtpm_d002 swtpm_dsoc; do
  printf '[INFO] Attesa healthcheck di %s...\n' "${service}"

  for _ in $(seq 1 30); do
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${service}" 2>/dev/null || true)"

    if [[ "${status}" == "healthy" || "${status}" == "running" ]]; then
      break
    fi

    sleep 1
  done

  status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${service}" 2>/dev/null || true)"
  [[ "${status}" == "healthy" || "${status}" == "running" ]] || \
    fail "Il servizio ${service} non e pronto. Stato rilevato: ${status:-sconosciuto}."
done

# Firma la CSR prodotta dal TPM senza mai esportare la chiave privata.
provision_device() {
  local client_service="$1"
  local user_id="$2"
  local device_id="$3"
  local device_dir="certs/devices/${device_id}"
  local config_file="${TMP_DIR}/${device_id}.cnf"
  local csr_file="${device_dir}/device.csr"

  mkdir -p "${device_dir}"

  printf '[INFO] Generazione CSR TPM per user=%s device=%s...\n' \
    "${user_id}" "${device_id}"

  docker compose --profile testing rm -sf "${client_service}" >/dev/null 2>&1 || true

  docker compose --profile testing run --rm --no-deps \
    "${client_service}" \
    /scripts/generate_device_csr.sh

  [[ -r "${csr_file}" ]] || fail "CSR non generata: ${csr_file}"

  # Il SAN URI lega in modo esplicito l'identita dell'utente al dispositivo.
  cat > "${config_file}" <<EOF_CONFIG
[v3_client]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = URI:spiffe://maritime.local/users/${user_id}/devices/${device_id}
EOF_CONFIG

  openssl x509 \
    -req \
    -sha256 \
    -days 365 \
    -in "${csr_file}" \
    -CA certs/ca/ca.crt \
    -CAkey certs/ca/ca.key \
    -CAserial certs/ca/ca.srl \
    -CAcreateserial \
    -extfile "${config_file}" \
    -extensions v3_client \
    -out "${device_dir}/device.crt"

  rm -f "${csr_file}"
  cp certs/ca/ca.crt "${device_dir}/ca.crt"

  chmod 644 \
    "${device_dir}/device.crt" \
    "${device_dir}/ca.crt" \
    "${device_dir}/device_tpm_public.pem" 2>/dev/null || true

  openssl verify \
    -CAfile certs/ca/ca.crt \
    "${device_dir}/device.crt"

  # Controlla che il SAN URI atteso sia realmente presente nel certificato.
  openssl x509 \
    -in "${device_dir}/device.crt" \
    -noout \
    -ext subjectAltName | \
    grep -Fq "spiffe://maritime.local/users/${user_id}/devices/${device_id}" || \
    fail "SAN URI non corretto per ${device_id}."

  printf '[OK] Certificato TPM creato per user=%s device=%s.\n' \
    "${user_id}" "${device_id}"
}

provision_device "client_d001_tpm" "operatore_ancona" "D-001"
provision_device "client_d002_tpm" "capitano_claudia" "D-002"
provision_device "client_dsoc_tpm" "soc_admin" "D-SOC"

printf '\n[OK] Provisioning TPM completato.\n'
printf '[OK] Le chiavi private restano nei volumi SWTPM e non vengono esportate.\n'
