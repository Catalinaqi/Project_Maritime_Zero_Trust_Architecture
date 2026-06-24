#!/usr/bin/env bash
# Crea o riutilizza una chiave TPM persistente e genera la relativa CSR.
set -Eeuo pipefail

USER_ID="${USER_ID:?USER_ID non definito}"
DEVICE_ID="${DEVICE_ID:?DEVICE_ID non definito}"
DEVICE_LOCATION="${DEVICE_LOCATION:-Unknown-Location}"
TPM_HANDLE="${TPM_HANDLE:?TPM_HANDLE non definito}"
FORCE_REPROVISION="${FORCE_REPROVISION:-0}"

CERT_ROOT="/certs/device"
IDENTITY_DIR="${CERT_ROOT}/identities/${USER_ID}"
TPM_WORK_DIR="/tpm/identities/${USER_ID}__${DEVICE_ID}"

CSR_FILE="${IDENTITY_DIR}/identity.csr"
PUBLIC_KEY_FILE="${IDENTITY_DIR}/identity_tpm_public.pem"
KEY_CONTEXT="${TPM_WORK_DIR}/identity.ctx"

log() {
  printf '[%s] %s\n' "$1" "$2"
}

fail() {
  log ERROR "$1" >&2
  exit 1
}

validate_identifier() {
  local label="$1"
  local value="$2"

  [[ "${value}" =~ ^[A-Za-z0-9._-]+$ ]] || \
    fail "${label} contiene caratteri non consentiti: ${value}"
}

cleanup_transient_contexts() {
  tpm2_flushcontext -t 2>/dev/null || true
  tpm2_flushcontext -s 2>/dev/null || true
  tpm2_flushcontext -l 2>/dev/null || true
}

persistent_handle_exists() {
  tpm2_getcap handles-persistent 2>/dev/null |
    grep -Fqi -- "${TPM_HANDLE}"
}

validate_identifier "USER_ID" "${USER_ID}"
validate_identifier "DEVICE_ID" "${DEVICE_ID}"

[[ "${TPM_HANDLE}" =~ ^0x81[0-9A-Fa-f]{6}$ ]] || \
  fail "TPM_HANDLE non valido: ${TPM_HANDLE}"

mkdir -p "${IDENTITY_DIR}" "${TPM_WORK_DIR}"

log INFO "Utente: ${USER_ID}"
log INFO "Dispositivo: ${DEVICE_ID}"
log INFO "Posizione: ${DEVICE_LOCATION}"
log INFO "Handle TPM: ${TPM_HANDLE}"
log INFO "TCTI tools: ${TPM2TOOLS_TCTI:-not_set}"
log INFO "TCTI OpenSSL: ${TPM2OPENSSL_TCTI:-not_set}"

log STEP "Verifica della connessione al TPM"
tpm2_getrandom 8 >/dev/null
cleanup_transient_contexts

if persistent_handle_exists; then
  if [[ "${FORCE_REPROVISION}" == "1" ]]; then
    log WARN "Rimozione esplicita dell'handle persistente ${TPM_HANDLE}"
    tpm2_evictcontrol -C o -c "${TPM_HANDLE}"
    cleanup_transient_contexts
  else
    log INFO "Handle gia' presente: la chiave viene riutilizzata"
  fi
fi

if ! persistent_handle_exists; then
  log STEP "Creazione della chiave primaria TPM non esportabile"

  rm -f "${KEY_CONTEXT}"

  # La chiave primaria viene resa persistente direttamente. Questa sequenza
  # evita di saturare gli object context dei TPM emulati piu' piccoli.
  tpm2_createprimary \
    -C o \
    -G rsa2048 \
    -g sha256 \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign" \
    -c "${KEY_CONTEXT}"

  log STEP "Persistenza della chiave su ${TPM_HANDLE}"

  tpm2_evictcontrol \
    -C o \
    -c "${KEY_CONTEXT}" \
    "${TPM_HANDLE}"

  cleanup_transient_contexts
  rm -f "${KEY_CONTEXT}"
fi

persistent_handle_exists || \
  fail "L'handle ${TPM_HANDLE} non risulta persistente dopo il provisioning"

log STEP "Esportazione della sola chiave pubblica"

tpm2_readpublic \
  -c "${TPM_HANDLE}" \
  -f pem \
  -o "${PUBLIC_KEY_FILE}"

log STEP "Generazione della CSR TPM-backed"

rm -f "${CSR_FILE}"

openssl req -new \
  -provider tpm2 \
  -provider default \
  -key "handle:${TPM_HANDLE}" \
  -out "${CSR_FILE}" \
  -subj "/O=Maritime_Zero_Trust/OU=${USER_ID}/CN=${DEVICE_ID}/L=${DEVICE_LOCATION}"

openssl req \
  -in "${CSR_FILE}" \
  -noout \
  -verify >/dev/null

cleanup_transient_contexts

chmod 0644 "${CSR_FILE}" "${PUBLIC_KEY_FILE}" 2>/dev/null || true

log OK "CSR generata: ${CSR_FILE}"
log OK "Chiave pubblica esportata: ${PUBLIC_KEY_FILE}"
log INFO "La chiave privata resta nel TPM all'handle ${TPM_HANDLE}"
