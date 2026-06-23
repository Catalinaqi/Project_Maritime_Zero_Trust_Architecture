#!/usr/bin/env bash

# =============================================================================
# PROVISIONING DI UNA IDENTITÀ UTENTE-HARDWARE NEL TPM
# =============================================================================
#
# Lo script:
# 1. crea o riutilizza una chiave privata distinta per la coppia USER_ID/DEVICE_ID;
# 2. mantiene la chiave privata dentro il TPM;
# 3. esporta solamente la chiave pubblica;
# 4. genera una CSR usando il provider OpenSSL TPM2.
#
# La chiave privata della CA non viene mai montata nel container.
# =============================================================================

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

PARENT_CONTEXT="${TPM_WORK_DIR}/parent.ctx"
KEY_PUBLIC_BLOB="${TPM_WORK_DIR}/identity.pub"
KEY_PRIVATE_BLOB="${TPM_WORK_DIR}/identity.priv"
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
  # Elimina esclusivamente oggetti e sessioni temporanei.
  # Gli handle persistenti non vengono rimossi.
  tpm2_flushcontext --transient-object 2>/dev/null || true
  tpm2_flushcontext --loaded-session 2>/dev/null || true
  tpm2_flushcontext --saved-session 2>/dev/null || true
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
    log INFO "Handle già presente: la chiave viene riutilizzata"
  fi
fi

if ! persistent_handle_exists; then
  log STEP "Creazione del parent primario TPM"

  rm -f \
    "${PARENT_CONTEXT}" \
    "${KEY_PUBLIC_BLOB}" \
    "${KEY_PRIVATE_BLOB}" \
    "${KEY_CONTEXT}"

  # Il primary object è usato soltanto come parent temporaneo.
  tpm2_createprimary \
    -C o \
    -G rsa2048 \
    -g sha256 \
    -c "${PARENT_CONTEXT}"

  log STEP "Creazione della chiave di firma non esportabile"

  # fixedtpm e fixedparent impediscono la migrazione della chiave.
  # sensitivedataorigin impone che il materiale privato venga generato dal TPM.
  tpm2_create \
    -C "${PARENT_CONTEXT}" \
    -G rsa2048 \
    -g sha256 \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign" \
    -u "${KEY_PUBLIC_BLOB}" \
    -r "${KEY_PRIVATE_BLOB}"

  log STEP "Caricamento e persistenza della chiave su ${TPM_HANDLE}"

  tpm2_load \
    -C "${PARENT_CONTEXT}" \
    -u "${KEY_PUBLIC_BLOB}" \
    -r "${KEY_PRIVATE_BLOB}" \
    -c "${KEY_CONTEXT}"

  tpm2_evictcontrol \
    -C o \
    -c "${KEY_CONTEXT}" \
    "${TPM_HANDLE}"

  cleanup_transient_contexts

  # I blob TPM non sono chiavi private esportabili, ma vengono comunque
  # rimossi dopo la persistenza per ridurre i file temporanei.
  rm -f \
    "${PARENT_CONTEXT}" \
    "${KEY_PUBLIC_BLOB}" \
    "${KEY_PRIVATE_BLOB}" \
    "${KEY_CONTEXT}"
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
