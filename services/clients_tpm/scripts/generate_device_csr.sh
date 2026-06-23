#!/bin/bash
set -euo pipefail

: "${USER_ID:?USER_ID non definito}"
: "${DEVICE_ID:?DEVICE_ID non definito}"
: "${TPM_HANDLE:?TPM_HANDLE non definito}"

TPM_DIR="/tpm/${DEVICE_ID}"
CERT_DIR=/certs/device
mkdir -p "$TPM_DIR" "$CERT_DIR"

command -v tpm2_getrandom >/dev/null || { echo "tpm2-tools non disponibile" >&2; exit 1; }
openssl list -providers -provider tpm2 -provider default >/dev/null

tpm2_getrandom 8 >/dev/null
tpm2_flushcontext -t 2>/dev/null || true
tpm2_flushcontext -s 2>/dev/null || true
tpm2_flushcontext -l 2>/dev/null || true
tpm2_evictcontrol -C o -c "$TPM_HANDLE" 2>/dev/null || true
rm -f "$TPM_DIR/device_primary.ctx" "$CERT_DIR/device.csr" \
      "$CERT_DIR/device.crt" "$CERT_DIR/device_tpm_public.pem"

tpm2_createprimary \
  -C o -G rsa -g sha256 \
  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign" \
  -c "$TPM_DIR/device_primary.ctx"

tpm2_evictcontrol -C o -c "$TPM_DIR/device_primary.ctx" "$TPM_HANDLE"
tpm2_flushcontext -t 2>/dev/null || true
tpm2_flushcontext -s 2>/dev/null || true
tpm2_flushcontext -l 2>/dev/null || true

tpm2_readpublic -c "$TPM_HANDLE" -f pem -o "$CERT_DIR/device_tpm_public.pem"

openssl req -new \
  -provider tpm2 -provider default \
  -key "handle:${TPM_HANDLE}" \
  -out "$CERT_DIR/device.csr" \
  -subj "/O=Maritime_Zero_Trust/OU=${DEVICE_ID}/CN=${USER_ID}"

printf '[client] CSR generata per user=%s device=%s handle=%s\n' \
  "$USER_ID" "$DEVICE_ID" "$TPM_HANDLE"
