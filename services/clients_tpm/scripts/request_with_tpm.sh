#!/bin/bash

set -e

METHOD="${METHOD:-GET}"
PATH_URL="${PATH_URL:-/risorse/R-001}"
USER_ID="${USER_ID:-operatore_ancona}"

ENVOY_HOST="${ENVOY_HOST:-pep_gateway}"
ENVOY_PORT="${ENVOY_PORT:-8443}"

TPM_HANDLE="${TPM_HANDLE:-0x81000001}"

DEVICE_CERT="${CLIENT_CERT:-/certs/device/device.crt}"
CA_CERT="${CA_CERT:-/ca/ca.crt}"

TLS_DEBUG_LOG="/tmp/tpm_tls_debug.log"

echo "============================================================"
echo " Richiesta mTLS con chiave TPM-backed"
echo "============================================================"
echo "Metodo:     $METHOD"
echo "Path:       $PATH_URL"
echo "User ID:    $USER_ID"
echo "Envoy:      $ENVOY_HOST:$ENVOY_PORT"
echo "Cert:       $DEVICE_CERT"
echo "TPM handle: $TPM_HANDLE"
echo ""

if [ ! -f "$DEVICE_CERT" ]; then
  echo "[ERROR] Certificato device non trovato: $DEVICE_CERT"
  echo "Esegui prima /scripts/provision_device_tpm.sh"
  exit 1
fi

if [ ! -f "$CA_CERT" ]; then
  echo "[ERROR] Certificato CA non trovato: $CA_CERT"
  exit 1
fi

HTTP_REQUEST="${METHOD} ${PATH_URL} HTTP/1.1\r\nHost: ${ENVOY_HOST}\r\nX-User-Id: ${USER_ID}\r\nConnection: close\r\n\r\n"

# La chiave privata non viene letta da device.key.
# Viene usata tramite handle TPM, appoggiandosi al provider OpenSSL tpm2.
#
# stderr viene salvato in un file di debug per non sporcare l'output del test
# con warning interni del provider TPM/OpenSSL.
printf "$HTTP_REQUEST" | openssl s_client \
  -connect "${ENVOY_HOST}:${ENVOY_PORT}" \
  -servername "${ENVOY_HOST}" \
  -cert "$DEVICE_CERT" \
  -key "handle:${TPM_HANDLE}" \
  -provider tpm2 \
  -provider default \
  -CAfile "$CA_CERT" \
  -quiet \
  2>"$TLS_DEBUG_LOG"