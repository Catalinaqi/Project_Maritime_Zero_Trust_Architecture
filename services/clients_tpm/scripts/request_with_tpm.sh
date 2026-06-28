#!/bin/bash
# Invia una richiesta HTTPS mTLS firmandola con la chiave privata nel TPM.
set -euo pipefail

METHOD="${METHOD:-GET}"
PATH_URL="${PATH_URL:-/risorse/R-001}"
ENVOY_HOST="${ENVOY_HOST:-pep_gateway}"
ENVOY_PORT="${ENVOY_PORT:-8443}"
TPM_HANDLE="${TPM_HANDLE:?TPM_HANDLE non definito}"
DEVICE_CERT="${CLIENT_CERT:-/certs/device/device.crt}"
CA_CERT="${CA_CERT:-/ca/ca.crt}"
VERIFY_SERVER="${VERIFY_SERVER:-0}"

[ -r "$DEVICE_CERT" ] || { echo "Certificato client assente: $DEVICE_CERT" >&2; exit 1; }
if [ "$VERIFY_SERVER" = "1" ]; then
  [ -r "$CA_CERT" ] || { echo "CA assente: $CA_CERT" >&2; exit 1; }
fi

body="${REQUEST_BODY:-}"
request="${METHOD} ${PATH_URL} HTTP/1.1\r\nHost: ${ENVOY_HOST}\r\nConnection: close\r\n"
if [ -n "$body" ]; then
  request+="Content-Type: application/json\r\nContent-Length: ${#body}\r\n\r\n${body}"
else
  request+="\r\n"
fi

openssl_args=(
  -connect "${ENVOY_HOST}:${ENVOY_PORT}" \
  -servername "$ENVOY_HOST" \
  -tls1_2 \
  -cert "$DEVICE_CERT" \
  -key "handle:${TPM_HANDLE}" \
  -provider tpm2 -provider default \
  -quiet
)

if [ "$VERIFY_SERVER" = "1" ]; then
  openssl_args+=(-CAfile "$CA_CERT" -verify_return_error)
else
  openssl_args+=(-no-CAfile -no-CApath)
fi

echo "[client] Invio ${METHOD} ${PATH_URL} verso ${ENVOY_HOST}:${ENVOY_PORT} con TPM ${TPM_HANDLE}"

set +e
printf '%b' "$request" | openssl s_client "${openssl_args[@]}"
status=$?
set -e

if [ "$status" -ne 0 ]; then
  echo "[client] Richiesta fallita con codice ${status}." >&2
else
  echo "[client] Richiesta completata."
fi

exit "$status"
