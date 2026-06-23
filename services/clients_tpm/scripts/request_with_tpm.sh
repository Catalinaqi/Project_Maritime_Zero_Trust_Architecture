#!/bin/bash
set -euo pipefail

METHOD="${METHOD:-GET}"
PATH_URL="${PATH_URL:-/risorse/R-001}"
ENVOY_HOST="${ENVOY_HOST:-pep_gateway}"
ENVOY_PORT="${ENVOY_PORT:-8443}"
TPM_HANDLE="${TPM_HANDLE:?TPM_HANDLE non definito}"
DEVICE_CERT="${CLIENT_CERT:-/certs/device/device.crt}"
CA_CERT="${CA_CERT:-/ca/ca.crt}"

[ -r "$DEVICE_CERT" ] || { echo "Certificato client assente: $DEVICE_CERT" >&2; exit 1; }
[ -r "$CA_CERT" ] || { echo "CA assente: $CA_CERT" >&2; exit 1; }

body="${REQUEST_BODY:-}"
request="${METHOD} ${PATH_URL} HTTP/1.1\r\nHost: ${ENVOY_HOST}\r\nConnection: close\r\n"
if [ -n "$body" ]; then
  request+="Content-Type: application/json\r\nContent-Length: ${#body}\r\n\r\n${body}"
else
  request+="\r\n"
fi

printf '%b' "$request" | openssl s_client \
  -connect "${ENVOY_HOST}:${ENVOY_PORT}" \
  -servername "$ENVOY_HOST" \
  -cert "$DEVICE_CERT" \
  -key "handle:${TPM_HANDLE}" \
  -provider tpm2 -provider default \
  -CAfile "$CA_CERT" \
  -verify_return_error \
  -quiet
