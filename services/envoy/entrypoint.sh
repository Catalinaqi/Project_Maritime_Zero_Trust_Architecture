#!/bin/sh
# Prepara i file TLS e avvia Envoy come Policy Enforcement Point.
set -eu

CERT_FILE=/certs/server.crt
KEY_FILE=/certs/server.key
CA_FILE=/ca/ca.crt

for file in "$CERT_FILE" "$KEY_FILE" "$CA_FILE"; do
    if [ ! -r "$file" ]; then
        echo "[envoy] File TLS mancante o non leggibile: $file" >&2
        echo "[envoy] Eseguire: bash scripts/generate_certs.sh" >&2
        exit 1
    fi
done

exec "$@"
