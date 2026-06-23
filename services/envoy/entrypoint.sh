#!/bin/sh
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

FIREWALL_IP="${FIREWALL_ZEROTRUST_IP:-172.20.2.10}"
for subnet in \
    "${NETWORK_CORPORATE_SUBNET:-172.20.10.0/24}" \
    "${NETWORK_VPN_SUBNET:-172.20.11.0/24}" \
    "${NETWORK_SATELLITE_SUBNET:-172.20.12.0/24}" \
    "${NETWORK_PUBLIC_SUBNET:-172.20.13.0/24}"; do
    ip route replace "$subnet" via "$FIREWALL_IP"
done

exec "$@"
