#!/bin/sh

# Interrompe lo script in caso di errore o variabile non definita.
set -eu

# Indirizzo del firewall nella rete Zero Trust.
FIREWALL_IP="${FIREWALL_ZEROTRUST_IP:-172.20.2.10}"

# Sottoreti nelle quali si trovano i client.
CORPORATE_NET="${NETWORK_CORPORATE_SUBNET:-172.20.10.0/24}"
VPN_NET="${NETWORK_VPN_SUBNET:-172.20.11.0/24}"
SATELLITE_NET="${NETWORK_SATELLITE_SUBNET:-172.20.12.0/24}"
PUBLIC_NET="${NETWORK_PUBLIC_SUBNET:-172.20.13.0/24}"

echo "Configurazione route di ritorno di Envoy..."

# Le risposte destinate alla rete corporate devono tornare al firewall.
ip route replace "$CORPORATE_NET" via "$FIREWALL_IP"

# Le risposte destinate alla VPN devono tornare al firewall.
ip route replace "$VPN_NET" via "$FIREWALL_IP"

# Le risposte destinate alla rete satellitare devono tornare al firewall.
ip route replace "$SATELLITE_NET" via "$FIREWALL_IP"

# Le risposte destinate alla rete pubblica devono tornare al firewall.
ip route replace "$PUBLIC_NET" via "$FIREWALL_IP"

echo "Route di ritorno configurate:"
ip route

# Avvia il comando ricevuto dal Dockerfile o dal Compose.
exec "$@"