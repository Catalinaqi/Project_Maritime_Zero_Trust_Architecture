#!/bin/bash
# ====================================================================
# FILE 1: test_env.sh
# CONFIGURAZIONE DELLE VARIABILI D'AMBIENTE PER IL PIAN DI TEST ZTA
# ====================================================================

# Nomi dei Container Docker (Origini dei test)
export CONTAINER_VPN="client_d001_tpm"
export CONTAINER_SAT="client_d002_tpm"
export CONTAINER_CORP="client_dsoc_tpm"
export CONTAINER_ENVOY="pep_gateway"
export CONTAINER_API="api_backend"
export CONTAINER_TPM="client_d001_tpm"

# Indirizzi IP dell'Architettura
export NFTABLES_VPN_NET="172.20.11.0/24"
export NFTABLES_SATELLITE_NET="172.20.12.0/24"
export NFTABLES_CORPORATE_NET="172.20.10.0/24"

export NFTABLES_ENVOY_IP="172.20.2.7"
export NFTABLES_API_IP="172.20.3.20"
export NFTABLES_MONGODB_IP="172.20.3.5"
export NFTABLES_OPA_IP="172.20.2.6"
export NFTABLES_SPLUNK_IP="172.20.4.8"
export NFTABLES_SNORT_IP="172.20.4.11"
export NFTABLES_SWTPM_IP="172.20.11.30"

# Porte dei Servizi
export NFTABLES_PEP_PORT="8443"
export NFTABLES_API_PORT="3000"
export NFTABLES_MONGO_PORT="27017"
export NFTABLES_OPA_PORTS="9191"
export NFTABLES_ENVOY_ADMIN_PORT="9901"
export NFTABLES_SIEM_HEC_PORT="8088"
export NFTABLES_SIEM_WEB_PORT="8000"

# Definizione dinamica degli endpoint per i test di movimento laterale
export TARGET_IP_SAT="172.20.12.5"  # IP di un contenitore satellite fittizio
export TARGET_IP_VPN="172.20.11.5"  # IP di un contenitore VPN fittizio

export NFTABLES_FIREWALL_IP="172.20.11.10"
