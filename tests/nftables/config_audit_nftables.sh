#!/bin/bash
# =============================================================================
# MARITIME ZTA - CONFIGURAZIONE DELL'AUDIT DI NFTABLES (FIREWALL PERIMETRALE)
# File: config_audit_nftables.sh
# =============================================================================

export FW_CONTAINER="firewall_perimeter"
export REPORT_FILE="report_tests_nftables.txt"

# -----------------------------------------------------------------------------
# INDIRIZZO IP DEL FIREWALL IN OGNI RETE (Target per DNAT e INPUT)
# -----------------------------------------------------------------------------
export FW_ZEROTRUST_IP="172.20.2.10"
export FW_MONITORING_IP="172.20.4.10"
export FW_CORPORATE_IP="172.20.10.10"
export FW_VPN_IP="172.20.11.10"
export FW_SATELLITE_IP="172.20.12.10"
export FW_PUBLIC_IP="172.20.13.10"

# -----------------------------------------------------------------------------
# INDIRIZZI DEI CLIENT (Target per Movimento Laterale / FORWARD)
# -----------------------------------------------------------------------------
export CLIENT_D001_IP="172.20.11.31"
export CLIENT_D002_IP="172.20.12.31"
export CLIENT_DSOC_IP="172.20.10.31"

# -----------------------------------------------------------------------------
# SERVIZI INTERNI (Uso informativo, il FW li protegge)
# -----------------------------------------------------------------------------
export ENVOY_IP="172.20.2.7"
export OPA_IP="172.20.2.6"
export MONGO_IP="172.20.3.5"
export API_IP="172.20.3.20"
export SPLUNK_IP="172.20.2.8"

# -----------------------------------------------------------------------------
# PORTE
# -----------------------------------------------------------------------------
export ENVOY_PORT=8443
export OPA_PORT=8181
export MONGO_PORT=27017
export API_PORT=3000
export SPLUNK_WEB_PORT=8000
export SPLUNK_HEC_PORT=8088

# -----------------------------------------------------------------------------
# CONTENITORI CLIENT (Origine degli attacchi)
# -----------------------------------------------------------------------------
export CLIENT_D001="client_d001_tpm"
export CLIENT_D002="client_d002_tpm"
export CLIENT_DSOC="client_dsoc_tpm"

export NFT_LOG_FILE="/var/log/nftables/ulogd-alerts.log"
export RED='\033[0;31m'; export GREEN='\033[0;32m'; export YELLOW='\033[1;33m'; export BLUE='\033[0;34m'; export CYAN='\033[0;36m'; export NC='\033[0m'
