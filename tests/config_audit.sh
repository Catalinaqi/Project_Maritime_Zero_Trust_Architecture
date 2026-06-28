#!/bin/bash
# =============================================================================
# MARITIME ZTA - CONFIGURAZIONE UNIFICATA PER AUDIT NFTABLES E SNORT
# File: config_audit.sh
# =============================================================================

# --- Container names (comuni a entrambi) ---
export FW_CONTAINER="firewall_perimeter"
export ENVOY_CONTAINER="pep_gateway"
export CLIENT_D001="client_d001_tpm"
export CLIENT_D002="client_d002_tpm"
export CLIENT_DSOC="client_dsoc_tpm"

# Directory script e cartella output
AUDIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$AUDIT_DIR/out"

# --- File di report separati per i due audit ---
export REPORT_FILE_NFTABLES="$AUDIT_DIR/out/report_tests_nftables.txt"
export REPORT_FILE_SNORT="$AUDIT_DIR/out/report_tests_snort.txt"

# -------------------------------------------------------------------------
# INDIRIZZI IP DEL FIREWALL SU CIASCUNA RETE
# (usati come target nei test di nftables e snort)
# -------------------------------------------------------------------------
export FW_ZEROTRUST_IP="172.20.2.10"
export FW_MONITORING_IP="172.20.4.10"
export FW_CORPORATE_IP="172.20.10.10"
export FW_VPN_IP="172.20.11.10"
export FW_SATELLITE_IP="172.20.12.10"
export FW_PUBLIC_IP="172.20.13.10"

# Alias per compatibilità con test_audit_snort.sh (nomi TARGET_*)
export TARGET_VPN_IP="$FW_VPN_IP"
export TARGET_CORPORATE_IP="$FW_CORPORATE_IP"
export TARGET_SATELLITE_IP="$FW_SATELLITE_IP"

# -------------------------------------------------------------------------
# INDIRIZZI DEI CLIENT (per test movimento laterale con nftables)
# -------------------------------------------------------------------------
export CLIENT_D001_IP="172.20.11.31"
export CLIENT_D002_IP="172.20.12.31"
export CLIENT_DSOC_IP="172.20.10.31"

# -------------------------------------------------------------------------
# ENVOY PEP GATEWAY - IP su ogni rete
# (usati da nftables per le regole DNAT/FORWARD)
# -------------------------------------------------------------------------
# IP principale nella rete Zero Trust (Usato da nftables per il bersaglio DNAT)
export ENVOY_IP="172.20.2.7"
# IP secondari di Envoy nelle varie reti (A causa della topologia attuale)
export ENVOY_BACKEND_IP="172.20.3.7"
export ENVOY_CORPORATE_IP="172.20.10.7"
export ENVOY_VPN_IP="172.20.11.7"
export ENVOY_SATELLITE_IP="172.20.12.7"
export ENVOY_PUBLIC_IP="172.20.13.7"

# -------------------------------------------------------------------------
# ALTRI SERVIZI INTERNI (per informazione)
# -------------------------------------------------------------------------
export OPA_IP="172.20.2.6"
export MONGO_IP="172.20.3.5"
export API_IP="172.20.3.20"
export SPLUNK_IP="172.20.2.8"

# -------------------------------------------------------------------------
# PORTE (unificate)
# -------------------------------------------------------------------------
export ENVOY_PORT=8443
export OPA_PORT=8181
export MONGO_PORT=27017
export API_PORT=3000
export SPLUNK_WEB_PORT=8000
export SPLUNK_HEC_PORT=8088
export PORT_ENVOY_ADMIN=9901
export PORT_SSH=22

# Alias per test_audit_snort.sh (nomi PORT_*)
export PORT_PEP="$ENVOY_PORT"
export PORT_MONGO="$MONGO_PORT"
export PORT_API="$API_PORT"
export PORT_OPA="$OPA_PORT"
export PORT_SPLUNK_WEB="$SPLUNK_WEB_PORT"
export PORT_SPLUNK_HEC="$SPLUNK_HEC_PORT"

# -------------------------------------------------------------------------
# LOG E COLORI
# -------------------------------------------------------------------------
export NFT_LOG_FILE="/var/log/nftables/ulogd-alerts.log"

# Log Snort
export SNORT_ALERT_FILE="/var/log/snort/alert_json.txt"   # Alert JSON di Snort

export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export CYAN='\033[0;36m'
export NC='\033[0m'
