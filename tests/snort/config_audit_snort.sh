# =============================================================================
# MARITIME ZTA - CONFIGURAZIONE DELL'AUDIT DI SICUREZZA (VERSIONE COMPLETA)
# File: config_audit_snort.sh
# =============================================================================

# Configurazione Generale
export REPORT_FILE="report_tests_snort.txt"
export SNORT_CONTAINER="ids_network_monitor"

# -----------------------------------------------------------------------------
# IP DEI TARGET – IP del firewall in ogni rete
# -----------------------------------------------------------------------------
export TARGET_VPN_IP="172.20.11.10"      # Firewall/Snort su vpn_net
export TARGET_ZT_IP="172.20.2.10"        # Firewall/Snort su zerotrust_net
export TARGET_SATELLITE_IP="172.20.12.10" # Firewall/Snort su satellite_net
export TARGET_CORPORATE_IP="172.20.10.10" # Firewall/Snort su corporate_net

# -----------------------------------------------------------------------------
# PORTE DEFINITE NELLE REGOLE SNORT
# -----------------------------------------------------------------------------
export PORT_PEP=8443
export PORT_API=3000
export PORT_MONGO=27017
export PORT_OPA=8181
export PORT_OPA_ADMIN=8282   # Non presente nelle regole, ma usato per admin
export PORT_ENVOY_ADMIN=9901
export PORT_SPLUNK_WEB=8000
export PORT_SPLUNK_HEC=8088
export PORT_SSH=22

# -----------------------------------------------------------------------------
# COLORI PER LA CONSOLE
# -----------------------------------------------------------------------------
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export CYAN='\033[0;36m'
export NC='\033[0m'
