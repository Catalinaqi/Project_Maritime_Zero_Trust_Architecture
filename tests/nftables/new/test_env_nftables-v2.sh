#!/bin/bash
# ====================================================================
# FILE 1: test_env_nftables.sh
# CONFIGURAZIONE DELLE VARIABILI D'AMBIENTE PER IL PIAN DI TEST ZTA
# ====================================================================

# --------------------------------------------------------------------
# NOMI DEI CONTAINER DOCKER (Origini ed esecutori dei test)
# --------------------------------------------------------------------
export CONTAINER_VPN="client_d001_tpm"
export CONTAINER_SAT="client_d002_tpm"
export CONTAINER_CORP="client_dsoc_tpm"
export CONTAINER_PUB="client_intruso" # Da creare o mappare se esiste nel Compose
export CONTAINER_ENVOY="pep_gateway"
export CONTAINER_API="api_backend"
export CONTAINER_TPM="client_d001_tpm"

# --------------------------------------------------------------------
# INDIRIZZI IP DEL FIREWALL NELLE RETI CLIENT (Target per i test)
# --------------------------------------------------------------------
export FW_VPN_IP="172.20.11.10"
export FW_SAT_IP="172.20.12.10"
export FW_CORP_IP="172.20.10.10"
export FW_PUB_IP="172.20.13.10"

# --------------------------------------------------------------------
# INDIRIZZI IP DEI COMPONENTI INTERNI DELL'ARCHITETTURA
# --------------------------------------------------------------------
export ENVOY_IP="172.20.2.7"
export API_IP="172.20.3.20"
export MONGODB_IP="172.20.3.5"
export OPA_IP="172.20.2.6"
export SPLUNK_IP="172.20.4.8"
export SNORT_IP="172.20.4.11"
export SWTPM_IP="172.20.11.30"

# --------------------------------------------------------------------
# PORTE DEI SERVIZI
# --------------------------------------------------------------------
export PEP_PORT="8443"
export API_PORT="3000"
export MONGO_PORT="27017"
export OPA_PORT="9191"
export ENVOY_ADMIN_PORT="9901"
export SIEM_HEC_PORT="8088"
export SIEM_WEB_PORT="8000"

# --------------------------------------------------------------------
# ENDPOINT PER I TEST DI MOVIMENTO LATERALE
# (IP fittizi o reali per testare il blocco del traffico tra subnet)
# --------------------------------------------------------------------
export TARGET_IP_SAT="172.20.12.5"
export TARGET_IP_VPN="172.20.11.5"
export TARGET_IP_CORP="172.20.10.5"
export TARGET_IP_PUB="172.20.13.5"
