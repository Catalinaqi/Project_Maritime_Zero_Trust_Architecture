#!/bin/bash
# ====================================================================
# FILE: execute_tests_nftables.sh
# SCRIPT DI AUTOMAZIONE ED ESECUZIONE DELLA MATRICE DI CONNETTIVITÀ ZTA
# ====================================================================

# ====================================================================
# 1. MOCK ENVIRONMENT (Sincronizzato con docker-compose.yml)
# ====================================================================
# Inseriamo i valori predefiniti qui poiché non utilizziamo un file .env globale
FW_VPN_IP="172.20.11.10"
FW_SAT_IP="172.20.12.10"
FW_CORP_IP="172.20.10.10"
FW_PUB_IP="172.20.13.10"

TARGET_IP_VPN="172.20.11.30"
TARGET_IP_SAT="172.20.12.30"
TARGET_IP_CORP="172.20.10.30"

PEP_PORT="8443"
API_PORT="3000"
MONGO_PORT="27017"
ENVOY_ADMIN_PORT="9901"

OPA_IP="172.20.2.6"
OPA_PORT="8181"
API_IP="172.20.3.20"

SWTPM_IP="172.20.11.30"

# Nomi dei container reali nel compose
CONTAINER_VPN="client_d001_tpm"
CONTAINER_SAT="client_d002_tpm"
CONTAINER_CORP="client_dsoc_tpm"
CONTAINER_ENVOY="pep_gateway"

# Creiamo un container alpino temporaneo per simulare un attaccante pubblico
CONTAINER_PUB="public_attacker_temp"

# Reset dei contatori
PASSED=0
FAILED=0

echo "===================================================================="
echo "AVVIO DEL PIANO DI TEST AUTOMATIZZATO: ZERO TRUST ARCHITECTURE"
echo "===================================================================="

# Creazione container pubblico temporaneo se non esiste
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_PUB}$"; then
    echo "[!] Creazione container temporaneo per test Rete Pubblica..."
    docker run -d --rm --name "$CONTAINER_PUB" --network maritime-zta_public alpine sleep 3600 >/dev/null
fi

# ====================================================================
# FUNZIONI DI VALIDAZIONE
# ====================================================================
assert_accept() {
    local container=$1; local ip=$2; local port=$3; local id=$4; local desc=$5
    echo -e "\n[\033[1;34m$id\033[0m] $desc"
    echo "-> Test: docker exec $container curl -v --connect-timeout 3 http://$ip:$port"

    if docker exec "$container" curl -v --connect-timeout 3 "http://$ip:$port" 2>&1 | grep -qi "Connected to"; then
        echo -e "\033[0;32m✓ ESITO: PERMESSO (ACCEPT) - TEST SUPERATO\033[0m"
        ((PASSED++))
    else
        echo -e "\033[0;31m✗ ESITO: ERRORE (CONNESSIONE FALLITA) - TEST FALLITO\033[0m"
        ((FAILED++))
    fi
}

assert_drop() {
    local container=$1; local ip=$2; local port=$3; local id=$4; local desc=$5; local splunk_query=$6
    echo -e "\n[\033[1;34m$id\033[0m] $desc"
    echo "-> Test: docker exec $container curl -v --connect-timeout 3 http://$ip:$port"

    if docker exec "$container" curl -v --connect-timeout 3 "http://$ip:$port" 2>&1 | grep -qi "Connected to"; then
        echo -e "\033[0;31m✗ ESITO: PERMESSO (ACCEPT) - TEST FALLITO (Dovrebbe essere bloccato!)\033[0m"
        ((FAILED++))
    else
        echo -e "\033[0;32m✓ ESITO: BLOCCATO (DROP) - TEST SUPERATO\033[0m"
        echo -e "\033[0;33m[AUDIT SIEM] Verifica query in Splunk: $splunk_query\033[0m"
        ((PASSED++))
    fi
}

# ====================================================================
# CATEGORIA 1: FLUSSI LEGITTIMI E ACCESSO PERIMETRALE (CASI POSITIVI)
# Il NAT traduce le richieste verso la porta PEP del Firewall in Envoy.
# ====================================================================
assert_accept "$CONTAINER_VPN" "$FW_VPN_IP" "$PEP_PORT" "TC-01" "Accesso legittimo VPN verso PEP Gateway (Envoy)"
assert_accept "$CONTAINER_SAT" "$FW_SAT_IP" "$PEP_PORT" "TC-02" "Accesso legittimo SATELLITE verso PEP Gateway"
assert_accept "$CONTAINER_CORP" "$FW_CORP_IP" "$PEP_PORT" "TC-03" "Accesso legittimo CORPORATE verso PEP Gateway"
assert_accept "$CONTAINER_PUB" "$FW_PUB_IP" "$PEP_PORT" "TC-04" "Accesso legittimo PUBLIC verso PEP Gateway"

# ====================================================================
# CATEGORIA 2: TRAFFICO DI BACKEND INTERNO
# ====================================================================
assert_accept "$CONTAINER_ENVOY" "$OPA_IP" "$OPA_PORT" "TC-05" "Plano di Controllo: Interrogazione policy da Envoy a OPA Engine"
assert_accept "$CONTAINER_ENVOY" "$API_IP" "$API_PORT" "TC-06" "Inoltro del traffico validato da Envoy verso API Backend"

# ====================================================================
# CATEGORIA 3: SICUREZZA RIGOROSA E ISOLAMENTO (CASI NEGATIVI - BYPASS)
# Regola CHAIN INPUT: Nessuna eccezione, tutto scartato e loggato.
# ====================================================================
assert_drop "$CONTAINER_VPN" "$FW_VPN_IP" "$API_PORT" "TC-07" "Tentativo Bypass: Attacco diretto da VPN a API Backend" "index=* \"NFT-INPUT-DROP\""
assert_drop "$CONTAINER_VPN" "$FW_VPN_IP" "$MONGO_PORT" "TC-08" "Tentativo Bypass: Attacco diretto al DB MongoDB da VPN" "index=* \"NFT-INPUT-DROP\""
assert_drop "$CONTAINER_VPN" "$FW_VPN_IP" "$ENVOY_ADMIN_PORT" "TC-09" "Tentativo Bypass: Accesso non autorizzato ad Admin Envoy" "index=* \"NFT-INPUT-DROP\""

# ====================================================================
# CATEGORIA 4: PREVENZIONE DEL MOVIMENTO LATERALE (ZERO TRUST CORE)
# Regola CHAIN FORWARD: Verifica drop incrociati tra le zone
# ====================================================================
assert_drop "$CONTAINER_VPN" "$TARGET_IP_SAT" "80" "TC-10" "Movimento Laterale: VPN verso Satellitare" "index=* \"NFT-LATERAL-VPN-SAT\""
assert_drop "$CONTAINER_SAT" "$TARGET_IP_VPN" "80" "TC-11" "Movimento Laterale: Satellitare verso VPN" "index=* \"NFT-LATERAL-SAT-VPN\""
assert_drop "$CONTAINER_PUB" "$TARGET_IP_VPN" "80" "TC-12" "Movimento Laterale: Pubblica verso VPN" "index=* \"NFT-LATERAL-PUB-VPN\""
assert_drop "$CONTAINER_PUB" "$TARGET_IP_SAT" "80" "TC-13" "Movimento Laterale: Pubblica verso Satellitare" "index=* \"NFT-LATERAL-PUB-SAT\""
assert_drop "$CONTAINER_PUB" "$TARGET_IP_CORP" "80" "TC-14" "Movimento Laterale: Pubblica verso Corporate" "index=* \"NFT-LATERAL-PUB-CORP\""

# ====================================================================
# CATEGORIA 5: DEFAULT DENY & ROOT OF TRUST
# ====================================================================
assert_drop "$CONTAINER_VPN" "$SWTPM_IP" "2321" "TC-15" "Isolamento Root of Trust: Blocco transito traffico TPM su Firewall" "index=* \"NFT-FORWARD-DROP\""

echo -e "\n===================================================================="
echo "RIASSUNTO DELLE PROVE"
echo "===================================================================="
echo -e "Test Superati: \033[0;32m$PASSED\033[0m"
echo -e "Test Falliti:  \033[0;31m$FAILED\033[0m"
echo "===================================================================="

# Pulizia finale
docker stop "$CONTAINER_PUB" >/dev/null 2>&1 || true
