#!/bin/bash
# ====================================================================
# FILE 2: execute_tests.sh
# SCRIPT DI AUTOMAZIONE ED ESECUZIONE DELLA MATRICE DI CONNETTIVITÀ ZTA
# ====================================================================

# Carica le variabili d'ambiente
if [ -f "./test_env_nftables.sh" ]; then
    source ./test_env_nftables-v2.sh
else
    echo "Errore: test_env_nftables-v2.sh non trovato!"
    exit 1
fi

# Reset dei contatori
PASSED=0
FAILED=0

echo "===================================================================="
echo "AVVIO DEL PIANO DI TEST AUTOMATIZZATO: ZERO TRUST ARCHITECTURE"
echo "===================================================================="

# Funzioni di validazione assert
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
assert_accept "$CONTAINER_VPN" "$FW_VPN_IP" "$PEP_PORT" "TC-01" "Accesso utente legittimo VPN verso PEP Gateway (Envoy)"
assert_accept "$CONTAINER_SAT" "$FW_SAT_IP" "$PEP_PORT" "TC-02" "Accesso utente legittimo SATELLITE verso PEP Gateway"

# I componenti di backend comunicano tra loro direttamente nelle reti interne.
assert_accept "$CONTAINER_ENVOY" "$OPA_IP" "$OPA_PORT" "TC-03" "Plano di Controllo: Interrogazione policy da Envoy a OPA Engine"
assert_accept "$CONTAINER_ENVOY" "$API_IP" "$API_PORT" "TC-04" "Inoltro del traffico validato da Envoy verso API Backend"

# ====================================================================
# CATEGORIA 2: SICUREZZA RIGOROSA E ISOLAMENTO (CASI NEGATIVI - BYPASS)
# Il NAT non esiste per queste porte, vengono scartate in INPUT o FORWARD.
# ====================================================================
assert_drop "$CONTAINER_VPN" "$FW_VPN_IP" "$API_PORT" "TC-05" "Tentativo Bypass: Attacco diretto da VPN a API Backend" "index=* \"NFT-INPUT-DROP\""
assert_drop "$CONTAINER_VPN" "$FW_VPN_IP" "$MONGO_PORT" "TC-06" "Tentativo Bypass: Attacco diretto al DB MongoDB da VPN" "index=* \"NFT-INPUT-DROP\""
assert_drop "$CONTAINER_VPN" "$FW_VPN_IP" "$ENVOY_ADMIN_PORT" "TC-07" "Tentativo Bypass: Accesso non autorizzato ad Admin Envoy" "index=* \"NFT-INPUT-DROP\""

# ====================================================================
# CATEGORIA 3: PREVENZIONE DEL MOVIMENTO LATERALE (ZERO TRUST CORE)
# Verifica delle regole di FORWARD per bloccare il traffico tra reti.
# ====================================================================
assert_drop "$CONTAINER_VPN" "$TARGET_IP_SAT" "80" "TC-08" "Movimento Laterale: Salto da VPN a rete Satellitare" "index=* \"NFT-LATERAL-VPN-SAT\""
assert_drop "$CONTAINER_SAT" "$TARGET_IP_VPN" "80" "TC-09" "Movimento Laterale: Salto da Satellitare a rete VPN" "index=* \"NFT-LATERAL-SAT-VPN\""

# Test sulle nuove regole per la rete Pubblica
assert_drop "$CONTAINER_PUB" "$TARGET_IP_VPN" "80" "TC-10" "Movimento Laterale: Salto da Pubblica a VPN" "index=* \"NFT-LATERAL-PUB-VPN\""
assert_drop "$CONTAINER_PUB" "$TARGET_IP_CORP" "80" "TC-11" "Movimento Laterale: Salto da Pubblica a Corporate" "index=* \"NFT-LATERAL-PUB-CORP\""

# ====================================================================
# CATEGORIA 4: ISOLAMENTO ROOT OF TRUST (CASO SPECIALE TPM)
# Nessuna regola di forward permette l'accesso esterno ai servizi TPM.
# ====================================================================
assert_drop "$CONTAINER_VPN" "$SWTPM_IP" "2321" "TC-12" "Isolamento Root of Trust: Blocco transito traffico TPM su Firewall" "index=* \"NFT-FORWARD-DROP\""

echo -e "\n===================================================================="
echo "RIASSUNTO DELLE PROVE"
echo "===================================================================="
echo -e "Test Superati: \033[0;32m$PASSED\033[0m"
echo -e "Test Falliti:  \033[0;31m$FAILED\033[0m"
echo "===================================================================="
