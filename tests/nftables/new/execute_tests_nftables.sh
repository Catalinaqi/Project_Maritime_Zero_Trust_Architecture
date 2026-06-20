#!/bin/bash
# ====================================================================
# FILE 2: execute_tests.sh
# SCRIPT DI AUTOMAZIONE ED ESECUZIONE DELLA MATRICE DI CONNETTIVITÀ ZTA
# ====================================================================

# Carica le variabili d'ambiente
if [ -f "./test_env_nftables.sh" ]; then
    source ./test_env_nftables.sh
else
    echo "Errore: test_env_nftables.sh non trovato!"
    exit 1
fi

# Reset dei contatori
PASSED=0
FAILED=0

echo "===================================================================="
echo "AVVIO DEL PIANO DI TEST AUTOMATIZZATO: ZERO TRUST ARCHITECTURE"
echo "===================================================================="

# Funzioni di validazione assert (AGGIORNATO CON CURL)
assert_accept() {
    local container=$1; local ip=$2; local port=$3; local id=$4; local desc=$5
    echo -e "\n[\033[1;34m$id\033[0m] $desc"
    echo "-> Test: docker exec $container curl -v --connect-timeout 3 http://$ip:$port"

    # Verificamos si se logra completar el Handshake TCP (Connected to)
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

    # Si se logra conectar, es un fallo (porque el firewall debió bloquearlo)
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
# ====================================================================
# MODIFICADO: El cliente ataca al Firewall, y el Firewall hace NAT hacia Snort/Envoy
assert_accept "$CONTAINER_VPN" "$NFTABLES_FIREWALL_IP" "$NFTABLES_PEP_PORT" "TC-01" "Accesso utente legittimo VPN verso PEP Gateway (Envoy)"
assert_accept "$CONTAINER_ENVOY" "$NFTABLES_OPA_IP" "$NFTABLES_OPA_PORTS" "TC-02" "Plano di Controllo: Interrogazione policy da Envoy a OPA Engine"
assert_accept "$CONTAINER_ENVOY" "$NFTABLES_API_IP" "$NFTABLES_API_PORT" "TC-03" "Inoltro del traffico validato da Envoy verso API Backend"
assert_accept "$CONTAINER_API" "$NFTABLES_MONGODB_IP" "$NFTABLES_MONGO_PORT" "TC-04" "Accesso alla persistenza dati da API Backend a MongoDB"

# ====================================================================
# CATEGORIA 2: SICUREZZA RIGOROSA E ISOLAMENTO (CASI NEGATIVI)
# ====================================================================
# MODIFICADO: El atacante intenta tocar puertos prohibidos apuntando al Firewall
assert_drop "$CONTAINER_VPN" "$NFTABLES_FIREWALL_IP" "$NFTABLES_API_PORT" "TC-05" "Tentativo di Bypass del PEP: Attacco diretto da VPN a API Backend" "index=* \"DPT=3000\""
assert_drop "$CONTAINER_VPN" "$NFTABLES_FIREWALL_IP" "$NFTABLES_MONGO_PORT" "TC-06" "Tentativo di attacco diretto al DB MongoDB da rete esterna" "index=* \"DPT=27017\""
assert_drop "$CONTAINER_VPN" "$NFTABLES_FIREWALL_IP" "$NFTABLES_ENVOY_ADMIN_PORT" "TC-07" "Tentativo di accesso non autorizzato alla porta Admin di Envoy" "index=* \"DPT=9901\""

# ====================================================================
# CATEGORIA 3: PREVENZIONE DEL MOVIMENTO LATERALE (ZERO TRUST CORE)
# ====================================================================
assert_drop "$CONTAINER_VPN" "$TARGET_IP_SAT" "80" "TC-08" "Movimento Laterale: Salto da rete VPN a rete Satellitare" "index=main \"LATERAL_VPN_SAT\""
assert_drop "$CONTAINER_SAT" "$TARGET_IP_VPN" "80" "TC-09" "Movimento Laterale: Salto da rete Satellitare a rete VPN" "index=main \"LATERAL_SAT_VPN\""

# ====================================================================
# CATEGORIA 4: ISOLAMENTO ROOT OF TRUST (CASO SPECIALE TPM)
# ====================================================================
assert_drop "$CONTAINER_TPM" "$NFTABLES_SWTPM_IP" "2321" "TC-10" "Isolamento Root of Trust: Blocco transito traffico TPM su Firewall perimetrale" "index=main \"DROP\""

echo -e "\n===================================================================="
echo "RIASSUNTO DELLE PROVE"
echo "===================================================================="
echo -e "Test Superati: \033[0;32m$PASSED\033[0m"
echo -e "Test Falliti:  \033[0;31m$FAILED\033[0m"
echo "===================================================================="
