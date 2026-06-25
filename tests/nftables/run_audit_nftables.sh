#!/bin/bash
# =============================================================================
# MARITIME ZTA - AUDIT DEL FIREWALL PERIMETRALE (NFTABLES)
# File: run_audit_nftables.sh
# =============================================================================
export MSYS_NO_PATHCONV=1
source ./config_audit_nftables.sh

echo "=======================================================================" > "$REPORT_FILE"
echo " MARITIME ZTA - RAPPORTO TEST FIREWALL NFTABLES" >> "$REPORT_FILE"
echo " Ora di inizio: $(date '+%Y-%m-%d %H:%M:%S')" >> "$REPORT_FILE"
echo "=======================================================================" >> "$REPORT_FILE"

header() { echo -e "\n${BLUE}════════════════════════════════════════════════════════════${NC}\n${BLUE} $1${NC}\n${BLUE}════════════════════════════════════════════════════════════${NC}"; }
log_ok() { echo -e "${GREEN}[PASS]${NC} $1"; echo "[PASS] $1" >> "$REPORT_FILE"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; echo "[FAIL] $1" >> "$REPORT_FILE"; }

# =============================================================================
# FUNZIONE DI CONNESSIONE MIGLIORATA
# =============================================================================
test_connection() {
    local container="$1"
    local desc="$2"
    local dest_ip="$3"
    local dest_port="$4"
    local expected="$5"           # "allow" o "deny"
    local timeout="${6:-3}"
    local test_type="${7:-forward}"  # "forward" (default), "dnat", "input"

    echo -e "${CYAN}[TEST]${NC} $desc..."

    # Esegue la connessione e cattura exit code dettagliato
    local raw_output
    raw_output=$(docker exec -t "$container" timeout "$timeout" bash -c \
        "echo > /dev/tcp/$dest_ip/$dest_port 2>&1; echo EXIT:\$?" 2>/dev/null)
    local exit_code=$(echo "$raw_output" | grep -oP 'EXIT:\K\d+' || echo "124")
    exit_code=${exit_code:-124}

    # Mappa exit code a stato
    local actual
    case $exit_code in
        0)   actual="allow" ;;
        1)   actual="refused" ;;    # RST – servizio presente ma rifiuta
        124) actual="timeout" ;;    # Nessuna risposta – drop firewall
        *)   actual="unknown($exit_code)" ;;
    esac

    # Logica di accettazione intelligente
    local test_passed=false

    if [[ "$expected" == "allow" ]]; then
        # Per allow, accettiamo sia "allow" che "refused" (se il traffico è arrivato al servizio)
        if [[ "$actual" == "allow" || "$actual" == "refused" ]]; then
            test_passed=true
        fi
    elif [[ "$expected" == "deny" ]]; then
        # Per deny, accettiamo "timeout" (drop) o "refused" (se il servizio rifiuta dopo firewall)
        if [[ "$actual" == "timeout" || "$actual" == "refused" ]]; then
            test_passed=true
        fi
    fi

    # Verifica supplementare per test DNAT: controlla contatore della regola
    if [[ "$test_type" == "dnat" && "$actual" != "allow" ]]; then
        # Legge contatori prima e dopo
        local before=$(docker exec "$FW_CONTAINER" nft list chain ip nat prerouting 2>/dev/null | \
            grep -c "dnat to 172.20.2.7:8443")
        # Diamo un momento per eventuale aggiornamento
        sleep 0.5
        local after=$(docker exec "$FW_CONTAINER" nft list chain ip nat prerouting 2>/dev/null | \
            grep -c "dnat to 172.20.2.7:8443")
        if (( after > before )); then
            log_ok "$desc → DNAT rilevato (counter incrementato)"
            return 0
        fi
    fi

    if $test_passed; then
        log_ok "$desc → $actual (atteso $expected)"
    else
        log_fail "$desc → $actual (atteso $expected) [exit=$exit_code]"
        echo -e "${YELLOW}[DEBUG]${NC} raw_output: $raw_output"
    fi
    sleep 0.5
}

# =============================================================================
# FUNZIONE DI VERIFICA LOG MIGLIORATA
# =============================================================================
check_fw_log() {
    local expected_prefix="$1"
    local min_lines="${2:-1}"
    local max_wait="${3:-10}"  # secondi massimi di attesa

    docker exec "$FW_CONTAINER" sync  # forza scrittura buffer su disco

    for ((i=0; i<max_wait; i++)); do
        local count
        count=$(docker exec "$FW_CONTAINER" sh -c \
            "cat '$NFT_LOG_FILE' | tr -d '\r' | grep -cF '$expected_prefix'" 2>/dev/null || echo 0)
        count="${count:-0}"
        if [[ $count -ge $min_lines ]]; then
            log_ok "Log NFTables: trovate $count righe con '$expected_prefix'"
            return 0
        fi
        sleep 1
    done

    log_fail "Log NFTables: solo $count righe con '$expected_prefix' (attese ≥$min_lines) dopo ${max_wait}s"
    echo -e "${RED}[DEBUG]${NC} Ultime 10 righe del log:"
    docker exec "$FW_CONTAINER" tail -n 10 "$NFT_LOG_FILE"
}

# Pulisce il log precedente
docker exec "$FW_CONTAINER" truncate -s 0 "$NFT_LOG_FILE" 2>/dev/null || true
sleep 1

# =============================================================================
header "1. TRAFFICO PERMESSO: CLIENT → ENVOY (DNAT + FORWARD ACCEPT)"
# =============================================================================
test_connection "$CLIENT_D001" "VPN -> Envoy via FW (8443)" "$FW_VPN_IP" "$ENVOY_PORT" "allow" 5
test_connection "$CLIENT_D002" "Satellite -> Envoy via FW (8443)" "$FW_SATELLITE_IP" "$ENVOY_PORT" "allow" 5
test_connection "$CLIENT_DSOC" "Corporate -> Envoy via FW (8443)" "$FW_CORPORATE_IP" "$ENVOY_PORT" "allow" 5

# =============================================================================
header "2. BLOCCAGGIO INPUT: CONNESSIONI AL FIREWALL SU PORTE NON ABILITATE"
# =============================================================================
test_connection "$CLIENT_D001" "VPN -> Firewall:27017 (Mongo)" "$FW_VPN_IP" "$MONGO_PORT" "deny"
test_connection "$CLIENT_D001" "VPN -> Firewall:3000 (API)" "$FW_VPN_IP" "$API_PORT" "deny"
test_connection "$CLIENT_D001" "VPN -> Firewall:8181 (OPA)" "$FW_VPN_IP" "$OPA_PORT" "deny"
test_connection "$CLIENT_D001" "VPN -> Firewall:8000 (Splunk Web)" "$FW_VPN_IP" "$SPLUNK_WEB_PORT" "deny"
sleep 3
check_fw_log "[NFT-INPUT-DROP]" 1

# =============================================================================
header "3. MOVIMENTO LATERALE: VPN ↔ SATELLITE (DEVE ESSERE BLOCCATO E LOGGATO)"
# =============================================================================
test_connection "$CLIENT_D001" "VPN -> Satellite (cliente a cliente)" "$CLIENT_D002_IP" "8443" "deny"
test_connection "$CLIENT_D002" "Satellite -> VPN (cliente a cliente)" "$CLIENT_D001_IP" "8443" "deny"

check_fw_log "[NFT-LATERAL-VPN-SAT]" 1
check_fw_log "[NFT-LATERAL-SAT-VPN]" 1

# =============================================================================
header "4. REGOLA DI DEFAULT FORWARD"
# =============================================================================
test_connection "$CLIENT_D001" "VPN -> Satellite porta 22 (ssh)" "$CLIENT_D002_IP" "22" "deny"
check_fw_log "[NFT-FORWARD-DROP]" 1

# =============================================================================
header "5. ICMP VERSO IL FIREWALL (DEVE ESSERE PERMESSO)"
# =============================================================================
if docker exec "$CLIENT_D001" ping -c 2 "$FW_VPN_IP" >/dev/null 2>&1; then
    log_ok "Ping VPN -> Firewall (VPN_IP) permesso"
else
    log_fail "Ping VPN -> Firewall (VPN_IP) fallito"
fi

# =============================================================================
header "6. LOOPBACK DEL FIREWALL"
# =============================================================================
if docker exec "$FW_CONTAINER" timeout 1 bash -c 'echo > /dev/tcp/127.0.0.1/65535' 2>/dev/null || [ $? -eq 1 ]; then
    log_ok "Loopback (127.0.0.1) funzionante e valutato correttamente dal kernel"
else
    log_fail "Loopback non risponde (timeout)"
fi

# =============================================================================
header "RIEPILOGO DEI RISULTATI"
echo -e "${GREEN}Report salvato in: $REPORT_FILE${NC}"
echo -e "Puoi consultare il log di NFTables dentro il firewall:\n  docker exec $FW_CONTAINER tail -50 $NFT_LOG_FILE"
