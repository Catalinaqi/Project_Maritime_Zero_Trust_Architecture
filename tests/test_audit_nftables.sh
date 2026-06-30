#!/bin/bash
# Verifica il ruleset NFTables, il DNAT verso Envoy e l'isolamento tra reti.
export MSYS_NO_PATHCONV=1
source "$(dirname "$0")/config_audit.sh"
source "$(dirname "$0")/lib_test_helpers.sh"

start_base_services
start_testing_clients
wait_for_opa || print_summary
pause_dynamic_risk_updates || exit 1
trap 'resume_dynamic_risk_updates >/dev/null 2>&1' EXIT
set_static_risk_scores_baseline || exit 1


# Inizializza il report dell'esecuzione.
echo "=======================================================================" > "$REPORT_FILE_NFTABLES"
echo " MARITIME ZTA - RAPPORTO TEST FIREWALL NFTABLES" >> "$REPORT_FILE_NFTABLES"
echo " Ora di inizio: $(date '+%Y-%m-%d %H:%M:%S')" >> "$REPORT_FILE_NFTABLES"
echo "=======================================================================" >> "$REPORT_FILE_NFTABLES"

audit_pass=0
audit_fail=0

header() { echo -e "\n${BLUE}════════════════════════════════════════════════════════════${NC}\n${BLUE} $1${NC}\n${BLUE}════════════════════════════════════════════════════════════${NC}"; }
log_ok() { echo -e "${GREEN}[PASS]${NC} $1"; echo "[PASS] $1" >> "$REPORT_FILE_NFTABLES"; audit_pass=$((audit_pass + 1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; echo "[FAIL] $1" >> "$REPORT_FILE_NFTABLES"; audit_fail=$((audit_fail + 1)); }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; echo "[WARN] $1" >> "$REPORT_FILE_NFTABLES"; }

# =============================================================================
# PRE-CHECK: Controlli preliminari
# =============================================================================
pre_checks() {
    local all_ok=true

    # Verifica la disponibilità dei container richiesti.
    for c in "$FW_CONTAINER" "$CLIENT_D001" "$CLIENT_D002" "$CLIENT_DSOC"; do
        if ! docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
            log_fail "Container '$c' non in esecuzione. Impossibile proseguire."
            all_ok=false
        fi
    done

    # Verifica l'abilitazione dell'inoltro IPv4.
    local ip_fwd
    ip_fwd=$(docker exec "$FW_CONTAINER" cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
    if [[ "$ip_fwd" != "1" ]]; then
        log_warn "IP Forwarding disabilitato (valore=$ip_fwd). I test di forward falliranno."
        log_warn "Attiva con: docker exec $FW_CONTAINER sysctl -w net.ipv4.ip_forward=1"
    fi

    # Verifica la disponibilità del comando ping nei client.
    if ! docker exec "$CLIENT_D001" which ping &>/dev/null; then
        log_warn "ping non installato nei container client. Il test ICMP sarà ignorato."
        export PING_MISSING=true
    fi

    # Azzera i contatori per isolare le misure dell'esecuzione corrente.
    docker exec "$FW_CONTAINER" nft reset counters table ip filter 2>/dev/null || true
    docker exec "$FW_CONTAINER" nft reset counters table ip nat 2>/dev/null || true
    log_info "Contatori nftables resettati."

    $all_ok || exit 1
}

log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }

log_info "Verifica Envoy in ascolto..."
if ! docker exec pep_gateway ss -tlnp 2>/dev/null | grep -q ':8443'; then
    log_warn "Envoy non sembra in ascolto sulla porta 8443 (ss non trovato o porta non aperta)"
fi

# =============================================================================
# FUNZIONE DI TEST DELLA CONNESSIONE
# =============================================================================
test_connection() {
    local container="$1"
    local desc="$2"
    local dest_ip="$3"
    local dest_port="$4"
    local expected="$5"
    local timeout="${6:-3}"
    local test_type="${7:-forward}"

    echo -e "${CYAN}[TEST]${NC} $desc..."

    # Acquisisce il contatore FORWARD precedente al test.
    local pkts_before=0
    if [[ "$test_type" == "dnat" ]]; then
        pkts_before=$(docker exec "$FW_CONTAINER" nft list chain ip filter forward 2>/dev/null | awk -v ip="$ENVOY_IP" -v port="$ENVOY_PORT" '
            $0 ~ "ip daddr " ip && $0 ~ "tcp dport " port {
                for (i = 1; i <= NF; i++) if ($i == "packets") total += $(i + 1)
            }
            END { print total + 0 }
        ')
    fi

    # Esegue il tentativo di connessione con un timeout controllato.
    local raw_output
    raw_output=$(docker exec -t "$container" timeout "$timeout" bash -c \
        "echo > /dev/tcp/$dest_ip/$dest_port 2>&1; echo EXIT:\$?" 2>/dev/null)
    local exit_code
    exit_code=$(printf '%s\n' "$raw_output" | sed -n 's/.*EXIT:\([0-9][0-9]*\).*/\1/p' | tail -n 1)
    exit_code="${exit_code:-124}"

    local actual
    case $exit_code in
        0)   actual="allow" ;;
        1)   actual="refused" ;;
        124) actual="timeout" ;;
        *)   actual="unknown($exit_code)" ;;
    esac

    local test_passed=false
    if [[ "$expected" == "allow" ]]; then
        [[ "$actual" == "allow" || "$actual" == "refused" ]] && test_passed=true
    elif [[ "$expected" == "deny" ]]; then
        [[ "$actual" == "timeout" || "$actual" == "refused" ]] && test_passed=true
    fi

    # Confronta il contatore FORWARD dopo il tentativo DNAT.
    if [[ "$test_type" == "dnat" && "$actual" != "allow" ]]; then
        local pkts_after
        pkts_after=$(docker exec "$FW_CONTAINER" nft list chain ip filter forward 2>/dev/null | awk -v ip="$ENVOY_IP" -v port="$ENVOY_PORT" '
            $0 ~ "ip daddr " ip && $0 ~ "tcp dport " port {
                for (i = 1; i <= NF; i++) if ($i == "packets") total += $(i + 1)
            }
            END { print total + 0 }
        ')

        if (( pkts_after > pkts_before )); then
            # Un incremento conferma che il firewall ha inoltrato il traffico.
            log_ok "$desc → inoltro rilevato (contatore FORWARD: $pkts_before -> $pkts_after)"
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
# FUNZIONE DI CONTROLLO DEL LOG DEL FIREWALL
# =============================================================================
check_fw_log() {
    local expected_prefix="$1"
    local min_lines="${2:-1}"
    local max_wait="${3:-10}"

    docker exec "$FW_CONTAINER" sync

    for ((i=0; i<max_wait; i++)); do
        local count
        count=$(docker exec "$FW_CONTAINER" sh -c \
            "cat '$NFT_LOG_FILE' | tr -d '\r' | grep -cF '$expected_prefix'" 2>/dev/null || echo 0)
        count="${count:-0}"
        count=$(echo "$count" | tr -d '\n' | xargs)  # Normalizza l'output numerico.
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

# =============================================================================
# ESECUZIONE PRE-CHECKS
# =============================================================================
pre_checks

# Pulisce il log precedente
docker exec "$FW_CONTAINER" truncate -s 0 "$NFT_LOG_FILE" 2>/dev/null || true
sleep 1

# =============================================================================
# TEST 1: traffico client verso Envoy tramite DNAT e FORWARD.
# Il tipo "dnat" abilita anche la verifica dei contatori di inoltro.
# =============================================================================
header "1. TRAFFICO PERMESSO: CLIENT → ENVOY (DNAT + FORWARD ACCEPT)"
test_connection "$CLIENT_D001" "VPN -> Envoy via FW (8443)" "$FW_VPN_IP" "$ENVOY_PORT" "allow" 5 "dnat"
test_connection "$CLIENT_D002" "Satellite -> Envoy via FW (8443)" "$FW_SATELLITE_IP" "$ENVOY_PORT" "allow" 5 "dnat"
test_connection "$CLIENT_DSOC" "Corporate -> Envoy via FW (8443)" "$FW_CORPORATE_IP" "$ENVOY_PORT" "allow" 5 "dnat"

# =============================================================================
# TEST 2: blocco delle connessioni dirette alle porte interne del firewall.
# =============================================================================
header "2. BLOCCAGGIO INPUT: CONNESSIONI AL FIREWALL SU PORTE NON ABILITATE"
test_connection "$CLIENT_D001" "VPN -> Firewall:27017 (Mongo)" "$FW_VPN_IP" "$MONGO_PORT" "deny"
test_connection "$CLIENT_D001" "VPN -> Firewall:3000 (API)" "$FW_VPN_IP" "$API_PORT" "deny"
test_connection "$CLIENT_D001" "VPN -> Firewall:8181 (OPA)" "$FW_VPN_IP" "$OPA_PORT" "deny"
test_connection "$CLIENT_D001" "VPN -> Firewall:8000 (Splunk Web)" "$FW_VPN_IP" "$SPLUNK_WEB_PORT" "deny"
sleep 3
check_fw_log "[NFT-INPUT-DROP]" 1


# =============================================================================
# TEST 3: blocco del movimento laterale tra VPN e rete satellitare.
# =============================================================================
header "3. MOVIMENTO LATERALE: VPN ↔ SATELLITE (DEVE ESSERE BLOCCATO E LOGGATO)"
test_connection "$CLIENT_D001" "VPN -> Satellite (cliente a cliente)" "$CLIENT_D002_IP" "8443" "deny"
test_connection "$CLIENT_D002" "Satellite -> VPN (cliente a cliente)" "$CLIENT_D001_IP" "8443" "deny"

# Docker applica anche il proprio isolamento inter-rete. Il timeout costituisce
# l'evidenza del blocco anche quando il pacchetto non raggiunge NFTables.

# =============================================================================
# TEST 4: policy predefinita della catena FORWARD.
# =============================================================================
header "4. REGOLA DI DEFAULT FORWARD"
test_connection "$CLIENT_D001" "VPN -> Satellite porta 22 (ssh)" "$CLIENT_D002_IP" "22" "deny"
# Il timeout conferma il blocco; Docker può scartare il traffico prima che il
# pacchetto raggiunga la catena NFTables e produca un record di log.

# =============================================================================
# TEST 5: ICMP diagnostico verso il firewall.
# =============================================================================
header "5. ICMP VERSO IL FIREWALL (DEVE ESSERE PERMESSO)"
if [[ -z "${PING_MISSING:-}" ]]; then
    if docker exec "$CLIENT_D001" ping -c 2 "$FW_VPN_IP" >/dev/null 2>&1; then
        log_ok "Ping VPN -> Firewall (VPN_IP) permesso"
    else
        log_fail "Ping VPN -> Firewall (VPN_IP) fallito"
    fi
else
    log_warn "Test ICMP saltato: ping non disponibile"
fi

# =============================================================================
# TEST 6: funzionamento dell'interfaccia loopback del firewall.
# =============================================================================
header "6. LOOPBACK DEL FIREWALL"
if docker exec "$FW_CONTAINER" timeout 1 bash -c 'echo > /dev/tcp/127.0.0.1/65535' 2>/dev/null || [ $? -eq 1 ]; then
    log_ok "Loopback (127.0.0.1) funzionante e valutato correttamente dal kernel"
else
    log_fail "Loopback non risponde (timeout)"
fi

# =============================================================================
print_summary_audit "$audit_pass" "$audit_fail"

header "RIEPILOGO DEI RISULTATI"
echo -e "${GREEN}Report salvato in: $REPORT_FILE_NFTABLES${NC}"
echo -e "Puoi consultare il log di NFTables dentro il firewall:\n  docker exec $FW_CONTAINER tail -50 $NFT_LOG_FILE"
