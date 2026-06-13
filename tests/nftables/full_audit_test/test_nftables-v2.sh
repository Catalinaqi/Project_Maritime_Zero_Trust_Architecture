#!/bin/bash
# =============================================================================
# MARITIME ZTA - TEST NFTABLES FIREWALL
# Run from path: Project_Maritime_Zero_Trust_Architecture/tests/nftables/full_audit_test
# Prerequisite: docker compose --profile testing up -d
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'
YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS=0; FAIL=0; TOTAL=0
REPORT_FILE="nftables_audit_report-v2.txt"

# Initialize English report
echo "=======================================================================" > "$REPORT_FILE"
echo " MARITIME ZTA - NFTABLES FIREWALL AUDIT REPORT" >> "$REPORT_FILE"
echo " Execution Start Time: $(date '+%Y-%m-%d %H:%M:%S')" >> "$REPORT_FILE"
echo "=======================================================================" >> "$REPORT_FILE"

header() {
    echo -e "\n${BLUE}══════════════════════════════════════════${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}══════════════════════════════════════════${NC}"
    echo -e "\n--- $1 ---" >> "$REPORT_FILE"
}

test_tcp() {
    local container=$1 ip=$2 port=$3 expected=$4 desc=$5
    TOTAL=$((TOTAL+1))

    result=$(docker exec "$container" \
        sh -c "timeout 3 bash -c 'echo > /dev/tcp/$ip/$port' 2>/dev/null \
               && echo CONNECTED || echo BLOCKED" 2>/dev/null)
    [ -z "$result" ] && result="BLOCKED"

    if   [ "$expected" = "BLOCK" ] && [ "$result" = "BLOCKED"   ]; then
        echo -e "${GREEN}[PASS]${NC} $desc — blocked ✔"
        echo "[PASS] $desc — blocked ✔" >> "$REPORT_FILE"
        PASS=$((PASS+1))
    elif [ "$expected" = "PASS"  ] && [ "$result" = "CONNECTED" ]; then
        echo -e "${GREEN}[PASS]${NC} $desc — connected ✔"
        echo "[PASS] $desc — connected ✔" >> "$REPORT_FILE"
        PASS=$((PASS+1))
    elif [ "$expected" = "BLOCK" ] && [ "$result" = "CONNECTED" ]; then
        echo -e "${RED}[FAIL]${NC} $desc — SHOULD BE BLOCKED ⚠️"
        echo "[FAIL] $desc — SHOULD BE BLOCKED ⚠️" >> "$REPORT_FILE"
        FAIL=$((FAIL+1))
    else
        echo -e "${RED}[FAIL]${NC} $desc — SHOULD CONNECT but was blocked/timeout"
        echo "[FAIL] $desc — SHOULD CONNECT but was blocked/timeout" >> "$REPORT_FILE"
        FAIL=$((FAIL+1))
    fi
}

# =============================================================================
# Envoy IPs per network
# =============================================================================
ENVOY_VPN="172.20.11.7"
ENVOY_SATELLITE="172.20.12.7"
ENVOY_CORPORATE="172.20.10.7"
ENVOY_PUBLIC="172.20.13.7"

# Internal IPs
MONGODB_IP="172.20.3.5"
API_IP="172.20.3.20"
OPA_IP="172.20.2.6"
SPLUNK_IP="172.20.4.8"
ENVOY_ADMIN_IP="172.20.2.7"

# =============================================================================
header "BLOCK 1: LEGITIMATE FLOWS — nftables MUST ALLOW"
# =============================================================================
test_tcp "client_operatore_ancona" "$ENVOY_VPN"       8443 "PASS" "vpn_net → Envoy :8443"
test_tcp "client_capitano_claudia" "$ENVOY_SATELLITE"  8443 "PASS" "satellite_net → Envoy :8443"
test_tcp "client_soc_admin"        "$ENVOY_CORPORATE"  8443 "PASS" "corporate_net → Envoy :8443"
test_tcp "client_intruso"          "$ENVOY_PUBLIC"     8443 "PASS" "public_net → Envoy :8443"

# Rule 7: Corporate UI
test_tcp "client_soc_admin"        "$SPLUNK_IP"        8000 "PASS" "corporate_net → Splunk UI :8000"

# Rule 6: HEC Logs (NEW TESTS ADDED)
test_tcp "client_operatore_ancona" "$SPLUNK_IP"        8088 "PASS" "vpn_net → Splunk HEC :8088"
test_tcp "client_capitano_claudia" "$SPLUNK_IP"        8088 "PASS" "satellite_net → Splunk HEC :8088"

# =============================================================================
header "BLOCK 2: PEP BYPASS — nftables MUST BLOCK"
# =============================================================================
test_tcp "client_intruso"          "$MONGODB_IP"    27017 "BLOCK" "public_net → MongoDB :27017 direct"
test_tcp "client_intruso"          "$API_IP"        3000  "BLOCK" "public_net → api_backend :3000 direct"
test_tcp "client_intruso"          "$OPA_IP"        8181  "BLOCK" "public_net → OPA REST :8181 direct"
test_tcp "client_intruso"          "$OPA_IP"        9191  "BLOCK" "public_net → OPA gRPC :9191 direct"
test_tcp "client_intruso"          "$ENVOY_ADMIN_IP" 9901 "BLOCK" "public_net → Envoy Admin :9901"
test_tcp "client_operatore_ancona" "$MONGODB_IP"    27017 "BLOCK" "vpn_net → MongoDB :27017 direct"
test_tcp "client_capitano_claudia" "$OPA_IP"        8181  "BLOCK" "satellite_net → OPA :8181 direct"

# =============================================================================
header "BLOCK 3: LATERAL MOVEMENT — nftables MUST BLOCK"
# =============================================================================
test_tcp "client_intruso"          "172.20.11.20" 8443 "BLOCK" "public_net → vpn_net (operatore_ancona)"
test_tcp "client_intruso"          "172.20.12.21" 8443 "BLOCK" "public_net → satellite_net (capitano_claudia)"
test_tcp "client_intruso"          "172.20.10.20" 8443 "BLOCK" "public_net → corporate_net (soc_admin)"
test_tcp "client_capitano_claudia" "172.20.10.20" 8443 "BLOCK" "satellite_net → corporate_net (escalation capitano→SOC)"

# =============================================================================
header "BLOCK 4: SPLUNK UI — SOC ONLY ALLOWED"
# =============================================================================
test_tcp "client_intruso"          "$SPLUNK_IP" 8000 "BLOCK" "public_net → Splunk UI :8000"
test_tcp "client_capitano_claudia" "$SPLUNK_IP" 8000 "BLOCK" "satellite_net → Splunk UI :8000"
test_tcp "client_operatore_ancona" "$SPLUNK_IP" 8000 "BLOCK" "vpn_net → Splunk UI :8000"

# =============================================================================
header "BLOCK 5: TRACEABILITY"
# =============================================================================
echo -e "\n${YELLOW}► Active rules:${NC}"
echo -e "\n--- TRACEABILITY: Active rules ---" >> "$REPORT_FILE"
docker exec firewall_perimeter nft list ruleset | \
    grep -E "policy|dport|saddr|daddr|log prefix" | tee -a "$REPORT_FILE"

echo -e "\n${YELLOW}► Firewall container logs:${NC}"
echo -e "\n--- TRACEABILITY: Firewall container logs ---" >> "$REPORT_FILE"
docker logs firewall_perimeter --tail 10 2>&1 | tee -a "$REPORT_FILE"

echo -e "\n${YELLOW}► Splunk HEC Status:${NC}"
echo -e "\n--- TRACEABILITY: Splunk HEC Status ---" >> "$REPORT_FILE"
SPLUNK_STATUS=$(docker exec siem_central \
    curl -sk -o /dev/null -w "%{http_code}" \
    http://localhost:8088/services/collector/health 2>/dev/null)
if [ "$SPLUNK_STATUS" = "200" ]; then
    echo -e "${GREEN}Splunk HEC active ✔${NC}"
    echo "Splunk HEC active ✔" >> "$REPORT_FILE"
else
    echo -e "${YELLOW}Splunk HEC: $SPLUNK_STATUS — might be starting${NC}"
    echo "Splunk HEC: $SPLUNK_STATUS — might be starting" >> "$REPORT_FILE"
fi

# =============================================================================
header "SUMMARY"
# =============================================================================
echo -e "Total : $TOTAL"
echo -e "${GREEN}Pass  : $PASS${NC}"
echo -e "${RED}Fail  : $FAIL${NC}"
echo ""
echo "Total : $TOTAL" >> "$REPORT_FILE"
echo "Pass  : $PASS" >> "$REPORT_FILE"
echo "Fail  : $FAIL" >> "$REPORT_FILE"

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✔ NFTABLES OK — Level 1 completed${NC}"
    echo -e "${GREEN}  Next flow: Envoy mTLS → OPA → api_backend → MongoDB${NC}"
    echo "✔ NFTABLES OK — Level 1 completed" >> "$REPORT_FILE"
    echo "  Next flow: Envoy mTLS → OPA → api_backend → MongoDB" >> "$REPORT_FILE"
else
    echo -e "${RED}✘ $FAIL scenarios failed${NC}"
    echo "✘ $FAIL scenarios failed" >> "$REPORT_FILE"
    exit 1
fi
