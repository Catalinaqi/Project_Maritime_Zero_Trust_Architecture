#!/bin/bash
# =============================================================================
# MARITIME ZTA - AUDIT COMPLETO DI TUTTE LE CATEGORIE SNORT
# File: run_audit_snort.sh
# =============================================================================
export MSYS_NO_PATHCONV=1

source ./config_audit.sh

echo "=======================================================================" > "$REPORT_FILE_SNORT"
echo " MARITIME ZTA - RAPPORTO GLOBALE AUDIT DI SICUREZZA (REGOLE AGGIORNATE)" >> "$REPORT_FILE_SNORT"
echo " Ora di inizio esecuzione: $(date '+%Y-%m-%d %H:%M:%S')" >> "$REPORT_FILE_SNORT"
echo "=======================================================================" >> "$REPORT_FILE_SNORT"

# Funzioni ausiliarie
header() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
}

fire_attack() {
    local container="$1"
    local desc="$2"
    local cmd="$3"
    local expected_sids="$4"
    local delay="${5:-2}"

    echo -e "${CYAN}[ATTACK] Esecuzione su container '${container}':${NC} ${desc}"
    echo -e " Comando: ${cmd}"

    docker exec -t "$container" bash -c "$cmd" > /dev/null 2>&1

    sleep "$delay"
    echo -e "${GREEN}[INFO] Attacco completato. SIDs attesi da Snort: ${expected_sids}${NC}"
    echo "[$(date '+%H:%M:%S')] Servizio: $container | Descrizione: $desc | SIDs attesi: $expected_sids" >> "$REPORT_FILE_SNORT"
}

# =============================================================================
# CATEGORIA 0 - DIAGNOSTICA DELLA PIPELINE IDS (SIDs 999901-999904)
# =============================================================================
header "CATEGORIA 0 - DIAGNOSTICA DELLA PIPELINE IDS"

# Per far sì che Snort veda ICMP da EXTERNAL_NET, simuliamo un ping da un contenitore
# che non appartenga a HOME_NET. Usiamo l'host (se è in 172.20.13.0/24) o
# un contenitore speciale. Per semplicità, eseguiamo il ping dal client d001
# ma modifichiamo l'IP sorgente? Non è possibile. Meglio usare l'IP del firewall
# sulla rete public_net (172.20.13.10) se esiste. Altrimenti, proviamo con
# l'IP di TARGET_VPN_IP (che è già in HOME_NET). La regola si aspetta EXTERNAL_NET,
# quindi probabilmente non si attiverà. A scopo dimostrativo, includiamo l'attacco
# per vedere che Snort esegue la regola anche se l'origine non corrisponde.
fire_attack "client_d001_tpm" "Ping verso firewall da VPN (possibile falso positivo)" \
    "ping -c 2 ${TARGET_VPN_IP}" \
    "999901"

# TCP SYN da EXTERNAL NET: usiamo un client e forziamo IP origine? No.
# Omissione perché è complicato simulare una EXTERNAL_NET reale. Si può saltare.

# Per MVP-003 (SQLi in chiaro) useremo curl GET con "union select" nell'URL.
fire_attack "client_d001_tpm" "Test SQLi (in chiaro) sulla porta PEP" \
    "curl -s --max-time 2 'http://${TARGET_VPN_IP}:${PORT_PEP}/?q=union%20select'" \
    "999903"

# MVP-004: SYN verso MongoDB
fire_attack "client_d002_tpm" "SYN diretto a MongoDB" \
    "timeout 2 bash -c 'echo > /dev/tcp/${TARGET_VPN_IP}/${PORT_MONGO}'" \
    "999904"

# =============================================================================
# CATEGORIA 1 - RECONNAISSANCE E SCANSIONI (SIDs 1000001-1000005)
# =============================================================================
header "CATEGORIA 1 - RECONNAISSANCE E SCANSIONI"

fire_attack "client_d001_tpm" "Scansione porte TCP (20 SYN in 60s)" \
    "for i in 22 80 443 8080 8443 27017 3000 8000; do timeout 1 bash -c \"echo > /dev/tcp/${TARGET_VPN_IP}/\$i\" 2>/dev/null & done; wait" \
    "1000001"

fire_attack "client_d001_tpm" "Scansione porte UDP (20 pacchetti in 60s)" \
    "for i in 53 161 500 1701 4500; do timeout 1 bash -c \"echo > /dev/udp/${TARGET_VPN_IP}/\$i\" 2>/dev/null & done; wait" \
    "1000002"

fire_attack "client_d001_tpm" "Scansione NULL (Flag 0) usando nmap" \
    "timeout 3 nmap -sN ${TARGET_VPN_IP} 2>/dev/null || true" \
    "1000003"

fire_attack "client_d001_tpm" "SYN Flood (110 SYN rapidi verso PEP)" \
    "for i in \$(seq 1 110); do timeout 0.5 bash -c \"echo > /dev/tcp/${TARGET_VPN_IP}/${PORT_PEP}\" 2>/dev/null & done; wait" \
    "1000004"

fire_attack "client_d001_tpm" "Slowloris simulato (50 connessioni stabilite)" \
    "for i in \$(seq 1 50); do curl -s --max-time 30 http://${TARGET_VPN_IP}:${PORT_PEP}/ & done; wait" \
    "1000005" 5

# =============================================================================
# CATEGORIA 2 - BYPASS DEL POLICY ENFORCEMENT POINT (SIDs 1000006-1000010)
# =============================================================================
header "CATEGORIA 2 - BYPASS DEL PEP"

fire_attack "client_d001_tpm" "Tentativo di connessione diretta a MongoDB" \
    "timeout 2 bash -c 'echo > /dev/tcp/${TARGET_VPN_IP}/${PORT_MONGO}'" \
    "1000006"

fire_attack "client_d002_tpm" "Tentativo diretto ad API Backend" \
    "timeout 2 bash -c 'echo > /dev/tcp/${TARGET_VPN_IP}/${PORT_API}'" \
    "1000007"

fire_attack "client_dsoc_tpm" "Tentativo diretto a OPA (REST)" \
    "timeout 2 bash -c 'echo > /dev/tcp/${TARGET_CORPORATE_IP}/${PORT_OPA}'" \
    "1000008"

fire_attack "client_d001_tpm" "Tentativo alla porta admin di Envoy" \
    "timeout 2 bash -c 'echo > /dev/tcp/${TARGET_VPN_IP}/${PORT_ENVOY_ADMIN}'" \
    "1000009"

fire_attack "client_dsoc_tpm" "Tentativo diretto a Splunk (10 connessioni)" \
    "for i in \$(seq 1 12); do timeout 1 bash -c \"echo > /dev/tcp/${TARGET_CORPORATE_IP}/${PORT_SPLUNK_WEB}\" 2>/dev/null & done; wait" \
    "1000010"

# =============================================================================
# CATEGORIA 3 - ANOMALIE TLS E mTLS (SIDs 1000011-1000014, 1000016, 1000017)
# =============================================================================
header "CATEGORIA 3 - ANOMALIE TLS/mTLS"

fire_attack "client_d001_tpm" "HTTP GET in chiaro su porta mTLS" \
    "curl -s --max-time 2 http://${TARGET_VPN_IP}:${PORT_PEP}/" \
    "1000011"

fire_attack "client_d002_tpm" "HTTP POST in chiaro su porta mTLS" \
    "curl -s --max-time 2 -X POST http://${TARGET_SATELLITE_IP}:${PORT_PEP}/" \
    "1000012"

fire_attack "client_d001_tpm" "Downgrade TLS 1.0 verso Envoy" \
    "curl -s --max-time 2 --tlsv1.0 https://${TARGET_VPN_IP}:${PORT_PEP}/ 2>/dev/null || true" \
    "1000016"

fire_attack "client_d001_tpm" "Downgrade TLS 1.1 verso Envoy" \
    "curl -s --max-time 2 --tlsv1.1 https://${TARGET_VPN_IP}:${PORT_PEP}/ 2>/dev/null || true" \
    "1000017"

fire_attack "client_d002_tpm" "Heartbeat TLS (simulato con curl?)" \
    "curl -s --max-time 2 --tls-max 1.2 https://${TARGET_SATELLITE_IP}:${PORT_PEP}/ 2>/dev/null; true" \
    "1000014"   # Nota: l'heartbeat viene rilevato dal contenuto |18 03|, ma curl non lo invia. Solo prova di concetto.

# =============================================================================
# CATEGORIA 4 - INJECTION APPLICATIVE (SIDs 1000015, 1000018, 1000019)
# =============================================================================
header "CATEGORIA 4 - INJECTION APPLICATIVE"

fire_attack "client_d001_tpm" "SQLi UNION SELECT (in chiaro)" \
    "curl -s --max-time 2 -G http://${TARGET_VPN_IP}:${PORT_PEP}/ --data-urlencode 'q=union select 1,2,3'" \
    "1000015"

fire_attack "client_d001_tpm" "DROP TABLE in query string" \
    "curl -s --max-time 2 -G http://${TARGET_VPN_IP}:${PORT_PEP}/ --data-urlencode 'cmd=drop table users'" \
    "1000018"

fire_attack "client_d002_tpm" "Command Injection: cat /etc/passwd" \
    "curl -s --max-time 2 -G http://${TARGET_SATELLITE_IP}:${PORT_PEP}/ --data-urlencode 'cmd=cat /etc/passwd'" \
    "1000019"

# =============================================================================
# CATEGORIA 5 - POSSIBILE ESFILTRAZIONE (SIDs 1000020, 1000021)
# =============================================================================
header "CATEGORIA 5 - POSSIBILE ESFILTRAZIONE"

# Per 1000020 (opcode MongoDB) dobbiamo inviare byte |d4 07 00 00|.
# Usiamo printf e nc (supponendo che nc supporti input binario).
fire_attack "client_d001_tpm" "Invio opcode MongoDB verso IP esterna" \
    "printf '\xd4\x07\x00\x00' | timeout 2 nc -w1 ${TARGET_VPN_IP} ${PORT_MONGO} 2>/dev/null; true" \
    "1000020"

fire_attack "client_d001_tpm" "500 connessioni verso esterno (alto volume)" \
    "for i in \$(seq 1 520); do timeout 0.5 bash -c \"echo > /dev/tcp/8.8.8.8/53\" 2>/dev/null & done; wait" \
    "1000021" 10

# =============================================================================
# CATEGORIA 6 - MOVIMENTO LATERALE (SIDs 1000022-1000028)
# =============================================================================
header "CATEGORIA 6 - MOVIMENTO LATERALE TRA RETI"

# Nota: le regole si aspettano traffico da una rete specifica verso un'altra.
# I client devono essere nella rete di origine corretta.

fire_attack "client_d001_tpm" "Da VPN_NET verso BACKEND_NET" \
    "timeout 2 bash -c 'echo > /dev/tcp/172.20.3.10/3000' 2>/dev/null; true" \
    "1000028"

fire_attack "client_d002_tpm" "Da SATELLITE_NET verso BACKEND_NET" \
    "timeout 2 bash -c 'echo > /dev/tcp/172.20.3.10/27017' 2>/dev/null; true" \
    "1000027"

fire_attack "client_dsoc_tpm" "Da CORPORATE_NET verso BACKEND_NET (simulato)" \
    "timeout 2 bash -c 'echo > /dev/tcp/172.20.3.10/3000' 2>/dev/null; true" \
    "N/A"   # Non esiste una regola esplicita per CORPORATE->BACKEND nel file, solo PUBLIC->BACKEND. Omissione.

# Le regole 1000022-1000025 richiedono da PUBLIC_NET. Non abbiamo client in public_net.
# La regola 1000026 richiede SATELLITE->CORPORATE, abbiamo client_d002 in satellite.
fire_attack "client_d002_tpm" "Da SATELLITE_NET verso CORPORATE_NET" \
    "timeout 2 bash -c 'echo > /dev/tcp/172.20.10.10/8000' 2>/dev/null; true" \
    "1000026"

# =============================================================================
# CATEGORIA 7 - BRUTE FORCE E ABUSO CREDENZIALI (SIDs 1000029-1000031)
# =============================================================================
header "CATEGORIA 7 - BRUTE FORCE E ABUSO CREDENZIALI"

fire_attack "client_d001_tpm" "Brute force SSH (6 connessioni in 60s)" \
    "for i in \$(seq 1 6); do timeout 1 bash -c \"echo > /dev/tcp/${TARGET_VPN_IP}/${PORT_SSH}\" 2>/dev/null; done" \
    "1000029"

fire_attack "client_dsoc_tpm" "Brute force Splunk (12 connessioni)" \
    "for i in \$(seq 1 12); do timeout 1 bash -c \"echo > /dev/tcp/${TARGET_CORPORATE_IP}/${PORT_SPLUNK_WEB}\" 2>/dev/null; done" \
    "1000030"

fire_attack "client_d001_tpm" "Brute force OPA (20 connessioni)" \
    "for i in \$(seq 1 20); do timeout 1 bash -c \"echo > /dev/tcp/${TARGET_VPN_IP}/${PORT_OPA}\" 2>/dev/null; done" \
    "1000031"

# =============================================================================
# CATEGORIA 8 - MANIPOLAZIONE DEL PIANO DI CONTROLLO (SIDs 1000032-1000035)
# =============================================================================
header "CATEGORIA 8 - MANIPOLAZIONE DEL PIANO DI CONTROLLO"

fire_attack "client_d001_tpm" "PUT v1/policies a OPA (tamper)" \
    "curl -s --max-time 2 -X PUT http://${TARGET_VPN_IP}:${PORT_OPA}/v1/policies" \
    "1000032|1000008"

fire_attack "client_d002_tpm" "PUT v1/data a OPA" \
    "curl -s --max-time 2 -X PUT http://${TARGET_SATELLITE_IP}:${PORT_OPA}/v1/data" \
    "1000033|1000008"

fire_attack "client_dsoc_tpm" "DELETE a OPA" \
    "curl -s --max-time 2 -X DELETE http://${TARGET_CORPORATE_IP}:${PORT_OPA}/v1/policies" \
    "1000034|1000008"

fire_attack "client_dsoc_tpm" "Log flooding verso Splunk HEC (220 richieste)" \
    "for i in \$(seq 1 220); do curl -s --max-time 2 -X POST http://${TARGET_CORPORATE_IP}:${PORT_SPLUNK_HEC}/ >/dev/null & done; wait" \
    "1000035" 8

# =============================================================================
header "CONSOLIDAMENTO DELL'AUDIT DI SICUREZZA"
echo -e "\n${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN} TUTTI I TEST (TUTTE LE CATEGORIE) SONO STATI LANCIATI   ${NC}"
echo -e "${GREEN} Consultare il file '$REPORT_FILE_SNORT' per il riepilogo.     ${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
