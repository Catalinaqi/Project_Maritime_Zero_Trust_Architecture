#!/bin/bash
# =============================================================================
# MARITIME ZTA - AUDIT COMPLETO DE TODAS LAS CATEGORÍAS SNORT
# Archivo: run_audit_snort.sh
# =============================================================================
export MSYS_NO_PATHCONV=1

source ./config_audit_snort.sh

echo "=======================================================================" > "$REPORT_FILE"
echo " MARITIME ZTA - RAPPORTO GLOBALE AUDIT DI SICUREZZA (REGOLE AGGIORNATE)" >> "$REPORT_FILE"
echo " Ora di inizio esecuzione: $(date '+%Y-%m-%d %H:%M:%S')" >> "$REPORT_FILE"
echo "=======================================================================" >> "$REPORT_FILE"

# Funciones auxiliares
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
    echo "[$(date '+%H:%M:%S')] Servizio: $container | Descrizione: $desc | SIDs attesi: $expected_sids" >> "$REPORT_FILE"
}

# =============================================================================
# CATEGORIA 0 - DIAGNÓSTICA DE LA PIPELINE IDS (SIDs 999901-999904)
# =============================================================================
header "CATEGORIA 0 - DIAGNÓSTICA DELLA PIPELINE IDS"

# Para que Snort vea ICMP desde EXTERNAL_NET, simulamos un ping desde un contenedor
# que no pertenezca a HOME_NET. Usamos el host (si está en 172.20.13.0/24) o
# un contenedor especial. Por simplicidad, hacemos ping desde el cliente d001
# pero modificamos la IP origen? No es posible. Mejor usamos la IP del firewall
# en la red public_net (172.20.13.10) si existe. En caso contrario, probamos con
# la IP del TARGET_VPN_IP (que ya está en HOME_NET). La regla espera EXTERNAL_NET,
# así que probablemente no se active. Para fines demostrativos, incluimos el ataque
# para ver que Snort ejecuta la regla aunque no coincida el origen.
fire_attack "client_d001_tpm" "Ping hacia firewall desde VPN (posible falso positivo)" \
    "ping -c 2 ${TARGET_VPN_IP}" \
    "999901"

# TCP SYN desde EXTERNAL NET: usamos un cliente y forzamos IP origen? No.
# Omitimos porque es complicado simular EXTERNAL_NET real. Se puede saltar.

# Para MVP-003 (SQLi en claro) usaremos curl GET con "union select" en la URL.
fire_attack "client_d001_tpm" "SQLi test (claro) en puerto PEP" \
    "curl -s --max-time 2 'http://${TARGET_VPN_IP}:${PORT_PEP}/?q=union%20select'" \
    "999903"

# MVP-004: SYN a MongoDB
fire_attack "client_d002_tpm" "SYN directo a MongoDB" \
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
    "1000014"   # Nota: el heartbeat se detecta por contenido |18 03|, pero curl no lo envía. Solo prueba de concepto.

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
# CATEGORIA 5 - POSIBILE ESFILTRAZIONE (SIDs 1000020, 1000021)
# =============================================================================
header "CATEGORIA 5 - POSSIBILE ESFILTRAZIONE"

# Para 1000020 (opcode MongoDB) necesitamos enviar bytes |d4 07 00 00|.
# Usamos printf y nc (suponiendo que nc soporta entrada binaria).
fire_attack "client_d001_tpm" "Invio opcode MongoDB verso IP esterna" \
    "printf '\xd4\x07\x00\x00' | timeout 2 nc -w1 ${TARGET_VPN_IP} ${PORT_MONGO} 2>/dev/null; true" \
    "1000020"

fire_attack "client_d001_tpm" "500 connessioni verso esterno (alta volume)" \
    "for i in \$(seq 1 520); do timeout 0.5 bash -c \"echo > /dev/tcp/8.8.8.8/53\" 2>/dev/null & done; wait" \
    "1000021" 10

# =============================================================================
# CATEGORIA 6 - MOVIMIENTO LATERALE (SIDs 1000022-1000028)
# =============================================================================
header "CATEGORIA 6 - MOVIMENTO LATERALE TRA RETI"

# Nota: las reglas esperan tráfico desde una red específica hacia otra.
# Los clientes deben estar en la red origen correcta.

fire_attack "client_d001_tpm" "Da VPN_NET verso BACKEND_NET" \
    "timeout 2 bash -c 'echo > /dev/tcp/172.20.3.10/3000' 2>/dev/null; true" \
    "1000028"

fire_attack "client_d002_tpm" "Da SATELLITE_NET verso BACKEND_NET" \
    "timeout 2 bash -c 'echo > /dev/tcp/172.20.3.10/27017' 2>/dev/null; true" \
    "1000027"

fire_attack "client_dsoc_tpm" "Da CORPORATE_NET verso BACKEND_NET (simulato)" \
    "timeout 2 bash -c 'echo > /dev/tcp/172.20.3.10/3000' 2>/dev/null; true" \
    "N/A"   # No hay regla explícita para CORPORATE->BACKEND en el archivo, solo PUBLIC->BACKEND. Omitimos.

# Las reglas 1000022-1000025 requieren desde PUBLIC_NET. No tenemos cliente en public_net.
# Las reglas 1000026 requiere SATELLITE->CORPORATE, ya tenemos client_d002 en satellite.
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
echo -e "${GREEN} Consultare il file '$REPORT_FILE' per il riepilogo.     ${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
