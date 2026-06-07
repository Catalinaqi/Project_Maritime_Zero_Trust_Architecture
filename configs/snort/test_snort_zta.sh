#!/bin/bash
export MSYS_NO_PATHCONV=1
# ==============================================================================
# Test Automatizzato - Snort 3 IDS - Maritime ZTA (15 Regole)
# Clients: client_intruso (.13.21), client_operatore_ancona (.11.20),
#          client_soc_admin (.10.20)
# pep_gateway su public_net: 172.20.13.7 | vpn_net: 172.20.11.7
# ==============================================================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}======================================================${NC}"
echo -e "${YELLOW}  Test Sicurezza Snort 3 IDS - 15 Regole ZTA          ${NC}"
echo -e "${YELLOW}======================================================${NC}"

# ------------------------------------------------------------------------------
# STEP 0: Avvio client (nessun client attivo prima di questo script)
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}[0] Avvio container client con profilo testing...${NC}"
docker compose --profile testing up -d \
    client_intruso \
    client_operatore_ancona \
    client_soc_admin > /dev/null 2>&1
sleep 5

echo "Installazione tool nei client..."
docker exec client_intruso apk add --no-cache nmap netcat-openbsd curl > /dev/null 2>&1
docker exec client_operatore_ancona apk add --no-cache netcat-openbsd > /dev/null 2>&1
echo "Ambiente pronto."

# ------------------------------------------------------------------------------
# CATEGORIA 1: PORT SCANNING
# Target: pep_gateway su public_net = 172.20.13.7
# Atteso: ZTA-001, ZTA-002, ZTA-003 (3 alert)
# ------------------------------------------------------------------------------
echo -e "\n${RED}>>> CAT 1: PORT SCANNING <<<${NC}"

echo -e "${GREEN}[ZTA-001] TCP SYN Scan...${NC}"
docker exec client_intruso nmap -sS -p 1-30 172.20.13.7 > /dev/null 2>&1

echo -e "${GREEN}[ZTA-002] UDP Scan...${NC}"
docker exec client_intruso nmap -sU -p 1-25 172.20.13.7 > /dev/null 2>&1

echo -e "${GREEN}[ZTA-003] NULL Scan...${NC}"
docker exec client_intruso nmap -sN -p 80,443,8443 172.20.13.7 > /dev/null 2>&1

# ------------------------------------------------------------------------------
# CATEGORIA 2: SQL INJECTION
# Target: pep_gateway 172.20.13.7:8443
# Atteso: ZTA-004, ZTA-005, ZTA-006 (3 alert)
# ------------------------------------------------------------------------------
echo -e "\n${RED}>>> CAT 2: SQL INJECTION <<<${NC}"

echo -e "${GREEN}[ZTA-004] UNION SELECT...${NC}"
docker exec client_intruso curl -s -k \
    "https://172.20.13.7:8443/?q=UNION+SELECT+*+FROM+users" > /dev/null

echo -e "${GREEN}[ZTA-005] OR 1=1...${NC}"
docker exec client_intruso curl -s -k \
    "https://172.20.13.7:8443/?id=1'+OR+1=1--" > /dev/null

echo -e "${GREEN}[ZTA-006] DROP TABLE...${NC}"
docker exec client_intruso curl -s -k \
    "https://172.20.13.7:8443/?q=DROP+TABLE+users" > /dev/null

# ------------------------------------------------------------------------------
# CATEGORIA 3: DIRECT DATABASE ACCESS
# Target: db_primary 172.20.3.5:27017 (backend_net internal)
# Nota: backend_net e' internal:true, il traffico verra' bloccato dal firewall
#       ma Snort vede il tentativo uscire da client_intruso e puo' alertare
#       su ZTA-007. ZTA-008 dipende se il pacchetto arriva all'interfaccia IDS.
# Atteso: ZTA-007 probabile, ZTA-008 incerto (rete interna)
# ------------------------------------------------------------------------------
echo -e "\n${RED}>>> CAT 3: DIRECT DATABASE ACCESS <<<${NC}"

echo -e "${GREEN}[ZTA-007] TCP SYN a MongoDB 172.20.3.5:27017...${NC}"
docker exec client_intruso nc -z -w 1 172.20.3.5 27017 > /dev/null 2>&1 || true

echo -e "${GREEN}[ZTA-008] MongoDB Wire Protocol bytes...${NC}"
docker exec client_intruso sh -c \
    'printf "\xd4\x07\x00\x00" | nc -w 1 172.20.3.5 27017' > /dev/null 2>&1 || true

# ------------------------------------------------------------------------------
# CATEGORIA 4: TLS ANOMALIES
# Target: pep_gateway 172.20.13.7:8443
# Atteso: ZTA-009, ZTA-010, ZTA-011 (3 alert)
# ------------------------------------------------------------------------------
echo -e "\n${RED}>>> CAT 4: TLS ANOMALIES <<<${NC}"

echo -e "${GREEN}[ZTA-009] HTTP in chiaro su porta TLS 8443...${NC}"
docker exec client_intruso curl -s \
    "http://172.20.13.7:8443" > /dev/null 2>&1 || true

echo -e "${GREEN}[ZTA-010] Heartbleed signature 0x18 0x03...${NC}"
docker exec client_intruso sh -c \
    'printf "\x18\x03" | nc -w 1 172.20.13.7 8443' > /dev/null 2>&1 || true

echo -e "${GREEN}[ZTA-011] TLS Downgrade 0x16 0x03 0x01...${NC}"
docker exec client_intruso sh -c \
    'printf "\x16\x03\x01" | nc -w 1 172.20.13.7 8443' > /dev/null 2>&1 || true

# ------------------------------------------------------------------------------
# CATEGORIA 5: LATERAL MOVEMENT
# ZTA-012: operatore_ancona (.11.20) -> soc_admin (.10.20) porta 22
#          IP fissa: client_soc_admin e' su corporate_net 172.20.10.20
#          (DNS non funziona cross-network, usare IP)
# ZTA-013: brute force SSH su pep_gateway 172.20.13.7:22
# Atteso: ZTA-012, ZTA-013 (2 alert)
# ------------------------------------------------------------------------------
echo -e "\n${RED}>>> CAT 5: LATERAL MOVEMENT <<<${NC}"

echo -e "${GREEN}[ZTA-012] Lateral movement VPN->Corporate (op.ancona -> soc_admin)...${NC}"
docker exec client_operatore_ancona nc -z -w 1 172.20.10.20 22 > /dev/null 2>&1 || true

echo -e "${GREEN}[ZTA-013] SSH Brute Force (6 tentativi su pep_gateway)...${NC}"
docker exec client_intruso sh -c \
    'for i in $(seq 1 6); do nc -z -w 1 172.20.13.7 22 2>/dev/null; sleep 0.2; done'

# ------------------------------------------------------------------------------
# CATEGORIA 6: DDoS / RESOURCE EXHAUSTION
# Target: pep_gateway 172.20.13.7
# Atteso: ZTA-014, ZTA-015 (2 alert)
# ------------------------------------------------------------------------------
echo -e "\n${RED}>>> CAT 6: DDoS / RESOURCE EXHAUSTION <<<${NC}"

echo -e "${GREEN}[ZTA-014] SYN Flood (110 connessioni in rapida sequenza)...${NC}"
docker exec client_intruso sh -c \
    'for i in $(seq 1 110); do nc -z -w 1 172.20.13.7 8443 & done; wait'

echo -e "${GREEN}[ZTA-015] Slowloris POST flood (55 richieste parallele)...${NC}"
docker exec client_intruso sh -c \
    'for i in $(seq 1 55); do curl -s -k -X POST "https://172.20.13.7:8443" >/dev/null & done; wait'

# ------------------------------------------------------------------------------
# LETTURA LOG SNORT
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}======================================================${NC}"
echo -e "${YELLOW}  Attesa analisi Snort (5s)...                         ${NC}"
echo -e "${YELLOW}======================================================${NC}"
sleep 5

echo -e "\n${GREEN}Alert ZTA rilevati:${NC}"
docker exec ids_network_monitor sh -c \
    'cat /var/log/snort/alert_fast.txt 2>/dev/null | grep "ZTA-" | sed "s/.*\[ZTA/[ZTA/" | cut -d"]" -f1-2 | sort | uniq -c | sort -rn'

echo -e "\n${YELLOW}Conteggio per regola:${NC}"
docker exec ids_network_monitor sh -c \
    'cat /var/log/snort/alert_fast.txt 2>/dev/null | grep -oP "\[ZTA-\d+\]" | sort | uniq -c'

# ------------------------------------------------------------------------------
# PULIZIA
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}Pulizia container client...${NC}"
docker compose --profile testing stop \
    client_intruso \
    client_operatore_ancona \
    client_soc_admin > /dev/null 2>&1
echo "Terminato."
