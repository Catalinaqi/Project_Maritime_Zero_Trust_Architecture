#!/bin/bash
# ==============================================================================
# Script di Test Automatizzato - NFTables Firewall (Zero Trust)
# ==============================================================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}======================================================${NC}"
echo -e "${YELLOW}  Inizio Test di Sicurezza NFTables (Zero Trust)      ${NC}"
echo -e "${YELLOW}======================================================${NC}"

echo -e "\n${GREEN}[1] Creazione di un Intruso temporaneo sulla rete pubblica...${NC}"
# Usiamo un container Alpine nativo garantito per essere attivo
docker run -d --name hacker_temporaneo --network maritime-zta_public alpine sleep 100

echo -e "\n${GREEN}[2] TEST: Connettività base (Ping ICMP)...${NC}"
echo "Dovresti vedere le risposte del ping (Regola 6 funzionante):"
docker exec hacker_temporaneo ping -c 2 172.20.13.10

echo -e "\n${GREEN}[3] TEST: Attacco a MongoDB (Porta 27017)...${NC}"
echo "Il terminale si bloccherà per 2 secondi (Timeout) perché il Firewall DROPPA i pacchetti:"
docker exec hacker_temporaneo wget -T 2 -qO- http://172.20.13.10:27017 || echo "--> ATTACCO BLOCCATO (Timeout)"

echo -e "\n${GREEN}[4] TEST: Attacco a OPA (Porta 8181)...${NC}"
echo "Anche qui si bloccherà per 2 secondi:"
docker exec hacker_temporaneo wget -T 2 -qO- http://172.20.13.10:8181 || echo "--> ATTACCO BLOCCATO (Timeout)"

echo -e "\n${GREEN}[5] VERIFICA AUDIT: Log dal Kernel del Firewall...${NC}"
echo "Ecco la prova dal vivo che il firewall ha rilevato e distrutto i pacchetti:"
docker exec firewall_perimeter sh -c 'dmesg | grep "NFTABLES"' | tail -n 5

echo -e "\n${YELLOW}Pulizia: Rimozione dell'intruso temporaneo...${NC}"
docker rm -f hacker_temporaneo > /dev/null

echo -e "${YELLOW}======================================================${NC}"
echo -e "${YELLOW}  Test Completato!                            ${NC}"
echo -e "${YELLOW}======================================================${NC}"
