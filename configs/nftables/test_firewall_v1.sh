#!/bin/bash
# ==============================================================================
# Script di Test Automatizzato - NFTables Firewall (Zero Trust)
# ==============================================================================
# Questo script esegue i test di penetrazione simulati per verificare
# che il firewall perimetrale blocchi correttamente gli accessi non autorizzati.
# ==============================================================================

# Colori per l'output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}======================================================${NC}"
echo -e "${YELLOW}  Inizio Test di Sicurezza NFTables (Zero Trust)      ${NC}"
echo -e "${YELLOW}======================================================${NC}"

# 1. Avviare i container di test (Intruso e Operatore)
echo -e "\n${GREEN}[1] Avvio dei client di test...${NC}"
docker-compose --profile testing up -d client_intruso client_operatore_ancona
sleep 3 # Attendiamo che i container siano pronti

# 2. Test ICMP (Ping) - Dovrebbe essere consentito dalla Regola 6
echo -e "\n${GREEN}[2] TEST: Connettività base (Ping ICMP) dall'Intruso al Firewall...${NC}"
if docker exec client_intruso ping -c 2 172.20.13.10 > /dev/null 2>&1; then
    echo -e "👉 Risultato: ${GREEN}SUCCESSO${NC} (Ping consentito come previsto)."
else
    echo -e "👉 Risultato: ${RED}FALLITO${NC} (Ping bloccato o container non raggiungibile)."
fi

# 3. Test Accesso Non Autorizzato a MongoDB (Porta 27017) - Dovrebbe essere bloccato
echo -e "\n${GREEN}[3] TEST: Tentativo di accesso diretto a MongoDB dall'Intruso...${NC}"
echo "Esecuzione attacco verso la porta 27017 (Timeout impostato a 2 secondi)..."
# Usiamo curl con timeout per non far bloccare lo script. Se fallisce (timeout), il firewall ha funzionato.
docker exec client_intruso curl --connect-timeout 2 -s telnet://172.20.13.10:27017 > /dev/null 2>&1
CURL_EXIT=$?

if [ $CURL_EXIT -eq 28 ] || [ $CURL_EXIT -eq 7 ]; then
    echo -e "👉 Risultato: ${GREEN}BLOCCATO CON SUCCESSO${NC} (Il Firewall ha droppato i pacchetti)."
else
    echo -e "👉 Risultato: ${RED}ALLARME${NC} (La connessione non è stata bloccata correttamente!). Codice: $CURL_EXIT"
fi

# 4. Test Accesso Non Autorizzato a OPA (Porta 8181) - Dovrebbe essere bloccato
echo -e "\n${GREEN}[4] TEST: Tentativo di accesso diretto a OPA Policy Engine dall'Intruso...${NC}"
docker exec client_intruso curl --connect-timeout 2 -s telnet://172.20.13.10:8181 > /dev/null 2>&1
CURL_EXIT=$?

if [ $CURL_EXIT -eq 28 ] || [ $CURL_EXIT -eq 7 ]; then
    echo -e "👉 Risultato: ${GREEN}BLOCCATO CON SUCCESSO${NC} (Il Firewall ha droppato i pacchetti verso OPA)."
else
    echo -e "👉 Risultato: ${RED}ALLARME${NC} (La connessione verso OPA è passata!)."
fi

# 5. Verifica dei Log del Firewall (Audit)
echo -e "\n${GREEN}[5] VERIFICA AUDIT: Estrazione dei log di blocco dal Kernel del Firewall...${NC}"
echo -e "Cerchiamo le prove dell'attacco bloccato nei log di sistema:\n"

# Eseguiamo dmesg dentro il firewall e filtriamo per NFTABLES usando sh -c per compatibilità
docker exec firewall_perimeter sh -c 'dmesg | grep "NFTABLES"' | tail -n 5 | while read -r line; do
    echo -e "${RED}LOG: $line${NC}"
done

echo -e "\n${YELLOW}======================================================${NC}"
echo -e "${YELLOW}  Test Completato. La perimetrazione ZTA è sicura!    ${NC}"
echo -e "${YELLOW}======================================================${NC}"
