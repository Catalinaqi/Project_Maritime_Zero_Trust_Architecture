#!/bin/bash
# =============================================================================
# MARITIME ZTA - PRUEBAS DE FUERZA BRUTA Y RECONOCIMIENTO (CAT 1 & 7)
# =============================================================================
export MSYS_NO_PATHCONV=1
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
REPORT_FILE="resultado_fuerza_bruta.txt"

echo "=======================================================================" > "$REPORT_FILE"
echo " MARITIME ZTA - REPORTE DE FUERZA BRUTA Y RECONOCIMIENTO" >> "$REPORT_FILE"
echo " Fecha de ejecución: $(date '+%Y-%m-%d %H:%M:%S')" >> "$REPORT_FILE"
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
    local expected_sid=$4

    local start_time=$(date '+%H:%M:%S')
    echo -e "${YELLOW}► [${start_time}] DESDE [${source_container}]: ${attack_desc}${NC}"

    docker exec "$source_container" sh -c "$command" >/dev/null 2>&1 || true
    sleep 3 # Damos más tiempo porque son ataques basados en volumen

    local end_time=$(date '+%H:%M:%S')

    if docker exec ids_network_monitor sh -c "grep -q ':${expected_sid}:' /var/log/snort/alert_json.txt 2>/dev/null"; then
        echo -e "${GREEN}   [✔] DETECTADO a las ${end_time} (SID: $expected_sid)${NC}"
        echo "[✔ DETECTADO] $attack_desc (SID: $expected_sid) - Detectado a las $end_time" >> "$REPORT_FILE"
    else
        echo -e "${RED}   [✘] FALLO a las ${end_time} (Snort NO detectó el SID $expected_sid)${NC}"
        echo "[✘ FALLO] $attack_desc (SID: $expected_sid) - Snort ciego ante este evento" >> "$REPORT_FILE"
    fi
}

docker exec ids_network_monitor sh -c "> /var/log/snort/alert_json.txt"
echo -e "Limpiando logs de Snort para pruebas de volumen..."
sleep 2

header "FASE 1: RECONOCIMIENTO (CAT 1)"

# SID 1000004: DDOS SYN Flood (Simulamos ráfaga de conexiones al PEP)
fire_attack "client_intruso" "SYN Flood simulado a Envoy (Requiere 100 hits)" "for i in \$(seq 1 110); do nc -zv -w 1 172.20.13.7 8443 & done; wait" "1000004"

header "FASE 2: FUERZA BRUTA (CAT 7)"

# SID 1000029: SSH Brute Force (5 intentos rápidos a puerto 22)
fire_attack "client_intruso" "Fuerza Bruta SSH a Envoy" "for i in \$(seq 1 6); do nc -zv -w 1 172.20.13.7 22; done" "1000029"

# SID 1000031: OPA REST API Brute Force (15 intentos a puerto 8181)
fire_attack "client_intruso" "Fuerza Bruta API de OPA" "for i in \$(seq 1 20); do curl -s --max-time 1 http://172.20.13.6:8181 >/dev/null; done" "1000031"

header "REPORTE GENERADO"
echo -e "${GREEN}✔ El test ha finalizado. Los resultados se han guardado en: ${NC}$(pwd)/${REPORT_FILE}"
echo "=======================================================================" >> "$REPORT_FILE"
echo " FIN DEL REPORTE" >> "$REPORT_FILE"
