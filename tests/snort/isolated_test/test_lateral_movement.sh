#!/bin/bash
# =============================================================================
# MARITIME ZTA - PRUEBAS DE MOVIMIENTO LATERAL (ESTE-OESTE)
# =============================================================================
export MSYS_NO_PATHCONV=1

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
REPORT_FILE="resultado_movimiento_lateral.txt"

# Inicializar el archivo de reporte en la raíz del proyecto
echo "=======================================================================" > "$REPORT_FILE"
echo " MARITIME ZTA - REPORTE DE EJECUCIÓN DE MOVIMIENTO LATERAL" >> "$REPORT_FILE"
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

    # Ejecutamos el ataque desde el contenedor origen correspondiente
    docker exec "$source_container" sh -c "$command" >/dev/null 2>&1 || true

    # Damos tiempo a Snort para procesar el paquete
    sleep 2

    local end_time=$(date '+%H:%M:%S')

    # Búsqueda del SID
    if docker exec ids_network_monitor sh -c "grep -q ':${expected_sid}:' /var/log/snort/alert_json.txt 2>/dev/null"; then
        echo -e "${GREEN}   [✔] BLOQUEO/ALERTA CONFIRMADA a las ${end_time} (SID: $expected_sid)${NC}"
        echo "[✔ DETECTADO] $attack_desc (SID: $expected_sid) - $end_time" >> "$REPORT_FILE"
    else
        echo -e "${RED}   [✘] FALLO a las ${end_time} (Snort NO detectó el SID $expected_sid)${NC}"
        echo "[✘ FALLO] $attack_desc (SID: $expected_sid) - Snort ciego ante este evento" >> "$REPORT_FILE"
    fi
}

# Limpiamos los logs de Snort para no arrastrar resultados de pruebas anteriores
docker exec ids_network_monitor sh -c "> /var/log/snort/alert_json.txt"
echo -e "Preparando motores y limpiando buffer de Snort..."
sleep 2

header "FASE 1: INTRUSO (Red Pública) INTENTANDO SALTO LATERAL"
# SID 1000022: Public -> VPN (Operatore Ancona 172.20.11.20)
fire_attack "client_intruso" "Intruso hacia VPN Operatore" "curl -s --connect-timeout 1 http://172.20.11.20 || timeout 1 nc -zv 172.20.11.20 80 || echo > /dev/tcp/172.20.11.20/80" "1000022"

# SID 1000023: Public -> Satellite (Capitano Claudia 172.20.12.21)
fire_attack "client_intruso" "Intruso hacia Red Satelital Capitano" "curl -s --connect-timeout 1 http://172.20.12.21 || timeout 1 nc -zv 172.20.12.21 80 || echo > /dev/tcp/172.20.12.21/80" "1000023"

# SID 1000025: Public -> Backend (MongoDB 172.20.3.5)
fire_attack "client_intruso" "Intruso directo a BD Interna" "curl -s --connect-timeout 1 http://172.20.3.5:27017 || timeout 1 nc -zv 172.20.3.5 27017 || echo > /dev/tcp/172.20.3.5/27017" "1000025"


header "FASE 2: ABUSO DE PRIVILEGIOS DESDE ADENTRO"
# SID 1000026: Satellite -> Corporate (Capitano intentando llegar a SOC Admin 172.20.10.20)
fire_attack "client_capitano_claudia" "Capitano hacia Red SOC Corporativa" "curl -s --connect-timeout 1 http://172.20.10.20 || timeout 1 nc -zv 172.20.10.20 80 || echo > /dev/tcp/172.20.10.20/80" "1000026"

# SID 1000027: Satellite -> Backend (Capitano bypaseando Envoy/API directo a MongoDB 172.20.3.5)
fire_attack "client_capitano_claudia" "Capitano directo a MongoDB (Bypass API)" "curl -s --connect-timeout 1 http://172.20.3.5:27017 || timeout 1 nc -zv 172.20.3.5 27017 || echo > /dev/tcp/172.20.3.5/27017" "1000027"

# SID 1000028: VPN -> Backend (Operatore bypaseando Envoy/API directo a MongoDB 172.20.3.5)
fire_attack "client_operatore_ancona" "Operatore directo a MongoDB (Bypass API)" "curl -s --connect-timeout 1 http://172.20.3.5:27017 || timeout 1 nc -zv 172.20.3.5 27017 || echo > /dev/tcp/172.20.3.5/27017" "1000028"

header "REPORTE GENERADO"
echo -e "${GREEN}✔ El test ha finalizado. Los resultados se han guardado en: ${NC}$(pwd)/${REPORT_FILE}"
echo -e "${YELLOW}► Puedes ver el archivo abriéndolo en tu editor o ejecutando: cat ${REPORT_FILE}${NC}"
echo "=======================================================================" >> "$REPORT_FILE"
echo " FIN DEL REPORTE" >> "$REPORT_FILE"
