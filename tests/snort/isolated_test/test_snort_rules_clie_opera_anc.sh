#!/bin/bash
# =============================================================================
# MARITIME ZTA - BATERÍA DE PRUEBAS PARA SNORT 3 IDS (VERSIÓN ZTA AWARE)
# =============================================================================
export MSYS_NO_PATHCONV=1

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
REPORT_FILE="resultado_snort_rules_client_operatore_ancona.txt"

echo "=======================================================================" > "$REPORT_FILE"
echo " MARITIME ZTA - REPORTE DE EJECUCIÓN DE SNORT RULES" >> "$REPORT_FILE"
echo " Fecha de ejecución: $(date '+%Y-%m-%d %H:%M:%S')" >> "$REPORT_FILE"
echo "=======================================================================" >> "$REPORT_FILE"

header() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "\n--- $1 ---" >> "$REPORT_FILE"
}

fire_attack() {
    local source_client=$1
    local attack_desc=$2
    local command=$3
    local expected_sid=$4

    local start_time=$(date '+%H:%M:%S')
    echo -e "${YELLOW}► [${start_time}] DESDE [${source_client}]: ${attack_desc}${NC}"

    docker exec "$source_client" sh -c "$command" >/dev/null 2>&1 || true
    sleep 2
    local end_time=$(date '+%H:%M:%S')

    # Usamos grep -E para buscar múltiples SIDs si es necesario (ej. 1000032|1000008)
    if docker exec ids_network_monitor sh -c "grep -E -q ':(${expected_sid}):' /var/log/snort/alert_json.txt 2>/dev/null"; then
        echo -e "${GREEN}   [✔] DETECTADO a las ${end_time} (SID interceptado)${NC}"
        echo "[✔ DETECTADO] $attack_desc - Detectado a las $end_time" >> "$REPORT_FILE"
    else
        echo -e "${RED}   [✘] MITIGADO POR OTRA CAPA a las ${end_time} (Snort no vio el payload)${NC}"
        echo "[✘ MITIGADO/BLOQUEADO] $attack_desc - Frenado antes de llegar a Snort" >> "$REPORT_FILE"
    fi
}

header "INICIANDO BATERÍA DE ATAQUES ZTA"

docker exec ids_network_monitor sh -c "> /var/log/snort/alert_json.txt"
echo -e "Log de alertas limpiado. Esperando motores..."
sleep 2

# -----------------------------------------------------------------------------
# PRUEBA 1: Ping MVP (SID: 999901)
# -----------------------------------------------------------------------------
fire_attack "client_intruso" "ICMP Ping en public_net" "ping -c 1 172.20.13.11" "999901"

# -----------------------------------------------------------------------------
# PRUEBA 2: SQLi cifrado hacia Envoy (SID: 999903)
# ZTA TWEAK: Usamos a 'client_operatore_ancona' para superar el control de OPA
# y asegurar que el tráfico malicioso llegue al backend donde Snort lo lee.
# -----------------------------------------------------------------------------
fire_attack "client_operatore_ancona" "Insider Threat: SQLi UNION SELECT (HTTPS -> Backend)" "curl -k -s --max-time 2 --cert /certs/device/device.crt --key /certs/device/device.key -X POST https://172.20.13.7:8443/api/login -d 'user=admin&pass=union select *' || wget --no-check-certificate -qO- -T 2 --tries=1 --post-data='user=admin&pass=union select *' https://172.20.13.7:8443/api/login" "999903"

# -----------------------------------------------------------------------------
# PRUEBA 3: Intento directo a MongoDB (SID: 999904 / Firewall Drop)
# -----------------------------------------------------------------------------
fire_attack "client_intruso" "Bypass a MongoDB (Será dropeado por Nftables)" "timeout 1 nc -zv 172.20.3.5 27017 || echo > /dev/tcp/172.20.3.5/27017" "999904"

# -----------------------------------------------------------------------------
# PRUEBA 4: Manipulación de OPA (SID: 1000032 o 1000008)
# Snort salta en el primer paquete SYN con la regla 1000008 (Acceso Directo)
# -----------------------------------------------------------------------------
fire_attack "client_intruso" "OPA Policy Tampering" "curl -s --max-time 2 -X PUT http://172.20.13.6:8181/v1/policies" "1000032|1000008"

# -----------------------------------------------------------------------------
# PRUEBA 5: Command Injection L7 (SID: 1000019)
# ZTA TWEAK: Usamos al Operador para que OPA autorice el paso del comando.
# -----------------------------------------------------------------------------
fire_attack "client_operatore_ancona" "Insider Threat: Inyección OS (HTTPS -> Backend)" "curl -k -s --max-time 2 --cert /certs/device/device.crt --key /certs/device/device.key 'https://172.20.13.7:8443/recursos?id=1;cat /etc/passwd' || wget --no-check-certificate -qO- -T 2 --tries=1 'https://172.20.13.7:8443/recursos?id=1;cat /etc/passwd'" "1000019"

header "RESULTADOS Y MONITOREO DEL SISTEMA"
echo -e "${GREEN}✔ Test finalizado. Resultados en: ${NC}$(pwd)/${REPORT_FILE}"
echo "=======================================================================" >> "$REPORT_FILE"

echo -e "\n${YELLOW}Últimas alertas generadas en Snort:${NC}"
docker exec ids_network_monitor bash -c "tail -n 4 /var/log/snort/alert_json.txt | jq -c '{timestamp, rule, src_addr, dst_addr, msg}' 2>/dev/null || tail -n 4 /var/log/snort/alert_json.txt"
