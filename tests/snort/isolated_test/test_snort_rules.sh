#!/bin/bash
# =============================================================================
# MARITIME ZTA - BATERÍA DE PRUEBAS PARA SNORT 3 IDS (VERSIÓN WINDOWS/MINGW)
# =============================================================================
# Evita que Git Bash en Windows rompa las rutas de Linux
export MSYS_NO_PATHCONV=1

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
REPORT_FILE="resultado_snort_rules.txt"

# Inicializar el archivo de reporte en la raíz del proyecto
echo "=======================================================================" > "$REPORT_FILE"
echo " MARITIME ZTA - REPORTE DE EJECUCIÓN DE SNORT RULES (NORTE-SUR)" >> "$REPORT_FILE"
echo " Fecha de ejecución: $(date '+%Y-%m-%d %H:%M:%S')" >> "$REPORT_FILE"
echo "=======================================================================" >> "$REPORT_FILE"

header() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "\n--- $1 ---" >> "$REPORT_FILE"
}

fire_attack() {
    local attack_desc=$1
    local command=$2
    local expected_sid=$3

    local start_time=$(date '+%H:%M:%S')
    echo -e "${YELLOW}► [${start_time}] Lanzando: ${attack_desc}${NC}"

    # Ejecutamos el ataque desde el intruso
    docker exec client_intruso sh -c "$command" >/dev/null 2>&1 || true

    # Damos tiempo a Snort para procesar
    sleep 2

    local end_time=$(date '+%H:%M:%S')

    # Buscamos el SID en los logs (buscando :SID: para coincidir con 1:999901:2)
    if docker exec ids_network_monitor sh -c "grep -q ':${expected_sid}:' /var/log/snort/alert_json.txt 2>/dev/null"; then
        echo -e "${GREEN}   [✔] DETECTADO a las ${end_time} (SID: $expected_sid)${NC}"
        echo "[✔ DETECTADO] $attack_desc (SID: $expected_sid) - Detectado a las $end_time" >> "$REPORT_FILE"
    else
        echo -e "${RED}   [✘] FALLO a las ${end_time} (Snort NO detectó el SID $expected_sid)${NC}"
        echo "[✘ FALLO] $attack_desc (SID: $expected_sid) - Snort ciego ante este evento" >> "$REPORT_FILE"
    fi
}

header "INICIANDO BATERÍA DE ATAQUES DESDE 'client_intruso'"

docker exec ids_network_monitor sh -c "> /var/log/snort/alert_json.txt"
echo -e "Log de alertas limpiado. Esperando motores..."
sleep 2

# -----------------------------------------------------------------------------
# PRUEBA 1: Ping MVP (SID: 999901)
# -----------------------------------------------------------------------------
fire_attack "ICMP Ping en public_net" "ping -c 1 172.20.13.11" "999901"

# -----------------------------------------------------------------------------
# PRUEBA 2: SQLi cifrado hacia Envoy (SID: 999903)
# [MODIFICADO]: Uso de certificados mTLS del intruso y --tries=1
# -----------------------------------------------------------------------------
fire_attack "SQLi UNION SELECT (HTTPS 8443 -> Backend 3000)" "curl -k -s --max-time 2 --cert /certs/device/device.crt --key /certs/device/device.key -X POST https://172.20.13.7:8443/api/login -d 'user=admin&pass=union select *' || wget --no-check-certificate -qO- -T 2 --tries=1 --post-data='user=admin&pass=union select *' https://172.20.13.7:8443/api/login" "999903"

# -----------------------------------------------------------------------------
# PRUEBA 3: Intento directo a MongoDB - Evasión PEP (SID: 999904)
# -----------------------------------------------------------------------------
fire_attack "Bypass a MongoDB (TCP SYN)" "curl -s --connect-timeout 1 http://172.20.3.5:27017 || timeout 1 nc -zv 172.20.3.5 27017 || echo > /dev/tcp/172.20.3.5/27017" "999904"

# -----------------------------------------------------------------------------
# PRUEBA 4: Manipulación de OPA (SID: 1000032)
# -----------------------------------------------------------------------------
fire_attack "OPA Policy Tampering en public_net" "curl -s --max-time 2 -X PUT http://172.20.13.6:8181/v1/policies || wget -qO- -T 2 --method=PUT http://172.20.13.6:8181/v1/policies" "1000032"

# -----------------------------------------------------------------------------
# PRUEBA 5: Command Injection L7 (SID: 1000019)
# [MODIFICADO]: Uso de certificados mTLS del intruso y --tries=1
# -----------------------------------------------------------------------------
fire_attack "Inyección de Comandos OS (HTTPS 8443)" "curl -k -s --max-time 2 --cert /certs/device/device.crt --key /certs/device/device.key 'https://172.20.13.7:8443/recursos?id=1;cat /etc/passwd' || wget --no-check-certificate -qO- -T 2 --tries=1 'https://172.20.13.7:8443/recursos?id=1;cat /etc/passwd'" "1000019"

# =============================================================================
# CONFIRMACIÓN Y REPORTE
# =============================================================================
header "RESULTADOS Y MONITOREO DEL SISTEMA"

echo -e "${GREEN}✔ El test ha finalizado. Los resultados se han guardado en: ${NC}$(pwd)/${REPORT_FILE}"
echo "=======================================================================" >> "$REPORT_FILE"
echo " FIN DEL REPORTE" >> "$REPORT_FILE"

echo -e "\n${YELLOW}Últimas alertas generadas en Snort:${NC}"
docker exec ids_network_monitor bash -c "tail -n 3 /var/log/snort/alert_json.txt | jq -c '{timestamp, rule, src_addr, dst_addr, msg}' 2>/dev/null || tail -n 3 /var/log/snort/alert_json.txt"

echo -e "\n${CYAN}========================================================================${NC}"
echo -e "${GREEN}✔ Snort está escribiendo logs en:${NC} /var/log/snort/alert_json.txt"
echo -e "${YELLOW}► Splunk HEC:${NC} http://localhost:8000 (Búsqueda: index=\"main\" sourcetype=\"_json\")"
echo -e "${CYAN}========================================================================${NC}\n"
