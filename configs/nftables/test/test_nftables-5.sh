#!/bin/bash
# =============================================================================
# MARITIME ZTA - TEST NFTABLES FIREWALL
# Ejecutar desde raiz: bash test_nftables.sh
# Prerequisito: docker compose --profile testing up -d
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'
YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS=0; FAIL=0; TOTAL=0

header() {
    echo -e "\n${BLUE}══════════════════════════════════════════${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}══════════════════════════════════════════${NC}"
}

test_tcp() {
    local container=$1 ip=$2 port=$3 expected=$4 desc=$5
    TOTAL=$((TOTAL+1))

    result=$(docker exec "$container" \
        sh -c "timeout 3 bash -c 'echo > /dev/tcp/$ip/$port' 2>/dev/null \
               && echo CONNECTED || echo BLOCKED" 2>/dev/null)
    [ -z "$result" ] && result="BLOCKED"

    if   [ "$expected" = "BLOCK" ] && [ "$result" = "BLOCKED"   ]; then
        echo -e "${GREEN}[PASS]${NC} $desc — bloqueado ✔"
        PASS=$((PASS+1))
    elif [ "$expected" = "PASS"  ] && [ "$result" = "CONNECTED" ]; then
        echo -e "${GREEN}[PASS]${NC} $desc — conectó ✔"
        PASS=$((PASS+1))
    elif [ "$expected" = "BLOCK" ] && [ "$result" = "CONNECTED" ]; then
        echo -e "${RED}[FAIL]${NC} $desc — DEBERIA ESTAR BLOQUEADO ⚠️"
        FAIL=$((FAIL+1))
    else
        echo -e "${RED}[FAIL]${NC} $desc — DEBERIA CONECTAR pero fue bloqueado/timeout"
        FAIL=$((FAIL+1))
    fi
}

# =============================================================================
# IPs de Envoy por red — cada cliente usa la IP de su propia subred
# pep_gateway tiene una IP en cada red del compose
# =============================================================================
ENVOY_VPN="172.20.11.7"        # vpn_net       — client_operatore_ancona
ENVOY_SATELLITE="172.20.12.7"  # satellite_net  — client_capitano_claudia
ENVOY_CORPORATE="172.20.10.7"  # corporate_net  — client_soc_admin
ENVOY_PUBLIC="172.20.13.7"     # public_net     — client_intruso

# IPs internas — backend_net (nunca accesibles desde clientes si nftables funciona)
MONGODB_IP="172.20.3.5"
API_IP="172.20.3.20"

# OPA — zerotrust_net (nunca accesible desde clientes directamente)
OPA_IP="172.20.2.6"

# Splunk — monitoring_net
SPLUNK_IP="172.20.4.8"

# Envoy admin — zerotrust_net (nunca accesible desde clientes)
ENVOY_ADMIN_IP="172.20.2.7"

# =============================================================================
header "BLOQUE 1: FLUJOS LEGITIMOS — nftables debe PERMITIR"
# Cada cliente conecta a Envoy por su propia subred
# nftables: tcp dport 8443 accept — sin restriccion de origen
# =============================================================================
test_tcp "client_operatore_ancona" "$ENVOY_VPN"       8443 "PASS" "vpn_net → Envoy :8443 (operatore_ancona via 172.20.11.7)"
test_tcp "client_capitano_claudia" "$ENVOY_SATELLITE"  8443 "PASS" "satellite_net → Envoy :8443 (capitano_claudia via 172.20.12.7)"
test_tcp "client_soc_admin"        "$ENVOY_CORPORATE"  8443 "PASS" "corporate_net → Envoy :8443 (soc_admin via 172.20.10.7)"
test_tcp "client_intruso"          "$ENVOY_PUBLIC"     8443 "PASS" "public_net → Envoy :8443 (intruso via 172.20.13.7 — OPA decidirá)"
test_tcp "client_soc_admin"        "$SPLUNK_IP"        8000 "PASS" "corporate_net → Splunk UI :8000 (soc_admin)"

# =============================================================================
header "BLOQUE 2: BYPASS DEL PEP — nftables debe BLOQUEAR"
# Acceso directo a servicios internos evitando Envoy
# =============================================================================
test_tcp "client_intruso"          "$MONGODB_IP"    27017 "BLOCK" "public_net → MongoDB :27017 directo"
test_tcp "client_intruso"          "$API_IP"        3000  "BLOCK" "public_net → api_backend :3000 directo"
test_tcp "client_intruso"          "$OPA_IP"        8181  "BLOCK" "public_net → OPA REST :8181 directo"
test_tcp "client_intruso"          "$OPA_IP"        9191  "BLOCK" "public_net → OPA gRPC :9191 directo"
test_tcp "client_intruso"          "$ENVOY_ADMIN_IP" 9901 "BLOCK" "public_net → Envoy Admin :9901"
test_tcp "client_operatore_ancona" "$MONGODB_IP"    27017 "BLOCK" "vpn_net → MongoDB :27017 directo"
test_tcp "client_capitano_claudia" "$OPA_IP"        8181  "BLOCK" "satellite_net → OPA :8181 directo"

# =============================================================================
header "BLOQUE 3: MOVIMIENTO LATERAL — nftables debe BLOQUEAR"
# Clientes intentando alcanzar IPs de otras redes directamente
# =============================================================================
test_tcp "client_intruso"          "172.20.11.20" 8443 "BLOCK" "public_net → vpn_net (operatore_ancona)"
test_tcp "client_intruso"          "172.20.12.21" 8443 "BLOCK" "public_net → satellite_net (capitano_claudia)"
test_tcp "client_intruso"          "172.20.10.20" 8443 "BLOCK" "public_net → corporate_net (soc_admin)"
test_tcp "client_capitano_claudia" "172.20.10.20" 8443 "BLOCK" "satellite_net → corporate_net (escalada capitano→SOC)"

# =============================================================================
header "BLOQUE 4: SPLUNK UI — solo SOC permitido"
# =============================================================================
test_tcp "client_intruso"          "$SPLUNK_IP" 8000 "BLOCK" "public_net → Splunk UI :8000"
test_tcp "client_capitano_claudia" "$SPLUNK_IP" 8000 "BLOCK" "satellite_net → Splunk UI :8000"
test_tcp "client_operatore_ancona" "$SPLUNK_IP" 8000 "BLOCK" "vpn_net → Splunk UI :8000"

# =============================================================================
header "BLOQUE 5: TRAZABILIDAD"
# =============================================================================
echo -e "\n${YELLOW}► Reglas activas:${NC}"
docker exec firewall_perimeter nft list ruleset | \
    grep -E "policy|dport|saddr|daddr|log prefix"

echo -e "\n${YELLOW}► Logs del contenedor firewall:${NC}"
docker logs firewall_perimeter --tail 10 2>&1

echo -e "\n${YELLOW}► Estado Splunk HEC:${NC}"
SPLUNK_STATUS=$(docker exec siem_central \
    curl -sk -o /dev/null -w "%{http_code}" \
    http://localhost:8088/services/collector/health 2>/dev/null)
[ "$SPLUNK_STATUS" = "200" ] \
    && echo -e "${GREEN}Splunk HEC activo ✔${NC}" \
    || echo -e "${YELLOW}Splunk HEC: $SPLUNK_STATUS — puede estar iniciando${NC}"

# =============================================================================
header "RESUMEN"
# =============================================================================
echo -e "Total : $TOTAL"
echo -e "${GREEN}Pass  : $PASS${NC}"
echo -e "${RED}Fail  : $FAIL${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✔ NFTABLES OK — Nivel 1 completado${NC}"
    echo -e "${GREEN}  Flujo siguiente: Envoy mTLS → OPA → api_backend → MongoDB${NC}"
else
    echo -e "${RED}✘ $FAIL escenarios fallaron${NC}"
    exit 1
fi
