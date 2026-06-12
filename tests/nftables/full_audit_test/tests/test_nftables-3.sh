#!/bin/bash
# =============================================================================
# MARITIME ZTA - TEST NFTABLES FIREWALL
# Compatible: Git Bash (MINGW64) + Linux
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

# Test TCP usando timeout del sistema operativo del contenedor
# Usa /dev/tcp de bash nativo — no depende de nc ni curl
# $1=contenedor $2=ip $3=puerto $4=esperado $5=descripcion
test_tcp() {
    local container=$1 ip=$2 port=$3 expected=$4 desc=$5
    TOTAL=$((TOTAL+1))

    # bash /dev/tcp es la forma mas confiable: exit 0 = conectó, exit != 0 = bloqueado
    result=$(docker exec "$container" \
        bash -c "timeout 2 bash -c 'echo > /dev/tcp/$ip/$port' 2>/dev/null \
        && echo CONNECTED || echo BLOCKED")

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
        echo -e "${RED}[FAIL]${NC} $desc — DEBERIA CONECTAR pero fue bloqueado"
        FAIL=$((FAIL+1))
    fi
}

# IPs del compose
ENVOY_IP="172.20.2.7"
OPA_IP="172.20.2.6"
MONGODB_IP="172.20.3.5"
API_IP="172.20.3.20"
SPLUNK_IP="172.20.4.8"

# =============================================================================
header "BLOQUE 1: FLUJOS LEGITIMOS — nftables debe PERMITIR"
# =============================================================================
test_tcp "client_operatore_ancona" "$ENVOY_IP"  8443 "PASS"  "vpn_net → Envoy PEP :8443 (operatore_ancona)"
test_tcp "client_capitano_claudia" "$ENVOY_IP"  8443 "PASS"  "satellite_net → Envoy PEP :8443 (capitano_claudia)"
test_tcp "client_soc_admin"        "$ENVOY_IP"  8443 "PASS"  "corporate_net → Envoy PEP :8443 (soc_admin)"
test_tcp "client_intruso"          "$ENVOY_IP"  8443 "PASS"  "public_net → Envoy PEP :8443 (nftables permite — OPA decidirá)"
test_tcp "client_soc_admin"        "$SPLUNK_IP" 8000 "PASS"  "corporate_net → Splunk UI :8000 (soc_admin)"

# =============================================================================
header "BLOQUE 2: BYPASS DEL PEP — nftables debe BLOQUEAR"
# =============================================================================
test_tcp "client_intruso"          "$MONGODB_IP" 27017 "BLOCK" "public_net → MongoDB :27017 directo"
test_tcp "client_intruso"          "$API_IP"     3000  "BLOCK" "public_net → api_backend :3000 directo"
test_tcp "client_intruso"          "$OPA_IP"     8181  "BLOCK" "public_net → OPA REST :8181 directo"
test_tcp "client_intruso"          "$OPA_IP"     9191  "BLOCK" "public_net → OPA gRPC :9191 directo"
test_tcp "client_intruso"          "$ENVOY_IP"   9901  "BLOCK" "public_net → Envoy Admin :9901"
test_tcp "client_operatore_ancona" "$MONGODB_IP" 27017 "BLOCK" "vpn_net → MongoDB :27017 directo"
test_tcp "client_capitano_claudia" "$OPA_IP"     8181  "BLOCK" "satellite_net → OPA :8181 directo"

# =============================================================================
header "BLOQUE 3: MOVIMIENTO LATERAL — nftables debe BLOQUEAR"
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

echo -e "\n${YELLOW}► Reglas activas en firewall_perimeter:${NC}"
docker exec firewall_perimeter nft list ruleset | \
    grep -E "policy|dport|saddr|daddr|log prefix"

echo -e "\n${YELLOW}► Logs de eventos nftables (kernel via dmesg):${NC}"
docker exec firewall_perimeter dmesg 2>/dev/null | \
    grep -E "NFT-FWD|NFT-INPUT|CRITICAL|WARNING|DIRECT|UNAUTHORIZED|ENVOY_ADMIN" | \
    tail -20 || echo "Sin eventos en dmesg (WSL2/Docker Desktop aísla el kernel journal)"

echo -e "\n${YELLOW}► Logs del contenedor firewall (stdout entrypoint):${NC}"
docker logs firewall_perimeter --tail 10 2>&1

echo -e "\n${YELLOW}► Estado Splunk HEC:${NC}"
SPLUNK_STATUS=$(docker exec siem_central \
    curl -sk -o /dev/null -w "%{http_code}" \
    http://localhost:8088/services/collector/health 2>/dev/null)
if [ "$SPLUNK_STATUS" = "200" ]; then
    echo -e "${GREEN}Splunk HEC activo ✔ — logs siendo ingestados${NC}"
else
    echo -e "${YELLOW}Splunk HEC: $SPLUNK_STATUS — puede estar iniciando${NC}"
    echo -e "${YELLOW}Nota: para enviar logs de nftables a Splunk añadir al compose:${NC}"
    echo -e "${YELLOW}  SPLUNK_HEC_URL=https://siem_central:8088/services/collector/event${NC}"
    echo -e "${YELLOW}  SPLUNK_HEC_TOKEN=\${SPLUNK_HEC_TOKEN}${NC}"
fi

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
    echo -e "${RED}✘ $FAIL escenarios fallaron — revisar antes de continuar${NC}"
    exit 1
fi
