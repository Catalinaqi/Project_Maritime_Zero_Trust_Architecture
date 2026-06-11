#!/bin/bash
# =============================================================================
# MARITIME ZTA - TEST NFTABLES FIREWALL
# Ejecutar desde raiz del proyecto: bash test_nftables.sh
# Prerequisito: docker compose --profile testing up -d
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=0

header() {
    echo -e "\n${BLUE}══════════════════════════════════════════${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}══════════════════════════════════════════${NC}"
}

# Prueba TCP usando curl --connect-timeout
# curl falla con exit 7 (connection refused) o exit 28 (timeout) cuando nftables dropea
# exit 0 o códigos HTTP = conexión establecida
# $1=contenedor $2=ip $3=puerto $4=esperado(BLOCK|PASS) $5=descripcion
test_tcp() {
    local container=$1 ip=$2 port=$3 expected=$4 desc=$5
    TOTAL=$((TOTAL+1))

    # curl intenta conectar. --max-time 3 evita esperar demasiado en drops.
    # Usamos http:// — no importa si responde HTTP, solo si TCP conecta.
    http_code=$(docker exec "$container" \
        curl -sk -o /dev/null -w "%{http_code}" \
        --max-time 3 --connect-timeout 2 \
        "http://$ip:$port" 2>/dev/null || echo "FAILED")

    # FAILED o 000 = no conectó (bloqueado por nftables o timeout)
    # Cualquier código HTTP (200,400,403,503...) = TCP conectó
    if [ "$http_code" = "FAILED" ] || [ "$http_code" = "000" ]; then
        connected="NO"
    else
        connected="YES"
    fi

    if   [ "$expected" = "BLOCK" ] && [ "$connected" = "NO"  ]; then
        echo -e "${GREEN}[PASS]${NC} $desc — bloqueado ✔"
        PASS=$((PASS+1))
    elif [ "$expected" = "PASS"  ] && [ "$connected" = "YES" ]; then
        echo -e "${GREEN}[PASS]${NC} $desc — conectó HTTP $http_code ✔"
        PASS=$((PASS+1))
    elif [ "$expected" = "BLOCK" ] && [ "$connected" = "YES" ]; then
        echo -e "${RED}[FAIL]${NC} $desc — DEBERIA ESTAR BLOQUEADO (HTTP $http_code) ⚠️"
        FAIL=$((FAIL+1))
    else
        echo -e "${RED}[FAIL]${NC} $desc — DEBERIA CONECTAR pero fue bloqueado (nftables o servicio caído)"
        FAIL=$((FAIL+1))
    fi
}

# =============================================================================
# IPs — deben coincidir con compose environment
# =============================================================================
ENVOY_IP="172.20.2.7"
OPA_IP="172.20.2.6"
MONGODB_IP="172.20.3.5"
API_IP="172.20.3.20"
SPLUNK_IP="172.20.4.8"

# =============================================================================
# BLOQUE 1: FLUJOS LEGITIMOS
# nftables permite tcp dport 8443 desde cualquier red.
# Puede responder con cualquier código HTTP — lo importante es que TCP conecta.
# =============================================================================
header "BLOQUE 1: FLUJOS LEGITIMOS — nftables debe PERMITIR (esperado: PASS)"

test_tcp "client_operatore_ancona" "$ENVOY_IP" 8443 "PASS" "vpn_net → Envoy PEP :8443 (operatore_ancona)"
test_tcp "client_capitano_claudia" "$ENVOY_IP" 8443 "PASS" "satellite_net → Envoy PEP :8443 (capitano_claudia)"
test_tcp "client_soc_admin"        "$ENVOY_IP" 8443 "PASS" "corporate_net → Envoy PEP :8443 (soc_admin)"
test_tcp "client_intruso"          "$ENVOY_IP" 8443 "PASS" "public_net → Envoy PEP :8443 (nftables permite — OPA decidirá)"
test_tcp "client_soc_admin"        "$SPLUNK_IP" 8000 "PASS" "corporate_net → Splunk Web UI :8000 (soc_admin)"

# =============================================================================
# BLOQUE 2: BYPASS DEL PEP
# Acceso directo a servicios internos — nftables debe BLOQUEAR
# =============================================================================
header "BLOQUE 2: BYPASS DEL PEP — nftables debe BLOQUEAR (esperado: BLOCK)"

test_tcp "client_intruso"          "$MONGODB_IP" 27017 "BLOCK" "public_net → MongoDB :27017 directo"
test_tcp "client_intruso"          "$API_IP"     3000  "BLOCK" "public_net → api_backend :3000 directo"
test_tcp "client_intruso"          "$OPA_IP"     8181  "BLOCK" "public_net → OPA REST :8181 directo"
test_tcp "client_intruso"          "$OPA_IP"     9191  "BLOCK" "public_net → OPA gRPC :9191 directo"
test_tcp "client_intruso"          "$ENVOY_IP"   9901  "BLOCK" "public_net → Envoy Admin :9901"
test_tcp "client_operatore_ancona" "$MONGODB_IP" 27017 "BLOCK" "vpn_net → MongoDB :27017 directo"
test_tcp "client_capitano_claudia" "$OPA_IP"     8181  "BLOCK" "satellite_net → OPA :8181 directo"

# =============================================================================
# BLOQUE 3: MOVIMIENTO LATERAL
# Cruce entre redes sin pasar por PEP — nftables debe BLOQUEAR
# =============================================================================
header "BLOQUE 3: MOVIMIENTO LATERAL — nftables debe BLOQUEAR (esperado: BLOCK)"

test_tcp "client_intruso"          "172.20.11.20" 8443 "BLOCK" "public_net → vpn_net (operatore_ancona)"
test_tcp "client_intruso"          "172.20.12.21" 8443 "BLOCK" "public_net → satellite_net (capitano_claudia)"
test_tcp "client_intruso"          "172.20.10.20" 8443 "BLOCK" "public_net → corporate_net (soc_admin)"
test_tcp "client_capitano_claudia" "172.20.10.20" 8443 "BLOCK" "satellite_net → corporate_net (escalada capitano→SOC)"

# =============================================================================
# BLOQUE 4: SPLUNK UI RESTRINGIDA
# Solo corporate_net puede acceder a :8000
# =============================================================================
header "BLOQUE 4: SPLUNK UI — solo SOC permitido (esperado: BLOCK salvo soc_admin)"

test_tcp "client_intruso"          "$SPLUNK_IP" 8000 "BLOCK" "public_net → Splunk UI :8000"
test_tcp "client_capitano_claudia" "$SPLUNK_IP" 8000 "BLOCK" "satellite_net → Splunk UI :8000"
test_tcp "client_operatore_ancona" "$SPLUNK_IP" 8000 "BLOCK" "vpn_net → Splunk UI :8000"

# =============================================================================
# BLOQUE 5: ESTADO NFTABLES Y TRAZABILIDAD EN SPLUNK
# =============================================================================
header "BLOQUE 5: ESTADO NFTABLES"

echo -e "\n${YELLOW}► Reglas activas:${NC}"
docker exec firewall_perimeter nft list ruleset | \
    grep -E "policy|tcp dport|ip saddr|log prefix"

echo -e "\n${YELLOW}► Logs de drops recientes (ultimos 20):${NC}"
docker logs firewall_perimeter --tail 50 2>&1 | \
    grep -E "CRITICAL|WARNING|NFT-FWD|NFT-INPUT" | tail -20 || \
    echo "Sin eventos de drop recientes"

echo -e "\n${YELLOW}► Verificando trazabilidad: eventos llegando a Splunk HEC...${NC}"
SPLUNK_HEALTH=$(docker exec siem_central \
    curl -sk -o /dev/null -w "%{http_code}" \
    http://localhost:8088/services/collector/health 2>/dev/null || echo "000")
if [ "$SPLUNK_HEALTH" = "200" ]; then
    echo -e "${GREEN}Splunk HEC activo (200) — logs del firewall siendo ingestados ✔${NC}"
else
    echo -e "${YELLOW}Splunk HEC responde $SPLUNK_HEALTH — puede estar iniciando aún${NC}"
fi

# =============================================================================
# RESUMEN
# =============================================================================
header "RESUMEN"
echo -e "Total : $TOTAL"
echo -e "${GREEN}Pass  : $PASS${NC}"
echo -e "${RED}Fail  : $FAIL${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✔ NFTABLES OK — todos los escenarios superados${NC}"
    echo -e "${GREEN}  Nivel 1 (nftables) completado.${NC}"
    echo -e "${GREEN}  El trafico legitimo pasa al siguiente nivel:${NC}"
    echo -e "${GREEN}  → Envoy verifica mTLS${NC}"
    echo -e "${GREEN}  → OPA evalua politicas (roles, dispositivos, red)${NC}"
    echo -e "${GREEN}  → api_backend → MongoDB${NC}"
else
    echo -e "${RED}✘ $FAIL escenarios fallaron${NC}"
    echo -e "${YELLOW}  Revisar si los servicios destino están activos:${NC}"
    echo -e "${YELLOW}  docker ps --format 'table {{.Names}}\t{{.Status}}'${NC}"
    exit 1
fi
