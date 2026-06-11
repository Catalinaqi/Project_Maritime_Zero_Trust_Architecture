#!/bin/bash
# =============================================================================
# MARITIME ZTA - TEST NFTABLES FIREWALL
# Ejecutar desde el host: bash test_nftables.sh
# Prerequisito: docker compose --profile testing up -d
# =============================================================================
# Escenarios:
#   PASS = nftables permite (comportamiento esperado para flujo legítimo)
#   BLOCK = nftables bloquea (comportamiento esperado para ataque/bypass)
#   La salida de cada test llega a Splunk via logs del contenedor firewall
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=0

# =============================================================================
# Helpers
# =============================================================================

header() { echo -e "\n${BLUE}══════════════════════════════════════════${NC}"; echo -e "${BLUE} $1${NC}"; echo -e "${BLUE}══════════════════════════════════════════${NC}"; }

# Intenta conexion TCP. Espera BLOCK (nc falla) o PASS (nc conecta)
# $1=contenedor_origen $2=ip_destino $3=puerto $4=esperado(BLOCK|PASS) $5=descripcion
test_tcp() {
    local container=$1 dst_ip=$2 dst_port=$3 expected=$4 desc=$5
    TOTAL=$((TOTAL+1))

    # nc -z -w2: intento de conexion TCP con timeout 2s
    result=$(docker exec "$container" sh -c "nc -z -w2 $dst_ip $dst_port 2>&1" && echo "CONNECTED" || echo "BLOCKED")

    if [ "$expected" = "BLOCK" ] && [ "$result" = "BLOCKED" ]; then
        echo -e "${GREEN}[PASS]${NC} $desc — bloqueado como esperado"
        PASS=$((PASS+1))
    elif [ "$expected" = "PASS" ] && [ "$result" = "CONNECTED" ]; then
        echo -e "${GREEN}[PASS]${NC} $desc — conectado como esperado"
        PASS=$((PASS+1))
    elif [ "$expected" = "BLOCK" ] && [ "$result" = "CONNECTED" ]; then
        echo -e "${RED}[FAIL]${NC} $desc — DEBERIA ESTAR BLOQUEADO pero conectó ⚠️"
        FAIL=$((FAIL+1))
    else
        echo -e "${RED}[FAIL]${NC} $desc — DEBERIA CONECTAR pero fue bloqueado"
        FAIL=$((FAIL+1))
    fi
}

# Envia payload HTTP y espera BLOCK o respuesta
# $1=contenedor $2=url $3=esperado $4=descripcion
test_http() {
    local container=$1 url=$2 expected=$3 desc=$4
    TOTAL=$((TOTAL+1))

    result=$(docker exec "$container" sh -c "curl -sk -o /dev/null -w '%{http_code}' --max-time 3 $url" 2>/dev/null || echo "000")

    if [ "$expected" = "BLOCK" ] && [ "$result" = "000" ]; then
        echo -e "${GREEN}[PASS]${NC} $desc — bloqueado como esperado (000)"
        PASS=$((PASS+1))
    elif [ "$expected" = "PASS" ] && [ "$result" != "000" ]; then
        echo -e "${GREEN}[PASS]${NC} $desc — respondió HTTP $result"
        PASS=$((PASS+1))
    else
        echo -e "${RED}[FAIL]${NC} $desc — esperado=$expected obtenido=HTTP $result"
        FAIL=$((FAIL+1))
    fi
}

# =============================================================================
# IPs del compose (deben coincidir con .env)
# =============================================================================
ENVOY_IP="172.20.2.7"
OPA_IP="172.20.2.6"
MONGODB_IP="172.20.3.5"
API_IP="172.20.3.20"
SPLUNK_IP="172.20.2.8"

# =============================================================================
# BLOQUE 1: FLUJOS LEGITIMOS — deben pasar
# Estos son los flujos del negocio maritimo. Si fallan, el sistema no funciona.
# =============================================================================
header "BLOQUE 1: FLUJOS LEGITIMOS (esperado: PASS)"

# Todos los clientes pueden llegar al PEP (unico ingreso ZTA)
test_tcp "client_operatore_ancona"  "$ENVOY_IP"   8443  "PASS"  "vpn_net → Envoy PEP :8443 (operatore_ancona)"
test_tcp "client_capitano_claudia"  "$ENVOY_IP"   8443  "PASS"  "satellite_net → Envoy PEP :8443 (capitano_claudia)"
test_tcp "client_soc_admin"         "$ENVOY_IP"   8443  "PASS"  "corporate_net → Envoy PEP :8443 (soc_admin)"
test_tcp "client_intruso"           "$ENVOY_IP"   8443  "PASS"  "public_net → Envoy PEP :8443 (nftables permite, OPA decidira)"

# SOC puede acceder a Splunk Web UI (solo corporate_net)
test_tcp "client_soc_admin"         "$SPLUNK_IP"  8000  "PASS"  "corporate_net → Splunk Web UI :8000 (soc_admin)"

# =============================================================================
# BLOQUE 2: BYPASS DEL PEP — deben ser bloqueados por nftables
# Cualquier acceso directo que evite pep_gateway destruye el modelo ZTA
# =============================================================================
header "BLOQUE 2: BYPASS DEL PEP (esperado: BLOCK)"

# Intruso intenta acceder directamente a MongoDB
test_tcp "client_intruso"           "$MONGODB_IP" 27017 "BLOCK" "public_net → MongoDB :27017 directo (bypass PEP)"

# Intruso intenta acceder directamente a api_backend
test_tcp "client_intruso"           "$API_IP"     3000  "BLOCK" "public_net → api_backend :3000 directo (bypass PEP)"

# Intruso intenta acceder directamente a OPA
test_tcp "client_intruso"           "$OPA_IP"     8181  "BLOCK" "public_net → OPA REST :8181 directo (bypass PEP)"
test_tcp "client_intruso"           "$OPA_IP"     9191  "BLOCK" "public_net → OPA gRPC :9191 directo (bypass PEP)"

# Intruso intenta acceder al admin de Envoy
test_tcp "client_intruso"           "$ENVOY_IP"   9901  "BLOCK" "public_net → Envoy Admin :9901 (critico)"

# Operatore legítimo NO debe acceder directo a MongoDB (debe pasar por PEP)
test_tcp "client_operatore_ancona"  "$MONGODB_IP" 27017 "BLOCK" "vpn_net → MongoDB :27017 directo (debe pasar por PEP)"

# Capitano NO debe acceder a OPA directamente
test_tcp "client_capitano_claudia"  "$OPA_IP"     8181  "BLOCK" "satellite_net → OPA :8181 directo"

# =============================================================================
# BLOQUE 3: MOVIMIENTO LATERAL — deben ser bloqueados por nftables
# Cruce entre redes sin pasar por el PEP
# =============================================================================
header "BLOQUE 3: MOVIMIENTO LATERAL (esperado: BLOCK)"

# public_net no puede alcanzar ninguna red interna directamente
test_tcp "client_intruso"           "172.20.11.20" 8443 "BLOCK" "public_net → vpn_net (operatore_ancona)"
test_tcp "client_intruso"           "172.20.12.21" 8443 "BLOCK" "public_net → satellite_net (capitano_claudia)"
test_tcp "client_intruso"           "172.20.10.20" 8443 "BLOCK" "public_net → corporate_net (soc_admin)"

# satellite_net no puede alcanzar corporate_net directamente
test_tcp "client_capitano_claudia"  "172.20.10.20" 8443 "BLOCK" "satellite_net → corporate_net (escalada capitano→SOC)"

# =============================================================================
# BLOQUE 4: ACCESO A SPLUNK — solo corporate_net puede usar la UI
# =============================================================================
header "BLOQUE 4: SPLUNK UI RESTRINGIDA (esperado: BLOCK salvo SOC)"

test_tcp "client_intruso"           "$SPLUNK_IP"  8000  "BLOCK" "public_net → Splunk UI :8000 (no autorizado)"
test_tcp "client_capitano_claudia"  "$SPLUNK_IP"  8000  "BLOCK" "satellite_net → Splunk UI :8000 (no autorizado)"
test_tcp "client_operatore_ancona"  "$SPLUNK_IP"  8000  "BLOCK" "vpn_net → Splunk UI :8000 (no autorizado)"

# =============================================================================
# BLOQUE 5: VERIFICACION INTERNA — estado real de nftables
# =============================================================================
header "BLOQUE 5: VERIFICACION ESTADO NFTABLES"

echo -e "\n${YELLOW}► Ruleset activo en firewall_perimeter:${NC}"
docker exec firewall_perimeter nft list ruleset

echo -e "\n${YELLOW}► Contadores de paquetes por regla:${NC}"
docker exec firewall_perimeter nft list ruleset -a 2>/dev/null || echo "Contadores no disponibles"

echo -e "\n${YELLOW}► Ultimos logs del firewall (drops):${NC}"
docker logs firewall_perimeter --tail 30 2>&1 | grep -E "CRITICAL|WARNING|DROP" || echo "Sin eventos recientes"

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
    echo -e "${GREEN}  El trafico legitimo puede continuar al siguiente nivel:${NC}"
    echo -e "${GREEN}  Envoy (mTLS) → OPA (politicas) → api_backend → MongoDB${NC}"
    echo -e "${GREEN}  Los eventos de drop ya estan llegando a Splunk via HEC${NC}"
else
    echo -e "${RED}✘ $FAIL escenarios fallaron — revisar reglas nftables antes de continuar${NC}"
    exit 1
fi
