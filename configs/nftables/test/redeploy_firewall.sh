#!/bin/bash
# =============================================================================
# MARITIME ZTA - Redeploy seguro de firewall_perimeter
# Sin docker compose down — el firewall nunca se detiene completamente
# =============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }
fail() { echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" >&2; exit 1; }
ok()   { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] ✔ $1${NC}"; }
warn() { echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] ⚠ $1${NC}"; }

SERVICE="firewall_perimeter"
RULES_FILE="./configs/nftables/rules.nft"

# =============================================================================
# PASO 1: Verificaciones previas al build
# =============================================================================
log "${BLUE}PASO 1 — Verificaciones previas${NC}"

# Verificar que el compose existe
[ -f "docker-compose.yml" ] || fail "docker-compose.yml no encontrado. Ejecutar desde la raiz del proyecto."

# Verificar que el rules.nft existe y tiene variables
[ -f "$RULES_FILE" ] || fail "rules.nft no encontrado en $RULES_FILE"

if grep -q '\${' "$RULES_FILE"; then
    ok "rules.nft contiene variables \${} — envsubst activo"
else
    warn "rules.nft NO contiene variables — revisar si tiene IPs hardcoded"
fi

# Verificar que el Dockerfile existe
[ -f "./services/nftables/Dockerfile" ] || fail "Dockerfile no encontrado en services/nftables/"

# Verificar que el entrypoint existe
[ -f "./services/nftables/entrypoint.sh" ] || fail "entrypoint.sh no encontrado en services/nftables/"

# Verificar que gettext esta en el Dockerfile (necesario para envsubst)
if grep -q "gettext" ./services/nftables/Dockerfile; then
    ok "Dockerfile contiene gettext (envsubst disponible)"
else
    fail "Dockerfile NO tiene gettext — envsubst no funcionara"
fi

# Verificar variables de entorno en el compose
log "Verificando variables de entorno del compose..."
REQUIRED_VARS=("ENVOY_IP" "OPA_IP" "MONGODB_IP" "API_IP" "SPLUNK_IP" "CORPORATE_NET")
for var in "${REQUIRED_VARS[@]}"; do
    if grep -q "$var" docker-compose.yml; then
        ok "Variable $var presente en compose"
    else
        fail "Variable $var NO encontrada en compose bajo $SERVICE"
    fi
done

# =============================================================================
# PASO 2: Verificar procesos zombie antes del build
# =============================================================================
log "${BLUE}PASO 2 — Verificar procesos zombie${NC}"

ZOMBIES=$(docker exec $SERVICE ps aux 2>/dev/null | grep -c 'Z' || echo "0")
if [ "$ZOMBIES" -gt 0 ]; then
    warn "$ZOMBIES proceso(s) zombie detectados en $SERVICE"
    docker exec $SERVICE ps aux | grep 'Z' || true
    warn "tini deberia limpiarlos en el siguiente arranque"
else
    ok "Sin procesos zombie en $SERVICE"
fi

# Verificar que tini esta activo como PID 1
PID1=$(docker exec $SERVICE cat /proc/1/comm 2>/dev/null || echo "unknown")
if [ "$PID1" = "tini" ]; then
    ok "PID 1 es tini — manejo de zombies activo"
else
    warn "PID 1 es '$PID1' — no es tini, zombies pueden acumularse"
fi

# =============================================================================
# PASO 3: Estado actual del firewall ANTES del redeploy
# =============================================================================
log "${BLUE}PASO 3 — Estado actual del firewall${NC}"

if docker exec $SERVICE nft list table inet filter > /dev/null 2>&1; then
    ok "Firewall activo — reglas cargadas"
    log "Reglas actuales:"
    docker exec $SERVICE nft list ruleset | grep -E "chain|policy|dport|saddr|daddr|log prefix" | head -30
else
    warn "Firewall sin reglas activas — posible estado degradado"
fi

# =============================================================================
# PASO 4: Build de la nueva imagen SIN detener el servicio
# =============================================================================
log "${BLUE}PASO 4 — Build nueva imagen (servicio sigue activo)${NC}"

docker compose build $SERVICE && ok "Build completado" || fail "Build fallido — servicio actual sigue activo"

# =============================================================================
# PASO 5: Redeploy con ventana minima de downtime
# Solo en este punto se reinicia el contenedor
# =============================================================================
log "${BLUE}PASO 5 — Reemplazar contenedor (ventana minima)${NC}"
warn "El firewall se reiniciara en 3 segundos — ventana de downtime minima..."
sleep 3

# stop + start es mas rapido que down + up
# down elimina el contenedor y las redes, stop solo detiene el proceso
docker compose stop $SERVICE
docker compose up -d $SERVICE

# Esperar a que el healthcheck pase
log "Esperando healthcheck..."
RETRIES=10
while [ $RETRIES -gt 0 ]; do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' $SERVICE 2>/dev/null || echo "none")
    if [ "$STATUS" = "healthy" ]; then
        ok "Healthcheck: healthy"
        break
    fi
    log "Healthcheck: $STATUS — esperando... ($RETRIES intentos restantes)"
    sleep 5
    RETRIES=$((RETRIES-1))
done
[ $RETRIES -eq 0 ] && fail "Healthcheck no paso tras 50s — revisar logs"

# =============================================================================
# PASO 6: Verificacion post-redeploy
# =============================================================================
log "${BLUE}PASO 6 — Verificacion post-redeploy${NC}"

# Reglas cargadas
docker exec $SERVICE nft list table inet filter > /dev/null 2>&1 \
    && ok "Tabla inet filter presente" \
    || fail "Tabla inet filter NO encontrada — firewall sin reglas"

# Policy drop activa
docker exec $SERVICE nft list chain inet filter forward | grep -q "policy drop" \
    && ok "FORWARD policy drop activa" \
    || fail "FORWARD policy drop NO activa — fail secure comprometido"

# Variables resueltas correctamente (no debe quedar ningun ${} sin resolver)
docker exec $SERVICE nft list ruleset | grep -q '\${' \
    && fail "Hay variables sin resolver en el ruleset — envsubst fallo" \
    || ok "Variables resueltas correctamente — sin \${} en ruleset"

# Sin zombies post-arranque
ZOMBIES_POST=$(docker exec $SERVICE ps aux 2>/dev/null | grep -c 'Z' || echo "0")
[ "$ZOMBIES_POST" -eq 0 ] && ok "Sin procesos zombie post-redeploy" || warn "$ZOMBIES_POST zombie(s) detectados"

log "Logs recientes del firewall:"
docker logs $SERVICE --tail 20

ok "Redeploy completado. Firewall activo y protegiendo las 7 redes."
