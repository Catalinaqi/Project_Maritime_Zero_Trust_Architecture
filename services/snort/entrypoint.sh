#!/bin/bash
# =============================================================================
# Snort 3 IDS Entrypoint Script - Maritime Zero Trust
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR]${NC} $1" >&2; }
fail()      { log_error "$1"; exit 1; }

ORIGINAL_LUA="/etc/snort/snort-zta.lua"
RENDERED_LUA="/tmp/snort-rendered.lua"
RULES_FILE="/etc/snort/snort-zta.rules"
LOG_DIR="/var/log/snort"

echo "================================================================================"
echo -e "  ${GREEN}Snort 3 IDS - Entrypoint - Maritime Zero Trust Architecture${NC}"
echo "================================================================================"

# =============================================================================
# STEP 1: Pre-flight checks
# =============================================================================
log_info "[Entrypoint] STEP-1: Inicio... Verificaciones previas"

command -v snort >/dev/null 2>&1 || fail "[Entrypoint] STEP-1: Binario de Snort no encontrado"

# FIX: snort -V escribe en stderr — redirigir 2>&1
VERSION=$(snort -V 2>&1 | grep -i "version" | head -1 || echo "version desconocida")
log_info "[Entrypoint] STEP-1: Motor detectado: $VERSION"

[ -f "$ORIGINAL_LUA" ] || fail "[Entrypoint] STEP-1: File snort-zta.lua no encontrado: $ORIGINAL_LUA"
[ -f "$RULES_FILE"   ] || log_warn "[Entrypoint] STEP-1: File snort-zta.rules no encontrado: $RULES_FILE"

log_info "[Entrypoint] STEP-1: File original lua $ORIGINAL_LUA → file lua snort encontrado"
log_info "[Entrypoint] STEP-1: File rules files $RULES_FILE → file rules snort encontrado"

# FIX: permisos como root antes del exec — el volumen snort_logs llega montado como root
[ -d "$LOG_DIR" ] || mkdir -p "$LOG_DIR"
touch "$LOG_DIR/alert_json.txt"
if id snort &>/dev/null; then
    chown -R snort:snort "$LOG_DIR"
    chmod 755 "$LOG_DIR"
    chmod 644 "$LOG_DIR/alert_json.txt"
    log_info "[Entrypoint] STEP-1: Permisos $LOG_DIR → snort:snort aplicados"
else
    log_warn "[Entrypoint] STEP-1: Usuario snort no encontrado — logs como root"
fi

log_info "[Entrypoint] STEP-1: Fin... Pre-flight OK"

# =============================================================================
# STEP 2: Validacion variables ZTA
# =============================================================================
log_info "[Entrypoint] STEP-2: Inicio... Validando variables ZTA del compose"

REQUIRED_VARS=(
    ZTA_HOME_NET ZTA_PUBLIC_NET ZTA_VPN_NET
    ZTA_SATELLITE_NET ZTA_CORPORATE_NET ZTA_BACKEND_NET
    ZTA_PEP_PORT ZTA_OPA_PORTS ZTA_MONGO_PORT
    ZTA_API_PORT ZTA_SIEM_PORTS ZTA_ADMIN_PORT
)

ALL_OK=true
for var in "${REQUIRED_VARS[@]}"; do
    val="${!var:-}"
    if [ -z "$val" ]; then
        log_error "[Entrypoint] STEP-2: Variable $var VACIA — envsubst producira placeholders sin resolver"
        ALL_OK=false
    else
        log_info "[Entrypoint] STEP-2: $var = $val"
    fi
done
[ "$ALL_OK" = true ] || fail "[Entrypoint] STEP-2: Variables faltantes — fail secure"

log_info "[Entrypoint] STEP-2: Fin... Todas las variables ZTA presentes OK"

# =============================================================================
# STEP 3: Render envsubst
# =============================================================================
log_info "[Entrypoint] STEP-3: Inicio... Resolviendo variables en snort-zta.lua"

envsubst < "$ORIGINAL_LUA" > "$RENDERED_LUA"

# Verificar que no queden ${} sin resolver
if grep -q '\${' "$RENDERED_LUA"; then
    log_error "[Entrypoint] STEP-3: Variables sin resolver en lua renderizado:"
    grep '\${' "$RENDERED_LUA" >&2
    fail "[Entrypoint] STEP-3: envsubst incompleto — fail secure"
fi

log_info "[Entrypoint] STEP-3: Topologia ZTA activa:"
log_info "[Entrypoint] STEP-3:   HOME_NET      = $ZTA_HOME_NET"
log_info "[Entrypoint] STEP-3:   PUBLIC_NET    = $ZTA_PUBLIC_NET"
log_info "[Entrypoint] STEP-3:   VPN_NET       = $ZTA_VPN_NET"
log_info "[Entrypoint] STEP-3:   SATELLITE_NET = $ZTA_SATELLITE_NET"
log_info "[Entrypoint] STEP-3:   CORPORATE_NET = $ZTA_CORPORATE_NET"
log_info "[Entrypoint] STEP-3:   BACKEND_NET   = $ZTA_BACKEND_NET"
log_info "[Entrypoint] STEP-3:   PEP_PORT      = $ZTA_PEP_PORT"
log_info "[Entrypoint] STEP-3:   OPA_PORTS     = $ZTA_OPA_PORTS"

log_info "[Entrypoint] STEP-3: Fin... Render OK → $RENDERED_LUA"

# =============================================================================
# STEP 4: Resumen de reglas
# =============================================================================
log_info "[Entrypoint] STEP-4: Inicio... Contando firmas ZTA"

if [ -f "$RULES_FILE" ]; then
    TOTAL=$(grep -cE '^[[:space:]]*alert' "$RULES_FILE" 2>/dev/null || echo 0)
    log_info "[Entrypoint] STEP-4: Firmas ZTA cargadas: $TOTAL"
else
    log_warn "[Entrypoint] STEP-4: Archivo de reglas no encontrado — Snort arrancara sin firmas"
fi

log_info "[Entrypoint] STEP-4: Fin... Resumen OK"

# =============================================================================
# STEP 5: Validacion sintaxis Snort (fail-secure)
# =============================================================================
log_info "[Entrypoint] STEP-5: Inicio... Validando configuracion Snort (modo test)"

VALIDATION_LOG="/tmp/snort-validation.log"
snort -c "$RENDERED_LUA" -T 2>&1 | tee "$VALIDATION_LOG" > /dev/null

if grep -q "Snort successfully validated" "$VALIDATION_LOG"; then
    log_info "[Entrypoint] STEP-5: Validacion: PASSED ✔"
else
    log_error "[Entrypoint] STEP-5: Validacion: FAILED — output completo:"
    cat "$VALIDATION_LOG" >&2
    fail "[Entrypoint] STEP-5: Configuracion invalida — fail secure"
fi

log_info "[Entrypoint] STEP-5: Fin... Validacion OK"


# =============================================================================
# STEP 6: Detectar interfaz y arrancar
# =============================================================================
log_info "[Entrypoint] STEP-6: Inicio... Arrancando motor IDS"

# Lee la variable del entorno, si no existe o está vacía, usa eth0 por seguridad
INTERFACES="${ZTA_SNORT_INTERFACES:-eth2}"
# Definimos todas las interfaces ZTA descubiertas (separadas por dos puntos para Snort 3)
#INTERFACES="eth0:eth1:eth2:eth3:eth4:eth5:eth6"

log_info "[Entrypoint] STEP-6: Interfaces monitoreadas: $INTERFACES"
log_info "[Entrypoint] STEP-6: Logs: $LOG_DIR | Usuario: snort"
log_info "[Entrypoint] STEP-6: Alertas → $LOG_DIR/alert_json.txt"

# exec directo — tini gestiona señales correctamente sin shell wrapper
exec snort \
    -c "$RENDERED_LUA" \
    --daq afpacket \
    -i "$INTERFACES" \
    -l "$LOG_DIR" \
    -u snort -g snort \
    -k none \
    -A alert_json \
    --warn-all
