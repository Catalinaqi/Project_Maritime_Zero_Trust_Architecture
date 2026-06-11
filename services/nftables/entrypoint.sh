#!/bin/bash
# =============================================================================
# MARITIME ZTA - firewall_perimeter entrypoint
# =============================================================================
set -euo pipefail

RULES_SRC="/etc/nftables/rules.nft"
RULES_RENDERED="/tmp/rules_rendered.nft"
LOG_DIR="/var/log/nftables"

log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }
fail() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2; exit 1; }

# --- Variables obligatorias del compose ---
: "${ENVOY_IP:?ENVOY_IP no definida en compose}"
: "${OPA_IP:?OPA_IP no definida en compose}"
: "${MONGODB_IP:?MONGODB_IP no definida en compose}"
: "${API_IP:?API_IP no definida en compose}"
: "${SPLUNK_IP:?SPLUNK_IP no definida en compose}"
: "${CORPORATE_NET:?CORPORATE_NET no definida en compose}"

# Splunk HEC opcionales — si no están definidas los logs no se envían a Splunk
SPLUNK_HEC_URL="${SPLUNK_HEC_URL:-}"
SPLUNK_HEC_TOKEN="${SPLUNK_HEC_TOKEN:-}"

# --- Preparacion ---
[ -f "$RULES_SRC" ] || fail "rules.nft no encontrado: $RULES_SRC"
[ -d "$LOG_DIR" ]   || mkdir -p "$LOG_DIR"

# --- Render: sustituir variables del compose ---
log "Resolviendo variables del compose en rules.nft..."
envsubst < "$RULES_SRC" > "$RULES_RENDERED"

# --- Validacion de sintaxis ---
log "Validando sintaxis..."
nft -c -f "$RULES_RENDERED" || fail "Sintaxis invalida — contenedor abortado (fail secure)"

# --- Carga de reglas ---
log "Cargando reglas nftables..."
nft -f "$RULES_RENDERED" || fail "Error cargando reglas — contenedor abortado (fail secure)"

# --- Verificacion minima ---
nft list table inet filter > /dev/null 2>&1 \
    || fail "Tabla inet filter no encontrada"
nft list chain inet filter forward | grep -q "policy drop" \
    || fail "FORWARD policy drop no activa — fail secure"

log "Firewall activo. Ruleset:"
nft list ruleset

# --- Forwarder dmesg → Splunk HEC ---
# Lee eventos nftables del kernel journal y los envía al SIEM en tiempo real
forward_to_splunk() {
    if [ -z "$SPLUNK_HEC_URL" ] || [ -z "$SPLUNK_HEC_TOKEN" ]; then
        log "SPLUNK_HEC_URL/TOKEN no definidos — logs nftables solo en dmesg"
        return
    fi

    log "Iniciando forwarder dmesg → Splunk HEC..."

    # dmesg -w sigue el kernel journal en tiempo real
    # grep filtra solo eventos nftables (prefijos definidos en rules.nft)
    dmesg -w 2>/dev/null | grep --line-buffered \
        -E "NFT-FWD|NFT-INPUT|CRITICAL|WARNING|DIRECT|UNAUTHORIZED|ENVOY_ADMIN" | \
    while IFS= read -r line; do
        # Construir payload JSON para Splunk HEC
        payload=$(printf '{"event":{"message":"%s","host":"%s","source":"nftables"}}' \
            "$(echo "$line" | sed 's/"/\\"/g')" \
            "$(hostname)")

        # Enviar al HEC — silencioso en caso de error para no interrumpir el bucle
        curl -sk -o /dev/null \
            -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$payload" \
            "$SPLUNK_HEC_URL" || true
    done &

    log "Forwarder Splunk activo (PID $!)"
}

forward_to_splunk

# --- Bucle de monitoreo ---
log "Entrando en bucle de monitoreo (60s)..."
while true; do
    nft list table inet filter > /dev/null 2>&1 || {
        log "Reglas perdidas — recargando..."
        nft -f "$RULES_RENDERED" || fail "Recarga fallida"
    }
    sleep 60
done
