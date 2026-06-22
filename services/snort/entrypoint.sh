#!/bin/bash

# =============================================================================
# SNORT 3 IDS ENTRYPOINT
# Maritime Zero Trust Architecture
# =============================================================================

# Interrompe lo script:
# - in presenza di un errore;
# - se viene usata una variabile non definita;
# - se fallisce un comando all'interno di una pipeline.
set -euo pipefail


# =============================================================================
# COLORI E FUNZIONI DI LOG
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR]${NC} $1" >&2
}

fail() {
    log_error "$1"
    exit 1
}


# =============================================================================
# PERCORSI UTILIZZATI
# =============================================================================

# Configurazione originale montata dal docker-compose.
ORIGINAL_LUA="/etc/snort/snort-zta.lua"

# Configurazione generata dopo la sostituzione delle variabili.
RENDERED_LUA="/tmp/snort-rendered.lua"

# File contenente le regole Snort del progetto.
RULES_FILE="/etc/snort/snort-zta.rules"

# Directory nella quale vengono salvati gli alert JSON.
LOG_DIR="/var/log/snort"

# Interfaccia PCAP.
#
# "any" permette di osservare tutte le interfacce del namespace
# di rete condiviso con firewall_perimeter.
INTERFACES="${ZTA_SNORT_INTERFACES:-corp0:vpn0:sat0:public0}"


echo "================================================================================"
echo -e "  ${GREEN}Snort 3 IDS - Maritime Zero Trust Architecture${NC}"
echo "================================================================================"


# =============================================================================
# STEP 1: VERIFICHE PRELIMINARI
# =============================================================================

log_info "STEP 1: verifica del binario e dei file di configurazione"

# Verifica che il comando Snort sia disponibile.
command -v snort >/dev/null 2>&1 || \
    fail "Il binario Snort non è stato trovato"

# Recupera la versione di Snort.
VERSION="$(
    snort -V 2>&1 |
    grep -i "version" |
    head -1 ||
    echo "Versione non rilevata"
)"

log_info "Motore rilevato: $VERSION"

# Verifica la presenza della configurazione Lua.
[ -f "$ORIGINAL_LUA" ] || \
    fail "Configurazione non trovata: $ORIGINAL_LUA"

# Verifica la presenza del file delle regole.
[ -f "$RULES_FILE" ] || \
    fail "File delle regole non trovato: $RULES_FILE"

log_info "Configurazione trovata: $ORIGINAL_LUA"
log_info "Regole trovate: $RULES_FILE"


# =============================================================================
# STEP 2: PREPARAZIONE DELLA DIRECTORY DEI LOG
# =============================================================================

log_info "STEP 2: preparazione della directory dei log"

# Crea la directory se non esiste.
mkdir -p "$LOG_DIR"

# Crea il file che conterrà gli alert JSON.
touch "$LOG_DIR/alert_json.txt"

# Assegna i file all'utente Snort, se presente.
if id snort >/dev/null 2>&1; then
    chown -R snort:snort "$LOG_DIR"
    chmod 755 "$LOG_DIR"
    chmod 644 "$LOG_DIR/alert_json.txt"

    log_info "Permessi assegnati a snort:snort"
else
    log_warn "Utente snort non trovato: il processo continuerà come root"
fi


# =============================================================================
# STEP 3: VALIDAZIONE DELLE VARIABILI
# =============================================================================

log_info "STEP 3: validazione delle variabili ZTA"

# Tutte queste variabili devono essere definite nel docker-compose.yml.
REQUIRED_VARS=(
    ZTA_HOME_NET
    ZTA_PUBLIC_NET
    ZTA_VPN_NET
    ZTA_SATELLITE_NET
    ZTA_CORPORATE_NET
    ZTA_BACKEND_NET
    ZTA_PEP_PORT
    ZTA_OPA_PORTS
    ZTA_MONGO_PORT
    ZTA_API_PORT
    ZTA_SIEM_PORTS
    ZTA_ADMIN_PORT
)

ALL_OK=true

for var in "${REQUIRED_VARS[@]}"; do
    value="${!var:-}"

    if [ -z "$value" ]; then
        log_error "Variabile obbligatoria non definita: $var"
        ALL_OK=false
    else
        log_info "$var = $value"
    fi
done

[ "$ALL_OK" = true ] || \
    fail "Una o più variabili obbligatorie non sono definite"


# =============================================================================
# STEP 4: GENERAZIONE DELLA CONFIGURAZIONE
# =============================================================================

log_info "STEP 4: generazione della configurazione Snort"

# Sostituisce i placeholder ${VARIABILE} con i valori del container.
envsubst < "$ORIGINAL_LUA" > "$RENDERED_LUA"

# Verifica che non siano rimasti placeholder irrisolti.
if grep -q '\${' "$RENDERED_LUA"; then
    log_error "Sono presenti variabili non risolte nella configurazione:"

    grep '\${' "$RENDERED_LUA" >&2

    fail "Generazione della configurazione incompleta"
fi

log_info "Configurazione generata: $RENDERED_LUA"


# =============================================================================
# STEP 5: RIEPILOGO DELLA TOPOLOGIA
# =============================================================================

log_info "STEP 5: topologia utilizzata da Snort"

log_info "HOME_NET      = $ZTA_HOME_NET"
log_info "PUBLIC_NET    = $ZTA_PUBLIC_NET"
log_info "VPN_NET       = $ZTA_VPN_NET"
log_info "SATELLITE_NET = $ZTA_SATELLITE_NET"
log_info "CORPORATE_NET = $ZTA_CORPORATE_NET"
log_info "BACKEND_NET   = $ZTA_BACKEND_NET"

log_info "PEP_PORT      = $ZTA_PEP_PORT"
log_info "OPA_PORTS     = $ZTA_OPA_PORTS"
log_info "MONGO_PORT    = $ZTA_MONGO_PORT"
log_info "API_PORT      = $ZTA_API_PORT"
log_info "SIEM_PORTS    = $ZTA_SIEM_PORTS"
log_info "ADMIN_PORT    = $ZTA_ADMIN_PORT"

log_info "INTERFACCIA   = $INTERFACES"
log_info "DAQ            = afpacket"
log_info "MODALITÀ       = passiva"


# =============================================================================
# STEP 6: CONTEGGIO DELLE REGOLE
# =============================================================================

log_info "STEP 6: conteggio delle regole"

TOTAL_RULES="$(
    grep -cE '^[[:space:]]*alert' "$RULES_FILE" 2>/dev/null ||
    echo 0
)"

log_info "Regole alert rilevate: $TOTAL_RULES"


# =============================================================================
# STEP 7: VALIDAZIONE DELLA CONFIGURAZIONE
# =============================================================================

log_info "STEP 7: validazione della configurazione Snort"

VALIDATION_LOG="/tmp/snort-validation.log"

# -T esegue solamente la validazione senza avviare il sensore.
snort \
    -c "$RENDERED_LUA" \
    --daq afpacket \
    -T \
    2>&1 |
    tee "$VALIDATION_LOG" >/dev/null

# Verifica il risultato della validazione.
if grep -q "Snort successfully validated" "$VALIDATION_LOG"; then
    log_info "Validazione Snort completata correttamente"
else
    log_error "Validazione Snort fallita"

    cat "$VALIDATION_LOG" >&2

    fail "La configurazione Snort non è valida"
fi


# =============================================================================
# STEP 8: AVVIO DI SNORT
# =============================================================================

log_info "STEP 8: avvio di Snort in modalità IDS passiva"

log_info "DAQ utilizzato: pcap"
log_info "Interfacce monitorate: $INTERFACES"
log_info "Directory log: $LOG_DIR"
log_info "File alert: $LOG_DIR/alert_json.txt"

# Avvia Snort:
#
# --daq pcap:
#   usa PCAP per la cattura dei pacchetti;
#
# -i any:
#   osserva tutte le interfacce del namespace del firewall;
#
# assenza di -Q:
#   mantiene Snort in modalità passiva;
#
# -u e -g:
#   riducono i privilegi dopo l'apertura dell'interfaccia;
#
# -k none:
#   evita falsi errori di checksum nelle reti virtuali Docker;
#
# -A alert_json:
#   produce alert nel formato JSON.
exec snort \
    -c "$RENDERED_LUA" \
    --daq afpacket \
    -i "$INTERFACES" \
    -l "$LOG_DIR" \
    -u snort \
    -g snort \
    -k none \
    -A alert_json \
    --warn-all