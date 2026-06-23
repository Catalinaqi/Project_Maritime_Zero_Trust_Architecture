#!/usr/bin/env bash
set -Eeuo pipefail

# =============================================================================
# DEFINIZIONE VARIABILI E COLORI
# =============================================================================
RULES_SOURCE="/etc/nftables/rules.nft"
RULES_RENDERED="/tmp/rules-rendered.nft"
LOG_DIR="/var/log/nftables"
ULOGD_CONFIG="/etc/ulogd.conf"
ULOGD_PID_FILE="/run/ulogd.pid"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# =============================================================================
# FUNZIONI DI LOGGING
# =============================================================================
log_info()  { echo -e "${GREEN}[Entrypoint-NFTABLES] [INFO]${NC}  $(date '+%Y-%m-%d %H:%M:%S') - $1"; }
log_warn()  { echo -e "${YELLOW}[Entrypoint-NFTABLES] [WARN]${NC}  $(date '+%Y-%m-%d %H:%M:%S') - $1"; }
log_error() { echo -e "${RED}[Entrypoint-NFTABLES] [ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2; }

fail() {
  log_error "CRITICO: $1"
  exit 1
}

# =============================================================================
# FUNZIONI DI SUPPORTO E CLEANUP
# =============================================================================
cleanup() {
  if [[ -n "${FORWARD_LOGS_PID:-}" ]]; then
    kill "${FORWARD_LOGS_PID}" >/dev/null 2>&1 || true
  fi

  if [[ -r "${ULOGD_PID_FILE}" ]]; then
    kill "$(cat "${ULOGD_PID_FILE}")" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT INT TERM

# =============================================================================
# EXECUTION STEPS
# =============================================================================

log_info "[STEP-1] Start - Verificando i comandi di sistema richiesti"
command -v nft >/dev/null 2>&1 || fail "Comando nft non disponibile"
command -v envsubst >/dev/null 2>&1 || fail "Comando envsubst non disponibile"
command -v ulogd >/dev/null 2>&1 || fail "Comando ulogd non disponibile"
command -v jq >/dev/null 2>&1 || fail "Comando jq non disponibile"
command -v curl >/dev/null 2>&1 || fail "Comando curl non disponibile"
command -v ip >/dev/null 2>&1 || fail "Comando ip (iproute2) non disponibile"
command -v awk >/dev/null 2>&1 || fail "Comando awk non disponibile"

[[ -r "${RULES_SOURCE}" ]] || fail "File delle regole assente: ${RULES_SOURCE}"
mkdir -p "${LOG_DIR}" /run


log_info "[STEP-2] Start - Validating NFTables environment variables"
required_variables=(
  NFTABLES_ENVOY_IP
  NFTABLES_FW_CORPORATE_IP
  NFTABLES_FW_VPN_IP
  NFTABLES_FW_SATELLITE_IP
  NFTABLES_FW_PUBLIC_IP
  NFTABLES_CORPORATE_NET
  NFTABLES_VPN_NET
  NFTABLES_SATELLITE_NET
  NFTABLES_PUBLIC_NET
  NFTABLES_PEP_PORT
)

for variable in "${required_variables[@]}"; do
  [[ -n "${!variable:-}" ]] || fail "Variabile obbligatoria non definita: ${variable}"
done


log_info "[STEP-3] Start - Rinomina dinamica delle interfacce di rete (Docker Compose workaround)"

rename_interface_by_ip() {
  local target_ip=$1
  local new_name=$2

  # Trova l'interfaccia (ethX) che possiede l'IP specificato
  local current_name=$(ip -4 -o addr show | awk -v ip="$target_ip" '$4 ~ "^"ip"/" {print $2}')

  if [[ -n "$current_name" && "$current_name" != "$new_name" ]]; then
    log_info "  - Modifica interfaccia $current_name (IP $target_ip) in -> $new_name"
    ip link set dev "$current_name" down
    ip link set dev "$current_name" name "$new_name"
    ip link set dev "$new_name" up
  elif [[ -z "$current_name" ]]; then
    log_warn "  - Nessuna interfaccia trovata con IP $target_ip da rinominare in $new_name"
  else
    log_info "  - L'interfaccia $new_name è già correttamente configurata"
  fi
}

# Usa le variabili pre-validate per rinominare le interfacce assegnate da Compose
rename_interface_by_ip "172.20.2.10" "zt0"
rename_interface_by_ip "172.20.4.10" "monitor0"
rename_interface_by_ip "${NFTABLES_FW_CORPORATE_IP}" "corp0"
rename_interface_by_ip "${NFTABLES_FW_VPN_IP}" "vpn0"
rename_interface_by_ip "${NFTABLES_FW_SATELLITE_IP}" "sat0"
rename_interface_by_ip "${NFTABLES_FW_PUBLIC_IP}" "public0"

log_info "Interfacce di rete rinominate con successo."


log_info "[STEP-4] Start - Rendering delle regole NFTables (sostituzione variabili)"
# Elimina eventuali terminatori CRLF introdotti da Windows e sostituisce solo
# le variabili esplicitamente autorizzate, evitando sostituzioni accidentali.
tr -d '\r' < "${RULES_SOURCE}" \
  | envsubst '${NFTABLES_ENVOY_IP} ${NFTABLES_FW_CORPORATE_IP} ${NFTABLES_FW_VPN_IP} ${NFTABLES_FW_SATELLITE_IP} ${NFTABLES_FW_PUBLIC_IP} ${NFTABLES_CORPORATE_NET} ${NFTABLES_VPN_NET} ${NFTABLES_SATELLITE_NET} ${NFTABLES_PUBLIC_NET} ${NFTABLES_PEP_PORT}' \
  > "${RULES_RENDERED}"

if grep -q '\${' "${RULES_RENDERED}"; then
  fail "Sono presenti placeholder non risolti nelle regole NFTables (${RULES_RENDERED})"
fi


log_info "[STEP-5] Start - Validazione e caricamento regole NFTables"
nft -c -f "${RULES_RENDERED}" || fail "Sintassi NFTables non valida nel file renderizzato"
nft -f "${RULES_RENDERED}" || fail "Caricamento delle regole NFTables fallito nel kernel"
nft list table ip filter >/dev/null 2>&1 || fail "Tabella NFTables 'ip filter' assente dopo il caricamento"


log_info "[STEP-6] Start - Configurazione e avvio del demone ulogd (NFLOG)"
# Debian installa i plugin ulogd in una directory dipendente dall'architettura.
ULOGD_PLUGIN_DIR="$(find /usr/lib -type f -name 'ulogd_inppkt_NFLOG.so' -printf '%h\n' -quit)"
[[ -n "${ULOGD_PLUGIN_DIR}" ]] || fail "Plugin NFLOG di ulogd non trovato nel sistema"

cat > "${ULOGD_CONFIG}" <<EOF_ULOGD
[global]
logfile="${LOG_DIR}/ulogd-system.log"
plugin="${ULOGD_PLUGIN_DIR}/ulogd_inppkt_NFLOG.so"
plugin="${ULOGD_PLUGIN_DIR}/ulogd_raw2packet_BASE.so"
plugin="${ULOGD_PLUGIN_DIR}/ulogd_filter_IFINDEX.so"
plugin="${ULOGD_PLUGIN_DIR}/ulogd_filter_IP2STR.so"
plugin="${ULOGD_PLUGIN_DIR}/ulogd_filter_PRINTPKT.so"
plugin="${ULOGD_PLUGIN_DIR}/ulogd_output_LOGEMU.so"
stack=log1:NFLOG,base1:BASE,ifi1:IFINDEX,ip2str1:IP2STR,print1:PRINTPKT,emu1:LOGEMU

[log1]
group=0

[emu1]
file="${LOG_DIR}/ulogd-alerts.log"
sync=1
EOF_ULOGD

touch "${LOG_DIR}/ulogd-alerts.log"

ulogd -d -c "${ULOGD_CONFIG}" -p "${ULOGD_PID_FILE}"
sleep 1

[[ -r "${ULOGD_PID_FILE}" ]] || fail "Il demone ulogd non ha creato il PID file"
kill -0 "$(cat "${ULOGD_PID_FILE}")" >/dev/null 2>&1 || fail "Il demone ulogd non è in esecuzione"


log_info "[STEP-7] Start - Inizializzazione modulo di inoltro log (Splunk HEC)"
forward_logs() {
  local hec_url="${NFTABLES_SPLUNK_HEC_URL:-}"
  local hec_token="${NFTABLES_SPLUNK_HEC_TOKEN:-}"
  local host_name="${HOSTNAME:-nft-firewall}"

  if [[ -z "${hec_url}" || -z "${hec_token}" ]]; then
    log_warn "Credenziali HEC non configurate: inoltro dei log verso Splunk disabilitato"
    return 0
  fi

  log_info "Inoltro log attivo verso: ${hec_url}"
  tail -F "${LOG_DIR}/ulogd-alerts.log" 2>/dev/null \
    | grep --line-buffered -E 'NFT-' \
    | while IFS= read -r line; do
        payload="$(jq -cn \
          --arg message "${line}" \
          --arg host "${host_name}" \
          '{time: now, host: $host, source: "nftables", sourcetype: "nftables", index: "main", event: {message: $message}}')"

        if ! curl -fsS --max-time 5 \
          -H "Authorization: Splunk ${hec_token}" \
          -H 'Content-Type: application/json' \
          -d "${payload}" \
          "${hec_url}" >/dev/null; then
          log_error "Invio HEC fallito. L'evento rimane disponibile nel volume locale: ulogd-alerts.log"
        fi
      done
}

forward_logs &
FORWARD_LOGS_PID=$!


log_info "[STEP-8] Completato - Firewall caricato correttamente. Avvio loop di monitoraggio ruleset."
while sleep 60; do
  if ! nft list table ip filter >/dev/null 2>&1; then
    log_error "Ruleset assente (possibile flush accidentale)! Tentativo di ripristino in corso..."
    if nft -f "${RULES_RENDERED}"; then
      log_info "Ruleset ripristinato con successo dal file temporaneo."
    else
      fail "Ripristino del ruleset fallito. Il firewall potrebbe essere esposto."
    fi
  fi
done
