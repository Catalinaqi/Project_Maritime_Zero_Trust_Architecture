#!/usr/bin/env bash
set -Eeuo pipefail

RULES_SOURCE="/etc/nftables/rules.nft"
RULES_RENDERED="/tmp/rules-rendered.nft"
LOG_DIR="/var/log/nftables"
ULOGD_CONFIG="/etc/ulogd.conf"
ULOGD_PID_FILE="/run/ulogd.pid"

log() {
  printf '[nftables] %s\n' "$*"
}

fail() {
  printf '[nftables] ERRORE: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "${FORWARD_LOGS_PID:-}" ]]; then
    kill "${FORWARD_LOGS_PID}" >/dev/null 2>&1 || true
  fi

  if [[ -r "${ULOGD_PID_FILE}" ]]; then
    kill "$(cat "${ULOGD_PID_FILE}")" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT INT TERM

command -v nft >/dev/null 2>&1 || fail "Comando nft non disponibile"
command -v envsubst >/dev/null 2>&1 || fail "Comando envsubst non disponibile"
command -v ulogd >/dev/null 2>&1 || fail "Comando ulogd non disponibile"
command -v jq >/dev/null 2>&1 || fail "Comando jq non disponibile"
command -v curl >/dev/null 2>&1 || fail "Comando curl non disponibile"

[[ -r "${RULES_SOURCE}" ]] || fail "File delle regole assente: ${RULES_SOURCE}"

mkdir -p "${LOG_DIR}" /run

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

# Elimina eventuali terminatori CRLF introdotti da Windows e sostituisce solo
# le variabili esplicitamente autorizzate, evitando sostituzioni accidentali.
tr -d '\r' < "${RULES_SOURCE}" \
  | envsubst '${NFTABLES_ENVOY_IP} ${NFTABLES_FW_CORPORATE_IP} ${NFTABLES_FW_VPN_IP} ${NFTABLES_FW_SATELLITE_IP} ${NFTABLES_FW_PUBLIC_IP} ${NFTABLES_CORPORATE_NET} ${NFTABLES_VPN_NET} ${NFTABLES_SATELLITE_NET} ${NFTABLES_PUBLIC_NET} ${NFTABLES_PEP_PORT}' \
  > "${RULES_RENDERED}"

if grep -q '\${' "${RULES_RENDERED}"; then
  fail "Sono presenti placeholder non risolti nelle regole NFTables"
fi

nft -c -f "${RULES_RENDERED}" || fail "Sintassi NFTables non valida"
nft -f "${RULES_RENDERED}" || fail "Caricamento delle regole NFTables fallito"
nft list table ip filter >/dev/null 2>&1 || fail "Tabella NFTables ip filter assente"

# Debian installa i plugin ulogd in una directory dipendente
# dall'architettura. Il percorso viene rilevato automaticamente.
ULOGD_PLUGIN_DIR="$(find /usr/lib -type f -name 'ulogd_inppkt_NFLOG.so' -printf '%h\n' -quit)"
[[ -n "${ULOGD_PLUGIN_DIR}" ]] || fail "Plugin NFLOG di ulogd non trovato"

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

[[ -r "${ULOGD_PID_FILE}" ]] || fail "ulogd non ha creato il PID file"
kill -0 "$(cat "${ULOGD_PID_FILE}")" >/dev/null 2>&1 || fail "ulogd non è in esecuzione"

forward_logs() {
  local hec_url="${NFTABLES_SPLUNK_HEC_URL:-}"
  local hec_token="${NFTABLES_SPLUNK_HEC_TOKEN:-}"
  local host_name="${HOSTNAME:-nft-firewall}"

  if [[ -z "${hec_url}" || -z "${hec_token}" ]]; then
    log "HEC non configurato: inoltro dei log disabilitato"
    return 0
  fi

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
          log "Invio HEC non riuscito; l'evento rimane disponibile nel volume locale"
        fi
      done
}

forward_logs &
FORWARD_LOGS_PID=$!

log "Firewall caricato correttamente; monitoraggio attivo"

while sleep 60; do
  if ! nft list table ip filter >/dev/null 2>&1; then
    log "Ruleset assente: tentativo di ripristino"
    nft -f "${RULES_RENDERED}" || fail "Ripristino del ruleset fallito"
  fi

done
