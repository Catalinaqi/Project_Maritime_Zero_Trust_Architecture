#!/bin/bash
# =============================================================================
# MARITIME ZTA - firewall_perimeter entrypoint
# =============================================================================
set -euo pipefail

# =============================================================================
# Logging functions with color and level
# =============================================================================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[Entrypoint-NFTABLES] [INFO]${NC}  $(date '+%Y-%m-%d %H:%M:%S') - $1"; }
log_warn()  { echo -e "${YELLOW}[Entrypoint-NFTABLES] [WARN]${NC}  $(date '+%Y-%m-%d %H:%M:%S') - $1"; }
log_error() { echo -e "${RED}[Entrypoint-NFTABLES] [ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2; }
fail()      { log_error "$1"; exit 1; }

RULES_SRC="/etc/nftables/rules.nft"
RULES_RENDERED="/tmp/rules_rendered.nft"
LOG_DIR="/var/log/nftables"

echo "================================================================================"
echo -e "  ${CYAN}NFTables Firewall - Entrypoint - Maritime Zero Trust Architecture${NC}"
echo "================================================================================"

# =============================================================================
# STEP 1: Pre-flight checks
# =============================================================================
log_info "[STEP-1] Start - Pre-flight checks"

command -v nft >/dev/null 2>&1 || fail "[STEP-1] nft binary not found"
command -v envsubst >/dev/null 2>&1 || fail "[STEP-1] envsubst (gettext) not installed"

NFT_VERSION=$(nft --version 2>&1 | head -1 || echo "version unknown")
log_info "[STEP-1] Engine detected: $NFT_VERSION"

[ -f "$RULES_SRC" ] || fail "[STEP-1] rules.nft not found: $RULES_SRC"
[ -d "$LOG_DIR" ]   || mkdir -p "$LOG_DIR"

log_info "[STEP-1] Pre-flight checks completed OK"

# =============================================================================
# STEP 2: Validate environment variables (NFTABLES_ prefix)
# =============================================================================
log_info "[STEP-2] Start - Validating NFTables environment variables"

REQUIRED_VARS=(
    NFTABLES_ENVOY_IP NFTABLES_OPA_IP NFTABLES_MONGODB_IP
    NFTABLES_API_IP NFTABLES_SPLUNK_IP NFTABLES_CORPORATE_NET
    NFTABLES_VPN_NET NFTABLES_SATELLITE_NET NFTABLES_PUBLIC_NET
    NFTABLES_SNORT_IP
    NFTABLES_PEP_PORT NFTABLES_OPA_PORTS NFTABLES_MONGO_PORT
    NFTABLES_API_PORT NFTABLES_SIEM_HEC_PORT NFTABLES_SIEM_WEB_PORT
    NFTABLES_ENVOY_ADMIN_PORT
)

ALL_OK=true
for var in "${REQUIRED_VARS[@]}"; do
    val="${!var:-}"
    if [ -z "$val" ]; then
        log_error "[STEP-2] Variable $var is EMPTY - envsubst will produce unresolved placeholders"
        ALL_OK=false
    else
        log_info "[STEP-2] Variable $var = $val"
    fi
done

[ "$ALL_OK" = true ] || fail "[STEP-2] Missing variables - fail secure"
log_info "[STEP-2] All NFTables variables present - OK"

# =============================================================================
# STEP 3: Render rules.nft with envsubst
# =============================================================================
log_info "[STEP-3] Start - Resolving variables in rules.nft"

envsubst < "$RULES_SRC" > "$RULES_RENDERED"

# Check for any unresolved ${...}
if grep -q '\${' "$RULES_RENDERED"; then
    log_error "[STEP-3] Unresolved variables in rendered rules:"
    grep '\${' "$RULES_RENDERED" >&2
    fail "[STEP-3] envsubst incomplete - fail secure"
fi

log_info "[STEP-3] Render completed -> $RULES_RENDERED"
log_info "[STEP-3] Rendered rules summary:"
grep -E '(^table|chain|accept|drop|log)' "$RULES_RENDERED" | while IFS= read -r line; do
    log_info "[STEP-3]   $line"
done

# =============================================================================
# STEP 4: Syntax validation (fail-secure)
# =============================================================================
log_info "[STEP-4] Start - Validating nftables syntax"

nft -c -f "$RULES_RENDERED" || fail "[STEP-4] Invalid syntax - fail secure"
log_info "[STEP-4] Syntax validation: PASSED"

# =============================================================================
# STEP 5: Load rules and verify
# =============================================================================
log_info "[STEP-5] Start - Loading nftables rules"

nft -f "$RULES_RENDERED" || fail "[STEP-5] Error loading rules - fail secure"

# Verify table and chains exist
#nft list table inet filter > /dev/null 2>&1 || fail "[STEP-5] Table 'inet filter not found"
nft list table ip filter > /dev/null 2>&1 || fail "[STEP-5] Table 'ip filter' not found"

# Check the DROP policy ignoring uppercase/lowercase and spaces (-iq)
# nft for alpine:3.19 -> -q (quiet): It is mandatory
# nft for alpine:3.19 -> -i (ignore-case / ignore uppercase letters) :
#nft list chain inet filter forward | grep -iq "policy drop" \
#nft list chain ip filter forward | grep -iq "policy drop" \
nft list chain ip filter forward | grep -i "policy drop" > /dev/null \
    || fail "[STEP-5] FORWARD policy drop not active - fail secure"

log_info "[STEP-5] Rules loaded and verified - OK"
log_info "[STEP-5] Full ruleset:"
nft list ruleset | while IFS= read -r line; do
    log_info "[STEP-5]   $line"
done

#
## =============================================================================
## STEP 6: Log forwarder (ulogd -> Splunk HEC)
## =============================================================================
#log_info "[STEP-6] Start - Configuring log forwarder"
#
## 1. Iniciar ulogd en segundo plano
#log_info "[STEP-6] Iniciando ulogd para capturar logs en userspace..."
#ulogd -d
#sleep 2 # Darle tiempo a que cree el archivo de logs
#
#forward_to_splunk() {
#    HEC_URL="${NFTABLES_SPLUNK_HEC_URL:-$SPLUNK_HEC_URL}"
#    HEC_TOKEN="${NFTABLES_SPLUNK_HEC_TOKEN:-$SPLUNK_HEC_TOKEN}"
#
#    if [ -z "$HEC_URL" ] || [ -z "$HEC_TOKEN" ]; then
#        log_warn "[STEP-6] Splunk HEC URL/Token not defined - forwarder disabled"
#        return
#    fi
#
#    log_info "[STEP-6] Starting forwarder ulogd -> Splunk HEC (URL: $HEC_URL)"
#
#    # 2. Leemos el archivo local de ulogd
#    tail -F /var/log/ulogd.syslogemu 2>/dev/null | grep --line-buffered \
#        -E "NFT-FWD|NFT-INPUT|CRITICAL|WARNING|DIRECT|UNAUTHORIZED|ENVOY_ADMIN" | \
#    while IFS= read -r line; do
#
#        payload=$(printf '{"event":{"message":"%s","host":"%s","source":"nftables"}}' \
#            "$(echo "$line" | sed 's/"/\\"/g')" \
#            "$(hostname)")
#
#        curl -s --cacert /ca/ca.crt --max-time 5 -o /dev/null \
#            -H "Authorization: Splunk $HEC_TOKEN" \
#            -H "Content-Type: application/json" \
#            -d "$payload" \
#            "$HEC_URL" || log_warn "[STEP-6] Error de conexión segura con Splunk"
#    done &
#
#    log_info "[STEP-6] Forwarder Splunk active (PID $!)"
#}
#
#forward_to_splunk
#


# =============================================================================
# STEP 6: Log forwarder (ulogd -> Splunk HEC)
# =============================================================================
log_info "[STEP-6] Start - Configuring log forwarder"

# 1. Crear configuración mínima de ulogd para capturar el group 0
cat << 'EOF' > /etc/ulogd.conf
[global]
logfile="/var/log/nftables/ulogd_system.log"

# Carga de Plugins
plugin="/usr/lib/ulogd/ulogd_inppkt_NFLOG.so"
plugin="/usr/lib/ulogd/ulogd_raw2packet_BASE.so"
plugin="/usr/lib/ulogd/ulogd_filter_IFINDEX.so"
plugin="/usr/lib/ulogd/ulogd_filter_IP2STR.so"
plugin="/usr/lib/ulogd/ulogd_filter_PRINTPKT.so"
plugin="/usr/lib/ulogd/ulogd_output_LOGEMU.so"

# El stack DEBE incluir la traducción de formato antes de llegar a LOGEMU
stack=log1:NFLOG,base1:BASE,ifi1:IFINDEX,ip2str1:IP2STR,print1:PRINTPKT,emu1:LOGEMU

[log1]
group=0

[emu1]
file="/var/log/nftables/ulogd_alerts.log"
sync=1
EOF

# 2. Iniciar ulogd en segundo plano
log_info "[STEP-6] Iniciando ulogd para capturar logs en userspace..."
ulogd -d
sleep 2 # Darle tiempo a que cree el archivo de alertas

forward_to_splunk() {
    HEC_URL="${NFTABLES_SPLUNK_HEC_URL:-$SPLUNK_HEC_URL}"
    HEC_TOKEN="${NFTABLES_SPLUNK_HEC_TOKEN:-$SPLUNK_HEC_TOKEN}"

    if [ -z "$HEC_URL" ] || [ -z "$HEC_TOKEN" ]; then
        log_warn "[STEP-6] Splunk HEC URL/Token not defined - forwarder disabled"
        return
    fi

    log_info "[STEP-6] Starting forwarder ulogd -> Splunk HEC (URL: $HEC_URL)"

    # 3. Leemos el NUEVO archivo local de alertas de ulogd
    tail -F /var/log/nftables/ulogd_alerts.log 2>/dev/null | grep --line-buffered \
        -E "NFT-FWD|NFT-INPUT|CRITICAL|WARNING|DIRECT|UNAUTHORIZED|ENVOY_ADMIN" | \
    while IFS= read -r line; do

        payload=$(printf '{"event":{"message":"%s","host":"%s","source":"nftables"}}' \
            "$(echo "$line" | sed 's/"/\\"/g')" \
            "$(hostname)")

        #curl -s --cacert /ca/ca.crt --max-time 5 -o /dev/null \
        curl -s -k --max-time 5 -o /dev/null \
            -H "Authorization: Splunk $HEC_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$payload" \
            "$HEC_URL" || log_warn "[STEP-6] Error de conexión segura con Splunk"
    done &

    log_info "[STEP-6] Forwarder Splunk active (PID $!)"
}

forward_to_splunk

# =============================================================================
# STEP 7: Monitoring loop
# =============================================================================
log_info "[STEP-7] Start - Monitoring loop every 60 seconds"

while true; do
    #if nft list table inet filter > /dev/null 2>&1; then
    if nft list table ip filter > /dev/null 2>&1; then
        log_info "[STEP-7] Rules active - OK"
    else
        log_warn "[STEP-7] Rules lost - reloading..."
        nft -f "$RULES_RENDERED" || fail "[STEP-7] Reload failed"
        log_info "[STEP-7] Rules reloaded successfully"
    fi
    sleep 60
done
