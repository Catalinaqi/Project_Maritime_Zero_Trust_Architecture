#!/bin/bash
# =============================================================================
# Snort 3 IDS Entrypoint Script - Maritime Zero Trust
# =============================================================================
# Author: Network Guardian (Snort/IDS)
# Component: Layer 1 Intrusion Detection System
# Purpose:
#   - Validate Snort 3 configuration and custom rules.
#   - Start Snort in live IDS mode when supported.
#   - Provide a portable mode for Docker Desktop Windows/Mac/Linux.
# Data Creation: 2026-05-11
# Last Updated: 2026-06-01
# =============================================================================

set -euo pipefail

# =============================================================================
# STEP 0: Paths and Defaults
# =============================================================================
SNORT_CONF="/etc/snort/snort.lua"
SNORT_RULES="/etc/snort/rules/zta.rules"
SNORT_LOG_DIR="/var/log/snort"
SNORT_ALERT_FILE="${SNORT_LOG_DIR}/alert"
SNORT_PORTABLE_LOG="${SNORT_LOG_DIR}/ids-portable.log"

# Environment variables with defaults
IDS_MODE="${IDS_MODE:-portable}"
INTERFACE="${INTERFACE:-eth0}"
SPLUNK_HEC_URL="${SPLUNK_HEC_URL:-http://172.20.2.8:8088/services/collector}"
SPLUNK_HEC_TOKEN="${SPLUNK_HEC_TOKEN:-}"

# Colors for logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# =============================================================================
# STEP 1: Pre-flight checks
# =============================================================================
pre_flight_checks() {
    log_info "Running pre-flight checks..."

    # Check Snort binary
    if ! command -v snort >/dev/null 2>&1; then
        log_error "Snort binary not found!"
        exit 1
    fi

    log_info "Snort binary found:"
    snort -V | head -n 15 || true

    # Check configuration file
    if [ ! -f "${SNORT_CONF}" ]; then
        log_error "Config file not found: ${SNORT_CONF}"
        exit 1
    fi
    log_info "Config file found: ${SNORT_CONF}"

    # Check rules file
    if [ -f "${SNORT_RULES}" ]; then
        log_info "Rules file found: ${SNORT_RULES}"
    else
        log_warn "Rules file not found: ${SNORT_RULES}."
    fi

    # Check log directory
    mkdir -p "${SNORT_LOG_DIR}"

    if [ ! -w "${SNORT_LOG_DIR}" ]; then
        log_error "Log directory not writable: ${SNORT_LOG_DIR}"
        exit 1
    fi
    log_info "Log directory writable: ${SNORT_LOG_DIR}"

    # Check Splunk HEC token
    if [ -z "${SPLUNK_HEC_TOKEN}" ]; then
        log_warn "SPLUNK_HEC_TOKEN is empty! Alerts will not be authenticated."
        log_warn "Set SPLUNK_HEC_TOKEN in docker-compose environment."
    else
        log_info "Splunk HEC token is set (length: ${#SPLUNK_HEC_TOKEN} chars)"
    fi

    # Validate interface names only if possible.
    # Some minimal Docker images do not include the 'ip' command.
    if command -v ip >/dev/null 2>&1; then
        IFS=':' read -ra IFACES <<< "${INTERFACE}"
        for iface in "${IFACES[@]}"; do
            if ! ip link show "${iface}" >/dev/null 2>&1; then
                log_warn "Interface '${iface}' not found. Snort may not capture on it."
            else
                log_info "Interface '${iface}' exists and ready."
            fi
        done
    else
        log_warn "'ip' command not found. Skipping interface pre-check."
        log_info "Available interfaces from /proc/net/dev:"
        cat /proc/net/dev || true
    fi

    log_info "IDS mode: ${IDS_MODE}"
    log_info "Pre-flight checks passed!"
}

# =============================================================================
# STEP 2: Validate Snort configuration and rules
# =============================================================================
validate_config() {
    log_info "Validating Snort configuration and custom rules..."

    local VALIDATE_OUTPUT

    if [ -f "${SNORT_RULES}" ]; then
        if VALIDATE_OUTPUT=$(snort -c "${SNORT_CONF}" -R "${SNORT_RULES}" -T 2>&1); then
            log_info "Config validation: PASSED"
        else
            log_error "Config validation: FAILED"
            log_error "${VALIDATE_OUTPUT}"
            exit 1
        fi
    else
        if VALIDATE_OUTPUT=$(snort -c "${SNORT_CONF}" -T 2>&1); then
            log_info "Config validation: PASSED"
        else
            log_error "Config validation: FAILED"
            log_error "${VALIDATE_OUTPUT}"
            exit 1
        fi
    fi
}

# =============================================================================
# STEP 3: Show rules summary
# =============================================================================
show_rules_summary() {
    log_info "Custom rules summary (zta.rules):"

    if [ -f "${SNORT_RULES}" ]; then
        local total_rules
        total_rules=$(grep -cE '^alert' "${SNORT_RULES}" 2>/dev/null || echo 0)

        log_info "  - Total custom rules defined: ${total_rules}"
        log_info "  - Rules file loaded from: ${SNORT_RULES}"
    else
        log_warn "  - No custom rules file found"
    fi
}

# =============================================================================
# STEP 4A: Portable IDS mode
# =============================================================================
start_portable_mode() {
    log_info "Starting IDS in portable mode..."
    log_info "Portable mode is designed to work on Docker Desktop Windows, macOS and Linux."
    log_info "Snort configuration and custom rules have been validated."
    log_warn "Live packet capture is skipped to avoid raw socket compatibility issues."
    log_info "Container will stay alive for integration testing."

    {
        echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') [INFO] IDS portable mode started"
        echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') [INFO] Snort configuration validated successfully"
        echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') [INFO] Custom rules validated successfully"
        echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') [WARN] Live packet capture disabled in portable mode"
    } >> "${SNORT_PORTABLE_LOG}"

    tail -f "${SNORT_PORTABLE_LOG}"
}

# =============================================================================
# STEP 4B: Live IDS mode
# =============================================================================
# =============================================================================
# STEP 4B: Live IDS mode
# =============================================================================
start_live_mode() {
    log_info "Iniciando Snort (Modo TTY Directo a Pantalla)..."

    # Detección de interfaz limpia
    RAW_IFACE=$(ip -4 addr | grep "172.20.13.11" -B1 | head -n1 | awk '{print $2}' | tr -d ':')
    INTERFACE=${RAW_IFACE%%@*}
    if [ -z "$INTERFACE" ]; then INTERFACE="eth2"; fi

    log_info "Interfaz detectada: ${INTERFACE}"

    # Ejecución desnuda de Snort directo a consola (sin tuberías)
    exec snort -c "${SNORT_CONF}" \
               -R "${SNORT_RULES}" \
               -i "${INTERFACE}" \
               -A alert_json \
               --plugin-path /usr/local/lib/daq
}

# =============================================================================
# STEP 5: Select IDS mode
# =============================================================================
start_ids() {
    case "${IDS_MODE}" in
        portable)
            start_portable_mode
            ;;

        live)
            start_live_mode
            ;;

        *)
            log_error "Invalid IDS_MODE: ${IDS_MODE}"
            log_error "Use IDS_MODE=portable or IDS_MODE=live"
            exit 1
            ;;
    esac
}

# =============================================================================
# STEP 6: Shutdown handler
# =============================================================================
shutdown_handler() {
    echo ""
    log_info "Received shutdown signal. Stopping IDS container..."

    local SNORT_PID
    SNORT_PID=$(pgrep -x snort || true)

    if [ -n "${SNORT_PID}" ]; then
        log_info "Sending SIGTERM to Snort (PID: ${SNORT_PID})"
        kill -TERM "${SNORT_PID}" 2>/dev/null || true
        sleep 2

        if kill -0 "${SNORT_PID}" 2>/dev/null; then
            log_warn "Snort did not stop gracefully, sending SIGKILL"
            kill -KILL "${SNORT_PID}" 2>/dev/null || true
        fi

        log_info "Snort stopped."
    else
        log_info "No Snort process found."
    fi

    log_info "Container shutting down."
    exit 0
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    trap shutdown_handler SIGTERM SIGINT

    echo "============================================================"
    echo "  Snort 3 IDS - Maritime Zero Trust Architecture"
    echo "============================================================"
    echo ""

    pre_flight_checks
    validate_config
    show_rules_summary
    start_ids
}

main
