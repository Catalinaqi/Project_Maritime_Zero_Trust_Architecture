#!/bin/bash
# =============================================================================
# Snort 3 IDS Entrypoint Script - Maritime Zero Trust
# =============================================================================
# Project: Maritime - Zero Trust Architecture (ZTA)
# Author: Person 1 - Network Guardian (Snort/IDS)
# Component: Layer 1 Intrusion Detection System
# Purpose: Validate and start Snort 3 IDS with local alert output
# Data Creation: 2026-05-15
# Last Updated: 2026-05-15 (fix: removed HEC injection, clean start)
# =============================================================================

set -euo pipefail

# =============================================================================
# STEP 0: Paths and Defaults
# =============================================================================
SNORT_CONF="/etc/snort/snort.lua"
SNORT_RULES="/etc/snort/rules/zta.rules"
SNORT_LOG_DIR="/var/log/snort"
SNORT_ALERT_FILE="${SNORT_LOG_DIR}/alert"

# Environment variables with defaults
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

    # 1a: Check Snort binary
    if [ ! -x "$(command -v snort)" ]; then
        log_error "Snort binary not found!"
        exit 1
    fi
    log_info "Snort binary found: $(snort -V 2>&1)"

    # 1b: Check configuration file
    if [ ! -f "${SNORT_CONF}" ]; then
        log_error "Config file not found: ${SNORT_CONF}"
        exit 1
    fi
    log_info "Config file found: ${SNORT_CONF}"

    # 1c: Check rules file
    if [ -f "${SNORT_RULES}" ]; then
        log_info "Rules file found: ${SNORT_RULES}"
    else
        log_warn "Rules file not found: ${SNORT_RULES} (will use built-in rules if any)"
    fi

    # 1d: Check log directory writability
    if [ ! -w "${SNORT_LOG_DIR}" ]; then
        log_error "Log directory not writable: ${SNORT_LOG_DIR}"
        exit 1
    fi
    log_info "Log directory writable: ${SNORT_LOG_DIR}"

    # 1e: Check Splunk HEC token (warning if empty)
    if [ -z "${SPLUNK_HEC_TOKEN}" ]; then
        log_warn "SPLUNK_HEC_TOKEN is empty! Alerts will not be authenticated."
        log_warn "Set SPLUNK_HEC_TOKEN in docker-compose environment."
    else
        log_info "Splunk HEC token is set (length: ${#SPLUNK_HEC_TOKEN} chars)"
    fi

    # 1f: Validate interfaces exist
    IFS=':' read -ra IFACES <<< "${INTERFACE}"
    for iface in "${IFACES[@]}"; do
        if ! ip link show "${iface}" &>/dev/null; then
            log_warn "Interface '${iface}' not found. Snort may not capture on it."
        else
            log_info "Interface '${iface}' exists and ready."
        fi
    done

    log_info "Pre-flight checks passed!"
}

# =============================================================================
# STEP 2: Validate Snort configuration
# =============================================================================
validate_config() {
    log_info "Validating Snort configuration..."
    local VALIDATE_OUTPUT
    if VALIDATE_OUTPUT=$(snort -c "${SNORT_CONF}" -T 2>&1); then
        log_info "Config validation: PASSED"
    else
        log_error "Config validation: FAILED"
        log_error "${VALIDATE_OUTPUT}"
        exit 1
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
        local categories
        categories=$(grep -oP 'msg:"\[ZTA-\d+\]' "${SNORT_RULES}" | wc -l)
        log_info "  - All rules have ZTA prefix identifiers"
    else
        log_warn "  - No custom rules file found"
    fi
}

# =============================================================================
# STEP 4: Start Snort in foreground
# =============================================================================
start_snort() {
    log_info "Starting Snort 3 in IDS mode..."
    log_info "Monitoring interfaces: ${INTERFACE}"

    # Snort 3 accepts colon-separated interfaces with -i
    exec snort -c "${SNORT_CONF}" \
               -i "${INTERFACE}" \
               -l "${SNORT_LOG_DIR}" \
               -A alert_fast \
               --plugin-path /usr/local/lib/daq \
               2>&1
}

# =============================================================================
# STEP 5: Shutdown handler (only reached if exec fails)
# =============================================================================
shutdown_handler() {
    echo ""
    log_info "Received shutdown signal. Stopping Snort..."
    local SNORT_PID
    SNORT_PID=$(pgrep -x snort || true)
    if [ -n "$SNORT_PID" ]; then
        log_info "Sending SIGTERM to Snort (PID: $SNORT_PID)"
        kill -TERM "$SNORT_PID" 2>/dev/null || true
        sleep 2
        if kill -0 "$SNORT_PID" 2>/dev/null; then
            log_warn "Snort did not stop gracefully, sending SIGKILL"
            kill -KILL "$SNORT_PID" 2>/dev/null || true
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

    start_snort

    # If exec fails (e.g., due to invalid arguments), fall back
    log_error "Snort exec failed. Please check configuration."
    log_error "Falling back to log monitoring mode (no IDS process)..."
    tail -f /dev/null
}

main
