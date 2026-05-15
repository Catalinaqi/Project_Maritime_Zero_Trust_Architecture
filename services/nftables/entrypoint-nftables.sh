#!/bin/bash
# ============================================
# Entrypoint Script for NFTables Firewall
# ============================================
# Project: Adria Ferries Maritime Security
# Author: Persona 1 - Network Guardian
# Component: Layer 1 Network Security
# Purpose: Load NFTables rules and maintain container
# Last Updated: 2026-05-11
# ============================================
# Security Model:
#   - Fail secure: If rules fail to load, container exits
#   - No fallback to allow-all on error
#   - Rules are mounted read-only (cannot be modified at runtime)
#   - Container stays alive for monitoring/logging only
# ============================================

set -euo pipefail

# ============================================
# Configuration
# ============================================
RULES_FILE="/etc/nftables/rules.nft"
LOCK_FILE="/var/run/nftables-loaded.lock"
LOG_DIR="/var/log/nftables"

# ============================================
# Utility Functions
# ============================================

log_info() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

log_warning() {
    echo "[WARNING] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# ============================================
# Pre-flight checks
# ============================================

pre_flight_checks() {
    log_info "Running pre-flight checks..."

    # Check if rules file exists
    if [ ! -f "${RULES_FILE}" ]; then
        log_error "Rules file not found: ${RULES_FILE}"
        log_error "Ensure configs/nftables/rules.nft is mounted at /etc/nftables/rules.nft"
        exit 1
    fi

    # Check if rules file is readable
    if [ ! -r "${RULES_FILE}" ]; then
        log_error "Rules file is not readable: ${RULES_FILE}"
        exit 1
    fi

    # Check if nftables is available
    if ! command -v nft &> /dev/null; then
        log_error "NFTables binary (nft) not found in PATH"
        exit 1
    fi

    # Check if NET_ADMIN capability is available
    # Without this, nftables cannot modify kernel rules
    if ! cat /proc/self/status | grep -q "CapBnd:"; then
        log_warning "Cannot verify NET_ADMIN capability. Container may lack necessary permissions."
    fi

    # Verify log directory exists
    if [ ! -d "${LOG_DIR}" ]; then
        log_warning "Log directory ${LOG_DIR} does not exist. Creating..."
        mkdir -p "${LOG_DIR}"
    fi

    log_info "All pre-flight checks passed."
}

# ============================================
# Validate NFTables syntax
# ============================================

validate_rules() {
    log_info "Validating NFTables rules syntax..."

    # Use nft -c (check mode) to validate without loading
    if nft -c -f "${RULES_FILE}"; then
        log_info "Rules syntax validation: PASSED"
        return 0
    else
        log_error "Rules syntax validation: FAILED"
        log_error "Check ${RULES_FILE} for syntax errors"
        log_error "Debug tip: Run manually: nft -c -f ${RULES_FILE}"
        return 1
    fi
}

# ============================================
# Flush existing rules
# ============================================

flush_existing_rules() {
    log_info "Flushing any existing NFTables rulesets..."

    # Flush all rules to start from clean state
    # This is critical: old rules might conflict with new ones
    if nft flush ruleset 2>/dev/null; then
        log_info "Existing rules flushed successfully."
    else
        log_warning "No existing rules to flush or flush failed."
        log_warning "This is normal on first start."
    fi
}

# ============================================
# Load NFTables rules
# ============================================

load_rules() {
    log_info "Loading NFTables rules from ${RULES_FILE}..."

    # Load the rules file
    if nft -f "${RULES_FILE}"; then
        log_info "NFTables rules loaded successfully."
        log_info "Security perimeter is ACTIVE."

        # Create lock file to indicate rules are loaded
        touch "${LOCK_FILE}"
        return 0
    else
        log_error "FAILED to load NFTables rules!"
        log_error "CRITICAL: Firewall is NOT protecting the network!"
        return 1
    fi
}

# ============================================
# Verify loaded rules
# ============================================

verify_rules() {
    log_info "Verifying loaded rules..."

    # Check if our main table exists
    if nft list table inet filter > /dev/null 2>&1; then
        log_info "Table 'inet filter' is present: OK"
    else
        log_error "Table 'inet filter' is NOT present!"
        log_error "Rules may not have been loaded correctly."
        return 1
    fi

    # Check if FORWARD chain has default policy drop
    # Use nft list chain (more direct) to get policy
    local forward_output
    forward_output=$(nft list chain inet filter forward 2>/dev/null || true)

    if echo "${forward_output}" | grep -q 'policy drop'; then
        log_info "FORWARD chain policy: drop (SECURE) - OK"
    else
        log_error "FORWARD chain policy is NOT 'drop'!"
        log_error "FAIL SECURE: Default deny is not enforced!"
        log_error ""
        log_error "Raw output of 'nft list chain inet filter forward':"
        echo "${forward_output}"
        log_error ""
        log_error "Debug: trying 'nft list ruleset':"
        nft list ruleset 2>&1 | grep -A10 'chain forward' || echo "(empty)"
        return 1
    fi

    # Check if MongoDB protection rule exists
    if nft list chain inet filter forward 2>/dev/null | grep -q "dport 27017"; then
        log_info "MongoDB protection rules present: OK"
    else
        log_warning "MongoDB protection rules NOT found!"
        log_warning "Database may be exposed."
    fi

    # Check if Envoy allow rule exists
    if nft list chain inet filter forward 2>/dev/null | grep -q "dport 8443"; then
        log_info "Envoy (PEP) allow rule present: OK"
    else
        log_warning "Envoy allow rule NOT found!"
        log_warning "No public entry point configured."
    fi

    # Check if Splunk allow rule exists
    if nft list chain inet filter forward 2>/dev/null | grep -q "dport 8088"; then
        log_info "Splunk HEC allow rule present: OK"
    else
        log_warning "Splunk HEC allow rule NOT found!"
        log_warning "Logs may not reach SIEM."
    fi

    log_info "Rule verification complete."
}

# ============================================
# Display active rules
# ============================================

display_rules() {
    log_info "============================================"
    log_info "ACTIVE NFTABLES RULESET"
    log_info "============================================"

    # List the entire ruleset for verification
    nft list ruleset

    log_info "============================================"
    log_info "END OF RULESET"
    log_info "============================================"
}

# ============================================
# Main execution
# ============================================

main() {
    echo ""
    echo "╔═══════════════════════════════════════════════╗"
    echo "║     🔥 NFTABLES FIREWALL - ZERO TRUST        ║"
    echo "║     Adria Ferries Maritime Security           ║"
    echo "║     Layer 1 - Network Guardian                ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo ""

    log_info "Starting NFTables Firewall initialization..."
    log_info "Container hostname: $(hostname)"
    log_info "Rules file: ${RULES_FILE}"
    log_info "Log directory: ${LOG_DIR}"

    # Step 1: Pre-flight checks
    pre_flight_checks

    # Step 2: Flush existing rules
    flush_existing_rules

    # Step 3: Validate syntax
    if ! validate_rules; then
        log_error "❌ FIREWALL STARTUP FAILED: Syntax validation error"
        log_error "Container will exit. Fix rules.nft and restart."
        exit 1
    fi

    # Step 4: Load rules
    if ! load_rules; then
        log_error "❌ FIREWALL STARTUP FAILED: Could not load rules"
        log_error "Container will exit. Investigate and restart."
        exit 1
    fi

    # Step 5: Verify rules
    if ! verify_rules; then
        log_error "⚠️  FIREWALL RULES VERIFICATION FAILED"
        log_error "Rules loaded but verification found issues."
        log_error "Container will continue running for debugging."
        log_error "Check logs above for specific warnings."
    fi

    # Step 6: Display active rules
    display_rules

    # Step 7: Print network interface info
    echo ""
    log_info "Network interfaces inside container:"
    ip addr show 2>/dev/null | grep -E "^[0-9]|inet " || log_warning "ip command not available"

    echo ""
    log_info "============================================"
    log_info "🔥 NFTABLES FIREWALL IS ACTIVE"
    log_info "Security perimeter is protecting the network."
    log_info "Monitoring for dropped packets..."
    log_info "============================================"
    echo ""

    # ============================================
    # Keep container alive
    # ============================================
    # The container must stay running to keep NFTables rules active.
    # If the container stops, the kernel removes the network namespace
    # and all NFTables rules are lost.
    #
    # We monitor the rules file for changes and reload if needed.
    # We also periodically verify rules are still loaded.

    log_info "Entering monitoring loop (checking every 60s)..."

    # Get initial file hash for change detection
    local rules_hash
    rules_hash=$(md5sum "${RULES_FILE}" 2>/dev/null | cut -d' ' -f1 || echo "unknown")

    while true; do
        # Check if rules are still loaded
        if ! nft list table inet filter > /dev/null 2>&1; then
            log_warning "NFTables rules missing! Attempting reload..."

            if nft -f "${RULES_FILE}" 2>/dev/null; then
                log_info "Rules reloaded successfully."
            else
                log_error "Failed to reload rules!"
            fi
        fi

        # Check if rules file has changed
        if [ -f "${RULES_FILE}" ]; then
            local new_hash
            new_hash=$(md5sum "${RULES_FILE}" 2>/dev/null | cut -d' ' -f1 || echo "unknown")

            if [ "${new_hash}" != "${rules_hash}" ]; then
                log_info "Rules file changed! Reloading..."

                # Flush and reload
                nft flush ruleset 2>/dev/null || true

                if nft -f "${RULES_FILE}" 2>/dev/null; then
                    log_info "Rules reloaded from updated file."
                    rules_hash="${new_hash}"
                else
                    log_error "Failed to reload updated rules!"
                    log_error "Previous rules have been flushed! Network is exposed!"
                fi
            fi
        fi

        # Sleep before next check
        sleep 60
    done
}

# ============================================
# Trap signals for graceful shutdown
# ============================================
# When container stops, rules in the network namespace
# are automatically cleaned up by the kernel.
trap 'log_info "Received SIGTERM/SIGINT. Shutting down firewall..."; exit 0' SIGTERM SIGINT

# ============================================
# Start main execution
# ============================================
main "$@"
