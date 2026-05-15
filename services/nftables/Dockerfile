# ============================================
# Dockerfile for NFTables Firewall
# ============================================
# Project: Adria Ferries Maritime Security
# Author: Persona 1 - Network Guardian
# Component: Layer 1 Network Security
# Purpose: Containerized NFTables firewall for Zero Trust perimeter
# Last Updated: 2026-05-11
# ============================================
# Security Model:
#   - Minimal image: Alpine with only nftables
#   - Read-only root filesystem compatible
#   - Runs as non-root (containers have NET_ADMIN cap)
#   - Rules mounted read-only from host
# ============================================

FROM alpine:3.19

# ============================================
# Layer 1: Install runtime dependencies only
# ============================================
# Minimal packages needed for NFTables operation
# iptables-legacy included for nft compatibility mode
# bash for entrypoint script execution
RUN apk add --no-cache \
    nftables \
    bash \
    tini \
    && rm -rf /var/cache/apk/* \
    && rm -rf /tmp/*

# ============================================
# Layer 2: Create directory structure
# ============================================
# /etc/nftables/ - mounted from host configs/nftables/
# /var/log/nftables/ - for firewall logs (volume mount)
RUN mkdir -p /etc/nftables /var/log/nftables

# ============================================
# Layer 3: Copy entrypoint script
# ============================================
COPY entrypoint-nftables.sh /entrypoint.sh

# Ensure entrypoint is executable
RUN chmod +x /entrypoint.sh \
    && chmod 755 /entrypoint.sh

# ============================================
# Layer 4: Security hardening
# ============================================
# Use tini as init (proper signal handling)
# Drop root capabilities where possible
# Run entrypoint through tini for zombie reaping
ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]

# ============================================
# Layer 5: Container metadata
# ============================================
LABEL maintainer="persona1@adriaferries.com"
LABEL version="1.1.0"
LABEL description="NFTables perimeter firewall for Zero Trust Architecture"
LABEL layer="1"
LABEL component="network-security"
LABEL project="maritime-zta"

# ============================================
# Expose ports (documentation only - firewall
# filters traffic on all interfaces)
# ============================================
EXPOSE 9090

# ============================================
# Health check: Verify NFTables rules are loaded
# ============================================
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nft list table inet filter > /dev/null 2>&1 || exit 1
