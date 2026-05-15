# ============================================
# Dockerfile for Snort 3 IDS Container
# ============================================
# Project: Adria Ferries Maritime Security
# Author: Persona 1 - Network Guardian
# Component: Layer 1 Intrusion Detection System
# Build: Compiles Snort 3.9.2.0 + libdaq + dnet fix
# Creato: 2026-05-15
# Last Updated:
# ============================================


# ============================================
# STAGE 1: Build Environment (The "Constructor")
# ============================================
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# STEP 1: Install Build Dependencies
RUN apt-get update && \
    apt-get install --no-install-recommends -y \
        build-essential cmake pkg-config flex bison git ca-certificates \
        wget libtool autoconf automake libpcap-dev \
        libhwloc-dev libssl-dev libpcre2-dev libluajit-5.1-dev \
        liblzma-dev zlib1g-dev uuid-dev libmnl-dev libfl-dev \
        libnuma1 \
        libdumbnet-dev && \
    rm -rf /var/lib/apt/lists/*

# STEP 2: Path Shimming (The "Bridge") - usando dumbnet
# Ubuntu 22.04 usa libdumbnet-dev que instala el header como dumbnet.h
# Snort espera dnet.h — creamos el symlink correcto
RUN ln -sf /usr/include/dumbnet.h /usr/include/dnet.h && \
    ln -sf /usr/lib/x86_64-linux-gnu/libdumbnet.so /usr/lib/x86_64-linux-gnu/libdnet.so && \
    ldconfig

WORKDIR /tmp

# STEP 3: Build libdaq
RUN git clone https://github.com/snort3/libdaq.git && \
    cd libdaq && ./bootstrap && ./configure && \
    make -j$(nproc) && make install && ldconfig

# STEP 4: Build Snort 3 (Version 3.9.2.0)
# Key fix: point DDNET_INCLUDE_DIR to /usr/local/include where our dnet.h lives
RUN git clone --branch 3.9.2.0 --depth 1 https://github.com/snort3/snort3.git && \
    cd snort3 && \
    mkdir build && cd build && \
    cmake .. \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DENABLE_TCMALLOC=OFF \
        -DDNET_INCLUDE_DIR=/usr/include \
        -DFLEX_INCLUDE_DIR=/usr/include && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# ============================================
# STAGE 2: Runtime Image (The "Guardian")
# ============================================
FROM ubuntu:22.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# STEP 5: Install Runtime Libraries Only
RUN apt-get update && \
    apt-get install --no-install-recommends -y \
        libpcap0.8 libdumbnet1 hwloc libssl3 libpcre2-8-0 libluajit-5.1-2 \
        liblzma5 zlib1g libuuid1 libmnl0 ca-certificates bash \
        libnuma1 \
        tzdata tini && \
    rm -rf /var/lib/apt/lists/*

# STEP 6: Transfer the "Brain"
COPY --from=builder /usr/local/ /usr/local/
RUN ldconfig

# STEP 7: System Hardening
RUN mkdir -p /etc/snort/rules /var/log/snort && \
    groupadd --gid 1000 snort && \
    useradd --uid 1000 --gid snort --no-create-home --shell /bin/bash snort

# STEP 6b: Copy Snort configuration
COPY configs/snort/snort.lua /etc/snort/snort.lua
COPY configs/snort/rules/ /etc/snort/rules/
RUN chown -R snort:snort /var/log/snort /etc/snort

#COPY entrypoint-snort.sh /entrypoint.sh
COPY services/snort/entrypoint-snort.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER snort

# STEP 8: Health Check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD pgrep snort > /dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
