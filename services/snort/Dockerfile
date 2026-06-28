# Build multi-stage di Snort 3 per il sensore IDS del progetto.
# Il numero di processi di compilazione è limitato per evitare che Docker
# Desktop esaurisca memoria durante la build e interrompa BuildKit con EOF.
FROM ubuntu:22.04 AS builder

ARG SNORT_VERSION=3.9.2.0
ARG LIBDAQ_VERSION=v3.0.20
ARG BUILD_JOBS=2

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install --no-install-recommends -y \
      autoconf automake bison build-essential ca-certificates cmake flex git \
      libdumbnet-dev libfl-dev libhwloc-dev liblzma-dev libmnl-dev \
      libnuma1 libpcap-dev libpcre2-dev libssl-dev libtool \
      libluajit-5.1-dev pkg-config uuid-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Snort cerca libdnet; Ubuntu distribuisce la stessa libreria come libdumbnet.
RUN ln -sf /usr/include/dumbnet.h /usr/include/dnet.h \
    && ln -sf /usr/lib/x86_64-linux-gnu/libdumbnet.so /usr/lib/x86_64-linux-gnu/libdnet.so \
    && ldconfig

WORKDIR /tmp

# Compila LibDAQ usando un numero controllato di processi paralleli.
RUN git clone --branch "${LIBDAQ_VERSION}" --depth 1 https://github.com/snort3/libdaq.git \
    && cd libdaq \
    && ./bootstrap \
    && ./configure \
    && make -j"${BUILD_JOBS}" \
    && make install \
    && ldconfig

# Compila Snort limitando esplicitamente il parallelismo.
RUN git clone --branch "${SNORT_VERSION}" --depth 1 https://github.com/snort3/snort3.git \
    && cmake -S snort3 -B snort3/build \
         -DCMAKE_INSTALL_PREFIX=/usr/local \
         -DENABLE_TCMALLOC=OFF \
         -DDNET_INCLUDE_DIR=/usr/include \
         -DFLEX_INCLUDE_DIR=/usr/include \
    && cmake --build snort3/build --parallel "${BUILD_JOBS}" \
    && cmake --install snort3/build

FROM ubuntu:22.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install --no-install-recommends -y \
      bash ca-certificates curl ethtool gettext-base hwloc iproute2 \
      iputils-ping jq libdumbnet1 libluajit-5.1-2 liblzma5 libmnl0 \
      libnuma1 libpcap0.8 libpcre2-8-0 libssl3 libuuid1 psmisc \
      tcpdump tini tzdata zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/ /usr/local/

RUN ldconfig \
    && groupadd --gid 1000 snort \
    && useradd --uid 1000 --gid snort --no-create-home --shell /bin/bash snort \
    && mkdir -p /etc/snort/rules /var/log/snort /scripts \
    && chown -R snort:snort /etc/snort /var/log/snort /scripts \
    && chmod 755 /var/log/snort

COPY entrypoint.sh /scripts/entrypoint.sh
RUN sed -i 's/\r$//' /scripts/entrypoint.sh \
    && chmod 0755 /scripts/entrypoint.sh

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/scripts/entrypoint.sh"]
