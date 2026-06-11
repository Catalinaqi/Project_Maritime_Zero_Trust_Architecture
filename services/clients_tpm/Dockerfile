FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Dipendenze base:
# - tpm2-tools: comandi per creare e gestire chiavi TPM
# - OpenSSL: usato per CSR e handshake TLS
# - librerie TCTI: permettono di parlare con SWTPM
# - strumenti build: servono per compilare tpm2-openssl
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      jq \
      wget \
      git \
      build-essential \
      autoconf \
      autoconf-archive \
      automake \
      libtool \
      pkg-config \
      libssl-dev \
      libjson-c-dev \
      libcurl4-openssl-dev \
      tpm2-tools \
      libtss2-dev \
      libtss2-tcti-swtpm0 \
      libtss2-tcti-mssim0 \
      openssl && \
    rm -rf /var/lib/apt/lists/*

# Installazione provider tpm2-openssl.
# Questo provider permette a OpenSSL 3 di usare chiavi conservate nel TPM.
RUN git clone --depth 1 https://github.com/tpm2-software/tpm2-openssl.git /tmp/tpm2-openssl && \
    cd /tmp/tpm2-openssl && \
    ./bootstrap && \
    ./configure && \
    make -j"$(nproc)" && \
    make install && \
    ldconfig && \
    mkdir -p /usr/local/lib/ossl-modules && \
    TPM2_PROVIDER_PATH="$(find /usr -name 'tpm2.so' 2>/dev/null | head -n 1)" && \
    echo "TPM2 provider trovato in: ${TPM2_PROVIDER_PATH}" && \
    test -n "${TPM2_PROVIDER_PATH}" && \
    ln -sf "${TPM2_PROVIDER_PATH}" /usr/local/lib/ossl-modules/tpm2.so && \
    rm -rf /tmp/tpm2-openssl

WORKDIR /workspace

RUN mkdir -p /certs/device /ca /tpm /scripts

COPY scripts/provision_device_tpm.sh /scripts/provision_device_tpm.sh
COPY scripts/request_with_tpm.sh /scripts/request_with_tpm.sh

RUN chmod +x /scripts/provision_device_tpm.sh /scripts/request_with_tpm.sh

ENV OPENSSL_MODULES=/usr/local/lib/ossl-modules
ENV TPM2TOOLS_TCTI=swtpm:host=swtpm_d001,port=2321
ENV TPM2OPENSSL_TCTI=swtpm:host=swtpm_d001,port=2321

CMD ["bash"]