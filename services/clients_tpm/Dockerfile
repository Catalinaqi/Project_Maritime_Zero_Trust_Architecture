# Costruisce il client di test con OpenSSL, TPM tools e resource manager.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Il provider OpenSSL TPM2 consente di usare una chiave persistente nel
# dispositivo SWTPM senza esportarla nel filesystem del client.
# ----------------------------------------------------------------------
# ZTA AUDIT TOOLS ADDED:
# - iproute2: Necesario para el comando 'ip' (rutas de red)
# - iputils-ping: Necesario para los tests ICMP (Test 5)
# - curl: Necesario para las futuras pruebas de Capa 7 hacia Envoy/OPA
# ----------------------------------------------------------------------
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash ca-certificates dbus openssl tpm2-abrmd tpm2-openssl tpm2-tools \
       libtss2-tcti-swtpm0 libtss2-tcti-mssim0 libtss2-tcti-tabrmd0 \
       iproute2 iputils-ping curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/local/lib/ossl-modules \
    && provider_path="$(find /usr -name tpm2.so 2>/dev/null | head -n 1)" \
    && test -n "$provider_path" \
    && ln -sf "$provider_path" /usr/local/lib/ossl-modules/tpm2.so

RUN mkdir -p /certs/device /ca /tpm /scripts
COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

ENV OPENSSL_MODULES=/usr/local/lib/ossl-modules
ENTRYPOINT ["/scripts/client-entrypoint.sh"]
CMD ["bash"]
