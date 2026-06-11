FROM alpine:3.19

# nftables : firewall
# bash     : entrypoint
# tini     : manejo de señales y procesos zombie
# gettext  : provee envsubst para resolver ${VARS} del compose en rules.nft
# iproute2 : provee 'ip' para diagnostico de interfaces en el entrypoint
# ulogd    : demonio para extraer logs de netfilter a archivos locales
RUN apk add --no-cache \
    nftables \
    bash \
    tini \
    gettext \
    iproute2 \
    && rm -rf /var/cache/apk/*

RUN mkdir -p /etc/nftables /var/log/nftables

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nft list table inet filter > /dev/null 2>&1 || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
