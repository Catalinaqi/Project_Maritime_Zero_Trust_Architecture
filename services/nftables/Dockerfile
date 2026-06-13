FROM alpine:3.19

# nftables : firewall
# bash     : entrypoint
# tini     : signal and zombie process handling
# gettext  : provides envsubst to resolve ${VARS} from compose in rules.nft
# iproute2 : provides 'ip' for interface diagnostics in entrypoint
# ulogd    : daemon to extract netfilter logs to local files -> project v2
# curl     : allows sending logs to Splunk API (HEC)
# grep     : GNU version required for --line-buffered flag
# util-linux: complete dmesg version to read kernel in real time
RUN apk add --no-cache \
    nftables \
    bash \
    tini \
    gettext \
    iproute2 \
    curl \
    grep \
    util-linux \
    && rm -rf /var/cache/apk/*

RUN mkdir -p /etc/nftables /var/log/nftables

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nft list table inet filter > /dev/null 2>&1 || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
