# Immagine ufficiale Debian stabile, utilizzata per evitare le instabilità
# riscontrate durante il download dei pacchetti dai mirror Alpine.
FROM debian:12.14-slim

ENV DEBIAN_FRONTEND=noninteractive

# Configura retry e timeout di APT, installa esclusivamente i componenti
# necessari al firewall e rimuove gli indici dei pacchetti dalla layer finale.
RUN set -eux; \
    printf '%s\n' \
      'Acquire::Retries "5";' \
      'Acquire::http::Timeout "30";' \
      'Acquire::https::Timeout "30";' \
      > /etc/apt/apt.conf.d/80-network-retries; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      gettext-base \
      findutils \
      grep \
      iproute2 \
      jq \
      nftables \
      tini \
      ulogd2 \
      util-linux; \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/nftables /var/log/nftables /run

COPY entrypoint.sh /entrypoint.sh

# La conversione CRLF -> LF rende il file affidabile anche quando il progetto
# viene modificato o estratto su Windows.
RUN sed -i 's/\r$//' /entrypoint.sh \
    && chmod 0755 /entrypoint.sh

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
