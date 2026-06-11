FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Installo SWTPM, cioè l'emulatore software di TPM.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      swtpm \
      swtpm-tools \
      ca-certificates \
      bash \
      tini && \
    rm -rf /var/lib/apt/lists/*

# Directory dove SWTPM salva lo stato persistente del TPM emulato.
RUN mkdir -p /var/lib/swtpm

COPY entrypoint-swtpm.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 2321 2322

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]