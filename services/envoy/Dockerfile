# Immagine ufficiale di Envoy.
FROM envoyproxy/envoy:v1.30-latest

# Servono i privilegi root per installare i programmi necessari.
USER root

# curl viene usato dall'healthcheck.
# iproute2 fornisce il comando "ip", necessario per aggiungere
# le route di ritorno verso le reti dei client.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Copia lo script che configura le route prima di avviare Envoy.
COPY entrypoint.sh /usr/local/bin/envoy-zta-entrypoint.sh

# Rende lo script eseguibile.
RUN chmod +x /usr/local/bin/envoy-zta-entrypoint.sh

# Porta mTLS del PEP.
EXPOSE 8443

# Porta amministrativa di Envoy.
EXPOSE 9901

# Configura le route e poi avvia Envoy.
ENTRYPOINT ["/usr/local/bin/envoy-zta-entrypoint.sh"]

# Comando predefinito.
CMD ["envoy", "-c", "/etc/envoy/envoy.yaml", "--log-level", "info"]