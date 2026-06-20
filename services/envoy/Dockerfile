FROM envoyproxy/envoy:v1.30-latest

# Installa curl, utilizzato dall'healthcheck Docker per interrogare
# l'endpoint /ready dell'interfaccia amministrativa di Envoy.
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8443
EXPOSE 9901

CMD ["envoy", "-c", "/etc/envoy/envoy.yaml", "--log-level", "info"]
