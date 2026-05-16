FROM envoyproxy/envoy:v1.30-latest

EXPOSE 8443
EXPOSE 9901

CMD ["envoy", "-c", "/etc/envoy/envoy.yaml", "--log-level", "info"]