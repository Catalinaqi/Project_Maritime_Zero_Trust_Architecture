#!/bin/bash
# =============================================================================
# RECARGA RÁPIDA DEL MOTOR SNORT 3 IDS
#  cd tests/snort/run/
# ./reload_ids.sh
# =============================================================================
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${YELLOW}► Reiniciando el contenedor ids_network_monitor...${NC}"
docker restart ids_network_monitor > /dev/null

echo -e "${YELLOW}► Esperando inicialización del motor DAQ y compilación de reglas...${NC}"
# Leemos los logs en vivo hasta que veamos el mensaje de éxito de Snort o pasen 15 segundos
timeout 15 docker logs -f ids_network_monitor | grep -E --color=always "Snort successfully validated|commencing packet processing|FATAL|ERROR"

echo -e "\n${GREEN}[✔] Snort recargado. Listo para recibir tráfico.${NC}"
