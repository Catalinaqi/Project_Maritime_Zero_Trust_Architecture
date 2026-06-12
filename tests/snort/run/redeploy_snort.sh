docker compose build ids_network_monitor
docker compose up -d --force-recreate ids_network_monitor
docker logs ids_network_monitor -f

##!/bin/bash
## =============================================================================
## MARITIME ZTA - Redeploy seguro de ids_network_monitor (Snort 3)
## =============================================================================
#set -euo pipefail
#
#RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
#
#log()  { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }
#fail() { echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" >&2; exit 1; }
#ok()   { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] ✔ $1${NC}"; }
#warn() { echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] ⚠ $1${NC}"; }
#
#SERVICE="ids_network_monitor"
#
#log "${BLUE}PASO 1 — Verificaciones previas de Archivos ZTA${NC}"
#[ -f "docker-compose.yml" ] || fail "docker-compose.yml no encontrado."
#[ -f "./configs/snort/snort-zta.lua" ] || fail "snort-zta.lua no encontrado en ./configs/snort/"
#[ -f "./configs/snort/snort-zta.rules" ] || fail "snort-zta.rules no encontrado en ./configs/snort/"
#[ -f "./services/snort/entrypoint.sh" ] || fail "entrypoint.sh no encontrado en ./services/snort/"
#ok "Todos los archivos de configuración están presentes."
#
#log "${BLUE}PASO 2 — Build de la nueva imagen (Snort 3 + ZTA)${NC}"
#docker compose build $SERVICE && ok "Build completado" || fail "Build fallido. Revisa tu Dockerfile."
#
#log "${BLUE}PASO 3 — Redeploy con ventana mínima de downtime${NC}"
#docker compose stop $SERVICE
#docker compose up -d $SERVICE
#
#log "${BLUE}PASO 4 — Monitoreo de Arranque y Healthcheck${NC}"
#RETRIES=12
#while [ $RETRIES -gt 0 ]; do
#    STATUS=$(docker inspect --format='{{.State.Health.Status}}' $SERVICE 2>/dev/null || echo "none")
#    if [ "$STATUS" = "healthy" ]; then
#        ok "Healthcheck: healthy (Snort está corriendo y capturando)"
#        break
#    fi
#    log "Healthcheck: $STATUS — esperando... ($RETRIES intentos restantes)"
#    sleep 5
#    RETRIES=$((RETRIES-1))
#done
#
#if [ $RETRIES -eq 0 ] || [ "$STATUS" != "healthy" ]; then
#    echo -e "\n${RED}============================================================${NC}"
#    echo -e "${RED} 🚨 SNORT HA FALLADO AL ARRANCAR. GUÍA DE DIAGNÓSTICO: 🚨${NC}"
#    echo -e "${RED}============================================================${NC}"
#    echo -e "Revisa los logs exactos ejecutando: ${YELLOW}docker logs $SERVICE${NC}\n"
#    fail "Redeploy abortado por seguridad."
#fi
#
#log "${BLUE}PASO 5 — Verificación Post-Redeploy${NC}"
#docker exec $SERVICE ls -l /var/log/snort/alert_json.txt >/dev/null 2>&1 \
#    && ok "Archivo alert_json.txt inicializado correctamente." \
#    || warn "alert_json.txt no encontrado."
#
#docker exec $SERVICE ps aux | grep snort | grep -v grep >/dev/null \
#    && ok "Proceso de Snort verificado en memoria." \
#    || fail "Snort no está en memoria."
#
#ok "¡Redeploy de Snort completado con éxito! Listo para las pruebas."
