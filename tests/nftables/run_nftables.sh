#!/bin/bash
# =============================================================================
# MARITIME ZTA - Pre-Build Validator & Deployer for NFTables
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}=== Iniciando Validación y Despliegue del Firewall ===${NC}"

# 1. Corregir saltos de línea (CRLF a LF) en los archivos críticos
echo -e "\n${YELLOW}[1] Corrigiendo saltos de línea (Windows a Linux)...${NC}"
sed -i 's/\r$//' ./services/nftables/entrypoint.sh
sed -i 's/\r$//' ./configs/nftables/rules.nft
chmod +x ./services/nftables/entrypoint.sh
echo -e "${GREEN} -> Listo. Archivos convertidos a formato UNIX (LF).${NC}"

# 2. Cargar el archivo .env local
echo -e "\n${YELLOW}[2] Cargando variables de entorno desde .env...${NC}"
if [ -f ".env" ]; then
    set -a
    source .env
    set +a
    echo -e "${GREEN} -> Archivo .env cargado exitosamente.${NC}"
else
    echo -e "${RED} [ERROR] No se encontró el archivo .env en la raíz.${NC}"
    exit 1
fi

# 3. Validar variables ESTRICTAMENTE necesarias en el .env
echo -e "\n${YELLOW}[3] Validando variables requeridas en .env...${NC}"
# Como Compose maneja las IPs, solo verificamos tokens o secretos sin fallback
REQUIRED_ENV_VARS=(
  "SPLUNK_HEC_TOKEN"
)

ALL_VARS_OK=true
for var in "${REQUIRED_ENV_VARS[@]}"; do
    val="${!var:-}"
    if [ -z "$val" ]; then
        echo -e "${RED} [ERROR] Falta la variable ${var} en tu archivo .env${NC}"
        ALL_VARS_OK=false
    fi
done

if [ "$ALL_VARS_OK" = false ]; then
    echo -e "${RED} -> Abortando. Faltan secretos en el .env requeridos por el contenedor.${NC}"
    exit 1
else
    echo -e "${GREEN} -> Validación de secretos correcta.${NC}"
fi

# 4. Simular el entorno de Docker Compose y renderizar rules.nft
echo -e "\n${YELLOW}[4] Simulando renderizado local de rules.nft (Docker Compose Mock)...${NC}"

# Exportamos las variables simulando lo que hace Docker Compose antes de ejecutar envsubst
export NFTABLES_ENVOY_IP="172.20.2.7"
export NFTABLES_FW_CORPORATE_IP="172.20.10.10"
export NFTABLES_FW_VPN_IP="172.20.11.10"
export NFTABLES_FW_SATELLITE_IP="172.20.12.10"
export NFTABLES_FW_PUBLIC_IP="172.20.13.10"
# Usamos las variables del .env si existen, o los fallbacks definidos en tu Compose
export NFTABLES_CORPORATE_NET="${NETWORK_CORPORATE_SUBNET:-172.20.10.0/24}"
export NFTABLES_VPN_NET="${NETWORK_VPN_SUBNET:-172.20.11.0/24}"
export NFTABLES_SATELLITE_NET="${NETWORK_SATELLITE_SUBNET:-172.20.12.0/24}"
export NFTABLES_PUBLIC_NET="${NETWORK_PUBLIC_SUBNET:-172.20.13.0/24}"
export NFTABLES_PEP_PORT="${ENVOY_LISTENER_PORT:-8443}"

RULES_SRC="./configs/nftables/rules.nft"
RULES_RENDERED="./configs/nftables/preview_rules.nft"

if command -v envsubst >/dev/null 2>&1; then
    mkdir -p ./configs/nftables/

    # Ejecutamos la sustitución usando las variables recién exportadas
    envsubst '${NFTABLES_ENVOY_IP} ${NFTABLES_FW_CORPORATE_IP} ${NFTABLES_FW_VPN_IP} ${NFTABLES_FW_SATELLITE_IP} ${NFTABLES_FW_PUBLIC_IP} ${NFTABLES_CORPORATE_NET} ${NFTABLES_VPN_NET} ${NFTABLES_SATELLITE_NET} ${NFTABLES_PUBLIC_NET} ${NFTABLES_PEP_PORT}' \
      < "$RULES_SRC" > "$RULES_RENDERED"

    # Revisar si quedaron variables sin resolver
    if grep -q '\${' "$RULES_RENDERED"; then
        echo -e "${RED} [ERROR] Faltan variables. Quedaron referencias sin resolver en el preview:${NC}"
        grep -n '\${' "$RULES_RENDERED"
        echo -e "${RED} -> Abortando el despliegue para prevenir fallos en el contenedor.${NC}"
        exit 1
    else
        echo -e "${GREEN} -> Renderizado simulado con éxito. Archivo generado en: ./configs/nftables/preview_rules.nft${NC}"
    fi
else
    echo -e "${RED} [ADVERTENCIA] Comando 'envsubst' no encontrado localmente en tu sistema.${NC}"
    echo " Omitiendo simulación de reglas..."
fi

echo -e "\n${CYAN}=== Validación Local Completada. Iniciando Docker ===${NC}"

# 5. Ejecutar el Build
echo -e "\n${YELLOW}[5] Construyendo la imagen del Firewall (Fase 1)...${NC}"
if docker compose build firewall_perimeter; then
    echo -e "${GREEN} -> Build completado con éxito.${NC}"
else
    echo -e "${RED} [ERROR] Falló la construcción de la imagen. Revisa la sintaxis del Dockerfile.${NC}"
    exit 1
fi

# 6. Levantar el contenedor y mostrar los logs del Entrypoint
echo -e "\n${YELLOW}[6] Levantando el contenedor del Firewall (Fase 2)...${NC}"
if docker compose up -d --force-recreate firewall_perimeter; then
    echo -e "${GREEN} -> Contenedor arriba. Conectando a los logs del Entrypoint...${NC}"
    echo -e "${CYAN}--------------------------------------------------------------------------------${NC}"
    docker compose logs -f firewall_perimeter
else
    echo -e "${RED} [ERROR] Falló el despliegue del contenedor.${NC}"
    exit 1
fi
