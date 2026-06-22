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

# 3. Validar variables para el Renombrado Dinámico de Interfaces (Step 2.5)
echo -e "\n${YELLOW}[3] Validando variables de Interfaces e IPs (Step 2.5)...${NC}"
REQUIRED_IFACE_VARS=(
    "FW_ZT_IP"      "FW_ZT_IFACE"
    "FW_BACKEND_IP" "FW_BACKEND_IFACE"
    "FW_MONITOR_IP" "FW_MONITOR_IFACE"
    "FW_CORP_IP"    "FW_CORP_IFACE"
    "FW_VPN_IP"     "FW_VPN_IFACE"
    "FW_SAT_IP"     "FW_SAT_IFACE"
    "FW_PUBLIC_IP"  "FW_PUBLIC_IFACE"
)

ALL_VARS_OK=true
for var in "${REQUIRED_IFACE_VARS[@]}"; do
    # Usamos indirección para obtener el valor de la variable cuyo nombre está en $var
    val="${!var:-}"
    if [ -z "$val" ]; then
        echo -e "${RED} [ERROR] Falta la variable ${var} en tu archivo .env${NC}"
        ALL_VARS_OK=false
    fi
done

if [ "$ALL_VARS_OK" = false ]; then
    echo -e "${RED} -> Abortando. Faltan variables críticas para renombrar las interfaces del Firewall.${NC}"
    exit 1
else
    echo -e "${GREEN} -> Todas las IPs e Interfaces están configuradas correctamente.${NC}"
fi

# 4. Simular el envsubst (Paso 3 del entrypoint)
echo -e "\n${YELLOW}[4] Simulando renderizado de rules.nft...${NC}"
RULES_SRC="./configs/nftables/rules.nft"
RULES_RENDERED="./configs/nftables/preview_rules.nft"

if command -v envsubst >/dev/null 2>&1; then
    mkdir -p ./configs/nftables/
    envsubst < "$RULES_SRC" > "$RULES_RENDERED"

    # Revisar si quedaron variables sin resolver
    if grep -q '\${' "$RULES_RENDERED"; then
        echo -e "${RED} [ERROR] Faltan variables. Quedaron referencias sin resolver:${NC}"
        grep -n '\${' "$RULES_RENDERED"
        echo -e "${RED} -> Abortando el despliegue para prevenir fallos en el contenedor.${NC}"
        exit 1 # Detenemos el script aquí si hay errores
    else
        echo -e "${GREEN} -> Renderizado exitoso. Archivo generado en: preview_rules.nft${NC}"
    fi
else
    echo -e "${RED} [ADVERTENCIA] Comando 'envsubst' no encontrado en tu sistema.${NC}"
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
if docker compose up -d firewall_perimeter; then
    echo -e "${GREEN} -> Contenedor arriba. Conectando a los logs del Entrypoint...${NC}"
    echo -e "${CYAN}--------------------------------------------------------------------------------${NC}"
    # Mostrar los logs en vivo para ver las validaciones internas de Alpine
    docker compose logs -f firewall_perimeter
else
    echo -e "${RED} [ERROR] Falló el despliegue del contenedor.${NC}"
    exit 1
fi
