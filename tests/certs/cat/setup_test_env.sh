#!/bin/bash

# Salir inmediatamente si algún comando falla
set -e

# Definición de colores para los mensajes en la terminal
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # Sin color

echo -e "${YELLOW}======================================================${NC}"
echo -e "${YELLOW}   Iniciando aprovisionamiento y despliegue ZTA       ${NC}"
echo -e "${YELLOW}======================================================${NC}\n"

# 1. Limpiar certificados antiguos
echo -e "${GREEN}[1/6] Eliminando directorio 'certs' antiguo...${NC}"
rm -rf certs
echo "Directorio limpio."

# 2. Generar nuevos certificados base
echo -e "\n${GREEN}[2/6] Ejecutando script de generación de certificados...${NC}"
if [ -f "scripts/generate_certs.sh" ]; then
    bash scripts/generate_certs.sh
else
    echo -e "${RED}Error: No se encuentra 'scripts/generate_certs.sh'. Revisa tu ruta.${NC}"
    exit 1
fi

# 3. Avviare gli emulatori TPM
echo -e "\n${GREEN}[3/6] Levantando servicios TPM (swtpm)...${NC}"
docker compose --profile testing up -d --build swtpm_d001 swtpm_d002 swtpm_dsoc

# Pequeña pausa para asegurar que los contenedores TPM estén listos para recibir conexiones
echo "Esperando 3 segundos a que los emuladores TPM se inicialicen..."
sleep 3

# 4. Provisionar los dispositivos TPM
echo -e "\n${GREEN}[4/6] Provisionando dispositivos TPM...${NC}"
docker compose --profile testing run --rm --no-deps client_d001_tpm /scripts/provision_device_tpm.sh
docker compose --profile testing run --rm --no-deps client_d002_tpm /scripts/provision_device_tpm.sh
docker compose --profile testing run --rm --no-deps client_dsoc_tpm /scripts/provision_device_tpm.sh

# 5. Verificaciones
echo -e "\n${GREEN}[5/6] Verificando los certificados de los dispositivos...${NC}"
for device in "D-001" "D-002" "D-SOC"; do
    echo -e "\n${YELLOW}--- Verificando certs/devices/$device ---${NC}"
    if [ -d "certs/devices/$device" ]; then
        ls -la "certs/devices/$device"
    else
        echo -e "${RED}Error: El directorio certs/devices/$device NO existe. La provisión falló.${NC}"
        exit 1
    fi
done

# 6. Levantar todo el entorno
echo -e "\n${GREEN}[6/6] Levantando todo el entorno de pruebas...${NC}"
docker compose --profile testing up -d --build

echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}  ¡Proceso completado con éxito! Entorno levantado.   ${NC}"
echo -e "${GREEN}======================================================${NC}"
