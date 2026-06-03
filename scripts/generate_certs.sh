#!/usr/bin/env bash

# Prevent Git Bash from automatically converting Unix-like paths (e.g., '/O=...') into Windows paths.
export MSYS_NO_PATHCONV=1
export COMPOSE_CONVERT_WINDOWS_PATHS=0

echo "============================================================"
echo " Starting mTLS Certificate Generation (Maritime ZTA)"
echo "============================================================"

# Create base directories
mkdir -p certs/ca certs/server
mkdir -p certs/clients/operatore_ancona \
         certs/clients/capitano_claudia \
         certs/clients/soc_admin \
         certs/clients/intruso
mkdir -p certs/devices/D-001 \
         certs/devices/D-002 \
         certs/devices/D-SOC

# ------------------------------------------------------------
# 1. ROOT CA GENERATION
# ------------------------------------------------------------
echo "Generating Root CA..."
openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:4096 \
  -keyout certs/ca/ca.key -out certs/ca/ca.crt \
  -subj "/O=Maritime_Zero_Trust/CN=Maritime_Root_CA"

# ------------------------------------------------------------
# 2. ENVOY SERVER GENERATION (pep_gateway)
# ------------------------------------------------------------
echo "Generating Server Certificate (pep_gateway)..."
openssl req -newkey rsa:2048 -nodes \
  -keyout certs/server/server.key -out certs/server/server.csr \
  -subj "/O=Maritime_Zero_Trust/CN=pep_gateway"

cat > certs/server/server.ext << EOF
basicConstraints=CA:FALSE
subjectAltName = DNS:pep_gateway, DNS:localhost
EOF

openssl x509 -req -days 365 -sha256 -in certs/server/server.csr \
  -CA certs/ca/ca.crt -CAkey certs/ca/ca.key -CAcreateserial \
  -out certs/server/server.crt -extfile certs/server/server.ext
rm -f certs/server/server.csr certs/server/server.ext

# ------------------------------------------------------------
# 3. USER GENERATION FUNCTION (CLIENTS)
# ------------------------------------------------------------
generate_client() {
    local FOLDER=$1   # Target folder -> must match docker-compose configuration
    local CN=$2       # Common Name -> must match OPA policy identity
    local OU=$3       # Device ID mapped in the devices database

    echo "Generating Client: CN=$CN (folder: $FOLDER)..."
    openssl req -newkey rsa:2048 -nodes \
      -keyout certs/clients/$FOLDER/client.key \
      -out    certs/clients/$FOLDER/client.csr \
      -subj "/O=Maritime_Zero_Trust/OU=$OU/CN=$CN"

    openssl x509 -req -days 365 -sha256 \
      -in certs/clients/$FOLDER/client.csr \
      -CA certs/ca/ca.crt -CAkey certs/ca/ca.key -CAcreateserial \
      -out certs/clients/$FOLDER/client.crt
    rm -f certs/clients/$FOLDER/client.csr

    # Copy the CA certificate into each client folder for mTLS verification and debugging
    cp certs/ca/ca.crt certs/clients/$FOLDER/ca.crt
}

# ------------------------------------------------------------
# 4. DEVICE GENERATION FUNCTION (DEVICES)
# ------------------------------------------------------------
generate_device() {
    local FOLDER=$1
    local DEVICE_ID=$2
    local LOCATION=$3

    echo "Generating Device: ID=$DEVICE_ID (folder: $FOLDER)..."
    openssl req -newkey rsa:2048 -nodes \
      -keyout certs/devices/$FOLDER/device.key \
      -out    certs/devices/$FOLDER/device.csr \
      -subj "/O=Maritime_Zero_Trust/OU=Device/CN=$DEVICE_ID/L=$LOCATION"

    openssl x509 -req -days 365 -sha256 \
      -in certs/devices/$FOLDER/device.csr \
      -CA certs/ca/ca.crt -CAkey certs/ca/ca.key -CAcreateserial \
      -out certs/devices/$FOLDER/device.crt
    rm -f certs/devices/$FOLDER/device.csr

    # Copy the CA certificate into the device folders (required by curl during integration tests)
    cp certs/ca/ca.crt certs/devices/$FOLDER/ca.crt
}

# Execute Client generation tasks
generate_client "operatore_ancona" "Marco Rossi"    "D-001"
generate_client "capitano_claudia" "Elena Bianchi"  "D-002"
generate_client "soc_admin"        "Admin SOC"      "D-SOC"
generate_client "intruso"          "hacker_esterno" "Sconosciuto"

# Execute Device generation tasks
generate_device "D-001" "D-001" "Terminal-Ancona"
generate_device "D-002" "D-002" "Ponte-Comando"
generate_device "D-SOC" "D-SOC" "SOC-Center"

# Final cleanup of the CA serial file
rm -f certs/ca/ca.srl

echo "============================================================"
echo " Certificates successfully generated and ready for use!"
echo "============================================================"
