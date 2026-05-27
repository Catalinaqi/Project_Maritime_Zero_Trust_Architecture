#!/bin/bash
echo "Inizio generazione certificati mTLS..."

mkdir -p certs/ca certs/server
mkdir -p certs/clients/operatore_ancona \
         certs/clients/capitano_claudia \
         certs/clients/soc_admin \
         certs/clients/intruso

# CA Root
openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:4096 \
  -keyout certs/ca/ca.key -out certs/ca/ca.crt \
  -subj "/O=Maritime_Zero_Trust/CN=Maritime_Root_CA"

# Server Envoy
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
rm certs/server/server.csr certs/server/server.ext

# Funzione generazione client
generate_client() {
    local FOLDER=$1   # cartella → deve combaciare col docker-compose
    local CN=$2       # deve combaciare con la policy OPA
    local OU=$3       # device ID dal DB dispositivi

    echo "Generazione: CN=$CN (cartella: $FOLDER)..."
    openssl req -newkey rsa:2048 -nodes \
      -keyout certs/clients/$FOLDER/client.key \
      -out    certs/clients/$FOLDER/client.csr \
      -subj "/O=Maritime_Zero_Trust/OU=$OU/CN=$CN"

    openssl x509 -req -days 365 -sha256 \
      -in certs/clients/$FOLDER/client.csr \
      -CA certs/ca/ca.crt -CAkey certs/ca/ca.key -CAcreateserial \
      -out certs/clients/$FOLDER/client.crt
    rm certs/clients/$FOLDER/client.csr

    # Copia la CA in ogni cartella client (utile per debug)
    cp certs/ca/ca.crt certs/clients/$FOLDER/ca.crt
}

# Generazione — FOLDER=docker-compose, CN=OPA policy, OU=DB dispositivi
generate_client "operatore_ancona" "Marco Rossi"    "D-001"
generate_client "capitano_claudia" "Elena Bianchi"  "D-002"
generate_client "soc_admin"        "Admin SOC"      "D-SOC"
generate_client "intruso"          "hacker_esterno" "Sconosciuto"

rm -f certs/ca/ca.srl
echo "Certificati generati correttamente."


# Certificati dispositivi
mkdir -p certs/devices/D-001 \
         certs/devices/D-002 \
         certs/devices/D-SOC

generate_device() {
    local FOLDER=$1
    local DEVICE_ID=$2
    local LOCATION=$3

    openssl req -newkey rsa:2048 -nodes \
      -keyout certs/devices/$FOLDER/device.key \
      -out    certs/devices/$FOLDER/device.csr \
      -subj "/O=Maritime_Zero_Trust/OU=Device/CN=$DEVICE_ID/L=$LOCATION"

    openssl x509 -req -days 365 -sha256 \
      -in certs/devices/$FOLDER/device.csr \
      -CA certs/ca/ca.crt -CAkey certs/ca/ca.key -CAcreateserial \
      -out certs/devices/$FOLDER/device.crt
    rm certs/devices/$FOLDER/device.csr
}

generate_device "D-001" "D-001" "Terminal-Ancona"
generate_device "D-002" "D-002" "Ponte-Comando"
generate_device "D-SOC" "D-SOC" "SOC-Center"
