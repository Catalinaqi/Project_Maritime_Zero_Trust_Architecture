#!/bin/bash

set -e
export MSYS_NO_PATHCONV=1

echo "Inizio generazione certificati mTLS..."

# Creo tutte le cartelle necessarie per CA, Envoy, MongoDB, client e dispositivi
mkdir -p certs/ca certs/server certs/mongodb

mkdir -p certs/clients/operatore_ancona \
         certs/clients/capitano_claudia \
         certs/clients/soc_admin \
         certs/clients/intruso

mkdir -p certs/devices/D-001 \
         certs/devices/D-002 \
         certs/devices/D-SOC


# ------------------------------------------------------------
# 1. CA ROOT
# ------------------------------------------------------------
# Genera la Certification Authority principale del progetto.
# Questa CA firmerà i certificati di Envoy, MongoDB, utenti e dispositivi.
openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:4096 \
  -keyout certs/ca/ca.key \
  -out certs/ca/ca.crt \
  -subj "/O=Maritime_Zero_Trust/CN=Maritime_Root_CA"


# ------------------------------------------------------------
# 2. CERTIFICATO SERVER ENVOY
# ------------------------------------------------------------
# Certificato usato dal PEP Envoy per esporre l'endpoint HTTPS/mTLS.
# Il CN e il SAN devono contenere pep_gateway, cioè il nome del servizio Docker.
echo "Generazione certificato server Envoy..."

openssl req -newkey rsa:2048 -nodes \
  -keyout certs/server/server.key \
  -out certs/server/server.csr \
  -subj "/O=Maritime_Zero_Trust/CN=pep_gateway"

cat > certs/server/server.ext << EOF
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:pep_gateway,DNS:localhost
EOF

openssl x509 -req -days 365 -sha256 \
  -in certs/server/server.csr \
  -CA certs/ca/ca.crt \
  -CAkey certs/ca/ca.key \
  -CAcreateserial \
  -out certs/server/server.crt \
  -extfile certs/server/server.ext

rm -f certs/server/server.csr certs/server/server.ext

# Copio la CA anche nella cartella server, utile per debug e configurazioni
cp certs/ca/ca.crt certs/server/ca.crt


# ------------------------------------------------------------
# 3. CERTIFICATO SERVER MONGODB
# ------------------------------------------------------------
# Certificato usato da MongoDB per accettare connessioni TLS.
# Deve avere nomi coerenti con quelli usati nel docker-compose:
# - db_primary: nome del container
# - mongo-primary: hostname impostato nel servizio
# - 172.20.3.5: IP statico nella backend_net
echo "Generazione certificato server MongoDB..."

openssl req -newkey rsa:2048 -nodes \
  -keyout certs/mongodb/mongodb.key \
  -out certs/mongodb/mongodb.csr \
  -subj "/O=Maritime_Zero_Trust/CN=db_primary"

cat > certs/mongodb/mongodb.ext << EOF
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:db_primary,DNS:mongo-primary,IP:172.20.3.5
EOF

openssl x509 -req -days 365 -sha256 \
  -in certs/mongodb/mongodb.csr \
  -CA certs/ca/ca.crt \
  -CAkey certs/ca/ca.key \
  -CAcreateserial \
  -out certs/mongodb/mongodb.crt \
  -extfile certs/mongodb/mongodb.ext

# MongoDB richiede un file PEM contenente certificato e chiave privata insieme.
cat certs/mongodb/mongodb.crt certs/mongodb/mongodb.key > certs/mongodb/mongodb.pem

# Copio la CA nella cartella MongoDB, così il container può usarla facilmente.
cp certs/ca/ca.crt certs/mongodb/ca.crt

rm -f certs/mongodb/mongodb.csr certs/mongodb/mongodb.ext


# ------------------------------------------------------------
# 4. FUNZIONE GENERAZIONE CERTIFICATI CLIENT UTENTE
# ------------------------------------------------------------
# Ogni certificato client rappresenta l'identità dell'utente.
# Il CN viene usato per identificare l'utente, mentre l'OU contiene il device associato.
generate_client() {
    local FOLDER=$1   # Cartella: deve combaciare con il docker-compose
    local CN=$2       # Common Name: identità utente
    local OU=$3       # Organizational Unit: device ID

    echo "Generazione certificato client: CN=$CN, OU=$OU, cartella=$FOLDER"

    openssl req -newkey rsa:2048 -nodes \
      -keyout certs/clients/$FOLDER/client.key \
      -out    certs/clients/$FOLDER/client.csr \
      -subj "/O=Maritime_Zero_Trust/OU=$OU/CN=$CN"

    openssl x509 -req -days 365 -sha256 \
      -in certs/clients/$FOLDER/client.csr \
      -CA certs/ca/ca.crt \
      -CAkey certs/ca/ca.key \
      -CAcreateserial \
      -out certs/clients/$FOLDER/client.crt

    rm -f certs/clients/$FOLDER/client.csr

    # Copia la CA in ogni cartella client, utile per curl, debug e test mTLS.
    cp certs/ca/ca.crt certs/clients/$FOLDER/ca.crt
}


# ------------------------------------------------------------
# 5. GENERAZIONE CERTIFICATI CLIENT UTENTE
# ------------------------------------------------------------
generate_client "operatore_ancona" "Marco Rossi"    "D-001"
generate_client "capitano_claudia" "Elena Bianchi"  "D-002"
generate_client "soc_admin"        "Admin SOC"      "D-SOC"
generate_client "intruso"          "hacker_esterno" "Sconosciuto"


# ------------------------------------------------------------
# 6. FUNZIONE GENERAZIONE CERTIFICATI DISPOSITIVO
# ------------------------------------------------------------
# Ogni certificato device rappresenta l'identità del dispositivo.
# Il CN contiene l'identificativo del dispositivo, per esempio D-001.
generate_device() {
    local FOLDER=$1
    local DEVICE_ID=$2
    local LOCATION=$3

    echo "Generazione certificato device: DEVICE_ID=$DEVICE_ID, cartella=$FOLDER"

    openssl req -newkey rsa:2048 -nodes \
      -keyout certs/devices/$FOLDER/device.key \
      -out    certs/devices/$FOLDER/device.csr \
      -subj "/O=Maritime_Zero_Trust/OU=Device/CN=$DEVICE_ID/L=$LOCATION"

    openssl x509 -req -days 365 -sha256 \
      -in certs/devices/$FOLDER/device.csr \
      -CA certs/ca/ca.crt \
      -CAkey certs/ca/ca.key \
      -CAcreateserial \
      -out certs/devices/$FOLDER/device.crt

    rm -f certs/devices/$FOLDER/device.csr

    # Copia la CA anche nella cartella del dispositivo.
    cp certs/ca/ca.crt certs/devices/$FOLDER/ca.crt
}


# ------------------------------------------------------------
# 7. GENERAZIONE CERTIFICATI DISPOSITIVO
# ------------------------------------------------------------
generate_device "D-001" "D-001" "Terminal-Ancona"
generate_device "D-002" "D-002" "Ponte-Comando"
generate_device "D-SOC" "D-SOC" "SOC-Center"


# ------------------------------------------------------------
# 8. PULIZIA FINALE
# ------------------------------------------------------------
rm -f certs/ca/ca.srl

echo "Certificati generati correttamente."
echo "Certificato MongoDB creato in: certs/mongodb/mongodb.pem"