#!/bin/bash

set -e
export MSYS_NO_PATHCONV=1

echo "Inizio generazione certificati mTLS base..."

# Creo tutte le cartelle necessarie per CA, Envoy, MongoDB, client e dispositivi.
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
# Questa CA firmerà:
# - certificato server Envoy
# - certificato server MongoDB
# - certificati utente legacy
# - CSR dei dispositivi generate tramite SWTPM
#
# ATTENZIONE:
# Se rigeneri la CA, devi rigenerare anche i certificati TPM-backed
# dei dispositivi con /scripts/provision_device_tpm.sh,
# perché i vecchi device.crt sarebbero firmati dalla vecchia CA.
echo "Generazione CA root..."

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

# Copio la CA anche nella cartella server, utile per debug e configurazioni.
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
# 4. FUNZIONE GENERAZIONE CERTIFICATI CLIENT UTENTE LEGACY
# ------------------------------------------------------------
# Questi certificati rappresentano l'identità utente nella modalità legacy.
# Nel flusso attuale Zero Trust:
# - il certificato mTLS identifica il dispositivo;
# - l'utente applicativo viene passato tramite X-User-Id;
# - la chiave privata del dispositivo è custodita nel TPM/SWTPM.
#
# Manteniamo questi certificati solo per compatibilità/debug.
generate_client() {
    local FOLDER=$1
    local CN=$2
    local OU=$3

    echo "Generazione certificato client legacy: CN=$CN, OU=$OU, cartella=$FOLDER"

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

    # Copia la CA in ogni cartella client, utile per curl, debug e test.
    cp certs/ca/ca.crt certs/clients/$FOLDER/ca.crt
}


# ------------------------------------------------------------
# 5. GENERAZIONE CERTIFICATI CLIENT UTENTE LEGACY
# ------------------------------------------------------------
generate_client "operatore_ancona" "Marco Rossi"    "D-001"
generate_client "capitano_claudia" "Elena Bianchi"  "D-002"
generate_client "soc_admin"        "Admin SOC"      "D-SOC"
generate_client "intruso"          "hacker_esterno" "Sconosciuto"


# ------------------------------------------------------------
# 6. PREPARAZIONE CARTELLE DEVICE TPM-BACKED
# ------------------------------------------------------------
# Da questo punto in poi NON generiamo più device.key con OpenSSL.
# I certificati dei dispositivi vengono generati tramite SWTPM:
#
#   docker compose --profile testing run --rm client_d001_tpm  /scripts/provision_device_tpm.sh
#   docker compose --profile testing run --rm client_d002_tpm  /scripts/provision_device_tpm.sh
#   docker compose --profile testing run --rm client_dsoc_tpm  /scripts/provision_device_tpm.sh
#
# Ogni provisioning:
# - crea una chiave privata dentro il TPM emulato;
# - esporta solo la chiave pubblica;
# - genera una CSR usando l'handle TPM;
# - firma la CSR con la CA del progetto;
# - produce device.crt senza esportare device.key.
prepare_device_folder() {
    local FOLDER=$1

    echo "Preparazione cartella device TPM-backed: $FOLDER"

    mkdir -p certs/devices/$FOLDER

    # Copio la CA nella cartella del dispositivo.
    cp certs/ca/ca.crt certs/devices/$FOLDER/ca.crt

    # Rimuovo eventuali certificati/chiavi device legacy.
    # La chiave privata device.key non deve più essere usata nel flusso TPM.
    rm -f certs/devices/$FOLDER/device.key
    rm -f certs/devices/$FOLDER/device.csr
    rm -f certs/devices/$FOLDER/device_tpm_public.pem

    # Rimuovo anche il vecchio device.crt, perché dovrà essere rigenerato
    # dal provisioning TPM-backed.
    rm -f certs/devices/$FOLDER/device.crt
}


# ------------------------------------------------------------
# 7. PREPARAZIONE DEVICE
# ------------------------------------------------------------
prepare_device_folder "D-001"
prepare_device_folder "D-002"
prepare_device_folder "D-SOC"


# ------------------------------------------------------------
# 8. PULIZIA FINALE
# ------------------------------------------------------------
rm -f certs/ca/ca.srl

echo ""
echo "Certificati base generati correttamente."
echo "Certificato MongoDB creato in: certs/mongodb/mongodb.pem"
echo ""
echo "ATTENZIONE:"
echo "I certificati device non sono stati generati con OpenSSL."
echo "Ora devi generare i certificati TPM-backed con:"
echo ""
echo "  docker compose --profile testing run --rm client_d001_tpm /scripts/provision_device_tpm.sh"
echo "  docker compose --profile testing run --rm client_d002_tpm /scripts/provision_device_tpm.sh"
echo "  docker compose --profile testing run --rm client_dsoc_tpm /scripts/provision_device_tpm.sh"
echo ""
echo "Nel nuovo flusso la chiave privata del device non viene esportata come device.key,"
echo "ma resta nel TPM emulato SWTPM."