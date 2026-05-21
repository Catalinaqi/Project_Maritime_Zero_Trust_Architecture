#!/bin/bash
#CN=COMMON NAME
#OU=ORGANIZATIONAL UNIT
#3 profili legali e dobbiamo aggiungere almeno 1 profilo "illegale" (per testare che il firewall/OPA blocchi gli intrusi).
echo "Inizio generazione certificati mTLS allineati a MongoDB..."

mkdir -p certs/ca certs/server
mkdir -p certs/clients/banchina certs/clients/nave certs/clients/admin certs/clients/intruso

# 1. CA Root
openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:4096 \
  -keyout certs/ca/ca.key -out certs/ca/ca.crt \
  -subj "/O=Maritime_Zero_Trust/CN=Maritime_Root_CA"

# 2. Server Envoy
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

# 3. Funzione Generazione Client
generate_client() {
    local FOLDER=$1
    local UTENTE_DB=$2
    local DISPOSITIVO_DB=$3

    echo "Generazione: $UTENTE_DB su $DISPOSITIVO_DB..."
    openssl req -newkey rsa:2048 -nodes \
      -keyout certs/clients/$FOLDER/client.key \
      -out certs/clients/$FOLDER/client.csr \
      -subj "/O=Maritime_Zero_Trust/OU=$DISPOSITIVO_DB/CN=$UTENTE_DB"

    openssl x509 -req -days 365 -sha256 -in certs/clients/$FOLDER/client.csr \
      -CA certs/ca/ca.crt -CAkey certs/ca/ca.key -CAcreateserial \
      -out certs/clients/$FOLDER/client.crt
    rm certs/clients/$FOLDER/client.csr
}

# 4. Creazione delle identità esatte dal tuo MongoDB
generate_client "banchina" "operatore_ancona" "D-001"
generate_client "nave" "capitano_claudia" "D-002"
generate_client "admin" "soc_admin" "D-SOC"
generate_client "intruso" "hacker_esterno" "Sconosciuto"

rm certs/ca/ca.srl
echo "Certificati generati."
