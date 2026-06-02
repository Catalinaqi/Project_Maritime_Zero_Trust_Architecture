#!/usr/bin/env bash

# Evita che Git Bash converta automaticamente path Linux come /certs/... in path Windows.
export MSYS_NO_PATHCONV=1
export COMPOSE_CONVERT_WINDOWS_PATHS=0

# ============================================================
# TEST ZERO TRUST - Maritime ZTA
# ============================================================
# Questo script valida i principali controlli della Zero Trust Architecture:
# - certificato mTLS del dispositivo;
# - identità applicativa utente tramite X-User-Id;
# - combinazione utente + dispositivo + rete;
# - risorsa richiesta;
# - metodo HTTP / comando logico;
# - risk score dinamico, se implementato nel filtro Lua;
# - generazione di eventi per Splunk.
# ============================================================

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

echo "============================================================"
echo " TEST ZERO TRUST - Maritime ZTA"
echo "============================================================"
echo ""

# ------------------------------------------------------------
# Funzione generica di test.
#
# Parametri:
# $1 = nome test
# $2 = client Docker Compose
# $3 = utente applicativo X-User-Id
# $4 = metodo HTTP
# $5 = endpoint
# $6 = codice HTTP atteso
# $7 = usa certificato device: yes/no
# $8 = risk score, oppure "-" se non usato
# ------------------------------------------------------------
run_test() {
  TEST_NAME="$1"
  CLIENT="$2"
  USER_ID="$3"
  METHOD="$4"
  ENDPOINT="$5"
  EXPECTED="$6"
  USE_CERT="$7"
  RISK_SCORE="$8"

  TOTAL_TESTS=$((TOTAL_TESTS + 1))

  echo "------------------------------------------------------------"
  echo "Test #$TOTAL_TESTS: $TEST_NAME"
  echo "Client:   $CLIENT"
  echo "User:     $USER_ID"
  echo "Metodo:   $METHOD"
  echo "Endpoint: $ENDPOINT"
  echo "Cert:     $USE_CERT"
  echo "Risk:     $RISK_SCORE"
  echo "Atteso:   $EXPECTED"
  echo ""

  if [ "$USE_CERT" = "yes" ]; then
    if [ "$RISK_SCORE" = "-" ]; then
      CODE=$(docker compose --profile testing run --rm "$CLIENT" \
        curl -sk \
        -X "$METHOD" \
        --cert /certs/device/device.crt \
        --key /certs/device/device.key \
        --cacert /ca/ca.crt \
        -H "X-User-Id: $USER_ID" \
        -o /dev/null \
        -w "%{http_code}" \
        "https://pep_gateway:8443$ENDPOINT")
    else
      CODE=$(docker compose --profile testing run --rm "$CLIENT" \
        curl -sk \
        -X "$METHOD" \
        --cert /certs/device/device.crt \
        --key /certs/device/device.key \
        --cacert /ca/ca.crt \
        -H "X-User-Id: $USER_ID" \
        -H "X-Risk-Score: $RISK_SCORE" \
        -o /dev/null \
        -w "%{http_code}" \
        "https://pep_gateway:8443$ENDPOINT")
    fi
  else
    if [ "$RISK_SCORE" = "-" ]; then
      CODE=$(docker compose --profile testing run --rm "$CLIENT" \
        curl -sk \
        -X "$METHOD" \
        --cacert /ca/ca.crt \
        -H "X-User-Id: $USER_ID" \
        -o /dev/null \
        -w "%{http_code}" \
        "https://pep_gateway:8443$ENDPOINT")
    else
      CODE=$(docker compose --profile testing run --rm "$CLIENT" \
        curl -sk \
        -X "$METHOD" \
        --cacert /ca/ca.crt \
        -H "X-User-Id: $USER_ID" \
        -H "X-Risk-Score: $RISK_SCORE" \
        -o /dev/null \
        -w "%{http_code}" \
        "https://pep_gateway:8443$ENDPOINT")
    fi
  fi

  echo "Ottenuto: $CODE"

  if [ "$CODE" = "$EXPECTED" ]; then
    echo "ESITO: TEST OK"
    PASSED_TESTS=$((PASSED_TESTS + 1))
  else
    echo "ESITO: TEST FALLITO"
    FAILED_TESTS=$((FAILED_TESTS + 1))
  fi

  echo ""
}

# ============================================================
# 1. TEST mTLS
# ============================================================

echo "============================================================"
echo " 1. TEST mTLS"
echo "============================================================"
echo ""

run_test \
  "mTLS valido - Claudia usa dispositivo D-002" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test \
  "mTLS assente - richiesta senza certificato dispositivo" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "000" \
  "no" \
  "-"

# ============================================================
# 2. TEST COMBINAZIONI AUTORIZZATE UTENTE + DEVICE + RETE
# ============================================================

echo "============================================================"
echo " 2. TEST COMBINAZIONI AUTORIZZATE"
echo "============================================================"
echo ""

run_test \
  "ALLOW - operatore_ancona + D-001 + vpn_net su /risorse" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test \
  "ALLOW - capitano_claudia + D-002 + satellite_net su /risorse" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test \
  "ALLOW - soc_admin + D-SOC + corporate_net su /all" \
  "client_soc_admin" \
  "soc_admin" \
  "GET" \
  "/all" \
  "200" \
  "yes" \
  "-"

# ============================================================
# 3. TEST COMBINAZIONI NON AUTORIZZATE
# ============================================================

echo "============================================================"
echo " 3. TEST COMBINAZIONI NON AUTORIZZATE"
echo "============================================================"
echo ""

run_test \
  "DENY - intruso + D-001 + public_net su /risorse" \
  "client_intruso" \
  "intruso" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test \
  "DENY - device D-002 valido ma utente intruso" \
  "client_capitano_claudia" \
  "intruso" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test \
  "DENY - device D-001 valido ma utente intruso su vpn_net" \
  "client_operatore_ancona" \
  "intruso" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test \
  "DENY - utente inesistente su device valido" \
  "client_capitano_claudia" \
  "utente_inesistente" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

# ============================================================
# 4. TEST RISORSE
# ============================================================

echo "============================================================"
echo " 4. TEST RISORSE"
echo "============================================================"
echo ""

run_test \
  "ALLOW - Claudia accede a /risorse" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test \
  "ALLOW - Claudia accede a /dispositivi" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/dispositivi" \
  "200" \
  "yes" \
  "-"

run_test \
  "DENY - Claudia prova ad accedere a /all" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/all" \
  "403" \
  "yes" \
  "-"

run_test \
  "ALLOW - SOC admin accede a /all" \
  "client_soc_admin" \
  "soc_admin" \
  "GET" \
  "/all" \
  "200" \
  "yes" \
  "-"

run_test \
  "DENY - operatore_ancona prova ad accedere a /all" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "GET" \
  "/all" \
  "403" \
  "yes" \
  "-"

run_test \
  "DENY - intruso prova ad accedere a /all" \
  "client_intruso" \
  "intruso" \
  "GET" \
  "/all" \
  "403" \
  "yes" \
  "-"

# ============================================================
# 5. TEST METODI HTTP / COMANDI LOGICI
# GET    -> find
# POST   -> insert
# PUT    -> update
# DELETE -> delete
# ============================================================

echo "============================================================"
echo " 5. TEST METODI HTTP / COMANDI LOGICI"
echo "============================================================"
echo ""

# operatore_ancona ha solo find, quindi GET passa, gli altri devono essere negati.
run_test \
  "ALLOW - operatore_ancona GET /risorse = find" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test \
  "DENY - operatore_ancona POST /risorse = insert non consentito" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "POST" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test \
  "DENY - operatore_ancona PUT /risorse = update non consentito" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "PUT" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test \
  "DENY - operatore_ancona DELETE /risorse = delete non consentito" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "DELETE" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

# capitano_claudia ha find, insert, update, ma non delete.
run_test \
  "ALLOW - capitano_claudia GET /risorse = find" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test \
  "ALLOW - capitano_claudia POST /risorse = insert" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "POST" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test \
  "ALLOW - capitano_claudia PUT /risorse = update" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "PUT" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test \
  "DENY - capitano_claudia DELETE /risorse = delete non consentito" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "DELETE" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

# soc_admin ha tutti i comandi e tutte le risorse.
run_test \
  "ALLOW - soc_admin GET /all" \
  "client_soc_admin" \
  "soc_admin" \
  "GET" \
  "/all" \
  "200" \
  "yes" \
  "-"

run_test \
  "ALLOW - soc_admin POST /all" \
  "client_soc_admin" \
  "soc_admin" \
  "POST" \
  "/all" \
  "200" \
  "yes" \
  "-"

run_test \
  "ALLOW - soc_admin PUT /all" \
  "client_soc_admin" \
  "soc_admin" \
  "PUT" \
  "/all" \
  "200" \
  "yes" \
  "-"

run_test \
  "ALLOW - soc_admin DELETE /all" \
  "client_soc_admin" \
  "soc_admin" \
  "DELETE" \
  "/all" \
  "200" \
  "yes" \
  "-"

# ============================================================
# 6. TEST RISK SCORE DINAMICO
# Funziona solo se il filtro Lua legge X-Risk-Score
# e lo inserisce nei metadata come risk_score.
# Se non è implementato, i test potrebbero fallire.
# ============================================================

echo "============================================================"
echo " 6. TEST RISK SCORE DINAMICO"
echo "============================================================"
echo ""

run_test \
  "ALLOW - Claudia con risk score basso 30 <= max 70" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "30"

run_test \
  "DENY - Claudia con risk score alto 90 > max 70" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "90"

run_test \
  "ALLOW - operatore_ancona con risk score basso 30 <= max 50" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "30"

run_test \
  "DENY - operatore_ancona con risk score alto 80 > max 50" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "80"

run_test \
  "ALLOW - soc_admin con risk score 90 <= max 100" \
  "client_soc_admin" \
  "soc_admin" \
  "GET" \
  "/all" \
  "200" \
  "yes" \
  "90"

# ============================================================
# 7. TEST COPERTURA UTENTE SU DEVICE/RETE DISPONIBILI
# Questi test cambiano solo l'header X-User-Id.
# Il dispositivo e la rete sono determinati dal container.
# ============================================================

echo "============================================================"
echo " 7. TEST UTENTI SU DEVICE/RETI DISPONIBILI"
echo "============================================================"
echo ""

# Container Claudia: D-002 + satellite_net
run_test \
  "D-002 + satellite_net usato da capitano_claudia" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test \
  "D-002 + satellite_net usato da operatore_ancona" \
  "client_capitano_claudia" \
  "operatore_ancona" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test \
  "D-002 + satellite_net usato da soc_admin" \
  "client_capitano_claudia" \
  "soc_admin" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test \
  "D-002 + satellite_net usato da intruso" \
  "client_capitano_claudia" \
  "intruso" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

# Container operatore: D-001 + vpn_net
run_test \
  "D-001 + vpn_net usato da operatore_ancona" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test \
  "D-001 + vpn_net usato da capitano_claudia" \
  "client_operatore_ancona" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test \
  "D-001 + vpn_net usato da soc_admin" \
  "client_operatore_ancona" \
  "soc_admin" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test \
  "D-001 + vpn_net usato da intruso" \
  "client_operatore_ancona" \
  "intruso" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

# Container SOC: D-SOC + corporate_net
run_test \
  "D-SOC + corporate_net usato da soc_admin" \
  "client_soc_admin" \
  "soc_admin" \
  "GET" \
  "/all" \
  "200" \
  "yes" \
  "-"

run_test \
  "D-SOC + corporate_net usato da capitano_claudia" \
  "client_soc_admin" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test \
  "D-SOC + corporate_net usato da operatore_ancona" \
  "client_soc_admin" \
  "operatore_ancona" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test \
  "D-SOC + corporate_net usato da intruso" \
  "client_soc_admin" \
  "intruso" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

# Container intruso: D-001 + public_net
run_test \
  "D-001 + public_net usato da intruso" \
  "client_intruso" \
  "intruso" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test \
  "D-001 + public_net usato da operatore_ancona" \
  "client_intruso" \
  "operatore_ancona" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test \
  "D-001 + public_net usato da capitano_claudia" \
  "client_intruso" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test \
  "D-001 + public_net usato da soc_admin" \
  "client_intruso" \
  "soc_admin" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

# ============================================================
# 8. RIEPILOGO
# ============================================================

echo "============================================================"
echo " RIEPILOGO TEST ZERO TRUST"
echo "============================================================"
echo "Totale test: $TOTAL_TESTS"
echo "Test OK:     $PASSED_TESTS"
echo "Test falliti:$FAILED_TESTS"
echo "============================================================"

if [ "$FAILED_TESTS" -eq 0 ]; then
  echo "ESITO FINALE: TUTTI I TEST SONO STATI SUPERATI"
  exit 0
else
  echo "ESITO FINALE: ALCUNI TEST SONO FALLITI"
  exit 1
fi