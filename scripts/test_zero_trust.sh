#!/usr/bin/env bash

# Evita conversioni automatiche dei path Linux in Git Bash.
export MSYS_NO_PATHCONV=1
export COMPOSE_CONVERT_WINDOWS_PATHS=0

# Usa sempre il docker compose di backup.
COMPOSE="docker compose -f docker-compose-backup.yml --profile testing"

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

echo "============================================================"
echo " TEST ZERO TRUST - Maritime ZTA"
echo "============================================================"
echo ""

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

  # 1. INIEZIONE DINAMICA DEL RISCHIO IN OPA (Simulazione Updater Splunk)
  if [ "$RISK_SCORE" != "-" ]; then
    # Invia il JSON direttamente al database interno di OPA tramite le sue API REST (porta 8181 di default)
    curl -s -X PUT http://localhost:8181/v1/data/risk_data/risk_scores/$USER_ID \
      -H "Content-Type: application/json" \
      -d "{\"risk_score\": $RISK_SCORE}" > /dev/null

    # Piccola pausa per dare a OPA il tempo di aggiornare la memoria
    sleep 1
  fi

  # 2. PREPARAZIONE DELLA CHIAMATA AL PROXY ENVOY
  CURL_ARGS=(
    curl -sk
    -X "$METHOD"
    --cacert /ca/ca.crt
    -H "X-User-Id: $USER_ID"
    -o /dev/null
    -w "%{http_code}"
  )

  if [ "$USE_CERT" = "yes" ]; then
    CURL_ARGS+=(--cert /certs/device/device.crt --key /certs/device/device.key)
  fi

  # RIMOSSO: Il blocco if che aggiungeva l'header X-Risk-Score è stato eliminato

  #commentato poichè proviamo ad aggiungere dinamicamente il rischio
  #if [ "$RISK_SCORE" != "-" ]; then
  #  CURL_ARGS+=(-H "X-Risk-Score: $RISK_SCORE")
  #fi

  CURL_ARGS+=("https://pep_gateway:8443$ENDPOINT")

  CODE=$($COMPOSE run --rm "$CLIENT" "${CURL_ARGS[@]}")

  echo "Ottenuto: $CODE"

  if [ "$CODE" = "000" ]; then
    echo "NOTA: 000 significa che curl non ha ricevuto risposta HTTP."
    echo "Possibili cause: errore TLS, certificato mancante, rete non raggiungibile o Envoy non disponibile."
  fi

  if [ "$CODE" = "$EXPECTED" ]; then
    echo "ESITO: TEST OK"
    PASSED_TESTS=$((PASSED_TESTS + 1))
  else
    echo "ESITO: TEST FALLITO"
    FAILED_TESTS=$((FAILED_TESTS + 1))
  fi

  echo ""
}

# 1. TEST mTLS
echo "============================================================"
echo " 1. TEST mTLS"
echo "============================================================"
echo ""
run_test "mTLS valido - Claudia usa dispositivo D-002" "client_capitano_claudia" "capitano_claudia" "GET" "/risorse" "200" "yes" "-"
run_test "mTLS assente - richiesta senza certificato dispositivo" "client_capitano_claudia" "capitano_claudia" "GET" "/risorse" "000" "no" "-"

# 2. TEST COMBINAZIONI AUTORIZZATE
echo "============================================================"
echo " 2. TEST COMBINAZIONI AUTORIZZATE"
echo "============================================================"
echo ""
run_test "ALLOW - operatore_ancona + D-001 + vpn_net su /risorse" "client_operatore_ancona" "operatore_ancona" "GET" "/risorse" "200" "yes" "-"
run_test "ALLOW - capitano_claudia + D-002 + satellite_net su /risorse" "client_capitano_claudia" "capitano_claudia" "GET" "/risorse" "200" "yes" "-"
run_test "ALLOW - soc_admin + D-SOC + corporate_net su /all" "client_soc_admin" "soc_admin" "GET" "/all" "200" "yes" "-"

# 3. TEST COMBINAZIONI NON AUTORIZZATE
echo "============================================================"
echo " 3. TEST COMBINAZIONI NON AUTORIZZATE"
echo "============================================================"
echo ""
run_test "DENY - intruso + D-001 + public_net su /risorse" "client_intruso" "intruso" "GET" "/risorse" "403" "yes" "-"
run_test "DENY - device D-002 valido ma utente intruso" "client_capitano_claudia" "intruso" "GET" "/risorse" "403" "yes" "-"
run_test "DENY - device D-001 valido ma utente intruso su vpn_net" "client_operatore_ancona" "intruso" "GET" "/risorse" "403" "yes" "-"
run_test "DENY - utente inesistente su device valido" "client_capitano_claudia" "utente_inesistente" "GET" "/risorse" "403" "yes" "-"

# 4. TEST RISORSE
echo "============================================================"
echo " 4. TEST RISORSE"
echo "============================================================"
echo ""
run_test "ALLOW - Claudia accede a /risorse" "client_capitano_claudia" "capitano_claudia" "GET" "/risorse" "200" "yes" "-"
run_test "ALLOW - Claudia accede a /dispositivi" "client_capitano_claudia" "capitano_claudia" "GET" "/dispositivi" "200" "yes" "-"
run_test "DENY - Claudia prova ad accedere a /all" "client_capitano_claudia" "capitano_claudia" "GET" "/all" "403" "yes" "-"
run_test "ALLOW - SOC admin accede a /all" "client_soc_admin" "soc_admin" "GET" "/all" "200" "yes" "-"
run_test "DENY - operatore_ancona prova ad accedere a /all" "client_operatore_ancona" "operatore_ancona" "GET" "/all" "403" "yes" "-"
run_test "DENY - intruso prova ad accedere a /all" "client_intruso" "intruso" "GET" "/all" "403" "yes" "-"

# 5. TEST METODI HTTP / COMANDI LOGICI
echo "============================================================"
echo " 5. TEST METODI HTTP / COMANDI LOGICI"
echo "============================================================"
echo ""
run_test "ALLOW - operatore_ancona GET /risorse = find" "client_operatore_ancona" "operatore_ancona" "GET" "/risorse" "200" "yes" "-"
run_test "DENY - operatore_ancona POST /risorse = insert non consentito" "client_operatore_ancona" "operatore_ancona" "POST" "/risorse" "403" "yes" "-"
run_test "DENY - operatore_ancona PUT /risorse = update non consentito" "client_operatore_ancona" "operatore_ancona" "PUT" "/risorse" "403" "yes" "-"
run_test "DENY - operatore_ancona DELETE /risorse = delete non consentito" "client_operatore_ancona" "operatore_ancona" "DELETE" "/risorse" "403" "yes" "-"
run_test "ALLOW OPA - capitano_claudia GET /risorse = find" "client_capitano_claudia" "capitano_claudia" "GET" "/risorse" "200" "yes" "-"
run_test "ALLOW OPA - capitano_claudia POST /risorse = insert, backend non implementa la rotta" "client_capitano_claudia" "capitano_claudia" "POST" "/risorse" "404" "yes" "-"
run_test "ALLOW OPA - capitano_claudia PUT /risorse = update, backend non implementa la rotta" "client_capitano_claudia" "capitano_claudia" "PUT" "/risorse" "404" "yes" "-"
run_test "DENY - capitano_claudia DELETE /risorse = delete non consentito" "client_capitano_claudia" "capitano_claudia" "DELETE" "/risorse" "403" "yes" "-"
run_test "ALLOW - soc_admin GET /all" "client_soc_admin" "soc_admin" "GET" "/all" "200" "yes" "-"
run_test "ALLOW OPA - soc_admin POST /all, backend non implementa la rotta" "client_soc_admin" "soc_admin" "POST" "/all" "404" "yes" "-"
run_test "ALLOW OPA - soc_admin PUT /all, backend non implementa la rotta" "client_soc_admin" "soc_admin" "PUT" "/all" "404" "yes" "-"
run_test "ALLOW OPA - soc_admin DELETE /all, backend non implementa la rotta" "client_soc_admin" "soc_admin" "DELETE" "/all" "404" "yes" "-"

# 6. TEST RISK SCORE DINAMICO
echo "============================================================"
echo " 6. TEST RISK SCORE DINAMICO"
echo "============================================================"
echo ""
run_test "ALLOW - Claudia con risk score basso 30 <= max 70" "client_capitano_claudia" "capitano_claudia" "GET" "/risorse" "200" "yes" "30"
run_test "DENY - Claudia con risk score alto 90 > max 70" "client_capitano_claudia" "capitano_claudia" "GET" "/risorse" "403" "yes" "90"
run_test "ALLOW - operatore_ancona con risk score basso 30 <= max 50" "client_operatore_ancona" "operatore_ancona" "GET" "/risorse" "200" "yes" "30"
run_test "DENY - operatore_ancona con risk score alto 80 > max 50" "client_operatore_ancona" "operatore_ancona" "GET" "/risorse" "403" "yes" "80"
run_test "ALLOW - soc_admin con risk score 90 <= max 100" "client_soc_admin" "soc_admin" "GET" "/all" "200" "yes" "90"

# 7. TEST UTENTI SU DEVICE/RETI DISPONIBILI
echo "============================================================"
echo " 7. TEST UTENTI SU DEVICE/RETI DISPONIBILI"
echo "============================================================"
echo ""
run_test "D-002 + satellite_net usato da capitano_claudia" "client_capitano_claudia" "capitano_claudia" "GET" "/risorse" "200" "yes" "-"
run_test "D-002 + satellite_net usato da operatore_ancona" "client_capitano_claudia" "operatore_ancona" "GET" "/risorse" "200" "yes" "-"
run_test "D-002 + satellite_net usato da soc_admin" "client_capitano_claudia" "soc_admin" "GET" "/risorse" "200" "yes" "-"
run_test "D-002 + satellite_net usato da intruso" "client_capitano_claudia" "intruso" "GET" "/risorse" "403" "yes" "-"
run_test "D-001 + vpn_net usato da operatore_ancona" "client_operatore_ancona" "operatore_ancona" "GET" "/risorse" "200" "yes" "-"
run_test "D-001 + vpn_net usato da capitano_claudia" "client_operatore_ancona" "capitano_claudia" "GET" "/risorse" "200" "yes" "-"
run_test "D-001 + vpn_net usato da soc_admin" "client_operatore_ancona" "soc_admin" "GET" "/risorse" "200" "yes" "-"
run_test "D-001 + vpn_net usato da intruso" "client_operatore_ancona" "intruso" "GET" "/risorse" "403" "yes" "-"
run_test "D-SOC + corporate_net usato da soc_admin" "client_soc_admin" "soc_admin" "GET" "/all" "200" "yes" "-"
run_test "D-SOC + corporate_net usato da capitano_claudia" "client_soc_admin" "capitano_claudia" "GET" "/risorse" "403" "yes" "-"
run_test "D-SOC + corporate_net usato da operatore_ancona" "client_soc_admin" "operatore_ancona" "GET" "/risorse" "403" "yes" "-"
run_test "D-SOC + corporate_net usato da intruso" "client_soc_admin" "intruso" "GET" "/risorse" "403" "yes" "-"
run_test "D-001 + public_net usato da intruso" "client_intruso" "intruso" "GET" "/risorse" "403" "yes" "-"
run_test "D-001 + public_net usato da operatore_ancona" "client_intruso" "operatore_ancona" "GET" "/risorse" "403" "yes" "-"
run_test "D-001 + public_net usato da capitano_claudia" "client_intruso" "capitano_claudia" "GET" "/risorse" "403" "yes" "-"
run_test "D-001 + public_net usato da soc_admin" "client_intruso" "soc_admin" "GET" "/risorse" "403" "yes" "-"

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
