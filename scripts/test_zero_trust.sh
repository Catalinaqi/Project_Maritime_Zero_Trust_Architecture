#!/usr/bin/env bash

set -e

# Evita conversioni automatiche dei path Linux in Git Bash.
export MSYS_NO_PATHCONV=1
export COMPOSE_CONVERT_WINDOWS_PATHS=0

# Usa il docker-compose principale con profilo testing.
COMPOSE="docker compose -f docker-compose.yml --profile testing"

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

echo "============================================================"
echo " TEST ZERO TRUST - Maritime ZTA"
echo "============================================================"
echo ""

# ============================================================================
# RISK SCORE DEFAULT
# ============================================================================

default_risk_score() {
  local USER_ID="$1"

  case "$USER_ID" in
    operatore_ancona)
      echo 10
      ;;
    capitano_claudia)
      echo 10
      ;;
    soc_admin)
      echo 10
      ;;
    intruso)
      echo 99
      ;;
    *)
      echo 99
      ;;
  esac
}

is_known_user() {
  local USER_ID="$1"

  case "$USER_ID" in
    operatore_ancona|capitano_claudia|soc_admin|intruso)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

# ============================================================================
# OPA / SPLUNK RISK HELPERS
# ============================================================================

wait_for_opa_health() {
  local MAX_ATTEMPTS=30
  local ATTEMPT=1

  echo "Attendo OPA..."

  while [ "$ATTEMPT" -le "$MAX_ATTEMPTS" ]; do
    if curl -s http://localhost:8181/health > /dev/null 2>&1; then
      echo "OPA raggiungibile."
      return 0
    fi

    sleep 1
    ATTEMPT=$((ATTEMPT + 1))
  done

  echo "ERRORE: OPA non è raggiungibile."
  return 1
}

get_opa_risk_score() {
  local USER_ID="$1"

  curl -s "http://localhost:8181/v1/data/risk_data/risk_scores/$USER_ID/risk_score" \
    | sed -n 's/.*"result":[ ]*\([0-9][0-9]*\).*/\1/p'
}

wait_for_opa_risk_score() {
  local USER_ID="$1"
  local EXPECTED_RISK="$2"
  local MAX_ATTEMPTS=20
  local ATTEMPT=1

  echo "Attendo rischio OPA: $USER_ID = $EXPECTED_RISK"

  while [ "$ATTEMPT" -le "$MAX_ATTEMPTS" ]; do
    CURRENT_RISK=$(get_opa_risk_score "$USER_ID")

    if [ "$CURRENT_RISK" = "$EXPECTED_RISK" ]; then
      echo "Rischio OPA aggiornato: $USER_ID = $CURRENT_RISK"
      return 0
    fi

    echo "Tentativo $ATTEMPT/$MAX_ATTEMPTS: rischio attuale='$CURRENT_RISK', atteso='$EXPECTED_RISK'"
    sleep 1
    ATTEMPT=$((ATTEMPT + 1))
  done

  echo "ERRORE: OPA non ha ricevuto il rischio atteso per $USER_ID."
  return 1
}

set_splunk_risk_score() {
  local USER_ID="$1"
  local RISK_SCORE="$2"
  local IS_ANOMALY="0"
  local DENIED_COUNT="0"

  if [ "$RISK_SCORE" -ge 80 ]; then
    IS_ANOMALY="1"
    DENIED_COUNT="5"
  fi

  echo "Aggiorno rischio tramite Splunk updater: $USER_ID -> $RISK_SCORE"

  # Scrive il lookup CSV usato dall'app Splunk opa_risk_updater
  # e poi esegue lo script updater dentro il container Splunk.
  $COMPOSE exec -T --user root \
    -e TEST_USER_ID="$USER_ID" \
    -e TEST_RISK_SCORE="$RISK_SCORE" \
    -e TEST_IS_ANOMALY="$IS_ANOMALY" \
    -e TEST_DENIED_COUNT="$DENIED_COUNT" \
    siem_central bash -lc '
      set -e

      SPLUNK_CSV="/opt/splunk/etc/apps/search/lookups/historical_risk_scores.csv"
      mkdir -p /opt/splunk/etc/apps/search/lookups

      cat > "$SPLUNK_CSV" <<CSV
user_id,risk_score,isAnomaly,denied_count
${TEST_USER_ID},${TEST_RISK_SCORE},${TEST_IS_ANOMALY},${TEST_DENIED_COUNT}
CSV

      SPLUNK_PYTHON="/opt/splunk/bin/python3"
      if [ ! -x "$SPLUNK_PYTHON" ]; then
        SPLUNK_PYTHON="python3"
      fi

      printf '\''{"configuration":{"param.opa_json_path":"/opa_data/risk_data/risk_scores.json"}}'\'' \
        | "$SPLUNK_PYTHON" /opt/splunk/etc/apps/opa_risk_updater/bin/opa_risk_updater.py
    '

  # OPA legge il file JSON dal volume condiviso.
  # Per rendere il test riproducibile, ricarichiamo OPA dopo l'aggiornamento del file.
  $COMPOSE restart pdp_engine > /dev/null

  wait_for_opa_health
  wait_for_opa_risk_score "$USER_ID" "$RISK_SCORE"
}

ensure_splunk_risk_score() {
  local USER_ID="$1"
  local DESIRED_RISK="$2"
  local CURRENT_RISK

  CURRENT_RISK=$(get_opa_risk_score "$USER_ID")

  if [ "$CURRENT_RISK" = "$DESIRED_RISK" ]; then
    echo "Risk già corretto in OPA: $USER_ID = $CURRENT_RISK"
  else
    set_splunk_risk_score "$USER_ID" "$DESIRED_RISK"
  fi
}

# ============================================================================
# FUNZIONE GENERICA DI TEST
# ============================================================================

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

  if [ "$RISK_SCORE" = "-" ]; then
    EFFECTIVE_RISK_SCORE=$(default_risk_score "$USER_ID")
  else
    EFFECTIVE_RISK_SCORE="$RISK_SCORE"
  fi

  echo "Risk effettivo richiesto a Splunk/OPA: $EFFECTIVE_RISK_SCORE"

if is_known_user "$USER_ID"; then
  ensure_splunk_risk_score "$USER_ID" "$EFFECTIVE_RISK_SCORE"
else
  echo "Utente non presente nelle policy: salto aggiornamento risk score."
fi

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

  CURL_ARGS+=("https://pep_gateway:8443$ENDPOINT")

  CODE=$($COMPOSE run --rm "$CLIENT" "${CURL_ARGS[@]}" 2>/dev/null || echo "000")
  CODE=$(echo "$CODE" | tail -c 4 | tr -d '\n\r ')

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

# ============================================================================
# AVVIO SERVIZI
# ============================================================================

echo "Avvio servizi Docker con profilo testing..."
$COMPOSE up -d

echo ""
echo "Attesa inizializzazione servizi..."
sleep 8

echo ""
echo "Stato container:"
$COMPOSE ps

echo ""
wait_for_opa_health

# ============================================================================
# 1. TEST mTLS
# ============================================================================

echo "============================================================"
echo " 1. TEST mTLS"
echo "============================================================"
echo ""

run_test "mTLS valido - Claudia usa dispositivo D-002" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test "mTLS assente - richiesta senza certificato dispositivo" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "000" \
  "no" \
  "-"

# ============================================================================
# 2. TEST COMBINAZIONI AUTORIZZATE
# ============================================================================

echo "============================================================"
echo " 2. TEST COMBINAZIONI AUTORIZZATE"
echo "============================================================"
echo ""

run_test "ALLOW - operatore_ancona + D-001 + vpn_net su /risorse" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test "ALLOW - capitano_claudia + D-002 + satellite_net su /risorse" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test "ALLOW - soc_admin + D-SOC + corporate_net su /all" \
  "client_soc_admin" \
  "soc_admin" \
  "GET" \
  "/all" \
  "200" \
  "yes" \
  "-"

# ============================================================================
# 3. TEST COMBINAZIONI NON AUTORIZZATE
# ============================================================================

echo "============================================================"
echo " 3. TEST COMBINAZIONI NON AUTORIZZATE"
echo "============================================================"
echo ""

run_test "DENY - intruso + D-001 + public_net su /risorse" \
  "client_intruso" \
  "intruso" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test "DENY - device D-002 valido ma utente intruso" \
  "client_capitano_claudia" \
  "intruso" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test "DENY - device D-001 valido ma utente intruso su vpn_net" \
  "client_operatore_ancona" \
  "intruso" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test "DENY - utente inesistente su device valido" \
  "client_capitano_claudia" \
  "utente_inesistente" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

# ============================================================================
# 4. TEST RISORSE
# ============================================================================

echo "============================================================"
echo " 4. TEST RISORSE"
echo "============================================================"
echo ""

run_test "ALLOW - Claudia accede a /risorse" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test "ALLOW - Claudia accede a /dispositivi" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/dispositivi" \
  "200" \
  "yes" \
  "-"

run_test "DENY - Claudia prova ad accedere a /all" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/all" \
  "403" \
  "yes" \
  "-"

run_test "ALLOW - SOC admin accede a /all" \
  "client_soc_admin" \
  "soc_admin" \
  "GET" \
  "/all" \
  "200" \
  "yes" \
  "-"

run_test "DENY - operatore_ancona prova ad accedere a /all" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "GET" \
  "/all" \
  "403" \
  "yes" \
  "-"

run_test "DENY - intruso prova ad accedere a /all" \
  "client_intruso" \
  "intruso" \
  "GET" \
  "/all" \
  "403" \
  "yes" \
  "-"

# ============================================================================
# 5. TEST METODI HTTP / COMANDI LOGICI
# ============================================================================

echo "============================================================"
echo " 5. TEST METODI HTTP / COMANDI LOGICI"
echo "============================================================"
echo ""

run_test "ALLOW - operatore_ancona GET /risorse = find" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test "DENY - operatore_ancona POST /risorse = insert non consentito" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "POST" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test "DENY - operatore_ancona PUT /risorse = update non consentito" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "PUT" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test "DENY - operatore_ancona DELETE /risorse = delete non consentito" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "DELETE" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test "ALLOW OPA - capitano_claudia GET /risorse = find" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test "ALLOW OPA - capitano_claudia POST /risorse = insert, backend non implementa la rotta" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "POST" \
  "/risorse" \
  "404" \
  "yes" \
  "-"

run_test "ALLOW OPA - capitano_claudia PUT /risorse = update, backend non implementa la rotta" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "PUT" \
  "/risorse" \
  "404" \
  "yes" \
  "-"

run_test "DENY - capitano_claudia DELETE /risorse = delete non consentito" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "DELETE" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test "ALLOW - soc_admin GET /all" \
  "client_soc_admin" \
  "soc_admin" \
  "GET" \
  "/all" \
  "200" \
  "yes" \
  "-"

run_test "ALLOW OPA - soc_admin POST /all, backend non implementa la rotta" \
  "client_soc_admin" \
  "soc_admin" \
  "POST" \
  "/all" \
  "404" \
  "yes" \
  "-"

run_test "ALLOW OPA - soc_admin PUT /all, backend non implementa la rotta" \
  "client_soc_admin" \
  "soc_admin" \
  "PUT" \
  "/all" \
  "404" \
  "yes" \
  "-"

run_test "ALLOW OPA - soc_admin DELETE /all, backend non implementa la rotta" \
  "client_soc_admin" \
  "soc_admin" \
  "DELETE" \
  "/all" \
  "404" \
  "yes" \
  "-"

# ============================================================================
# 6. TEST RISK SCORE DINAMICO DA SPLUNK
# ============================================================================

echo "============================================================"
echo " 6. TEST RISK SCORE DINAMICO DA SPLUNK"
echo "============================================================"
echo ""

run_test "ALLOW - Claudia con risk score basso 30 <= max 70 da Splunk" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "30"

run_test "DENY - Claudia con risk score alto 90 > max 70 da Splunk" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "90"

run_test "ALLOW - operatore_ancona con risk score basso 30 <= max 50 da Splunk" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "30"

run_test "DENY - operatore_ancona con risk score alto 80 > max 50 da Splunk" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "80"

run_test "ALLOW - soc_admin con risk score 90 <= max 100 da Splunk" \
  "client_soc_admin" \
  "soc_admin" \
  "GET" \
  "/all" \
  "200" \
  "yes" \
  "90"

run_test "DENY - soc_admin con risk score 120 > max 100 da Splunk" \
  "client_soc_admin" \
  "soc_admin" \
  "GET" \
  "/all" \
  "403" \
  "yes" \
  "120"

# ============================================================================
# 7. TEST UTENTI SU DEVICE/RETI DISPONIBILI
# ============================================================================

echo "============================================================"
echo " 7. TEST UTENTI SU DEVICE/RETI DISPONIBILI"
echo "============================================================"
echo ""

run_test "D-002 + satellite_net usato da capitano_claudia" \
  "client_capitano_claudia" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test "D-002 + satellite_net usato da operatore_ancona" \
  "client_capitano_claudia" \
  "operatore_ancona" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test "D-002 + satellite_net usato da soc_admin" \
  "client_capitano_claudia" \
  "soc_admin" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test "D-002 + satellite_net usato da intruso" \
  "client_capitano_claudia" \
  "intruso" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test "D-001 + vpn_net usato da operatore_ancona" \
  "client_operatore_ancona" \
  "operatore_ancona" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test "D-001 + vpn_net usato da capitano_claudia" \
  "client_operatore_ancona" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test "D-001 + vpn_net usato da soc_admin" \
  "client_operatore_ancona" \
  "soc_admin" \
  "GET" \
  "/risorse" \
  "200" \
  "yes" \
  "-"

run_test "D-001 + vpn_net usato da intruso" \
  "client_operatore_ancona" \
  "intruso" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test "D-SOC + corporate_net usato da soc_admin" \
  "client_soc_admin" \
  "soc_admin" \
  "GET" \
  "/all" \
  "200" \
  "yes" \
  "-"

run_test "D-SOC + corporate_net usato da capitano_claudia" \
  "client_soc_admin" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test "D-SOC + corporate_net usato da operatore_ancona" \
  "client_soc_admin" \
  "operatore_ancona" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test "D-SOC + corporate_net usato da intruso" \
  "client_soc_admin" \
  "intruso" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test "D-001 + public_net usato da intruso" \
  "client_intruso" \
  "intruso" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test "D-001 + public_net usato da operatore_ancona" \
  "client_intruso" \
  "operatore_ancona" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test "D-001 + public_net usato da capitano_claudia" \
  "client_intruso" \
  "capitano_claudia" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

run_test "D-001 + public_net usato da soc_admin" \
  "client_intruso" \
  "soc_admin" \
  "GET" \
  "/risorse" \
  "403" \
  "yes" \
  "-"

# ============================================================================
# RIEPILOGO
# ============================================================================

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
