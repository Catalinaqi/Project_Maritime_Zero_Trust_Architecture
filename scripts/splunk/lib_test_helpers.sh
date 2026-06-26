#!/usr/bin/env bash

# Funzioni comuni per i test Zero Trust con client TPM-backed.
# Questo file viene riutilizzato dai test di accesso consentito, negato e mTLS.

set -u

# Evita la conversione automatica dei path Linux da parte di Git Bash.
export MSYS_NO_PATHCONV=1
export COMPOSE_CONVERT_WINDOWS_PATHS=0

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$LIB_DIR/.." && pwd)"
OPA_RISK_FILE="$PROJECT_ROOT/configs/opa/data/risk_data/risk_scores.json"

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

compose() {
  (
    cd "$PROJECT_ROOT" || exit 1
    docker compose -f docker-compose.yml --profile testing "$@"
  )
}

print_section() {
  echo ""
  echo "============================================================"
  echo " $1"
  echo "============================================================"
  echo ""
}

start_base_services() {
  echo "Avvio servizi principali..."
  compose up -d db_primary siem_central api_backend pdp_engine pep_gateway ids_network_monitor firewall_perimeter
}

start_testing_clients() {
  echo "Avvio emulatori TPM e client TPM-backed..."

  # I client hanno IP statici. Devono essere avviati una sola volta con up -d.
  # Le richieste vengono poi eseguite con compose exec, non con compose run.
  compose up -d swtpm_d001 swtpm_d002 swtpm_dsoc client_d001_tpm client_d002_tpm client_dsoc_tpm

  local cert
  for cert in \
    "$PROJECT_ROOT/certs/devices/D-001/device.crt" \
    "$PROJECT_ROOT/certs/devices/D-002/device.crt" \
    "$PROJECT_ROOT/certs/devices/D-SOC/device.crt"
  do
    if [ ! -f "$cert" ]; then
      echo "ERRORE: certificato TPM-backed non trovato: $cert"
      echo "Esegui nuovamente il provisioning TPM del dispositivo."
      return 1
    fi
  done
}

wait_for_opa_health() {
  local max_attempts=30
  local attempt=1

  echo "Attendo OPA..."

  while [ "$attempt" -le "$max_attempts" ]; do
    if curl -fsS http://localhost:8181/health >/dev/null 2>&1; then
      echo "OPA raggiungibile."
      return 0
    fi

    sleep 1
    attempt=$((attempt + 1))
  done

  echo "ERRORE: OPA non è raggiungibile."
  return 1
}

get_opa_risk_score() {
  local user_id="$1"
  curl -s "http://localhost:8181/v1/data/risk_data/risk_scores/$user_id/risk_score" | sed -n 's/.*"result":[ ]*\([0-9][0-9]*\).*/\1/p'
}

set_static_risk_scores_baseline() {
  echo "Imposto baseline risk score per i test di accesso..."

  mkdir -p "$(dirname "$OPA_RISK_FILE")"

  printf '%s\n' '{"risk_scores":{"operatore_ancona":{"risk_score":10,"is_anomaly":false,"denied_count":0},"capitano_claudia":{"risk_score":10,"is_anomaly":false,"denied_count":0},"soc_admin":{"risk_score":10,"is_anomaly":false,"denied_count":0},"intruso":{"risk_score":90,"is_anomaly":true,"denied_count":8}}}' > "$OPA_RISK_FILE"

  local max_attempts=20
  local attempt=1

  while [ "$attempt" -le "$max_attempts" ]; do
    if [ "$(get_opa_risk_score operatore_ancona)" = "10" ] && \
       [ "$(get_opa_risk_score capitano_claudia)" = "10" ] && \
       [ "$(get_opa_risk_score soc_admin)" = "10" ]; then
      echo "Baseline caricata correttamente in OPA."
      return 0
    fi

    sleep 1
    attempt=$((attempt + 1))
  done

  echo "ERRORE: OPA non ha caricato la baseline."
  return 1
}

extract_http_status() {
  local response="$1"

  printf '%s\n' "$response" \
    | tr -d '\r' \
    | sed -n 's/^HTTP\/[0-9.]*[[:space:]]\([0-9][0-9][0-9]\).*/\1/p' \
    | head -n 1
}

extract_curl_status() {
  local response="$1"

  printf '%s\n' "$response" \
    | sed -n 's/.*__HTTP_CODE__:\([0-9][0-9][0-9]\).*/\1/p' \
    | tail -n 1
}

record_test_result() {
  local code="$1"
  local expected="$2"
  local response="$3"
  local output_label="${4:-Output completo della richiesta:}"

  echo "Ottenuto:   $code"

  if [ "$code" = "$expected" ]; then
    echo "ESITO: TEST OK"
    PASSED_TESTS=$((PASSED_TESTS + 1))
  else
    echo "ESITO: TEST FALLITO"
    FAILED_TESTS=$((FAILED_TESTS + 1))
    echo ""
    echo "$output_label"
    printf '%s\n' "$response"
  fi

  echo ""
  return 0
}

run_access_test() {
  local test_name="$1"
  local client_service="$2"
  local user_id="$3"
  local method="$4"
  local endpoint="$5"
  local expected="$6"

  local response=""
  local code="000"

  TOTAL_TESTS=$((TOTAL_TESTS + 1))

  echo "------------------------------------------------------------"
  echo "Test #$TOTAL_TESTS: $test_name"
  echo "Client TPM: $client_service"
  echo "User:       $user_id"
  echo "Metodo:     $method"
  echo "Endpoint:   $endpoint"
  echo "Atteso:     $expected"

  # Il container TPM è già avviato con il suo IP statico.
  # Usiamo exec per evitare la creazione di un secondo container con lo stesso IP.
  response="$(
    compose exec -T \
      -e METHOD="$method" \
      -e PATH_URL="$endpoint" \
      -e USER_ID="$user_id" \
      "$client_service" \
      /scripts/request_with_tpm.sh 2>&1 || true
  )"

  code="$(extract_http_status "$response")"
  [ -n "$code" ] || code="000"

  record_test_result "$code" "$expected" "$response" "Output completo della richiesta TPM:"
}

run_mtls_test() {
  local test_name="$1"
  local client_service="$2"
  local user_id="$3"
  local method="$4"
  local endpoint="$5"
  local expected="$6"
  local cert_mode="$7"

  local response=""
  local code="000"

  TOTAL_TESTS=$((TOTAL_TESTS + 1))

  echo "------------------------------------------------------------"
  echo "Test #$TOTAL_TESTS: $test_name"
  echo "Client TPM: $client_service"
  echo "User:       $user_id"
  echo "Metodo:     $method"
  echo "Endpoint:   $endpoint"
  echo "Modalità:   $cert_mode"
  echo "Atteso:     $expected"

  case "$cert_mode" in
    valid)
      # Certificato device valido; la chiave privata viene usata dal TPM.
      response="$(
        compose exec -T \
          -e METHOD="$method" \
          -e PATH_URL="$endpoint" \
          -e USER_ID="$user_id" \
          "$client_service" \
          /scripts/request_with_tpm.sh 2>&1 || true
      )"
      code="$(extract_http_status "$response")"
      ;;

    none)
      # Nessun certificato client: il TLS deve fallire prima di arrivare a OPA.
      response="$(
        compose exec -T \
          "$client_service" \
          curl -sS \
          -X "$method" \
          --cacert /ca/ca.crt \
          -H "X-User-Id: $user_id" \
          -o /dev/null \
          -w "__HTTP_CODE__:%{http_code}" \
          "https://pep_gateway:8443$endpoint" 2>&1 || true
      )"
      code="$(extract_curl_status "$response")"
      ;;

    missing)
      # I file indicati non esistono: curl deve fallire localmente.
      response="$(
        compose exec -T \
          "$client_service" \
          curl -sS \
          -X "$method" \
          --cacert /ca/ca.crt \
          --cert /certs/device/missing.crt \
          --key /certs/device/missing.key \
          -H "X-User-Id: $user_id" \
          -o /dev/null \
          -w "__HTTP_CODE__:%{http_code}" \
          "https://pep_gateway:8443$endpoint" 2>&1 || true
      )"
      code="$(extract_curl_status "$response")"
      ;;

    no_header)
      # mTLS valido tramite TPM, ma richiesta HTTP senza X-User-Id.
      response="$(
        compose exec -T \
          -e TEST_METHOD="$method" \
          -e TEST_ENDPOINT="$endpoint" \
          "$client_service" \
          sh -lc 'printf "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" "$TEST_METHOD" "$TEST_ENDPOINT" "$ENVOY_HOST" | openssl s_client -connect "${ENVOY_HOST}:${ENVOY_PORT}" -servername "$ENVOY_HOST" -cert "$CLIENT_CERT" -key "handle:${TPM_HANDLE}" -provider tpm2 -provider default -CAfile "$CA_CERT" -quiet' 2>&1 || true
      )"
      code="$(extract_http_status "$response")"
      ;;

    *)
      response="Modalità certificato non valida: $cert_mode"
      code="INVALID"
      ;;
  esac

  [ -n "$code" ] || code="000"

  record_test_result "$code" "$expected" "$response" "Output completo del test mTLS:"
}

print_summary() {
  echo "============================================================"
  echo " RIEPILOGO TEST"
  echo "============================================================"
  echo "Totali:   $TOTAL_TESTS"
  echo "Passati:  $PASSED_TESTS"
  echo "Falliti:  $FAILED_TESTS"

  if [ "$FAILED_TESTS" -eq 0 ]; then
    echo "ESITO COMPLESSIVO: OK"
    return 0
  fi

  echo "ESITO COMPLESSIVO: FALLITO"
  return 1
}
