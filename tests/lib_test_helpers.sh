#!/bin/bash
# Funzioni comuni per i test end-to-end dell'ambiente Zero Trust.
set -u

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_PROJECT_DIR="$PROJECT_ROOT"
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0
RISK_UPDATER_SAVED_SEARCH="Calcolo%20Dinamico%20Risk%20Score%20OPA"

compose() {
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker compose --profile testing "$@"
}

print_section() {
  printf '\n== %s ==\n' "$1"
}

read_env_value() {
  local key="$1"
  local default_value="${2:-}"
  local env_file="$PROJECT_ROOT/.env"

  if [ -f "$env_file" ]; then
    local value
    value="$(grep -E "^${key}=" "$env_file" | tail -n 1 | cut -d= -f2-)"
    if [ -n "$value" ]; then
      printf '%s' "$value"
      return 0
    fi
  fi

  printf '%s' "$default_value"
}

record_pass() {
  PASSED_TESTS=$((PASSED_TESTS + 1))
  printf '[PASS] %s\n' "$1"
}

record_fail() {
  FAILED_TESTS=$((FAILED_TESTS + 1))
  printf '[FAIL] %s\n' "$1"
}

record_skip() {
  SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
  printf '[SKIP] %s\n' "$1"
}

extract_http_status() {
  sed -n 's/^HTTP\/[0-9.]* \([0-9][0-9][0-9]\).*/\1/p' | tail -n 1
}

start_base_services() {
  print_section "Avvio servizi base"
  compose up -d db_primary siem_central api_backend pdp_engine pep_gateway ids_network_monitor firewall_perimeter
}

start_testing_clients() {
  print_section "Avvio client TPM"
  compose up -d swtpm_d001 swtpm_d002 swtpm_dsoc client_d001_tpm client_d002_tpm client_dsoc_tpm
}

wait_for_opa() {
  local opa_port
  opa_port="$(read_env_value OPA_REST_PORT 8181)"

  printf '[INFO] Attendo OPA su localhost:%s' "$opa_port"
  for _ in $(seq 1 45); do
    if curl -fsS "http://localhost:${opa_port}/health?plugins" >/dev/null 2>&1; then
      printf '\n'
      return 0
    fi
    printf '.'
    sleep 2
  done

  printf '\n'
  record_fail "OPA non raggiungibile"
  return 1
}

wait_for_splunk_hec() {
  local hec_port token
  hec_port="$(read_env_value SPLUNK_HEC_PORT 8088)"
  token="$(read_env_value SPLUNK_HEC_TOKEN 00000000-0000-0000-0000-000000000000)"

  printf '[INFO] Attendo Splunk HEC su localhost:%s' "$hec_port"
  for _ in $(seq 1 90); do
    if curl -fsS "http://localhost:${hec_port}/services/collector/health" \
      -H "Authorization: Splunk ${token}" >/dev/null 2>&1; then
      printf '\n'
      return 0
    fi
    printf '.'
    sleep 2
  done

  printf '\n'
  record_fail "Splunk HEC non raggiungibile"
  return 1
}

wait_for_splunk_search_api() {
  local password
  password="$(read_env_value SPLUNK_PASSWORD)"

  printf '[INFO] Attendo Splunk Search API'
  for _ in $(seq 1 90); do
    if compose exec -T \
      -e SPLUNK_TEST_PASSWORD="$password" \
      siem_central sh -lc \
      'curl -kfsS -u "admin:${SPLUNK_TEST_PASSWORD}" "https://localhost:8089/services/server/info?output_mode=json"' \
      >/dev/null 2>&1; then
      printf '\n'
      return 0
    fi
    printf '.'
    sleep 2
  done

  printf '\n'
  record_fail "Splunk Search API non raggiungibile"
  return 1
}

run_splunk_search_json() {
  local query="$1"
  local password encoded_query
  password="$(read_env_value SPLUNK_PASSWORD)"
  encoded_query="$(printf '%s' "$query" | base64 | tr -d '\r\n')"

  compose exec -T \
    -e SPLUNK_TEST_PASSWORD="$password" \
    -e SPLUNK_TEST_QUERY_B64="$encoded_query" \
    siem_central sh -lc '
      SPLUNK_TEST_QUERY="$(printf "%s" "${SPLUNK_TEST_QUERY_B64}" | base64 -d)"
      curl -kfsS \
        --max-time 30 \
        -u "admin:${SPLUNK_TEST_PASSWORD}" \
        --data-urlencode "search=${SPLUNK_TEST_QUERY}" \
        --data-urlencode "output_mode=json" \
        "https://localhost:8089/services/search/jobs/export"
    '
}

set_dynamic_risk_updates() {
  local requested_state="$1"
  local action password

  case "$requested_state" in
    enabled) action="enable" ;;
    disabled) action="disable" ;;
    *)
      printf '[ERRORE] Stato aggiornamento rischio non valido: %s\n' "$requested_state" >&2
      return 1
      ;;
  esac

  password="$(read_env_value SPLUNK_PASSWORD)"
  if [ -z "$password" ]; then
    printf '[ERRORE] SPLUNK_PASSWORD non definita nel file .env.\n' >&2
    return 1
  fi

  compose exec -T \
    -e SPLUNK_TEST_PASSWORD="$password" \
    -e SPLUNK_RISK_ACTION="$action" \
    -e SPLUNK_RISK_SEARCH="$RISK_UPDATER_SAVED_SEARCH" \
    siem_central sh -lc '
      curl -kfsS --max-time 20 -X POST \
        -u "admin:${SPLUNK_TEST_PASSWORD}" \
        "https://localhost:8089/servicesNS/nobody/opa_risk_updater/saved/searches/${SPLUNK_RISK_SEARCH}/${SPLUNK_RISK_ACTION}" \
        >/dev/null
    '
}

pause_dynamic_risk_updates() {
  print_section "Sospensione aggiornamento dinamico del rischio"
  wait_for_splunk_search_api || return 1
  set_dynamic_risk_updates disabled || return 1

  # Consente a un'eventuale esecuzione già avviata di terminare prima del reset.
  sleep 2
}

resume_dynamic_risk_updates() {
  set_dynamic_risk_updates enabled
}

extract_splunk_stat() {
  local field="$1"
  sed -n "s/.*\"${field}\":\"\([0-9][0-9]*\)\".*/\1/p" | tail -n 1
}

identity_for() {
  local user_id client_service matrix_file raw_user raw_device raw_service raw_handle
  user_id="${1//$'\r'/}"
  client_service="${2//$'\r'/}"
  matrix_file="$PROJECT_ROOT/scripts/identity_bindings.testing.conf"

  while IFS='|' read -r raw_user raw_device raw_service raw_handle _; do
    raw_user="${raw_user//$'\r'/}"
    raw_service="${raw_service//$'\r'/}"
    raw_handle="${raw_handle//$'\r'/}"

    [ -n "$raw_user" ] || continue
    case "$raw_user" in
      \#*) continue ;;
    esac

    if [ "$raw_user" = "$user_id" ] && [ "$raw_service" = "$client_service" ]; then
      printf '%s|%s\n' "/certs/device/identities/${user_id}/identity.crt" "$raw_handle"
      return 0
    fi
  done < "$matrix_file"

  return 1
}

run_access_test() {
  local label="$1"
  local client_service="$2"
  local user_id="$3"
  local method="$4"
  local path_url="$5"
  local expected_status="$6"

  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  printf '\n[TEST] %s\n' "$label"

  local identity cert handle output status
  if ! identity="$(identity_for "$user_id" "$client_service")"; then
    record_skip "${label} -> certificato TPM non previsto per ${user_id} su ${client_service}"
    return 0
  fi

  cert="${identity%%|*}"
  handle="${identity##*|}"
  output="$(compose exec -T "$client_service" env \
    METHOD="$method" \
    PATH_URL="$path_url" \
    CLIENT_CERT="$cert" \
    TPM_HANDLE="$handle" \
    /scripts/request_with_tpm.sh 2>&1)"

  status="$(printf '%s\n' "$output" | extract_http_status)"
  if [ -z "$status" ]; then
    status="nessuno"
  fi

  if [ "$status" = "$expected_status" ]; then
    record_pass "${label} -> HTTP ${status}"
  else
    record_fail "${label} -> HTTP ${status}, atteso ${expected_status}"
    printf '%s\n' "$output"
  fi
}

run_plain_tls_test() {
  local label="$1"
  local client_service="$2"
  local expected_status="$3"

  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  printf '\n[TEST] %s\n' "$label"

  local output status
  output="$(compose exec -T "$client_service" sh -lc \
    "printf 'GET /risorse/R-001 HTTP/1.1\r\nHost: pep_gateway\r\nConnection: close\r\n\r\n' | openssl s_client -connect pep_gateway:8443 -servername pep_gateway -tls1_2 -no-CAfile -no-CApath -quiet" 2>&1)"

  status="$(printf '%s\n' "$output" | extract_http_status)"
  if [ -z "$status" ]; then
    status="000"
  fi

  if [ "$status" = "$expected_status" ]; then
    record_pass "${label} -> HTTP ${status}"
  else
    record_fail "${label} -> HTTP ${status}, atteso ${expected_status}"
    printf '%s\n' "$output"
  fi
}

run_missing_cert_test() {
  local label="$1"
  local client_service="$2"
  local expected_status="$3"

  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  printf '\n[TEST] %s\n' "$label"

  local output status
  output="$(compose exec -T "$client_service" env \
    METHOD="GET" \
    PATH_URL="/risorse/R-001" \
    CLIENT_CERT="/certs/device/missing.crt" \
    TPM_HANDLE="0x81000001" \
    /scripts/request_with_tpm.sh 2>&1)"

  status="$(printf '%s\n' "$output" | extract_http_status)"
  if [ -z "$status" ]; then
    status="000"
  fi

  if [ "$status" = "$expected_status" ]; then
    record_pass "${label} -> HTTP ${status}"
  else
    record_fail "${label} -> HTTP ${status}, atteso ${expected_status}"
    printf '%s\n' "$output"
  fi
}

set_static_risk_scores_baseline() {
  print_section "Ripristino risk score bassi"
  cp "$PROJECT_ROOT/configs/runtime-templates/risk_scores.json" \
    "$PROJECT_ROOT/configs/opa/data/risk_data/risk_scores.json"
  compose restart pdp_engine >/dev/null
  wait_for_opa >/dev/null || return 1

  local user_id expected actual
  while IFS='|' read -r user_id expected; do
    actual="$(get_opa_risk_score "$user_id")"
    if [ "$actual" != "$expected" ]; then
      printf '[ERRORE] Baseline OPA non applicata per %s: valore %s, atteso %s.\n' \
        "$user_id" "${actual:-non disponibile}" "$expected" >&2
      return 1
    fi
  done <<'RISK_BASELINE'
operatore_ancona|10
capitano_claudia|10
soc_admin|10
intruso|90
RISK_BASELINE
}

get_opa_risk_score() {
  local user_id="$1"
  local opa_port
  opa_port="$(read_env_value OPA_REST_PORT 8181)"

  curl -fsS "http://localhost:${opa_port}/v1/data/risk_data/risk_scores/${user_id}" 2>/dev/null \
    | sed -n 's/.*"risk_score"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' \
    | tail -n 1
}

send_splunk_hec_event() {
  local source="$1"
  local sourcetype="$2"
  local event_json="$3"
  local hec_port token
  hec_port="$(read_env_value SPLUNK_HEC_PORT 8088)"
  token="$(read_env_value SPLUNK_HEC_TOKEN 00000000-0000-0000-0000-000000000000)"

  curl -fsS "http://localhost:${hec_port}/services/collector/event" \
    -H "Authorization: Splunk ${token}" \
    -H "Content-Type: application/json" \
    -d "{\"source\":\"${source}\",\"sourcetype\":\"${sourcetype}\",\"event\":${event_json}}" >/dev/null
}

print_summary() {
  printf '\n== Riepilogo ==\n'
  printf 'Totali: %s | OK: %s | Falliti: %s | Saltati: %s\n' \
    "$TOTAL_TESTS" "$PASSED_TESTS" "$FAILED_TESTS" "$SKIPPED_TESTS"

  if [ "$FAILED_TESTS" -gt 0 ]; then
    exit 1
  fi
}

print_summary_audit() {
  local pass_count="$1"
  local fail_count="$2"
  local total=$((pass_count + fail_count))
  printf '\n== Riepilogo Audit ==\n'
  printf 'Totali: %d | OK: %d | Falliti: %d | Saltati: 0\n' \
    "$total" "$pass_count" "$fail_count"
  if [ "$fail_count" -gt 0 ]; then
    return 1
  fi
}
