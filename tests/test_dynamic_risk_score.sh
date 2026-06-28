#!/bin/bash
# Test del risk score dinamico tramite eventi inviati a Splunk HEC.
set -u

source "$(dirname "$0")/lib_test_helpers.sh"

cd "$PROJECT_ROOT" || exit 1

start_base_services
start_testing_clients
wait_for_opa || print_summary
wait_for_splunk_hec || print_summary
wait_for_splunk_search_api || print_summary
set_static_risk_scores_baseline
trap 'set_static_risk_scores_baseline >/dev/null 2>&1' EXIT

print_section "Risk score dinamico"

TEST_RUN_ID="risk-test-$(date -u +%Y%m%dT%H%M%SZ)-$$"
EVENT_SOURCE="dynamic-risk-test"
baseline="$(get_opa_risk_score operatore_ancona)"
printf '[INFO] Risk iniziale operatore_ancona: %s\n' "${baseline:-non disponibile}"
printf '[INFO] Identificativo esecuzione: %s\n' "$TEST_RUN_ID"

TOTAL_TESTS=$((TOTAL_TESTS + 1))
printf '[TEST] Invio eventi deny a Splunk HEC\n'
hec_ok=1
for i in $(seq 1 8); do
  event="{\"test_run_id\":\"${TEST_RUN_ID}\",\"event_id\":${i},\"result\":{\"allowed\":false,\"dynamic_metadata\":{\"reason_codes\":[\"command_not_allowed\"]}},\"input\":{\"attributes\":{\"metadataContext\":{\"filterMetadata\":{\"envoy.filters.http.lua\":{\"context_extensions\":{\"user_id\":\"operatore_ancona\",\"device_id\":\"D-001\",\"source_network\":\"vpn_net\",\"path\":\"/all\"}}}}}}}"
  if ! send_splunk_hec_event "$EVENT_SOURCE" "opa_decision" "$event"; then
    hec_ok=0
  fi
done

if [ "$hec_ok" = "1" ]; then
  record_pass "Eventi deny inviati a Splunk HEC"
else
  record_fail "Invio eventi deny a Splunk HEC non riuscito"
fi

TOTAL_TESTS=$((TOTAL_TESTS + 1))
printf '[TEST] Verifico che Splunk abbia indicizzato gli 8 eventi\n'
indexed_count=0
unique_count=0
for _ in $(seq 1 45); do
  splunk_response="$(run_splunk_search_json \
    "search index=main sourcetype=opa_decision source=\"${EVENT_SOURCE}\" earliest=-15m | spath path=test_run_id output=test_run_id | spath path=event_id output=event_id | search test_run_id=\"${TEST_RUN_ID}\" | stats count as indexed_count dc(event_id) as unique_count" \
    2>/dev/null || true)"
  indexed_count="$(printf '%s\n' "$splunk_response" | extract_splunk_stat indexed_count)"
  unique_count="$(printf '%s\n' "$splunk_response" | extract_splunk_stat unique_count)"
  indexed_count="${indexed_count:-0}"
  unique_count="${unique_count:-0}"

  if [ "$indexed_count" -eq 8 ] && [ "$unique_count" -eq 8 ]; then
    break
  fi
  sleep 2
done

if [ "$indexed_count" -eq 8 ] && [ "$unique_count" -eq 8 ]; then
  record_pass "Splunk ha indicizzato 8 eventi univoci"
else
  record_fail "Eventi indicizzati: ${indexed_count}; univoci: ${unique_count}; attesi: 8"
fi

TOTAL_TESTS=$((TOTAL_TESTS + 1))
printf '[TEST] Attendo aggiornamento risk score in OPA\n'
risk_after=""
for _ in $(seq 1 45); do
  risk_after="$(get_opa_risk_score operatore_ancona)"
  if [ -n "$risk_after" ] && [ "$risk_after" -ge 80 ]; then
    break
  fi
  sleep 2
done

if [ -n "$risk_after" ] && [ "$risk_after" -ge 80 ]; then
  record_pass "Risk score aggiornato: ${risk_after}"

  run_access_test "DENY dinamico: accesso normalmente consentito bloccato dal rischio" \
    "client_d001_tpm" "operatore_ancona" "GET" "/risorse/R-001" "403"
else
  record_fail "Risk score non aggiornato entro il timeout; ultimo valore: ${risk_after:-non disponibile}"
  printf '[INFO] Apri Splunk e verifica la saved search di aggiornamento risk score.\n'
fi

print_section "Alert Snort indicizzato in Splunk"
TOTAL_TESTS=$((TOTAL_TESTS + 1))
printf '[TEST] Genero un tentativo diretto a MongoDB da D-SOC\n'
snort_start="$(date +%s)"
compose exec -T client_dsoc_tpm timeout 3 bash -lc \
  'echo >/dev/tcp/172.20.10.10/27017' >/dev/null 2>&1 || true

snort_count=0
for _ in $(seq 1 45); do
  splunk_response="$(run_splunk_search_json \
    "search index=main sourcetype=snort_alert_json earliest=${snort_start} | spath path=src_ap output=src_ap | spath path=rule output=rule | rex field=src_ap \"^(?<src_ip>[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+):\" | search src_ip=\"172.20.10.31\" rule=\"1:999904:*\" | stats count as snort_count" \
    2>/dev/null || true)"
  snort_count="$(printf '%s\n' "$splunk_response" | extract_splunk_stat snort_count)"
  snort_count="${snort_count:-0}"
  if [ "$snort_count" -ge 1 ]; then
    break
  fi
  sleep 2
done

if [ "$snort_count" -ge 1 ]; then
  record_pass "Alert Snort SID 999904 indicizzato e associato a D-SOC"
else
  record_fail "Alert Snort SID 999904 non trovato in Splunk"
fi

TOTAL_TESTS=$((TOTAL_TESTS + 1))
printf '[TEST] Attendo che l alert Snort aumenti il rischio di soc_admin\n'
soc_risk=""
for _ in $(seq 1 45); do
  soc_risk="$(get_opa_risk_score soc_admin)"
  if [ -n "$soc_risk" ] && [ "$soc_risk" -ge 90 ]; then
    break
  fi
  sleep 2
done

if [ -n "$soc_risk" ] && [ "$soc_risk" -ge 90 ]; then
  record_pass "Risk score soc_admin aggiornato da Snort: ${soc_risk}"
  run_access_test "DENY dinamico: soc_admin bloccato dopo alert Snort" \
    "client_dsoc_tpm" "soc_admin" "GET" "/all" "403"
else
  record_fail "Risk score soc_admin non aggiornato; ultimo valore: ${soc_risk:-non disponibile}"
fi

printf '\n[INFO] Query Splunk: source="%s" test_run_id="%s"\n' \
  "$EVENT_SOURCE" "$TEST_RUN_ID"

set_static_risk_scores_baseline
trap - EXIT
print_summary
