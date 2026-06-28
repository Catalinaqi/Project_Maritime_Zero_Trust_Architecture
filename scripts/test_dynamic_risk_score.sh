#!/bin/bash
# Test del risk score dinamico tramite eventi inviati a Splunk HEC.
set -u

source "$(dirname "$0")/lib_test_helpers.sh"

cd "$PROJECT_ROOT" || exit 1

start_base_services
start_testing_clients
wait_for_opa || print_summary
wait_for_splunk_hec || print_summary
set_static_risk_scores_baseline
trap 'set_static_risk_scores_baseline >/dev/null 2>&1' EXIT

print_section "Risk score dinamico"

baseline="$(get_opa_risk_score operatore_ancona)"
printf '[INFO] Risk iniziale operatore_ancona: %s\n' "${baseline:-non disponibile}"

TOTAL_TESTS=$((TOTAL_TESTS + 1))
printf '[TEST] Invio eventi deny a Splunk HEC\n'
hec_ok=1
for i in $(seq 1 8); do
  event="{\"result\":{\"allowed\":false,\"dynamic_metadata\":{\"reason_codes\":[\"command_not_allowed\"]}},\"input\":{\"attributes\":{\"metadataContext\":{\"filterMetadata\":{\"envoy.filters.http.lua\":{\"context_extensions\":{\"user_id\":\"operatore_ancona\",\"device_id\":\"D-001\",\"source_network\":\"vpn_net\",\"path\":\"/all\"}}}}}},\"test_event\":${i}}"
  if ! send_splunk_hec_event "opa_decision_log" "opa_decision" "$event"; then
    hec_ok=0
  fi
done

if [ "$hec_ok" = "1" ]; then
  record_pass "Eventi deny inviati a Splunk HEC"
else
  record_fail "Invio eventi deny a Splunk HEC non riuscito"
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

set_static_risk_scores_baseline
trap - EXIT
print_summary
