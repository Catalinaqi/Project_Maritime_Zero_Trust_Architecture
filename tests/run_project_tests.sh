#!/bin/bash
# Esegue tutte le suite di test e stampa le query Splunk di verifica.
set -u

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT" || exit 1

failed=0

run_suite() {
  local script="$1"
  printf '\n########################################\n'
  printf '# %s\n' "$script"
  printf '########################################\n'

  if ! bash "$script"; then
    failed=1
  fi
}

print_splunk_queries() {
  cat <<'SPLUNK_QUERIES'

================================================================
QUERY SPLUNK DA COPIARE IN SEARCH & REPORTING
Apri: http://localhost:8000
================================================================

[1] Eventi disponibili per sourcetype
index=main earliest=-30m
| stats count as eventi by sourcetype
| sort - eventi

[2] Decisioni OPA consentite e negate per utente
index=main sourcetype=opa_decision earliest=-30m
| rex field=_raw max_match=1 "\"user_id\":\"(?<user_id>[^\"]+)"
| rex field=_raw max_match=1 "\"allowed\":(?<allowed>true|false)"
| stats count as totale sum(eval(allowed="true")) as consentite sum(eval(allowed="false")) as negate by user_id
| sort user_id

[3] Eventi del test di rischio dinamico
index=main sourcetype=opa_decision source="dynamic-risk-test" earliest=-30m
| spath path=test_run_id output=test_run_id
| spath path=event_id output=event_id
| stats count as eventi dc(event_id) as eventi_univoci values(test_run_id) as esecuzioni

[4] Risk score correnti di tutti gli utenti
| inputlookup historical_risk_scores.csv
| table user_id risk_score isAnomaly denied_count unique_sources snort_alert_count snort_critical_count device_id trust_level updated_at
| sort user_id

[5] Alert Snort recenti
index=main sourcetype=snort_alert_json earliest=-30m
| spath path=src_ap output=src_ap
| spath path=dst_ap output=dst_ap
| spath path=rule output=rule
| spath path=action output=action
| table _time src_ap dst_ap rule action
| sort - _time

[6] Alert Snort per accesso diretto a MongoDB (SID 999904)
index=main sourcetype=snort_alert_json earliest=-30m
| spath path=src_ap output=src_ap
| spath path=dst_ap output=dst_ap
| spath path=rule output=rule
| search rule="1:999904:*"
| table _time src_ap dst_ap rule
| sort - _time

================================================================
SPLUNK_QUERIES
}

run_suite "tests/test_audit_nftables.sh"
run_suite "tests/test_audit_snort.sh"
run_suite "tests/test_access_success.sh"
run_suite "tests/test_access_denied.sh"
run_suite "tests/test_mtls_failures.sh"
run_suite "tests/test_dynamic_risk_score.sh"

print_splunk_queries

if [ "$failed" -ne 0 ]; then
  printf '\n[ERRORE] Una o piu suite di test sono fallite.\n'
  exit 1
fi

printf '\n[OK] Tutte le suite di test sono completate correttamente.\n'
