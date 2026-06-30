#!/bin/bash
# Test dei casi mTLS falliti e dei casi mTLS valido ma non autorizzato.
set -u

source "$(dirname "$0")/lib_test_helpers.sh"

cd "$PROJECT_ROOT" || exit 1

start_base_services
start_testing_clients
wait_for_opa || print_summary
pause_dynamic_risk_updates || exit 1
trap 'resume_dynamic_risk_updates >/dev/null 2>&1' EXIT
set_static_risk_scores_baseline || exit 1

print_section "mTLS e policy deny"
run_plain_tls_test "mTLS FAIL: richiesta senza certificato client" \
  "client_d001_tpm" "000"

run_missing_cert_test "mTLS FAIL: certificato client mancante nel container" \
  "client_d001_tpm" "000"

run_access_test "mTLS OK + OPA DENY: operatore_ancona su /all" \
  "client_d001_tpm" "operatore_ancona" "GET" "/all" "403"

run_access_test "mTLS OK + OPA DENY: capitano_claudia con DELETE" \
  "client_d002_tpm" "capitano_claudia" "DELETE" "/risorse/R-001" "403"

print_summary
