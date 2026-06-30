#!/bin/bash
# Test delle richieste Zero Trust che devono essere autorizzate.
set -u

source "$(dirname "$0")/lib_test_helpers.sh"

cd "$PROJECT_ROOT" || exit 1

start_base_services
start_testing_clients
wait_for_opa || print_summary
pause_dynamic_risk_updates || exit 1
trap 'resume_dynamic_risk_updates >/dev/null 2>&1' EXIT
set_static_risk_scores_baseline || exit 1

print_section "Accessi consentiti"
run_access_test "ALLOW: operatore_ancona da D-001 legge R-001" \
  "client_d001_tpm" "operatore_ancona" "GET" "/risorse/R-001" "200"

run_access_test "ALLOW: operatore_ancona da D-002 legge R-001" \
  "client_d002_tpm" "operatore_ancona" "GET" "/risorse/R-001" "200"

run_access_test "ALLOW: capitano_claudia da D-001 legge R-001" \
  "client_d001_tpm" "capitano_claudia" "GET" "/risorse/R-001" "200"

run_access_test "ALLOW: capitano_claudia da D-002 legge R-001" \
  "client_d002_tpm" "capitano_claudia" "GET" "/risorse/R-001" "200"

run_access_test "ALLOW: soc_admin da D-SOC legge vista completa" \
  "client_dsoc_tpm" "soc_admin" "GET" "/all" "200"

run_access_test "ALLOW: soc_admin da D-001 legge vista completa" \
  "client_d001_tpm" "soc_admin" "GET" "/all" "200"

run_access_test "ALLOW: soc_admin da D-002 legge vista completa" \
  "client_d002_tpm" "soc_admin" "GET" "/all" "200"

run_access_test "ALLOW: capitano_claudia da D-002 legge collezione risorse" \
  "client_d002_tpm" "capitano_claudia" "GET" "/risorse" "200"

print_summary
