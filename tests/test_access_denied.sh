#!/bin/bash
# Test delle richieste Zero Trust che devono essere bloccate dalla policy OPA.
set -u

source "$(dirname "$0")/lib_test_helpers.sh"

cd "$PROJECT_ROOT" || exit 1

start_base_services
start_testing_clients
wait_for_opa || print_summary
set_static_risk_scores_baseline

print_section "Accessi negati"
run_access_test "DENY: operatore_ancona non puo inserire risorse" \
  "client_d001_tpm" "operatore_ancona" "POST" "/risorse" "403"

run_access_test "DENY: operatore_ancona non puo usare /all" \
  "client_d001_tpm" "operatore_ancona" "GET" "/all" "403"

run_access_test "DENY: capitano_claudia non puo cancellare risorse" \
  "client_d002_tpm" "capitano_claudia" "DELETE" "/risorse/R-001" "403"

run_access_test "DENY: capitano_claudia non puo usare /all" \
  "client_d002_tpm" "capitano_claudia" "GET" "/all" "403"

run_access_test "DENY: soc_admin non puo accedere a risorsa inesistente vincolata" \
  "client_dsoc_tpm" "soc_admin" "GET" "/risorse/R-999" "403"

print_summary
