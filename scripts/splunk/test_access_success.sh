#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib_test_helpers.sh"

print_section "TEST ACCESSI AUTORIZZATI"

start_base_services
start_testing_clients
wait_for_opa_health
set_static_risk_scores_baseline

run_access_test "ALLOW - operatore_ancona legge /risorse" "client_d001_tpm" "operatore_ancona" "GET" "/risorse" "200"
run_access_test "ALLOW - capitano_claudia legge /risorse" "client_d002_tpm" "capitano_claudia" "GET" "/risorse" "200"
run_access_test "ALLOW - soc_admin legge /all" "client_dsoc_tpm" "soc_admin" "GET" "/all" "200"
run_access_test "ALLOW OPA - capitano_claudia tenta insert su /risorse" "client_d002_tpm" "capitano_claudia" "POST" "/risorse" "404"
run_access_test "ALLOW OPA - soc_admin tenta update su /risorse" "client_dsoc_tpm" "soc_admin" "PUT" "/risorse" "404"

print_summary
