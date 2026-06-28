#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib_test_helpers.sh"

print_section "TEST ACCESSI NEGATI DA POLICY OPA"

start_base_services
start_testing_clients
wait_for_opa_health
set_static_risk_scores_baseline

# Il certificato TPM è valido, ma l'utente intruso non è autorizzato.
run_access_test \
  "DENY - intruso usa il dispositivo valido D-001" \
  "client_d001_tpm" \
  "intruso" \
  "GET" \
  "/risorse" \
  "403"

# Operatore autorizzato alla lettura, ma non all'inserimento.
run_access_test \
  "DENY - operatore_ancona prova POST /risorse" \
  "client_d001_tpm" \
  "operatore_ancona" \
  "POST" \
  "/risorse" \
  "403"

# Operatore non autorizzato alla collection globale.
run_access_test \
  "DENY - operatore_ancona prova GET /all" \
  "client_d001_tpm" \
  "operatore_ancona" \
  "GET" \
  "/all" \
  "403"

# Capitano non autorizzato all'eliminazione.
run_access_test \
  "DENY - capitano_claudia prova DELETE /risorse" \
  "client_d002_tpm" \
  "capitano_claudia" \
  "DELETE" \
  "/risorse" \
  "403"

# Identità applicativa inesistente su dispositivo TPM valido.
run_access_test \
  "DENY - utente inesistente usa il dispositivo valido D-002" \
  "client_d002_tpm" \
  "utente_inesistente" \
  "GET" \
  "/risorse" \
  "403"

# L'utente intruso prova a riutilizzare il dispositivo D-002.
run_access_test \
  "DENY - intruso usa il dispositivo valido D-002" \
  "client_d002_tpm" \
  "intruso" \
  "GET" \
  "/risorse" \
  "403"

print_summary
