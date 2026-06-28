#!/bin/bash
# Esegue in sequenza i test applicativi principali del progetto.
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

run_suite "tests/test_access_success.sh"
run_suite "tests/test_access_denied.sh"
run_suite "tests/test_mtls_failures.sh"
run_suite "tests/test_dynamic_risk_score.sh"

if [ "$failed" -ne 0 ]; then
  printf '\n[ERRORE] Uno o piu test sono falliti.\n'
  exit 1
fi

printf '\n[OK] Tutti i test applicativi sono completati correttamente.\n'
