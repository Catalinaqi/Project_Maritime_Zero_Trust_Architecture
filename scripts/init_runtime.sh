#!/usr/bin/env bash
# Ripristina i dati runtime mutabili partendo dai template versionati.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RISK_TEMPLATE="$PROJECT_ROOT/configs/runtime-templates/risk_scores.json"
RISK_TARGET="$PROJECT_ROOT/configs/opa/data/risk_data/risk_scores.json"
HISTORY_TEMPLATE="$PROJECT_ROOT/configs/runtime-templates/historical_risk_scores.csv"
HISTORY_TARGET="$PROJECT_ROOT/configs/splunk/apps/opa_risk_updater/lookups/historical_risk_scores.csv"

for template in "$RISK_TEMPLATE" "$HISTORY_TEMPLATE"; do
  if [ ! -r "$template" ]; then
    printf 'Template runtime mancante: %s\n' "$template" >&2
    exit 1
  fi
done

mkdir -p "$(dirname "$RISK_TARGET")" "$(dirname "$HISTORY_TARGET")"
cp "$RISK_TEMPLATE" "$RISK_TARGET"
cp "$HISTORY_TEMPLATE" "$HISTORY_TARGET"

printf 'Dati runtime ripristinati dai template versionati.\n'
