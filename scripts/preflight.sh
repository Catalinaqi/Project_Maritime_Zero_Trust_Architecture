#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_ROOT"

errors=0
check_file() {
  if [ -r "$1" ]; then
    printf '[OK] %s\n' "$1"
  else
    printf '[ERRORE] %s\n' "$1" >&2
    errors=$((errors + 1))
  fi
}

version_at_least() {
  local current="$1" required="$2"
  [ "$(printf '%s\n%s\n' "$required" "$current" | sort -V | head -n 1)" = "$required" ]
}

check_file .env
check_file docker-compose.yml
check_file certs/ca/ca.crt
check_file certs/server/server.crt
check_file certs/server/server.key
check_file certs/mongodb/mongodb-server.pem
check_file certs/mongodb/api-client.pem
check_file certs/mongodb/healthcheck-client.pem
check_file configs/envoy/mongo_inspector.lua
check_file configs/opa/policies/authorization.rego

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  compose_version="$(docker compose version --short | sed 's/^v//')"
  if version_at_least "$compose_version" "2.36.0"; then
    printf '[OK] Docker Compose %s\n' "$compose_version"
  else
    printf '[ERRORE] Docker Compose %s: è richiesta almeno la versione 2.36.0\n' \
      "$compose_version" >&2
    errors=$((errors + 1))
  fi

  if docker compose config --quiet; then
    printf '[OK] docker compose config\n'
  else
    printf '[ERRORE] docker compose config\n' >&2
    errors=$((errors + 1))
  fi
else
  printf '[AVVISO] Docker Compose non disponibile: validazione Compose non eseguita\n'
fi

[ "$errors" -eq 0 ] || exit 1
