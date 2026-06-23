#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_ROOT"

command -v docker >/dev/null 2>&1 || {
  printf 'Docker non disponibile.\n' >&2
  exit 1
}
docker compose version >/dev/null 2>&1 || {
  printf 'Docker Compose v2 non disponibile.\n' >&2
  exit 1
}

docker compose --profile testing down --volumes --remove-orphans
printf 'Container, reti e volumi runtime del progetto rimossi.\n'
printf 'I certificati locali non sono stati eliminati.\n'
