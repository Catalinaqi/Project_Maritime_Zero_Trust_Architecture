#!/usr/bin/env bash

# Avvia D-Bus e tpm2-abrmd nel container client TPM.
# OpenSSL e tpm2-tools usano il resource manager locale tramite TCTI tabrmd.
set -Eeuo pipefail

SWTPM_HOST="${SWTPM_HOST:?SWTPM_HOST non definito}"
SWTPM_PORT="${SWTPM_PORT:-2321}"

DIRECT_TCTI="swtpm:host=${SWTPM_HOST},port=${SWTPM_PORT}"
TABRMD_TCTI="tabrmd:bus_type=system"

log() {
  printf '[TPM-RM] %s\n' "$*"
}

cleanup() {
  if [[ -n "${ABRMD_PID:-}" ]]; then
    kill "${ABRMD_PID}" 2>/dev/null || true
  fi

  if [[ -n "${DBUS_PID:-}" ]]; then
    kill "${DBUS_PID}" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM

log "SWTPM remoto: ${SWTPM_HOST}:${SWTPM_PORT}"

# Attende che lo SWTPM sia raggiungibile.
SWTPM_READY=0

for _ in $(seq 1 50); do
  if TPM2TOOLS_TCTI="${DIRECT_TCTI}" tpm2_getrandom 4 >/dev/null 2>&1; then
    SWTPM_READY=1
    break
  fi

  sleep 0.2
done

if [[ "${SWTPM_READY}" != "1" ]]; then
  log "ERRORE: SWTPM non raggiungibile tramite ${DIRECT_TCTI}"
  exit 1
fi

# Rimuove soltanto oggetti e sessioni temporanei.
# Gli handle persistenti del dispositivo non vengono eliminati.
TPM2TOOLS_TCTI="${DIRECT_TCTI}" tpm2_flushcontext --transient-object 2>/dev/null || true
TPM2TOOLS_TCTI="${DIRECT_TCTI}" tpm2_flushcontext --loaded-session 2>/dev/null || true
TPM2TOOLS_TCTI="${DIRECT_TCTI}" tpm2_flushcontext --saved-session 2>/dev/null || true

# ---------------------------------------------------------------------------
# Preparazione sicura del machine-id.
#
# Alcune immagini Docker contengono /etc/machine-id vuoto. In quel caso
# dbus-uuidgen termina con errore. Il file viene quindi rigenerato quando:
# - non esiste;
# - è vuoto;
# - non contiene esattamente 32 caratteri esadecimali.
# ---------------------------------------------------------------------------
mkdir -p /run/dbus /var/lib/dbus

if [[ ! -s /etc/machine-id ]] || ! grep -Eq '^[0-9a-fA-F]{32}$' /etc/machine-id; then
  rm -f /etc/machine-id
  dbus-uuidgen --ensure=/etc/machine-id
fi

# Alcuni componenti D-Bus cercano anche questo percorso.
ln -sf /etc/machine-id /var/lib/dbus/machine-id

# Elimina eventuali file lasciati da precedenti avvii del container.
rm -f /run/dbus/pid /run/dbus/system_bus_socket /tmp/dbus.pid

# Avvia il bus di sistema D-Bus e salva il PID restituito.
dbus-daemon \
  --system \
  --fork \
  --print-pid=1 \
  --nopidfile \
  > /tmp/dbus.pid

DBUS_PID="$(tr -d '[:space:]' < /tmp/dbus.pid)"

if [[ -z "${DBUS_PID}" ]] || ! kill -0 "${DBUS_PID}" 2>/dev/null; then
  log "ERRORE: D-Bus non è stato avviato correttamente"
  exit 1
fi

log "D-Bus operativo con PID ${DBUS_PID}"

# Avvia il resource manager collegato allo SWTPM del dispositivo.
tpm2-abrmd \
  --allow-root \
  --logger=stdout \
  --tcti="${DIRECT_TCTI}" \
  > /tmp/tpm2-abrmd.log 2>&1 &

ABRMD_PID="$!"

# Attende che il TCTI tabrmd diventi operativo.
TABRMD_READY=0

for _ in $(seq 1 100); do
  if TPM2TOOLS_TCTI="${TABRMD_TCTI}" tpm2_getrandom 4 >/dev/null 2>&1; then
    TABRMD_READY=1
    break
  fi

  if ! kill -0 "${ABRMD_PID}" 2>/dev/null; then
    break
  fi

  sleep 0.1
done

if [[ "${TABRMD_READY}" != "1" ]]; then
  log "ERRORE: tpm2-abrmd non è diventato operativo"
  cat /tmp/tpm2-abrmd.log >&2 || true
  exit 1
fi

log "Resource manager operativo: ${TABRMD_TCTI}"

# Avvia il comando definito da Docker Compose.
"$@" &
COMMAND_PID="$!"

wait "${COMMAND_PID}"
