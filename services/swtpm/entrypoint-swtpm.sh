#!/bin/bash
# Avvia un emulatore TPM 2.0 persistente esposto sulle porte TCP configurate.
set -euo pipefail

TPM_STATE_DIR="${TPM_STATE_DIR:-/var/lib/swtpm}"
TPM_SERVER_PORT="${TPM_SERVER_PORT:-2321}"
TPM_CTRL_PORT="${TPM_CTRL_PORT:-2322}"
mkdir -p "$TPM_STATE_DIR"

exec swtpm socket \
  --tpm2 \
  --tpmstate dir="$TPM_STATE_DIR" \
  --server type=tcp,port="$TPM_SERVER_PORT",bindaddr=0.0.0.0 \
  --ctrl type=tcp,port="$TPM_CTRL_PORT",bindaddr=0.0.0.0 \
  --flags not-need-init,startup-clear
