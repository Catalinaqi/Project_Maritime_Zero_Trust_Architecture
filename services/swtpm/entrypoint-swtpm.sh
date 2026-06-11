#!/bin/bash

set -e

echo "============================================================"
echo " SWTPM - TPM emulato per dispositivo"
echo "============================================================"

TPM_STATE_DIR="${TPM_STATE_DIR:-/var/lib/swtpm}"
TPM_SERVER_PORT="${TPM_SERVER_PORT:-2321}"
TPM_CTRL_PORT="${TPM_CTRL_PORT:-2322}"

mkdir -p "$TPM_STATE_DIR"

echo "[INFO] TPM state directory: $TPM_STATE_DIR"
echo "[INFO] TPM server port:     $TPM_SERVER_PORT"
echo "[INFO] TPM control port:    $TPM_CTRL_PORT"

# Avvio SWTPM in modalità TPM 2.0.
# Porta 2321: canale comandi TPM.
# Porta 2322: canale controllo TPM.
# startup-clear inizializza il TPM all'avvio mantenendo lo stato nella cartella persistente.
exec swtpm socket \
  --tpm2 \
  --tpmstate dir="$TPM_STATE_DIR" \
  --server type=tcp,port="$TPM_SERVER_PORT",bindaddr=0.0.0.0 \
  --ctrl type=tcp,port="$TPM_CTRL_PORT",bindaddr=0.0.0.0 \
  --flags not-need-init,startup-clear