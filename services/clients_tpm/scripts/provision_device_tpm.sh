#!/bin/bash

set -e

echo "============================================================"
echo " Provisioning TPM-backed device certificate"
echo "============================================================"

DEVICE_ID="${DEVICE_ID:-D-001}"
DEVICE_LOCATION="${DEVICE_LOCATION:-Terminal-Ancona}"

TPM_HANDLE="${TPM_HANDLE:-0x81000001}"

TPM_DIR="/tpm/${DEVICE_ID}"
CERT_DIR="/certs/device"

CA_CERT="/ca/ca.crt"
CA_KEY="/ca/ca.key"

mkdir -p "$TPM_DIR" "$CERT_DIR"

echo "[INFO] Device ID:        $DEVICE_ID"
echo "[INFO] Device location:  $DEVICE_LOCATION"
echo "[INFO] TPM handle:       $TPM_HANDLE"
echo "[INFO] TPM2TOOLS_TCTI:   ${TPM2TOOLS_TCTI:-not_set}"
echo "[INFO] TPM2OPENSSL_TCTI: ${TPM2OPENSSL_TCTI:-not_set}"

if [ ! -f "$CA_CERT" ]; then
  echo "[ERROR] CA certificate not found: $CA_CERT"
  exit 1
fi

if [ ! -f "$CA_KEY" ]; then
  echo "[ERROR] CA private key not found: $CA_KEY"
  echo "Per firmare la CSR TPM-backed serve montare anche certs/ca/ca.key nel container di provisioning."
  exit 1
fi

echo "[1/8] Verifica connessione al TPM emulato..."

tpm2_getrandom 8 >/dev/null

echo "[OK] TPM raggiungibile."

echo "[2/8] Pulizia aggressiva dello stato transitorio TPM..."

# Pulisce oggetti transitori e sessioni eventualmente rimaste aperte.
tpm2_flushcontext -t 2>/dev/null || true
tpm2_flushcontext -s 2>/dev/null || true
tpm2_flushcontext -l 2>/dev/null || true

echo "[3/8] Rimozione eventuale handle persistente precedente..."

# Se l'handle esiste già, lo libera.
tpm2_evictcontrol -C o -c "$TPM_HANDLE" 2>/dev/null || true

tpm2_flushcontext -t 2>/dev/null || true
tpm2_flushcontext -s 2>/dev/null || true
tpm2_flushcontext -l 2>/dev/null || true

rm -f \
  "$TPM_DIR/device_primary.ctx" \
  "$CERT_DIR/device.crt" \
  "$CERT_DIR/device.csr" \
  "$CERT_DIR/device_tpm_public.pem"

echo "[4/8] Creazione chiave primaria TPM usata come identità device..."

# In questa versione usiamo direttamente una primary key persistente come chiave device.
# Questo evita il passaggio tpm2_load, che nel tuo SWTPM sta fallendo per saturazione
# degli object contexts.
tpm2_createprimary \
  -C o \
  -G rsa \
  -g sha256 \
  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign" \
  -c "$TPM_DIR/device_primary.ctx"

echo "[5/8] Persistenza della chiave device su handle $TPM_HANDLE..."

tpm2_evictcontrol \
  -C o \
  -c "$TPM_DIR/device_primary.ctx" \
  "$TPM_HANDLE"

# Dopo la persistenza, libero i contesti transitori.
tpm2_flushcontext -t 2>/dev/null || true
tpm2_flushcontext -s 2>/dev/null || true
tpm2_flushcontext -l 2>/dev/null || true

echo "[6/8] Esportazione della sola chiave pubblica per audit/debug..."

tpm2_readpublic \
  -c "$TPM_HANDLE" \
  -f pem \
  -o "$CERT_DIR/device_tpm_public.pem"

echo "[7/8] Generazione CSR con chiave TPM-backed..."

openssl req -new \
  -provider tpm2 \
  -provider default \
  -key "handle:${TPM_HANDLE}" \
  -out "$CERT_DIR/device.csr" \
  -subj "/O=Maritime_Zero_Trust/OU=Device/CN=${DEVICE_ID}/L=${DEVICE_LOCATION}"

echo "[8/8] Firma della CSR con la CA del progetto..."

openssl x509 -req \
  -days 365 \
  -sha256 \
  -in "$CERT_DIR/device.csr" \
  -CA "$CA_CERT" \
  -CAkey "$CA_KEY" \
  -CAcreateserial \
  -out "$CERT_DIR/device.crt"

rm -f "$CERT_DIR/device.csr"

echo ""
echo "============================================================"
echo " Certificato TPM-backed generato correttamente"
echo "============================================================"
echo "Certificato device:"
echo "  $CERT_DIR/device.crt"
echo ""
echo "Chiave privata:"
echo "  NON esportata come device.key"
echo "  conservata nel TPM emulato SWTPM"
echo "  handle: $TPM_HANDLE"
echo ""
echo "Chiave pubblica esportata:"
echo "  $CERT_DIR/device_tpm_public.pem"
echo "============================================================"