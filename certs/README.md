# Certificati generati localmente

Questa directory viene mantenuta nel repository soltanto tramite file `.gitkeep`.
Le chiavi private e i certificati generati non devono essere versionati né inclusi
nel pacchetto di consegna.

Generazione dei certificati infrastrutturali:

```bash
bash scripts/generate_certs.sh
```

Provisioning dei certificati utente-dispositivo con chiave custodita in SWTPM:

```bash
bash scripts/provision_tpm_devices.sh
```

Il secondo comando richiede Docker Compose e avvia temporaneamente i tre TPM
emulati. La chiave privata della CA rimane sul sistema host e non viene montata
nei container client.
