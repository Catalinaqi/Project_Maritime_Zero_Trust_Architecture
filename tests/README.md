# Test

La suite applicativa autorevole della versione corrente si avvia dalla radice del
progetto con:

```bash
bash tests/run_project_tests.sh
```

Il runner esegue gli accessi consentiti, gli accessi negati, i fallimenti mTLS e
il risk score dinamico integrato con Splunk e Snort.

Gli script `run_audit_snort.sh`, `run_audit_nftables.sh`, `config_audit.sh` e il
materiale in `docs/` sono verifiche separate o storiche e non vengono eseguiti
automaticamente dal runner principale.

Per la verifica preliminare della configurazione usare:

```bash
bash scripts/preflight.sh
```
