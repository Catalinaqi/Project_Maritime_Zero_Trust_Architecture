# Script – Maritime Zero Trust Architecture

La directory `scripts/` contiene tutti gli script necessari per la generazione della
PKI, il provisioning delle identità TPM, la verifica preliminare, l'avvio e la
pulizia dell'ambiente di test. Ogni script è documentato qui con il proprio
ruolo all'interno del modello **Never Trust, Always Verify**.

## Struttura

```text
scripts/
├── generate_certs.sh                # PKI infrastrutturale (CA, server, MongoDB)
├── generate_device_certs.sh         # Certificati utente-dispositivo con TPM
├── provision_tpm_devices.sh         # Provisioning TPM (legacy, tre device fissi)
├── identity_bindings.testing.conf   # Matrice identità per testing (setup-testing.ps1)
├── init_runtime.sh                  # Ripristino dati runtime dai template
├── preflight.sh                     # Verifica prerequisiti e certificati
├── clean_runtime.sh                 # Arresto stack e rimozione volumi runtime
└── setup-testing.ps1                # Preparazione automatica su Windows
```

---

## 1. `generate_certs.sh` – PKI Infrastrutturale

### Scopo

Genera la **CA radice** e tutti i certificati **server e client infrastrutturali**
necessari per il funzionamento dello stack. Le chiavi private generate non
vengono versionate né incluse nel repository.

### Cosa produce

| File                           | Ruolo ZTA                                    |
|--------------------------------|----------------------------------------------|
| `certs/ca/ca.crt`              | Trust anchor per tutti i componenti          |
| `certs/ca/ca.key`              | Chiave di firma offline (MAI nei container)  |
| `certs/server/server.crt`      | Certificato server Envoy (PEP)               |
| `certs/server/server.key`      | Chiave privata Envoy                         |
| `certs/mongodb/mongodb-server.pem` | Certificato + chiave MongoDB (TLS mutuale) |
| `certs/mongodb/api-client.pem` | Certificato client per API backend → MongoDB |
| `certs/mongodb/healthcheck-client.pem` | Certificato client per healthcheck MongoDB |

### Dettagli implementativi

- **CA**: RSA 4096 bit con validità 3650 giorni (`pathlen:1`).
- **Server**: RSA 3072 bit con validità 825 giorni; SAN includono nomi servizio
  (`pep_gateway`, `db_primary`), localhost e IP statici Docker.
- **Client MongoDB**: RSA 3072 bit con `extendedKeyUsage = clientAuth`, SAN
  con DNS del servizio chiamante.
- I file `.pem` sono concatenazioni di certificato e chiave per compatibilità
  con MongoDB.
- Al termine esegue `openssl verify` e controlla la presenza delle SAN attese.

### Principi ZTA applicati

- **Nessuna fiducia implicita**: ogni componente ha un certificato distinto.
- **Minimo privilegio**: i certificati client hanno `clientAuth`, quelli server
  `serverAuth`.
- **Segregazione delle chiavi**: `ca.key` resta sull'host e non è montata in
  alcun container.

---

## 2. `generate_device_certs.sh` – Certificati Utente-Dispositivo TPM

### Scopo

Genera **certificati X.509 client** per ogni coppia **utente-dispositivo**
definita nella matrice autorevole `configs/identity/identity_bindings.conf`.
La chiave privata viene generata **dentro il TPM emulato** (SWTPM) e non viene
mai esportata su filesystem come file.

### Flusso

1. **Validazione della matrice** – Controlla che ogni binding sia unico,
   l'handle TPM sia nel formato `0x81......`, il servizio e la rete corrispondano
   al dispositivo atteso.
2. **Build delle immagini client** – Ricostruisce i container client TPM.
3. **Avvio degli emulatori SWTPM** – `swtpm_d001`, `swtpm_d002`, `swtpm_dsoc`.
4. **Provisioning per ogni binding** – Per ogni riga della matrice:
   - Esegue `docker compose run --rm` del client con lo script
     `/scripts/provision_device_tpm.sh` che genera la coppia TPM, esporta la
     chiave pubblica e produce una CSR.
   - La CSR viene firmata dall'host usando `ca.key` (mai montata nel container).
   - Il certificato firmato viene copiato in
     `certs/devices/{device_id}/identities/{user_id}/identity.crt`.
   - Viene verificato che l'impronta della chiave pubblica nel certificato
     corrisponda a quella generata dal TPM.
   - Viene verificato il Subject (OU=user_id, CN=device_id) e il SAN URI
     SPIFFE.
5. **Generazione del manifest** `certs/devices/identity-certificates.tsv` con
   tutte le identità.

### Output

```
certs/devices/{device_id}/identities/{user_id}/
├── identity.crt                # Certificato X.509 firmato
├── identity_tpm_public.pem     # Chiave pubblica TPM (per verifica)
└── ca.crt                      # CA radice (per validazione locale)
```

### Principi ZTA applicati

- **Hardware-bound identity**: la chiave privata nasce e resta nel TPM.
- **Minimo privilegio**: ogni certificato contiene un SAN SPIFFE che identifica
  univocamente la coppia utente-dispositivo.
- **Verifica continua**: lo script controlla che la chiave pubblica nel
  certificato corrisponda a quella TPM, impedendo binding fraudolenti.

---

## 3. `provision_tpm_devices.sh` – Provisioning TPM di compatibilità

### Scopo

Versione precedente dello script di provisioning, mantenuta per compatibilità.
Provisiona **solo tre identità fisse** (un utente per dispositivo):

| Utente             | Dispositivo | Servizio          |
|--------------------|-------------|-------------------|
| `operatore_ancona` | D-001       | `client_d001_tpm` |
| `capitano_claudia` | D-002       | `client_d002_tpm` |
| `soc_admin`        | D-SOC       | `client_dsoc_tpm` |

### Differenze con `generate_device_certs.sh`

- Non legge la matrice `identity_bindings.conf` ma usa valori hardcoded.
- Produce un certificato singolo per dispositivo (`device.crt`), non per coppia
  utente-dispositivo.
- Il SAN URI è comunque `spiffe://maritime.local/users/{user_id}/devices/{device_id}`.

### Utilizzo

```bash
bash scripts/provision_tpm_devices.sh
```

Richiede Docker Compose e avvia temporaneamente i tre TPM emulati.

---

## 4. `identity_bindings.testing.conf` – Matrice per Testing

### Scopo

Matrice di identità utilizzata dallo script `setup-testing.ps1` per il
provisioning durante la preparazione automatica dell'ambiente su Windows.

Contiene 7 binding (stessi utenti e dispositivi di `identity_bindings.conf` ma
con handle TPM diversi `0x81000001`-`0x81000007`).

### Formato

```
USER_ID|DEVICE_ID|CLIENT_SERVICE|TPM_HANDLE|DEVICE_LOCATION|NETWORK_NAME
```

---

## 5. `init_runtime.sh` – Inizializzazione Runtime

### Scopo

Copia le baseline versionate da `configs/runtime-templates/` nei percorsi
mutabili usati da OPA e Splunk. I file generati sono ignorati da Git, quindi
l'esecuzione dei test non modifica lo stato del repository.

### Utilizzo

```bash
bash scripts/init_runtime.sh
```

---

## 6. `preflight.sh` – Verifica Preliminare

### Scopo

Controlla che tutti i prerequisiti siano soddisfatti prima di avviare lo stack.

### Verifiche effettuate

1. **File obbligatori**:
   - `.env` – configurazione ambiente
   - `docker-compose.yml` – definizione dello stack
   - `certs/ca/ca.crt` – CA radice
   - `certs/server/server.crt` e `.key` – certificato Envoy
   - `certs/mongodb/mongodb-server.pem`, `api-client.pem`,
     `healthcheck-client.pem` – certificati MongoDB
   - `configs/envoy/mongo_inspector_active.lua` – filtro Lua
   - `configs/opa/policies/authorization.rego` – policy OPA
   - `configs/opa/data/risk_data/risk_scores.json` – stato runtime OPA
   - `configs/splunk/apps/opa_risk_updater/lookups/historical_risk_scores.csv` – lookup runtime Splunk
2. **Docker Compose**: versione >= 2.36.0.
3. **Validazione Compose**: `docker compose config --quiet`.

Esce con codice 1 in caso di errori.

### Principi ZTA applicati

- **Nessuna fiducia implicita**: tutto è verificato prima dell'avvio, non
  durante.

---

## 7. `clean_runtime.sh` – Pulizia Runtime

### Scopo

Arresta lo stack Docker e rimuove tutti i container, le reti e i volumi
runtime creati durante l'esecuzione.

### Cosa rimuove

- Container con profilo `testing`.
- Reti Docker create da Compose.
- Volumi Docker (inclusi quelli TPM e dei log).

Al termine ripristina anche i dati runtime dai template versionati.

### Cosa NON rimuove

- Certificati locali in `certs/`.
- File di configurazione.

### Utilizzo

```bash
bash scripts/clean_runtime.sh
```

---

## 8. `setup-testing.ps1` – Preparazione Automatica (Windows)

### Scopo

Script PowerShell per preparare l'ambiente di test su Windows con un solo
comando. Esegue in sequenza:

1. **Controllo prerequisiti**: Docker Desktop, Docker Compose, Git Bash.
2. **Creazione `.env`**: se mancante, parte da `.env.example` con credenziali
   dimostrative e token HEC univoco.
3. **Inizializzazione runtime**: ripristina risk score e lookup dai template.
4. **Validazione Compose**: `docker compose --profile testing config --quiet`.
5. **Generazione PKI infrastrutturale**: se i certificati non esistono già,
   esegue `bash scripts/generate_certs.sh`.
6. **Provisioning TPM**: esegue `bash scripts/generate_device_certs.sh` con
   `BINDINGS_FILE=scripts/identity_bindings.testing.conf`.
7. **Preflight**: esegue `bash scripts/preflight.sh`.
8. **Avvio stack**: `docker compose --profile testing up -d --build`.
9. **Attesa healthcheck**: per ogni servizio, attende fino a 360 secondi
   (720 per Splunk).

### Parametri

- `-SkipBuild`: se specificato, salta la ricostruzione delle immagini Docker.

### Principi ZTA applicati

- **Automazione della fiducia**: tutto è generato e verificato
  automaticamente, senza intervento manuale che potrebbe introdurre errori.

---

## Note operative

- **Ordine di esecuzione consigliato**:
  1. `bash scripts/generate_certs.sh`
  2. `bash scripts/generate_device_certs.sh` (o `provision_tpm_devices.sh`)
  3. `bash scripts/init_runtime.sh`
  4. `bash scripts/preflight.sh`
  5. `docker compose up -d --build`

- Su Windows, usare `setup-testing.ps1` per automatizzare tutti i passaggi.

- Dopo ogni modifica alla matrice `configs/identity/identity_bindings.conf`,
  è necessario **rieseguire** `generate_device_certs.sh` per allineare i
  certificati.

- I certificati generati NON devono essere versionati. La directory `certs/`
  esiste soltanto localmente ed è ignorata interamente da Git.
