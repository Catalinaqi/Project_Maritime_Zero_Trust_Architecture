# Maritime Zero Trust Architecture

Progetto universitario — Università Politecnica delle Marche, 2026.  
Corso: Ingegneria dell'Informazione — Tema: Zero Trust Architecture.

Il progetto simula una Zero Trust Architecture per un ambiente marittimo portuale.
Ogni richiesta viene autorizzata valutando congiuntamente identità utente, dispositivo,
rete sorgente, risorsa richiesta, operazione, finestra temporale e rischio dinamico.

---

## Architettura

```text
Client con SWTPM (certificato hardware-bound)
      │
      │  mTLS (CN=utente, SAN URI spiffe://.../users/<u>/devices/<d>)
      ▼
NFTables firewall ──── Snort 3 IDS (modalità passiva)
      │
      │  DNAT verso Envoy, IP sorgente preservato
      ▼
Envoy PEP ──── gRPC ext_authz ──── OPA PDP ──── decision log ──── Splunk
      │
      │  HTTP interno (x-zta-* headers)
      ▼
API backend (Node.js / Express)
      │
      │  mTLS + account applicativo a privilegi minimi
      ▼
MongoDB (TLS obbligatorio)
```

Il comportamento predefinito della policy è **deny**.  
La rete `backend_net` e `monitoring_net` sono reti Docker interne non accessibili
direttamente dall'esterno.

---

## Componenti

| Servizio              | Ruolo                                                         |
|-----------------------|---------------------------------------------------------------|
| `firewall_perimeter`  | Routing perimetrale DNAT, filtraggio L3/L4, log NFTables      |
| `ids_network_monitor` | IDS Snort 3 passivo sul percorso client-firewall              |
| `pep_gateway`         | Envoy: terminazione mTLS, ext_authz gRPC verso OPA            |
| `pdp_engine`          | OPA: policy ABAC, decision log su Splunk                      |
| `api_backend`         | API REST per MongoDB; non esposta direttamente ai client       |
| `db_primary`          | MongoDB 7: TLS obbligatorio, account applicativo limitato     |
| `siem_central`        | Splunk Enterprise: HEC, alert, calcolo risk score dinamico    |
| `swtpm_*`             | TPM emulati (profilo `testing`)                               |
| `client_*_tpm`        | Client dimostrativi con chiave nel TPM (profilo `testing`)    |

---

## Struttura delle directory

```
configs/
  envoy/          Configurazione Envoy e filtro Lua
  mongodb/        mongod.conf e script di inizializzazione
  nftables/       Regole NFTables perimetrali
  opa/            Policy Rego, dati statici, config OPA
  snort/          snort-zta.lua e regole IDS
  splunk/         default.yml e app opa_risk_updater
scripts/
  generate_certs.sh       Genera la PKI infrastrutturale
  provision_tpm_devices.sh Provisioning certificati utente-dispositivo via SWTPM
  preflight.sh            Verifica prerequisiti prima dell'avvio
  clean_runtime.sh        Rimuove container, reti e volumi
services/
  api_backend/    Dockerfile e server Node.js
  clients_tpm/    Dockerfile e script richiesta mTLS con TPM
  envoy/          Dockerfile ed entrypoint (route di ritorno)
  nftables/       Dockerfile ed entrypoint (ulogd + HEC)
  snort/          Dockerfile multi-stage (build Snort 3)
  swtpm/          Dockerfile e SWTPM emulato
certs/            Directory vuote (generate localmente, escluse da Git)
tests/            Riservato ai test automatici del gruppo
```

---

## Prerequisiti

- Docker Desktop con **Docker Compose ≥ 2.36.0**
  (il naming deterministico delle interfacce Snort/NFTables richiede questa versione)
- Almeno **8 GB RAM** assegnati a Docker (consigliati 10-12 GB per Splunk + Snort)
- **OpenSSL** e **Bash** per la generazione dei certificati
- Su Windows: **Git Bash** oppure **WSL** per eseguire gli script `.sh`

---

## 1. Configurazione del file `.env`

**Git Bash, WSL o Linux:**
```bash
cp .env.example .env
# Modificare le password CHANGE_ME e il token HEC
```

**PowerShell:**
```powershell
Copy-Item .env.example .env
notepad .env
```

Sostituire obbligatoriamente:

| Variabile             | Descrizione                                      |
|-----------------------|--------------------------------------------------|
| `MONGO_ROOT_PASSWORD` | Password amministrativa MongoDB                  |
| `MONGO_APP_PASSWORD`  | Password account applicativo MongoDB             |
| `SPLUNK_PASSWORD`     | Password admin Splunk (min. 8 caratteri)         |
| `SPLUNK_HEC_TOKEN`    | UUID valido per l'HTTP Event Collector di Splunk |

---

## 2. Generazione dei certificati

Da **Git Bash, WSL o Linux**, nella directory principale del progetto:

```bash
bash scripts/generate_certs.sh
```

Lo script genera:

- **CA radice** (`certs/ca/`)
- **Certificato server Envoy** (`certs/server/`) — SAN: `pep_gateway`, `localhost`
- **Certificato server MongoDB** (`certs/mongodb/`) — SAN: `db_primary`
- **Certificato client API backend** (`certs/mongodb/api-client.pem`)
- **Certificato client healthcheck** (`certs/mongodb/healthcheck-client.pem`)

Le chiavi private non sono incluse nello ZIP e sono escluse da Git (`.gitignore`).

---

## 3. Provisioning TPM dei dispositivi

Il certificato client lega l'identità utente al dispositivo tramite SAN URI SPIFFE.
La chiave privata non viene esportata: rimane nel volume del TPM emulato.

```bash
bash scripts/provision_tpm_devices.sh
```

| Utente             | Ruolo                  | Dispositivo | Rete        |
|--------------------|------------------------|-------------|-------------|
| `operatore_ancona` | `ruolo_banchina`       | `D-001`     | VPN         |
| `capitano_claudia` | `ruolo_equipaggio`     | `D-002`     | Satellite   |
| `soc_admin`        | `ruolo_gestione_flotta`| `D-SOC`     | Corporate   |

---

## 4. Verifica preliminare

```bash
bash scripts/preflight.sh
```

Verifica la presenza dei certificati, del file `.env` e la validità del Compose.

---

## 5. Avvio del progetto

```bash
docker compose up -d --build
```

La prima build di Snort 3 richiede diversi minuti. Splunk impiega fino a 4 minuti
per diventare disponibile.

Verifica lo stato:

```bash
docker compose ps
docker compose logs --tail 50 siem_central pdp_engine pep_gateway
```

---

## 6. Accesso a Splunk

URL: `http://localhost:8000`

- Utente: `admin`
- Password: valore `SPLUNK_PASSWORD` nel file `.env`

Query utili:

```spl
index=main sourcetype=opa_decision
index=main sourcetype=snort_alert_json
index=main sourcetype=nftables
index=main sourcetype=mongodb_log
index=main sourcetype=envoy_access_json
```

---

## 7. Richieste dimostrative

Avviare i client TPM:

```bash
docker compose --profile testing up -d
```

**Operatore Ancona** (lettura manifesto carico):
```bash
docker compose --profile testing exec client_d001_tpm \
  env METHOD=GET PATH_URL=/risorse/R-001 /scripts/request_with_tpm.sh
```

**Capitano** (lettura telemetria motori):
```bash
docker compose --profile testing exec client_d002_tpm \
  env METHOD=GET PATH_URL=/risorse/R-002 /scripts/request_with_tpm.sh
```

**SOC admin** (lettura globale):
```bash
docker compose --profile testing exec client_dsoc_tpm \
  env METHOD=GET PATH_URL=/all /scripts/request_with_tpm.sh
```

**SOC admin** (aggiornamento report sicurezza):
```bash
docker compose --profile testing exec client_dsoc_tpm \
  env METHOD=PUT PATH_URL=/risorse/R-003 \
  REQUEST_BODY='{"severita_massima":"critica"}' \
  /scripts/request_with_tpm.sh
```

---

## Flusso di autenticazione e autorizzazione

1. Il client presenta un certificato firmato dalla CA; la chiave RSA è nel TPM.
2. Envoy esegue il TLS handshake mTLS e verifica la CA.
3. Il filtro Lua estrae `user_id` e `device_id` dal SAN URI del certificato:  
   `spiffe://maritime.local/users/<utente>/devices/<dispositivo>`
4. OPA valuta i seguenti attributi (policy ABAC):
   - **Utente**: esiste nei ruoli? ha i permessi sulla risorsa e comando?
   - **Dispositivo**: esiste ed è trusted?
   - **Rete**: l'IP sorgente appartiene a una rete nota?
   - **Binding**: esiste una regola che lega utente + dispositivo + rete?
   - **Orario**: la richiesta è nella finestra temporale consentita?
   - **Rischio**: il risk score dinamico è sotto la soglia del ruolo?
5. Se OPA risponde `allow`, Envoy aggiunge gli header `x-zta-*` e invia la richiesta al backend.
6. OPA invia la decisione a Splunk tramite HEC.
7. La saved search di Splunk ricalcola il risk score ogni minuto e aggiorna il JSON letto da OPA.

---

## Gestione del rischio dinamico

Il risk score viene ricalcolato ogni minuto dalla saved search `Calcolo Dinamico Risk Score OPA`.  
La logica è:

| Condizione                        | Risk Score |
|-----------------------------------|------------|
| denied_count > 10                 | 95         |
| denied_count > 5                  | 80         |
| denied_count > 2                  | 50         |
| unique_sources > 3                | 40         |
| nessuna anomalia                  | 10         |

Soglie massime per ruolo:

| Ruolo                   | Max Risk Score |
|-------------------------|----------------|
| `ruolo_banchina`        | 50             |
| `ruolo_equipaggio`      | 70             |
| `ruolo_gestione_flotta` | 80             |

---

## Reti Docker

| Rete              | CIDR predefinito   | Tipo     | Scopo                              |
|-------------------|--------------------|----------|------------------------------------|
| `zerotrust_net`   | `172.20.2.0/24`    | Bridge   | Envoy, OPA, firewall perimetrale   |
| `backend_net`     | `172.20.3.0/24`    | Interno  | Envoy, API backend, MongoDB        |
| `monitoring_net`  | `172.20.4.0/24`    | Interno  | OPA, firewall, Splunk              |
| `corporate_net`   | `172.20.10.0/24`   | Bridge   | SOC e dispositivi corporate        |
| `vpn_net`         | `172.20.11.0/24`   | Bridge   | Operatori remoti via VPN           |
| `satellite_net`   | `172.20.12.0/24`   | Bridge   | Dispositivi di bordo               |
| `public_net`      | `172.20.13.0/24`   | Bridge   | Segmento non fidato                |

Le reti `backend_net` e `monitoring_net` sono dichiarate `internal: true`: i container
su queste reti non hanno accesso a Internet e non sono raggiungibili dall'host.

---

## Arresto e pulizia

Arresto standard:
```bash
docker compose --profile testing down
```

Pulizia completa (container, reti, volumi):
```bash
bash scripts/clean_runtime.sh
```

I certificati locali **non** vengono eliminati dallo script di pulizia.

---

## Risoluzione dei problemi più comuni

**Errore "certificati mancanti" all'avvio di Envoy o MongoDB**  
→ Eseguire `bash scripts/generate_certs.sh`

**Il client TPM non trova `device.crt`**  
→ Eseguire `bash scripts/provision_tpm_devices.sh`  
→ Se la CA è stata rigenerata, rigenerare anche i certificati TPM

**Splunk resta in stato `unhealthy` per più di 5 minuti**  
→ Controllare con `docker logs siem_central`  
→ Se il volume esiste da una versione precedente, eseguire `bash scripts/clean_runtime.sh` e riavviare

**Conflitto tra subnet Docker e VPN locale**  
→ Modificare tutte le variabili `NETWORK_*_SUBNET` in `.env`  
→ Aggiornare gli indirizzi IP statici in `docker-compose.yml` e i CIDR in `configs/opa/data/networks.json`

**Envoy restituisce HTTP 503 invece di 403**  
→ OPA non è ancora disponibile o supera il timeout (1s); attendere che `pdp_engine` sia healthy

---

## Note di sicurezza

- Il progetto è una simulazione didattica, non una configurazione production-ready.
- Splunk HEC usa HTTP solo sulla rete Docker interna `monitoring_net`.
- L'interfaccia REST di OPA è pubblicata su `127.0.0.1` per uso amministrativo locale.
- Snort opera in modalità passiva: il payload TLS è cifrato e non ispezionabile.
- L'identità hardware è simulata con SWTPM; su hardware reale si userebbe un TPM fisico o Secure Enclave.
- JA3 è conservato come dato informativo nel seed MongoDB; il certificato hardware-bound è l'identità primaria.

---

## Limitazioni note

- MongoDB è un'istanza singola (non replica set); la consegna non richiede la replica.
- Splunk HEC usa HTTP sulla rete interna (non HTTPS); il traffico non lascia mai Docker.
- Il naming deterministico delle interfacce NFTables/Snort richiede Docker Compose ≥ 2.36.0.
- I test automatici sono gestiti separatamente dal gruppo.
