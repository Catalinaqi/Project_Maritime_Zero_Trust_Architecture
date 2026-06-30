# Servizi – Maritime Zero Trust Architecture

La directory `services/` contiene i Dockerfile, gli entrypoint e gli script
dei componenti costruiti localmente. OPA, MongoDB e Splunk usano invece le
immagini ufficiali dichiarate nel Compose. La documentazione
seguente descrive il ruolo di ciascun componente all'interno del modello
**Never Trust, Always Verify**.

## Struttura

```text
services/
├── envoy/                # Policy Enforcement Point (Envoy)
│   ├── Dockerfile
│   └── entrypoint.sh
├── snort/                # IDS passivo Snort 3
│   ├── Dockerfile
│   └── entrypoint.sh
├── swtpm/                # Emulatore TPM 2.0 software
│   ├── Dockerfile
│   └── entrypoint-swtpm.sh
├── clients_tpm/          # Client dimostrativo con TPM emulato
│   ├── Dockerfile
│   └── scripts/
│       ├── client-entrypoint.sh
│       ├── request_with_tpm.sh
│       ├── generate_device_csr.sh
│       └── provision_device_tpm.sh
├── nftables/             # Firewall perimetrale NFTables
│   ├── Dockerfile
│   └── entrypoint.sh
├── api_backend/          # API REST Node.js / Express
│   ├── Dockerfile
│   ├── server.js
│   ├── package.json
│   └── package-lock.json
```

---

## 1. OPA – Policy Decision Point (PDP)

### Immagine

Utilizza l'immagine ufficiale OPA (definita in `docker-compose.yml`).
Non è presente un Dockerfile personalizzato nel repository.

### Ruolo ZTA

OPA è il **cuore delle decisioni di accesso**. Riceve da Envoy il contesto
della richiesta (utente, dispositivo, rete, risorsa, comando) tramite
gRPC `ext_authz` e valuta la policy ABAC definita in
`configs/opa/policies/authorization.rego`.

- Policy di default: **deny**.
- Dati statici: ruoli, dispositivi, reti, regole di accesso, risk score
  (da `configs/opa/data/`).
- Risk score dinamico: letto da `risk_scores.json`, aggiornato da Splunk.
- La risposta include header `x-zta-*` e, in caso di diniego, motivazioni
  dettagliate nel body HTTP 403.

---

## 2. `envoy/` – Policy Enforcement Point (PEP)

### Dockerfile

Basato su `envoyproxy/envoy:v1.30-latest`. Installa `curl` (per healthcheck)
e `iproute2` (per aggiungere le route di ritorno verso le reti client).

### Entrypoint: `entrypoint.sh`

Verifica la presenza dei file TLS (`/certs/server.crt`, `/certs/server.key`,
`/ca/ca.crt`) prima di avviare Envoy con il comando ricevuto.

### Ruolo ZTA

- **Terminazione mTLS**: richiede certificato client (`require_client_certificate:
  true`), verifica contro la CA del progetto.
- **Filtro Lua**: estrae `user_id` e `device_id` dal SAN URI SPIFFE del
  certificato client e li inserisce nel contesto per OPA.
- **Autorizzazione**: tramite filtro `ext_authz` gRPC verso OPA.
- **Routing**: solo dopo autorizzazione, inoltra la richiesta al backend API.
- **Access log JSON**: inviato a Splunk per auditing.
- **Route di ritorno**: le route verso le reti client sono configurate nel
  Compose per garantire il forward corretto dei pacchetti.

---

## 3. `snort/` – IDS Passivo (Network Monitoring)

### Dockerfile

Build multi-stage da `ubuntu:22.04`:

1. **Builder**: compila `libdaq` (v3.0.20) e `Snort 3` (v3.9.2.0) da sorgente
   con 2 job paralleli per limitare il consumo di RAM.
2. **Runtime**: immagine snella con librerie e binari; installa `tini` come
   init, `envsubst` per sostituzione variabili, `jq`, `curl`, `ethtool`, ecc.

### Entrypoint: `entrypoint.sh`

1. Verifica binario Snort e file di configurazione.
2. Prepara directory log e permessi.
3. Valida le variabili ZTA (subnet, porte) dal compose.
4. Genera la configurazione finale tramite `envsubst`.
5. Esegue la validazione Snort (`-T`) con la DAQ afpacket.
6. Avvia Snort in **modalità passiva** (`--daq afpacket`, senza `-Q`)
   sulle interfacce condivise con il firewall.

### Ruolo ZTA

- **Continuous monitoring**: osserva tutto il traffico `client → firewall → PEP`.
- Nessuna azione in linea (modalità passiva): non può bloccare ma rileva
  tentativi di bypass, scansioni, injection, movimenti laterali.
- I log confluiscono in Splunk tramite volume condiviso e `inputs.conf`.
- Le regole (35+ alert) coprono ricognizione, DoS, bypass del PEP, anomalie
  TLS, injection, esfiltrazione, movimento laterale, brute force e
  manipolazione del piano di controllo OPA.

---

## 4. `swtpm/` – Emulatore TPM 2.0 Software

### Dockerfile

Basato su `ubuntu:22.04`. Installa `swtpm` e `swtpm-tools`.

### Entrypoint: `entrypoint-swtpm.sh`

Avvia `swtpm socket` in modalità TPM 2.0:

- `--tpm2`: abilita TPM 2.0.
- `--tpmstate dir`: directory di stato persistente (montata come volume Docker).
- `--server type=tcp,port=2321`: esposizione del server TPM su TCP.
- `--ctrl type=tcp,port=2322`: porta di controllo.
- `--flags not-need-init,startup-clear`: non richiede inizializzazione e
  avvia in stato clear.

### Ruolo ZTA

- **Hardware-bound identity simulata**: la chiave privata del dispositivo
  viene generata dentro questo TPM emulato e non è mai esportabile.
- Ogni dispositivo demo (D-001, D-002, D-SOC) ha un container SWTPM dedicato.

---

## 5. Splunk – SIEM Splunk Enterprise

### Immagine

Utilizza l'immagine ufficiale Splunk (definita in `docker-compose.yml`).
Non è presente Dockerfile personalizzato.

### Ruolo ZTA

- **Centralizzazione dei log**: riceve e indicizza decision log OPA, alert
  Snort, log firewall (NFTables via HEC), log MongoDB e log Envoy.
- **Risk score dinamico**: tramite l'app `opa_risk_updater`, calcola ogni
  minuto il rischio per ogni utente e aggiorna il file JSON letto da OPA.
- **Baseline completa**: il lookup `risk_user_baseline.csv` mantiene nel
  risultato anche gli utenti senza eventi negli ultimi cinque minuti.
- **Correlazione eventi**: la saved search combina decision log e alert IDS
  per determinare anomalie (tentativi negati, traffico sospetto, ecc.).

---

## 6. `clients_tpm/` – Client di test con TPM

### Dockerfile

Basato su `ubuntu:22.04`. Installa:

- `tpm2-tools`, `tpm2-openssl`, `tpm2-abrmd`: toolchain TPM 2.0.
- `libtss2-tcti-swtpm0`, `libtss2-tcti-mssim0`, `libtss2-tcti-tabrmd0`:
  TCTI per connettersi allo SWTPM remoto.
- `iproute2`, `iputils-ping`, `curl`: strumenti di rete per test.
- Il provider OpenSSL TPM2 (`tpm2.so`) viene linkato in `/usr/local/lib/ossl-modules/`.

### Scripts

#### `client-entrypoint.sh`

Avviato come ENTRYPOINT del container. Esegue:

1. Attende che lo SWTPM remoto sia raggiungibile (connessione TCP sulla
   porta 2321).
2. Flush dei contesti TPM temporanei.
3. Genera `machine-id` se assente (necessario per D-Bus).
4. Avvia `dbus-daemon` (bus di sistema).
5. Avvia `tpm2-abrmd` collegato allo SWTPM remoto tramite TCTI diretto.
6. Attende che il resource manager sia operativo (TCTI tabrmd).
7. Esegue il comando passato (solitamente `bash` o lo script di richiesta).

**Ruolo ZTA**: rende disponibile l'identità hardware-bound via resource
manager, permettendo a OpenSSL e tpm2-tools di usare la chiave persistente
senza esportarla.

#### `provision_device_tpm.sh`

Eseguito durante il provisioning (da `generate_device_certs.sh`). Crea o
riutilizza una **chiave primaria TPM persistente** e genera la CSR:

1. Verifica la connessione al TPM.
2. Se l'handle TPM non esiste o `FORCE_REPROVISION=1`, crea una nuova
   chiave primaria (`tpm2_createprimary`) con attributi
   `fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign`.
3. Rende la chiave persistente con `tpm2_evictcontrol`.
4. Esporta la sola chiave pubblica in formato PEM.
5. Genera la CSR usando il provider `tpm2` di OpenSSL, con Subject
   `/O=Maritime_Zero_Trust/OU={user_id}/CN={device_id}/L={device_location}`.
6. La CSR viene firmata dall'host (fuori dal container).

**Ruolo ZTA**: l'identità utente-dispositivo è legata a una chiave che
non può lasciare il TPM.

#### `generate_device_csr.sh`

Versione alternativa (legacy) per singolo dispositivo demo. Genera la CSR
con Subject `/O=Maritime_Zero_Trust/OU={device_id}/CN={user_id}`.

#### `request_with_tpm.sh`

Invia una richiesta HTTPS mTLS firmata con la chiave TPM:

1. Legge `METHOD`, `PATH_URL`, `TPM_HANDLE`, `DEVICE_CERT`, `CA_CERT`.
2. Costruisce la richiesta HTTP (con eventuale body JSON).
3. Apre una connessione `openssl s_client` con:
   - `-tls1_2`: solo TLS 1.2.
   - `-cert <device.crt>`: certificato client.
   - `-key handle:<TPM_HANDLE>`: usa la chiave nel TPM tramite provider tpm2.
   - `-provider tpm2 -provider default`: carica i provider OpenSSL.
   - Senza verifica del server se `VERIFY_SERVER=0` (default per demo).

**Ruolo ZTA**: dimostra l'autenticazione forte con chiave hardware-bound;
la richiesta può passare solo se Envoy accetta il certificato e OPA
autorizza la coppia utente-dispositivo-rete.

---

## 7. `nftables/` – Firewall Perimetrale

### Dockerfile

Basato su `debian:12.14-slim`. Installa:

- `nftables`: il firewall stesso.
- `ulogd2`: demone di logging NFLOG.
- `iproute2`: per rinominare le interfacce.
- `curl`, `jq`: per inviare log a Splunk HEC.
- `gettext-base`: per `envsubst`.
- `tini`: init leggero.

### Entrypoint: `entrypoint.sh`

1. Verifica la presenza dei comandi necessari.
2. Valida le variabili d'ambiente obbligatorie.
3. **Rinomina le interfacce di rete**: assegna nomi logici (corp0, vpn0,
   sat0, public0, zt0, monitor0) in base agli IP statici, necessario
   perché Docker Compose assegna nomi ethX non predicibili.
4. Esegue `envsubst` sulle regole NFTables (`rules.nft`).
5. Valida la sintassi (`nft -c`) e carica le regole (`nft -f`).
6. Configura e avvia `ulogd` per catturare i log NFGROUP 0 (pacchetti
   scartati).
7. Avvia uno script di forward logs verso Splunk HEC in background con
   `tail -F` + `curl`.
8. Entra in un loop di monitoraggio (ogni 60 s) che verifica la presenza
   del ruleset e lo ripristina se accidentalmente flushato.

### Ruolo ZTA

- **Segmentazione di rete**: solo le connessioni verso Envoy (porta 8443)
  dalle reti autorizzate sono permesse in FORWARD.
- **Movimento laterale bloccato**: regole DROP esplicite tra VPN, satellite,
  corporate e public.
- **Logging continuo**: tutti i pacchetti scartati vengono loggati via
  NFLOG e inviati a Splunk HEC per analisi.
- **Source IP preservation**: il DNAT non effettua SNAT, quindi l'indirizzo
  originale del client è visibile a Envoy e OPA.

---

## 8. `api_backend/` – API REST Backend

### Dockerfile

Basato su `node:20-alpine`. Installa solo dipendenze di produzione
(`express`, `mongodb`), copia `server.js` e avvia con utente non
privilegiato (`node`).

### `server.js`

API REST Express che:

- Legge gli header **x-zta-user-id**, **x-zta-device-id**, **x-zta-network**,
  **x-zta-risk-score** inseriti da Envoy/OPA e li include nei log di audit.
- Endpoint:
  - `GET /health`: verifica connessione MongoDB.
  - `GET /`: elenco endpoint.
  - `GET /utenti`, `GET /dispositivi`, `GET /risorse`, `GET /risorse/:id`:
    lettura.
  - `POST /risorse`: creazione.
  - `PUT /risorse/:id`: aggiornamento.
  - `DELETE /risorse/:id`: cancellazione.
  - `GET /all`: join delle tre collezioni.
- Connessione a MongoDB con TLS obbligatorio, uscendo con `exit(1)` se il
  database non è raggiungibile.
- Si arresta pulitamente su SIGTERM/SIGINT.

### Ruolo ZTA

- **Ultimo miglio fidato**: il backend si fida degli header `x-zta-*` perché
  arrivano solo da Envoy (che li ha ricevuti da OPA), e la rete `backend_net`
  è isolata.
- **Account applicativo a minimi privilegi**: l'utente MongoDB (`api-client`)
  ha solo i permessi definiti in `01-init.js`.

---

## 9. MongoDB – Database con TLS mutuale

### Immagine

Utilizza l'immagine ufficiale MongoDB 7 (definita in `docker-compose.yml`).
Non è presente Dockerfile personalizzato; la configurazione TLS e gli script
`init-scripts` sono in `configs/mongodb/`.

### Ruolo ZTA

- **TLS mutuale obbligatorio**: MongoDB accetta solo connessioni con
  certificato client valido.
- **Authorization enabled**: ogni operazione è controllata dai ruoli MongoDB.
- **Account applicativo** con permessi limitati alle collezioni necessarie.
- **Rete interna**: il servizio è esposto solo sulla rete Docker `backend_net`
  (dichiarata `internal: true` in Compose).

---

## Principi ZTA trasversali

| Principio                     | Implementazione                                                                 |
|-------------------------------|---------------------------------------------------------------------------------|
| **Never trust, always verify**| Ogni richiesta è autenticata via mTLS (Envoy), autorizzata da OPA, e solo poi inoltrata al backend. |
| **Minimo privilegio**         | Account API ha solo i permessi necessari su MongoDB. Policy OPA limitano risorse e comandi per ruolo. |
| **Assume breach**             | IDS passivo monitora tutto il traffico. Firewall blocca movimento laterale. Splunk calcola risk score dinamico. |
| **Hardware-bound identity**   | Client TPM generano chiave privata dentro SWTPM. La chiave non lascia mai il TPM. |
| **Continuous monitoring**     | Snort, NFTables, Envoy e MongoDB inviano log a Splunk. Risk score aggiornato ogni minuto. |
| **Segregazione delle reti**   | Reti client isolate (corporate, VPN, satellite, public) senza routing laterale. Backend e monitoring sono reti interne Docker. |

---

## Note operative

- OPA, Splunk e MongoDB non hanno Dockerfile personalizzati perché usano
  immagini ufficiali. Le personalizzazioni
  (policy, configurazioni, script init) sono montate via volumi dichiarati
  in `docker-compose.yml` o copiate nei path attesi.
- I container client TPM richiedono che il relativo SWTPM sia già avviato
  e raggiungibile. L'orchestrazione è gestita da `depends_on` in Compose
  e dall'attesa nello script `client-entrypoint.sh`.
- Per il provisioning TPM, eseguire `bash scripts/generate_device_certs.sh`
  (o `provision_tpm_devices.sh` per la versione legacy).
