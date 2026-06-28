<div align="center">

# Maritime Zero Trust Architecture (ZTA)

<div style="margin:auto;" align="center">
  <img src="util/Zero-trust-Security.jpg" style="width:50%; height:50%; object-fit:cover; object-position:center;" />
</div>


![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Compose](https://img.shields.io/badge/Compose-2.36+-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Envoy](https://img.shields.io/badge/Envoy-1.30-2B4C7E?style=for-the-badge&logo=envoy-proxy&logoColor=white)
![OPA](https://img.shields.io/badge/OPA-0.60-7B5C9E?style=for-the-badge&logo=open-policy-agent&logoColor=white)
![Snort](https://img.shields.io/badge/Snort-3.9-E43921?style=for-the-badge&logo=snort&logoColor=white)
![NFTables](https://img.shields.io/badge/NFTables-1.0-00A4EF?style=for-the-badge&logo=linux&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-7.0-47A248?style=for-the-badge&logo=mongodb&logoColor=white)
![Splunk](https://img.shields.io/badge/Splunk-9.1-000000?style=for-the-badge&logo=splunk&logoColor=white)
![SWTPM](https://img.shields.io/badge/SWTPM-0.8-E95420?style=for-the-badge&logo=tpm&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-20-339933?style=for-the-badge&logo=node.js&logoColor=white)
![OpenSSL](https://img.shields.io/badge/OpenSSL-3.x-721412?style=for-the-badge&logo=openssl&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-5.x-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)

</div>

> _"Questo progetto è stato sviluppato esclusivamente per scopi accademici e di ricerca. L'architettura, le configurazioni, 
> le topologie di rete e i dati utilizzati sono puramente fittizi, generati sinteticamente o basati su best practice di settore 
> (NIST SP 800-207)._

<div align="center">
  <sub>Built with ❤️ for security-first operations 🔒</sub>
</div>
<br><br>
---

## Indice

1. [Panoramica](#panoramica)
2. [Architettura ZTA](#architettura-zta)
    - [2.1 Diagrammi](#diagrammi)
    - [2.2 Componenti del sistema](#componenti-del-sistema)
    - [2.3 Reti Docker](#reti-docker)
3. [Tecnologie e strumenti](#tecnologie-e-strumenti)
4. [Prerequisiti](#prerequisiti)
5. [Guida rapida](#guida-rapida)
    - [5.1 Configurazione ambiente](#1-configurazione-ambiente)
    - [5.2 Generazione PKI](#2-generazione-pki-infrastrutturale)
    - [5.3 Provisioning TPM](#3-provisioning-tpm)
    - [5.4 Verifica preliminare](#4-verifica-preliminare)
    - [5.5 Avvio dello stack](#5-avvio-dello-stack)
6. [Flusso Zero Trust](#flusso-zero-trust)
7. [Rischio dinamico](#rischio-dinamico)
8. [Esecuzione dei test](#esecuzione-dei-test)
9. [Accesso a Splunk](#accesso-a-splunk)
10. [Comandi utili](#comandi-utili)
11. [Struttura del progetto](#struttura-del-progetto)
12. [Caratteristiche di sicurezza](#caratteristiche-di-sicurezza)
    - [12.1 Principi ZTA implementati](#principi-zta-implementati)
    - [12.2 Autenticazione e autorizzazione](#autenticazione-e-autorizzazione)
    - [12.3 Sicurezza di rete](#sicurezza-di-rete)
    - [12.4 Protezione dei dati](#protezione-dei-dati)
    - [12.5 Monitoraggio e risposta](#monitoraggio-e-risposta)
13. [Documentazione dettagliata](#documentazione-dettagliata)
14. [Risoluzione problemi](#risoluzione-problemi)
15. [Limitazioni note](#limitazioni-note)
16. [Licenza](#licenza)

---

## Panoramica

Questo progetto implementa una **Zero Trust Architecture** (modello NIST SP 800-207) per un ambiente marittimo portuale. Ogni richiesta viene autorizzata valutando l'identità utente, il dispositivo, la rete sorgente, la risorsa richiesta, l'operazione, la finestra temporale e il rischio dinamico.

## Architettura ZTA

```text
Client con SWTPM e certificato hardware-bound
  -> mTLS con SAN URI spiffe://maritime.local/users/<u>/devices/<d>
  -> NFTables firewall perimetrale
  -> Snort 3 IDS passivo
  -> Envoy PEP con filtro Lua ed ext_authz gRPC
  -> OPA PDP con policy ABAC e decision log
  -> API backend Node.js / Express
  -> MongoDB con TLS obbligatorio

Decision log e alert confluiscono in Splunk.
```

Il comportamento predefinito della policy è **deny**. Le reti `backend_net` e
`monitoring_net` sono reti Docker interne non raggiungibili direttamente dai
client.

### Diagrammi

#### Flusso logico (Graph LR)

#### Architettura Generale (Graph TD)

#### Sequenza delle autorizzazioni (Sequence Diagram)

### Componenti del sistema

| Servizio              | Ruolo ZTA                                               | Tecnologia         | Rete Docker      |
|-----------------------|---------------------------------------------------------|--------------------|------------------|
| `firewall_perimeter`  | DNAT perimetrale, filtraggio L3/L4, log NFTables        | Debian + NFTables  | host             |
| `ids_network_monitor` | IDS Snort 3 passivo sul percorso client‑firewall        | Ubuntu + Snort 3   | host             |
| `pep_gateway`         | PEP: terminazione mTLS, filtro Lua, ext_authz gRPC      | Envoy 1.30         | zerotrust, backend, clienti |
| `pdp_engine`          | PDP: policy ABAC, decision log verso Splunk             | OPA 0.60           | zerotrust        |
| `api_backend`         | API REST Node.js/Express per MongoDB                    | Node.js 20 Alpine  | backend          |
| `db_primary`          | Database MongoDB con TLS e account applicativo limitato | MongoDB 7          | backend (interna) |
| `siem_central`        | SIEM con HEC, risk score dinamico, dashboard            | Splunk Enterprise 9.1 | monitoring  |
| `swtpm_d001/d002/dsoc`| Emulatori TPM 2.0 software                              | Ubuntu + SWTPM     | client           |
| `client_d001_tpm`     | Client dimostrativo VPN (terminal porto)                | Ubuntu + TPM tools | vpn_net          |
| `client_d002_tpm`     | Client dimostrativo Satellite (terminale nave)          | Ubuntu + TPM tools | satellite_net    |
| `client_dsoc_tpm`     | Client dimostrativo Corporate (postazione SOC)          | Ubuntu + TPM tools | corporate_net    |

### Reti Docker

| Rete             | CIDR predefinito | Tipo     | Esposta ai client |
|------------------|------------------|----------|-------------------|
| `zerotrust_net`  | `172.20.2.0/24`  | Bridge   | No                |
| `backend_net`    | `172.20.3.0/24`  | Interna  | No                |
| `monitoring_net` | `172.20.4.0/24`  | Interna  | No                |
| `corporate_net`  | `172.20.10.0/24` | Bridge   | Sì                |
| `vpn_net`        | `172.20.11.0/24` | Bridge   | Sì                |
| `satellite_net`  | `172.20.12.0/24` | Bridge   | Sì                |
| `public_net`     | `172.20.13.0/24` | Bridge   | Sì                |

---

## Tecnologie e strumenti

| Categoria         | Tecnologia              | Versione  | Ruolo                          |
|-------------------|-------------------------|-----------|--------------------------------|
| Container         | Docker / Docker Compose | 24.0+     | Orchestrazione dei servizi     |
| Proxy / PEP       | Envoy                   | 1.30      | Terminazione mTLS, autorizzazione via ext_authz |
| Policy Engine     | Open Policy Agent (OPA) | 0.60      | Decisioni di accesso ABAC      |
| IDS               | Snort 3                 | 3.9.2     | Rilevamento intrusioni di rete |
| Firewall          | NFTables                | 1.0+      | Filtraggio L3/L4, DNAT        |
| Database          | MongoDB                 | 7.0       | Archiviazione dati con TLS     |
| SIEM              | Splunk Enterprise       | 9.1       | Log centralizzato, risk score  |
| TPM               | SWTPM                   | 0.8+      | Emulazione TPM 2.0 per identità hardware |
| Backend API       | Node.js + Express       | 20 LTS    | API REST per MongoDB            |
| PKI               | OpenSSL                 | 3.x       | Generazione certificati X.509  |
| Scripting         | Bash / PowerShell       | —         | Automazione setup e test        |
| Test runner       | Bash                    | —         | Suite di test end-to-end        |

---

## Prerequisiti

- **Docker Desktop** con Docker Compose ≥ 2.36.0
- **Almeno 8 GB RAM** assegnati a Docker
- **OpenSSL** e **Bash** (su Windows: Git Bash o WSL)
- **Git** (per clonare il repository)

---

## Guida rapida

### 1. Configurazione ambiente

```bash
cp .env.example .env
```

Sostituire almeno i seguenti valori nel file `.env`:

| Variabile             | Descrizione                         |
|-----------------------|-------------------------------------|
| `MONGO_ROOT_PASSWORD` | Password amministrativa MongoDB     |
| `MONGO_APP_PASSWORD`  | Password account applicativo        |
| `SPLUNK_PASSWORD`     | Password admin Splunk               |
| `SPLUNK_HEC_TOKEN`    | Token HEC Splunk in formato UUID    |

**Preparazione automatica su Windows:**

```cmd
setup-testing.cmd
```

Lo script crea `.env` se mancante, genera i certificati, effettua il provisioning dei TPM, costruisce e avvia lo stack, attende gli healthcheck.

### 2. Generazione PKI infrastrutturale

```bash
bash scripts/generate_certs.sh
```

Produce:
- `certs/ca/ca.crt` — CA radice (trust anchor)
- `certs/server/server.crt` / `.key` — certificato Envoy (PEP)
- `certs/mongodb/mongodb-server.pem` — MongoDB TLS
- `certs/mongodb/api-client.pem` — client API → MongoDB
- `certs/mongodb/healthcheck-client.pem` — healthcheck MongoDB

> **Principio ZTA**: la chiave `ca.key` resta **sull'host** e NON viene mai montata nei container.

### 3. Provisioning TPM

```bash
bash scripts/generate_device_certs.sh
```

Oppure, per la versione legacy a tre identità fisse:

```bash
bash scripts/provision_tpm_devices.sh
```

Lo script genera certificati client con **chiave privata protetta dal TPM emulato** per ogni coppia utente‑dispositivo nella matrice `configs/identity/identity_bindings.conf`.

| Utente             | Ruolo                   | Dispositivo | Rete        | Handle TPM  |
|--------------------|-------------------------|-------------|-------------|-------------|
| `operatore_ancona` | `ruolo_banchina`        | `D-001`     | VPN         | `0x81000001`|
| `capitano_claudia` | `ruolo_equipaggio`      | `D-002`     | Satellite   | `0x81000002`|
| `soc_admin`        | `ruolo_gestione_flotta` | `D-SOC`     | Corporate   | `0x81000003`|

Il SAN URI dei certificati segue il formato:
```text
spiffe://maritime.local/users/<utente>/devices/<dispositivo>
```

> **Principio ZTA**: la chiave privata **nasce e resta nel TPM** — non è mai esportabile.

### 4. Verifica preliminare

```bash
bash scripts/preflight.sh
```

Il preflight controlla:
- File `.env` e certificati obbligatori
- Versione Docker Compose
- Validità del docker-compose.yml
- Presenza del filtro Lua Envoy e della policy OPA

### 5. Avvio dello stack

```bash
docker compose up -d --build
```

Splunk può impiegare alcuni minuti per diventare disponibile. Controllare lo stato:

```bash
docker compose ps
docker compose logs --tail 50 siem_central pdp_engine pep_gateway
```

---

## Flusso Zero Trust

1. **Il client** presenta un certificato firmato dalla CA; la **chiave privata rimane nel TPM emulato** (non esce mai dal chip).
2. **Firewall perimetrale** (NFTables) applica DNAT sulla porta 8443 verso Envoy, preservando l'IP sorgente originale.
3. **Snort IDS** (passivo) monitora tutto il traffico client → firewall → PEP e rileva anomalie con 35+ regole personalizzate.
4. **Envoy (PEP)** verifica il certificato client via mTLS (`require_client_certificate: true`).
5. **Filtro Lua** estrae `user_id` e `device_id` dal SAN URI SPIFFE del certificato e identifica la rete sorgente dall'IP.
6. **OPA (PDP)** valuta utente, dispositivo, rete, binding, risorsa, comando, orario e risk score applicando la policy ABAC.
7. Se OPA autorizza, Envoy aggiunge gli header `x-zta-*` e inoltra la richiesta al backend API.
8. **Backend API** legge gli header fidati e interroga MongoDB con TLS mutuale.
9. **MongoDB** (TLS obbligatorio, rete `backend_net` interna) risponde solo via account applicativo a minimi privilegi.
10. **Splunk** riceve decision log OPA, alert Snort, log firewall ed Envoy e calcola il risk score dinamico (ogni minuto), retroalimentando OPA.

---

## Rischio dinamico

| Condizione          | Risk Score |
|---------------------|------------|
| `denied_count > 10` | 95         |
| `denied_count > 5`  | 80         |
| `denied_count > 2`  | 50         |
| `unique_sources > 3`| 40         |
| Nessuna anomalia    | 10         |

Il risk score è calcolato da una saved search Splunk ogni 60 secondi, combinando decision log OPA e alert Snort, e viene scritto in `risk_scores.json` che OPA legge al ciclo successivo.

---

## Esecuzione dei test

La suite di test end-to-end si avvia con:

```bash
bash tests/run_project_tests.sh
```

Per un ambiente pulito:

```bash
bash scripts/clean_runtime.sh
rm -rf certs/
bash scripts/generate_certs.sh
BINDINGS_FILE="scripts/identity_bindings.testing.conf" bash scripts/generate_device_certs.sh
./run_project_tests.sh
```

### Categorie di test

| Suite                      | Cosa verifica                                                      |
|----------------------------|--------------------------------------------------------------------|
| `test_audit_nftables.sh`   | Firewall: DNAT, blocco INPUT/OUTPUT, movimento laterale            |
| `test_audit_snort.sh`      | IDS: 35 attacchi su 8 categorie (ricognizione, bypass, injection…) |
| `test_access_success.sh`   | Policy OPA: richieste autorizzate → HTTP 200                       |
| `test_access_denied.sh`    | Policy OPA: richieste negate → HTTP 403                            |
| `test_mtls_failures.sh`    | mTLS: senza certificato, cert mancante, OPA deny                   |
| `test_dynamic_risk_score.sh` | Risk score: Splunk → OPA → blocco adattivo                        |

---

## Accesso a Splunk

URL: `http://localhost:8000`

- **Utente:** `admin`
- **Password:** valore `SPLUNK_PASSWORD` in `.env`

### Query utili

```spl
index=main sourcetype=opa_decision
index=main sourcetype=snort_alert_json
index=main sourcetype=nftables
index=main sourcetype=mongodb_log
index=main sourcetype=envoy_access_json
```

---

## Comandi utili

### Richieste dimostrative (client TPM)

```bash
# Avviare i client TPM
 docker compose --profile testing up -d

# Operatore Ancona
 docker compose --profile testing exec client_d001_tpm \
   env METHOD=GET PATH_URL=/risorse/R-001 /scripts/request_with_tpm.sh

# Capitano Claudia
 docker compose --profile testing exec client_d002_tpm \
   env METHOD=GET PATH_URL=/risorse/R-002 /scripts/request_with_tpm.sh

# SOC admin
 docker compose --profile testing exec client_dsoc_tpm \
   env METHOD=GET PATH_URL=/all /scripts/request_with_tpm.sh

# Aggiornamento report sicurezza
 docker compose --profile testing exec client_dsoc_tpm \
   env METHOD=PUT PATH_URL=/risorse/R-003 \
   REQUEST_BODY='{"severita_massima":"critica"}' \
   /scripts/request_with_tpm.sh
```

### Arresto e pulizia

```bash
docker compose --profile testing down
bash scripts/clean_runtime.sh
```

I certificati locali (`certs/`) **non** vengono eliminati dallo script di pulizia.

---

## Struttura del progetto

```text
Project_Maritime_Zero_Trust_Architecture/
├── README.md                          # Questo file
├── README_CERTS.md                    # Documentazione certificati
├── README-project.md                  # README in inglese (storico)
├── .env.example                       # Template variabili d'ambiente
├── docker-compose.yml                 # Orchestrazione servizi
├── setup-testing.cmd                  # Setup automatico Windows
├── configs/                           # Configurazioni dei servizi
│   ├── identity/                      # Matrice identità (identity_bindings.conf)
│   ├── nftables/                      # Regole firewall (rules.nft)
│   ├── envoy/                         # Envoy YAML + filtro Lua
│   ├── snort/                         # Snort Lua + regole custom
│   ├── opa/                           # Policy Rego + dati statici
│   ├── mongodb/                       # mongod.conf + init scripts
│   └── splunk/                        # App opa_risk_updater + inputs
├── services/                          # Dockerfile e entrypoint
│   ├── opa/            envoy/         snort/         swtpm/
│   ├── splunk/        clients/        clients_tpm/   nftables/
│   ├── api_backend/   mongodb/
│   └── README_SERVICE.md              # Documentazione servizi
├── scripts/                           # Script di automazione
│   ├── generate_certs.sh              # PKI infrastrutturale
│   ├── generate_device_certs.sh       # Certificati TPM (tutti i binding)
│   ├── provision_tpm_devices.sh       # Provisioning TPM (legacy)
│   ├── preflight.sh                   # Verifica preliminare
│   ├── clean_runtime.sh               # Pulizia container/volumi
│   ├── setup-testing.ps1              # Setup automatico Windows
│   └── README_SCRIPTS.md              # Documentazione script
├── tests/                             # Suite di test end-to-end
│   ├── run_project_tests.sh           # Runner principale
│   ├── lib_test_helpers.sh            # Funzioni comuni
│   ├── config_audit.sh                # Config audit unificata
│   ├── test_*.sh                      # Suite specifiche
│   └── README_TESTS.md                # Documentazione test
├── certs/                             # Certificati (gitignored)
│   ├── ca/          server/           mongodb/         devices/
│   └── README_CERTS.md
└── docs/                              # Documentazione aggiuntiva
```

---

## Caratteristiche di sicurezza

### Principi ZTA implementati

| Principio                     | Implementazione                                                                 |
|-------------------------------|---------------------------------------------------------------------------------|
| **Never trust, always verify**| Ogni richiesta è autenticata via mTLS, autorizzata da OPA, e solo poi inoltrata al backend. |
| **Minimo privilegio**         | Account API ha solo i permessi necessari su MongoDB. Policy OPA limitano risorse e comandi per ruolo. |
| **Assume breach**             | IDS passivo monitora tutto il traffico. Firewall blocca movimento laterale. Splunk calcola risk score dinamico. |
| **Hardware-bound identity**   | Client TPM generano chiave privata dentro SWTPM. La chiave non lascia mai il TPM. |
| **Continuous monitoring**     | Snort, NFTables, Envoy e MongoDB inviano log a Splunk. Risk score aggiornato ogni minuto. |
| **Segregazione delle reti**   | Reti client isolate (corporate, VPN, satellite, public) senza routing laterale. Backend e monitoring sono reti interne Docker. |
| **Default deny**              | La policy OPA predefinita è `deny`; solo le regole esplicite concedono accesso. |

### Autenticazione e autorizzazione

- **mTLS**: certificato X.509 client obbligatorio per ogni connessione.
- **ABAC**: OPA valuta attributi (ruolo, dispositivo, rete, orario, rischio).
- **Binding esplicito**: solo coppie utente‑dispositivo registrate nella matrice possono operare.

### Sicurezza di rete

- **Segmentazione**: 7 reti Docker, 2 interne (`backend_net`, `monitoring_net`).
- **Firewall**: NFTables blocca INPUT non necessario e movimento laterale tra reti client.
- **DNAT senza SNAT**: l'IP sorgente originale è preservato per OPA.

### Protezione dei dati

- **MongoDB**: solo connessioni TLS, autorizzazione attiva, account applicativo a minimi privilegi.
- **Backend API**: non esposto direttamente; solo Envoy (su backend_net) può chiamarlo.

### Monitoraggio e risposta

- **Splunk HEC**: riceve decision log OPA, alert Snort, log firewall ed Envoy.
- **Risk score dinamico**: calcolato ogni minuto e retroalimentato a OPA.
- **Saved search**: correla decision log con alert IDS per rilevare anomalie.

---

## Documentazione dettagliata

| File                            | Contenuto                                               |
|---------------------------------|--------------------------------------------------------|
| `README_CERTS.md`               | Struttura e ruolo dei certificati nella ZTA           |
| `scripts/README_SCRIPTS.md`     | Descrizione completa di ogni script                   |
| `configs/README_CONFIG.md`      | Configurazioni di tutti i servizi                     |
| `services/README_SERVICE.md`    | Dockerfile, entrypoint e ruolo di ogni servizio       |
| `tests/README_TESTS.md`         | Documentazione della suite di test                    |
| `README-project.md`             | README storico in inglese                             |

---

## Risoluzione problemi

| Problema                              | Soluzione                                                                 |
|---------------------------------------|---------------------------------------------------------------------------|
| **Certificati mancanti**              | Eseguire `bash scripts/generate_certs.sh` e poi `bash scripts/provision_tpm_devices.sh` |
| **Client TPM senza certificato identità** | Rigenerare i certificati TPM con `bash scripts/provision_tpm_devices.sh` |
| **Splunk resta unhealthy**            | Attendere alcuni minuti; controllare `docker logs siem_central`. Se il volume è di versione precedente, eseguire `bash scripts/clean_runtime.sh` |
| **Conflitto subnet Docker/VPN locale**| Aggiornare le variabili `NETWORK_*_SUBNET` in `.env`, gli IP statici in `docker-compose.yml` e i CIDR in `configs/opa/data/networks.json` |
| **Test falliscono**                    | Verificare che lo stack sia in esecuzione e che i certificati esistano. Consultare `tests/README_TESTS.md` per diagnosi specifica. |

---

## Limitazioni note

- **MongoDB** è una singola istanza, non un replica set.
- **Splunk HEC** usa HTTP (non HTTPS) solo sulla rete Docker interna `monitoring_net`.
- **Snort** opera in modalità passiva: il payload mTLS resta cifrato; le regole analizzano solo header e metadati.
- **L'identità hardware** è simulata con SWTPM (emulatore software, non chip fisico).
- **Revoca dei certificati** non è implementata via CRL/OCSP; la revoca è gestita a livello di policy OPA.

---

## Licenza

Distribuito sotto licenza **MIT**. Vedi il file `LICENSE` per maggiori dettagli.

---


**Versione**: 1.0.0
**Ultimo aggiornamento**: 2026-06-28
