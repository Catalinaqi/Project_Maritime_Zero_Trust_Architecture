# Piano di Sicurezza — Maritime Zero Trust Architecture (ZTA)

Documento derivato dall'analisi del file `docker-compose.yml` e dell'architettura del progetto.

---

## Indice

1. [Principi generali](#1-principi-generali)
2. [Segmentazione di rete](#2-segmentazione-di-rete)
3. [Autenticazione e crittografia (mTLS)](#3-autenticazione-e-crittografia)
4. [Firewall perimetrale (NFTables)](#4-firewall-perimetrale)
5. [Intrusion Detection (Snort)](#5-intrusion-detection)
6. [Policy Engine (OPA)](#6-policy-engine)
7. [Identità hardware-bound (TPM)](#7-identità-hardware-bound)
8. [Protezione dei dati (MongoDB)](#8-protezione-dei-dati)
9. [SIEM e monitoraggio (Splunk)](#9-siem-e-monitoraggio)
10. [Hardening dei container](#10-hardening-dei-container)
11. [Gestione delle variabili d'ambiente](#11-gestione-delle-variabili-dambiente)
12. [Riepilogo delle misure di sicurezza](#12-riepilogo-delle-misure-di-sicurezza)

---

## 1. Principi generali

L'architettura segue il modello **NIST SP 800-207** Zero Trust Architecture con i seguenti pilastri:

- **Never trust, always verify**: ogni richiesta è autenticata (mTLS), autorizzata (OPA), e solo poi inoltrata.
- **Assume breach**: monitoraggio continuo di tutto il traffico e raccolta centralizzata dei log.
- **Minimo privilegio**: account applicativo MongoDB con permessi limitati, policy OPA granulari per ruolo.
- **Segregazione**: reti Docker interne per backend e monitoring, senza esposizione ai client.

---

## 2. Segmentazione di rete

Il progetto definisce **7 reti Docker** distinte, di cui **2 interne** (`backend_net`, `monitoring_net`).

| Rete               | CIDR predefinito     | Tipo      | Esposta ai client | Scopo                              |
|--------------------|----------------------|-----------|-------------------|------------------------------------|
| `corporate_net`    | `172.20.10.0/24`     | Bridge    | Sì                | Postazioni SOC e amministrazione   |
| `vpn_net`          | `172.20.11.0/24`     | Bridge    | Sì                | Terminali porto in VPN             |
| `satellite_net`    | `172.20.12.0/24`     | Bridge    | Sì                | Terminali nave (satellite)        |
| `public_net`       | `172.20.13.0/24`     | Bridge    | Sì                | Rete pubblica/ospiti               |
| `zerotrust_net`    | `172.20.2.0/24`      | Bridge    | No                | Comunicazione PEP↔OPA, firewall   |
| `backend_net`      | `172.20.3.0/24`      | **Interna** | No               | API↔MongoDB (TLS obbligatorio)    |
| `monitoring_net`   | `172.20.4.0/24`      | **Interna** | No               | Logging centralizzato (Splunk HEC) |

**Evidenze dal compose:**

```yaml
backend_net:
    driver: bridge
    name: maritime-zta_backend
    internal: true        # <-- rete isolata
monitoring_net:
    driver: bridge
    name: maritime-zta_monitoring
    internal: true        # <-- rete isolata
```

Le reti interne non hanno accesso a Internet e non sono raggiungibili da reti bridge non interne.

**Ipotesi di flusso** – Envoy è connesso a 5 reti (zerotrust, backend, corporate, vpn, satellite, public); il firewall perimetrale è su 6 reti (zerotrust, monitoring, corporate, vpn, satellite, public). Tutto il traffico dai client verso il backend transita attraverso:

```
client → rete client → firewall_perimeter → zerotrust_net → pep_gateway → backend_net → api_backend → backend_net → db_primary
```

---

## 3. Autenticazione e crittografia (mTLS)

### MongoDB

- Connessioni accettate **solo via TLS** (`mongod --config /etc/mongod.conf` con `requireTLS`).
- Certificati montati come volumi **read-only**:
  - `./certs/mongodb:/certs/mongodb:ro`
  - `./certs/ca/ca.crt:/certs/ca/ca.crt:ro`
- Healthcheck con autenticazione TLS:
  ```yaml
  test:
    - CMD
    - mongosh
    - --tls
    - --tlsCAFile /certs/ca/ca.crt
    - --tlsCertificateKeyFile /certs/mongodb/healthcheck-client.pem
    - --username ${MONGO_ROOT_USER}
    - --password ${MONGO_ROOT_PASSWORD}
  ```

### Envoy (PEP)

- Terminazione mTLS sul listener esterno.
- Certificato server montato da `./certs/server:/certs:ro`.
- CA radice montata da `./certs/ca/ca.crt:/ca/ca.crt:ro`.

### API Backend

- Connessione a MongoDB con TLS mutuale tramite certificato `api-client.pem`.
- Variabili d'ambiente per configurare CA e certificato:
  ```yaml
  MONGO_TLS_CA_FILE: /certs/ca/ca.crt
  MONGO_TLS_CERT_KEY_FILE: /certs/mongodb/api-client.pem
  ```

### SPIFFE URI

- I certificati client (generati via `generate_device_certs.sh`) contengono SAN URI nel formato:
  ```
  spiffe://maritime.local/users/<utente>/devices/<dispositivo>
  ```
- Envoy estrae `user_id` e `device_id` tramite filtro Lua e li invia a OPA.

---

## 4. Firewall perimetrale

Servizio: `firewall_perimeter` (container Debian + NFTables).

### Capacità Linux

```yaml
cap_add: [NET_ADMIN]
sysctls:
    net.ipv4.ip_forward: "1"
```

### Variabili di configurazione

| Variabile               | Valore predefinito    | Descrizione                               |
|--------------------------|-----------------------|-------------------------------------------|
| `NFTABLES_ENVOY_IP`      | `172.20.2.7`          | IP di Envoy nella rete zerotrust          |
| `NFTABLES_FW_*_IP`       | `172.20.{10-13}.10`   | IP del firewall su ogni rete client       |
| `NFTABLES_PEP_PORT`      | `8443` (variabile)    | Porta del PEP su cui fare DNAT            |
| `NFTABLES_SPLUNK_HEC_URL`| `http://172.20.4.8:8088/...` | Endpoint Splunk HEC interna        |
| `NFTABLES_SPLUNK_HEC_TOKEN` | `${SPLUNK_HEC_TOKEN}` | Token HEC per l'invio dei log          |

### Regole attese (da `rules.nft`)

- **DNAT** dalla porta 8443 su ogni interfaccia client verso Envoy (`172.20.2.7:8443`).
- **Blocco INPUT** non richiesto.
- **Blocco forwarding** tra reti client diverse (lateral movement).
- **Logging** di pacchetti drop/accept verso Splunk.

---

## 5. Intrusion Detection

Servizio: `ids_network_monitor` (Snort 3, modalità passiva).

### Posizionamento

```yaml
network_mode: service:firewall_perimeter
```

Condivide lo stesso spazio di rete del firewall, quindi vede tutto il traffico in transito verso il PEP.

### Capacità

```yaml
cap_add: [NET_RAW, NET_ADMIN]
security_opt: [apparmor:unconfined]
```

- `NET_RAW`: permette l'uso di socket raw per l'acquisizione pacchetti.
- `apparmor:unconfined`: rimuove le restrizioni di AppArmor per garantire il funzionamento di Snort.

### Variabili di configurazione

| Variabile                | Descrizione                                  |
|--------------------------|----------------------------------------------|
| `ZTA_SNORT_INTERFACES`   | Interfacce su cui Snort fa monitoring        |
| `ZTA_HOME_NET`           | Reti considerate "fidate" (tutte le subnet)  |
| `ZTA_PEP_PORT`           | Porta del PEP da monitorare                  |
| `ZTA_OPA_PORTS`          | Porte OPA da monitorare                      |
| `ZTA_MONGO_PORT`         | Porta MongoDB                                |
| `ZTA_SIEM_PORTS`         | Porte Splunk                                 |

### Regole custom (da `snort-zta.rules`)

35+ regole suddivise in 8 categorie: ricognizione, bypass, injection, brute force, anomalie di protocollo, traffico non autorizzato tra reti, tentativi di connessione diretta a backend, abusi di policy.

---

## 6. Policy Engine

Servizio: `pdp_engine` (OPA 1.17.1-envoy).

### Connessioni di rete

- **zerotrust_net** (`172.20.2.6`): riceve le richieste di autorizzazione gRPC da Envoy.
- **monitoring_net** (`172.20.4.6`): interroga Splunk per statistiche e risk score.

### Volumi montati

| Volume                         | Contenuto                                      |
|--------------------------------|-------------------------------------------------|
| `configs/opa/config.yaml`      | Configurazione OPA (logger, bundle, discovery)  |
| `configs/opa/policies/`        | Policy Rego (authorization.rego)                |
| `configs/opa/data/roles.json`  | Definizione dei ruoli                           |
| `configs/opa/data/devices.json`| Dispositivi autorizzati                         |
| `configs/opa/data/networks.json`| Reti e subnet                                  |
| `configs/opa/data/access_rules.json` | Regole di accesso ABAC                   |
| `configs/opa/data/risk_data/`  | Risk score dinamico (scritto da Splunk)         |

### Comando di avvio

```yaml
command:
  - run
  - --server
  - --addr=0.0.0.0:8181
  - --config-file=/config/opa-config.yaml
  - --log-level=info
  - --log-format=json
  - --watch /policies
```

- `--watch`: ricarica automaticamente policy e dati al cambiamento.

### Principi di policy (da `authorization.rego`)

- **Default deny**: tutte le richieste non esplicitamente autorizzate vengono negate.
- **ABAC**: l'autorizzazione valuta utente, dispositivo, rete, risorsa, comando, orario e risk score.
- **Binding esplicito**: solo coppie utente‑dispositivo registrate nella matrice `identity_bindings.conf` possono operare.
- **Risk score dinamico**: OPA interroga Splunk per ottenere il rischio corrente.

---

## 7. Identità hardware-bound (TPM)

I servizi `swtpm_d001`, `swtpm_d002`, `swtpm_dsoc` emulano TPM 2.0 via software.

### Architettura

```
swtpm_device (emulatore TPM) ↔ client_tpm (contiene certificato + chiave)
```

### Gestione delle chiavi

- La **chiave privata** viene generata **dentro il TPM** e non esce mai dal chip emulato.
- Il certificato di identità (`identity.crt`) è montato come volume read-only dal client.
- Il TPM handle (`0x81000001`, `0x81000002`, `0x81000003`) identifica univocamente la coppia utente‑dispositivo.

### Template YAML

```yaml
swtpm_d001: &swtpm_template
    volumes:
      - swtpm_d001_state:/var/lib/swtpm
    environment:
      TPM_STATE_DIR: /var/lib/swtpm
      TPM_SERVER_PORT: 2321
      TPM_CTRL_PORT: 2322
```

Ogni TPM ha un **volume dedicato** per preservare lo stato persistente:

```yaml
volumes:
  swtpm_d001_state: {name: maritime-zta_swtpm_d001_state}
  swtpm_d002_state: {name: maritime-zta_swtpm_d002_state}
  swtpm_dsoc_state: {name: maritime-zta_swtpm_dsoc_state}
```

### Client TPM

```yaml
client_d001_tpm: &client_tpm_template
    volumes:
      - ./certs/devices/D-001:/certs/device
      - tpm_d001_client_state:/tpm
    environment:
      TPM_HANDLE: "0x81000001"
      SWTPM_HOST: swtpm_d001
      TPM2TOOLS_TCTI: tabrmd:bus_type=system
      TPM2OPENSSL_TCTI: tabrmd:bus_type=system
      OPENSSL_MODULES: /usr/local/lib/ossl-modules
```

---

## 8. Protezione dei dati (MongoDB)

Servizio: `db_primary` (MongoDB 7.0).

### Requisiti

- **TLS obbligatorio** (`mongod --config /etc/mongod.conf`).
- **Autenticazione abilitata**: utente root e utente applicativo con privilegi separati.
- **Reti**: solo `backend_net` (rete interna, `internal: true`).
- **Volumi separati** per dati, configurazione e log:
  ```yaml
  volumes:
    - mongo_data:/data/db
    - mongo_config:/data/configdb
    - mongo_logs:/var/log/mongodb
  ```

### Account

| Account             | Utente                    | Password                        | Database di autenticazione | Privilegi                     |
|---------------------|---------------------------|---------------------------------|----------------------------|--------------------------------|
| Amministratore      | `${MONGO_ROOT_USER}`      | `${MONGO_ROOT_PASSWORD}`       | `admin`                    | root (tutti i database)       |
| Applicativo         | `${MONGO_APP_USER}`       | `${MONGO_APP_PASSWORD}`         | `maritime_zta`             | lettura/scrittura sul db app  |

### Healthcheck

```yaml
test:
  - CMD
  - mongosh
  - --tls
  - --tlsCAFile /certs/ca/ca.crt
  - --tlsCertificateKeyFile /certs/mongodb/healthcheck-client.pem
  - --username ${MONGO_ROOT_USER}
  - --password ${MONGO_ROOT_PASSWORD}
  - --eval "db.adminCommand('ping')"
```

---

## 9. SIEM e monitoraggio (Splunk)

Servizio: `siem_central` (Splunk Enterprise 9.1).

### Sorgenti di log

| Sorgente             | Tipo di log                          | Volume montato          |
|----------------------|--------------------------------------|-------------------------|
| OPA (decision log)   | Decisioni allow/deny in JSON          | — (via HEC)             |
| Snort                | Alert IDS in formato JSON             | `snort_logs` (read-only)|
| NFTables             | Log firewall (drop/accept)            | `nftables_logs` (read-only)|
| Envoy                | Access log in formato JSON            | `envoy_logs` (read-only)|
| MongoDB              | Log database                          | `mongo_logs` (read-only)|

### Endpoint HEC

```yaml
environment:
  SPLUNK_HEC_TOKEN: ${SPLUNK_HEC_TOKEN}
```

L'HEC è esposto sulla rete `monitoring_net` (interna) su porta `8088` (HTTP). Non è esposto su HTTPS.

### Risk score dinamico

Una saved search Splunk eseguita ogni 60 secondi calcola il risk score combinando:
- Decision log OPA (conteggio deny)
- Alert Snort (conteggio eventi)
- Unicità delle sorgenti

Il risultato viene scritto in `risk_scores.json` (montato in `/opa_data/risk_data/`) che OPA legge al ciclo successivo.

### Dashboard

Splunk fornisce dashboard per:
- Accessi autorizzati e negati
- Alert IDS per categoria
- Risk score per utente/dispositivo
- Log firewall
- Trend di sicurezza

---

## 10. Hardening dei container

### Capacità minime

| Servizio               | Capacità concesse      | Motivazione                                    |
|------------------------|------------------------|------------------------------------------------|
| `firewall_perimeter`   | `NET_ADMIN`            | Modifica delle regole NFTables                |
| `pep_gateway`          | `NET_ADMIN`            | Gestione interfacce di rete multiple          |
| `ids_network_monitor`  | `NET_RAW`, `NET_ADMIN` | Acquisizione pacchetti per Snort              |
| `siem_central`         | —                      | Nessuna capacità extra                        |
| `pdp_engine`           | —                      | Nessuna capacità extra                        |
| `api_backend`          | —                      | Nessuna capacità extra                        |
| `db_primary`           | —                      | Nessuna capacità extra                        |
| `swtpm_*`              | —                      | Nessuna capacità extra                        |
| `client_*_tpm`         | —                      | Nessuna capacità extra                        |

### AppArmor

- `snort`: `apparmor:unconfined` per garantire il funzionamento dell'acquisizione pacchetti.

### Volumi read-only

Tutti i certificati sono montati con `:ro` (read-only) per prevenire manomissioni:

```yaml
volumes:
  - ./certs/mongodb:/certs/mongodb:ro
  - ./certs/ca/ca.crt:/certs/ca/ca.crt:ro
  - ./certs/server:/certs:ro
```

### Healthcheck

Ogni servizio critico ha un healthcheck specifico:
- **Splunk**: `curl http://127.0.0.1:8000/en-US/account/login`
- **MongoDB**: `mongosh --tls --eval "db.adminCommand('ping')"`
- **Envoy**: `curl http://127.0.0.1:9901/ready`
- **OPA**: `/opa eval 1`
- **Firewall**: `nft list table ip filter`
- **Snort**: `pgrep snort`
- **API Backend**: `http://127.0.0.1:3000/health`
- **SWTPM**: `</dev/tcp/127.0.0.1/2321`

---

## 11. Gestione delle variabili d'ambiente

### Variabili obbligatorie (fail fast con `:?`)

```yaml
SPLUNK_PASSWORD: ${SPLUNK_PASSWORD:?Definire SPLUNK_PASSWORD nel file .env}
SPLUNK_HEC_TOKEN: ${SPLUNK_HEC_TOKEN:?Definire SPLUNK_HEC_TOKEN nel file .env}
MONGO_ROOT_USER: ${MONGO_ROOT_USER:?Definire MONGO_ROOT_USER}
MONGO_ROOT_PASSWORD: ${MONGO_ROOT_PASSWORD:?Definire MONGO_ROOT_PASSWORD}
MONGO_APP_USER: ${MONGO_APP_USER:?Definire MONGO_APP_USER}
MONGO_APP_PASSWORD: ${MONGO_APP_PASSWORD:?Definire MONGO_APP_PASSWORD}
```

### Variabili con valore predefinito

| Variabile                  | Predefinito           | Servizio         |
|----------------------------|-----------------------|------------------|
| `SPLUNK_WEB_PORT`          | `8000`                | Splunk           |
| `SPLUNK_HEC_PORT`          | `8088`                | Splunk           |
| `MONGO_DATABASE`           | `maritime_zta`        | MongoDB, API     |
| `API_PORT`                 | `3000`                | API Backend      |
| `ENVOY_LISTENER_PORT`      | `8443`                | Envoy, Firewall  |
| `OPA_REST_PORT`            | `8181`                | OPA              |
| `NETWORK_*_SUBNET`         | `172.20.{2-13}.0/24`  | Tutte le reti    |
| `TZ`                       | `Europe/Rome`         | Snort            |

---

## 12. Riepilogo delle misure di sicurezza

| Categoria                      | Misura adottata                                                      | Riferimento                  |
|--------------------------------|----------------------------------------------------------------------|------------------------------|
| **Segmentazione di rete**      | 7 reti Docker, 2 interne (`internal: true`)                          | Sezione 2                    |
| **Autenticazione**             | mTLS obbligatorio su MongoDB e Envoy                                 | Sezione 3                    |
| **Identità hardware**          | Chiave privata generata e conservata dentro SWTPM (emulatore TPM 2.0)| Sezione 7                    |
| **Firewall**                   | NFTables con DNAT, blocco INPUT, blocco lateral movement, log        | Sezione 4                    |
| **Intrusion Detection**        | Snort 3 passivo con 35+ regole custom                                | Sezione 5                    |
| **Autorizzazione**             | OPA con policy ABAC, default deny, risk score dinamico               | Sezione 6                    |
| **Protezione dati**            | MongoDB con TLS, account separati, rete interna                      | Sezione 8                    |
| **Monitoraggio**               | Splunk con HEC, decision log, alert IDS, log firewall, risk score   | Sezione 9                    |
| **Hardening container**        | Capacità minime, volumi read-only, healthcheck                       | Sezione 10                   |
| **Gestione segreti**           | Variabili d'ambiente obbligatorie con `:?` e file `.env`             | Sezione 11                   |
| **Log centralizzato**          | Snort, NFTables, Envoy, MongoDB → Splunk (volumi log condivisi)     | Sezioni 4, 5, 8, 9           |
| **Aggiornamento automatico**   | OPA con `--watch` per ricarica policy a caldo                        | Sezione 6                    |

---

