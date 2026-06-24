# Maritime Zero Trust Architecture

Progetto universitario - Universita Politecnica delle Marche, 2026.
Corso: Ingegneria dell'Informazione - Tema: Zero Trust Architecture.

Il progetto simula una Zero Trust Architecture per un ambiente marittimo portuale.
Ogni richiesta viene autorizzata valutando identita utente, dispositivo, rete
sorgente, risorsa richiesta, operazione, finestra temporale e rischio dinamico.

## Architettura

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

Il comportamento predefinito della policy e `deny`. Le reti `backend_net` e
`monitoring_net` sono reti Docker interne non raggiungibili direttamente dai
client.

## Componenti

| Servizio              | Ruolo                                                      |
|-----------------------|------------------------------------------------------------|
| `firewall_perimeter`  | DNAT perimetrale, filtraggio L3/L4, log NFTables           |
| `ids_network_monitor` | IDS Snort 3 passivo sul percorso client-firewall           |
| `pep_gateway`         | Envoy: terminazione mTLS, Lua context, ext_authz verso OPA |
| `pdp_engine`          | OPA: policy ABAC, decision log verso Splunk                |
| `api_backend`         | API REST per MongoDB, non esposta direttamente ai client   |
| `db_primary`          | MongoDB 7 con TLS e account applicativo limitato           |
| `siem_central`        | Splunk Enterprise con HEC e risk score dinamico            |
| `swtpm_*`             | TPM emulati per il profilo `testing`                       |
| `client_*_tpm`        | Client dimostrativi con chiave privata nel TPM             |

## Prerequisiti

- Docker Desktop con Docker Compose >= 2.36.0.
- Almeno 8 GB RAM assegnati a Docker.
- OpenSSL e Bash.
- Su Windows: Git Bash oppure WSL per eseguire gli script `.sh`.

## Configurazione

Creare il file `.env` partendo dall'esempio:

```bash
cp .env.example .env
```

Sostituire almeno:

| Variabile             | Descrizione                         |
|-----------------------|-------------------------------------|
| `MONGO_ROOT_PASSWORD` | Password amministrativa MongoDB     |
| `MONGO_APP_PASSWORD`  | Password account applicativo        |
| `SPLUNK_PASSWORD`     | Password admin Splunk               |
| `SPLUNK_HEC_TOKEN`    | Token HEC Splunk in formato UUID    |

### Preparazione automatica su Windows

Dopo un nuovo clone, con Docker Desktop gia avviato, eseguire dal Prompt dei
comandi:

```cmd
setup-testing.cmd
```

Lo script crea `.env` se manca, genera i certificati infrastrutturali, effettua
il provisioning dei tre TPM dimostrativi, costruisce e avvia lo stack, attende
gli healthcheck e lascia l'ambiente pronto per eseguire manualmente i test.
I file e i volumi gia presenti non vengono cancellati.

## Generazione certificati

Generare la PKI infrastrutturale:

```bash
bash scripts/generate_certs.sh
```

Lo script genera la CA, il certificato server Envoy, il certificato server
MongoDB e i certificati client usati da API backend e healthcheck MongoDB.
Le chiavi private generate non sono incluse nel repository e sono escluse da
Git.

## Provisioning TPM

Generare i certificati utente-dispositivo legati ai TPM emulati:

```bash
bash scripts/provision_tpm_devices.sh
```

Il comando usa `configs/identity/identity_bindings.conf` come matrice
autorevole. Per i client demo vengono generate queste identita:

| Utente             | Ruolo                   | Dispositivo | Rete        |
|--------------------|-------------------------|-------------|-------------|
| `operatore_ancona` | `ruolo_banchina`        | `D-001`     | VPN         |
| `capitano_claudia` | `ruolo_equipaggio`      | `D-002`     | Satellite   |
| `soc_admin`        | `ruolo_gestione_flotta` | `D-SOC`     | Corporate   |

Il SAN URI dei certificati segue il formato:

```text
spiffe://maritime.local/users/<utente>/devices/<dispositivo>
```

## Verifica preliminare

```bash
bash scripts/preflight.sh
```

Il preflight controlla `.env`, certificati generati, filtro Lua Envoy, policy
OPA e validita del Compose.

## Avvio

```bash
docker compose up -d --build
```

Splunk puo impiegare alcuni minuti per diventare disponibile. Stato e log:

```bash
docker compose ps
docker compose logs --tail 50 siem_central pdp_engine pep_gateway
```

## Accesso a Splunk

URL: `http://localhost:8000`

- Utente: `admin`
- Password: valore `SPLUNK_PASSWORD` in `.env`

Query utili:

```spl
index=main sourcetype=opa_decision
index=main sourcetype=snort_alert_json
index=main sourcetype=nftables
index=main sourcetype=mongodb_log
index=main sourcetype=envoy_access_json
```

## Richieste dimostrative

Avviare i client TPM:

```bash
docker compose --profile testing up -d
```

Operatore Ancona:

```bash
docker compose --profile testing exec client_d001_tpm \
  env METHOD=GET PATH_URL=/risorse/R-001 /scripts/request_with_tpm.sh
```

Capitano:

```bash
docker compose --profile testing exec client_d002_tpm \
  env METHOD=GET PATH_URL=/risorse/R-002 /scripts/request_with_tpm.sh
```

SOC admin:

```bash
docker compose --profile testing exec client_dsoc_tpm \
  env METHOD=GET PATH_URL=/all /scripts/request_with_tpm.sh
```

Aggiornamento report sicurezza:

```bash
docker compose --profile testing exec client_dsoc_tpm \
  env METHOD=PUT PATH_URL=/risorse/R-003 \
  REQUEST_BODY='{"severita_massima":"critica"}' \
  /scripts/request_with_tpm.sh
```

## Flusso Zero Trust

1. Il client presenta un certificato firmato dalla CA; la chiave privata rimane
   nel TPM emulato.
2. Envoy verifica il certificato client via mTLS.
3. Il filtro Lua estrae `user_id` e `device_id` dal SAN URI SPIFFE; per
   compatibilita accetta anche certificati legacy basati su Subject `OU`/`CN`.
4. OPA valuta utente, dispositivo, rete, binding utente-dispositivo-rete,
   risorsa, comando, orario e risk score.
5. Se OPA autorizza, Envoy aggiunge gli header `x-zta-*` e inoltra al backend.
6. OPA invia i decision log a Splunk.
7. Splunk aggiorna periodicamente il risk score letto da OPA.

## Rischio dinamico

| Condizione        | Risk Score |
|-------------------|------------|
| `denied_count > 10` | 95       |
| `denied_count > 5`  | 80       |
| `denied_count > 2`  | 50       |
| `unique_sources > 3`| 40       |
| Nessuna anomalia    | 10       |

## Reti Docker

| Rete             | CIDR predefinito | Tipo     |
|------------------|------------------|----------|
| `zerotrust_net`  | `172.20.2.0/24`  | Bridge   |
| `backend_net`    | `172.20.3.0/24`  | Interna  |
| `monitoring_net` | `172.20.4.0/24`  | Interna  |
| `corporate_net`  | `172.20.10.0/24` | Bridge   |
| `vpn_net`        | `172.20.11.0/24` | Bridge   |
| `satellite_net`  | `172.20.12.0/24` | Bridge   |
| `public_net`     | `172.20.13.0/24` | Bridge   |

## Arresto e pulizia

```bash
docker compose --profile testing down
bash scripts/clean_runtime.sh
```

I certificati locali non vengono eliminati dallo script di pulizia.

## Risoluzione problemi

**Certificati mancanti**
Eseguire `bash scripts/generate_certs.sh` e poi
`bash scripts/provision_tpm_devices.sh`.

**Client TPM senza certificato identita**
Rigenerare i certificati TPM con `bash scripts/provision_tpm_devices.sh`.

**Splunk resta unhealthy**
Attendere alcuni minuti e controllare `docker logs siem_central`. Se il volume
proviene da una versione precedente, eseguire `bash scripts/clean_runtime.sh`.

**Conflitto subnet Docker/VPN locale**
Aggiornare le variabili `NETWORK_*_SUBNET` in `.env`, gli IP statici nel
Compose e i CIDR in `configs/opa/data/networks.json`.

## Limitazioni note

- MongoDB e una singola istanza, non un replica set.
- Splunk HEC usa HTTP solo sulla rete Docker interna.
- Snort opera in modalita passiva: il payload mTLS resta cifrato.
- L'identita hardware e simulata con SWTPM.
- La suite di test definitiva e separata; in `tests/README.md` e indicato lo
  stato della cartella test.
