# Test – Maritime Zero Trust Architecture

## Indice

- [Panoramica](#panoramica)
- [Struttura della directory](#struttura-della-directory)
- [Esecuzione](#esecuzione)
- [Runner principale](#1-run_project_testssh--runner-principale)
- [Libreria condivisa](#2-lib_test_helperssh--libreria-condivisa)
- [Configurazione unificata audit](#3-config_auditsh--configurazione-unificata-audit)
- [Test applicativi (Policy OPA)](#test-applicativi-policy-opa)
  - [4. Accessi consentiti](#4-test_access_succes-sh--accessi-consentiti)
  - [5. Accessi negati](#5-test_access_deniedsh--accessi-negati)
  - [6. Fallimenti mTLS](#6-test_mtls_failuressh--fallimenti-mtls)
  - [7. Rischio dinamico](#7-test_dynamic_risk_scoresh--rischio-dinamico)
- [Test di audit (Firewall e IDS)](#test-di-audit-firewall-e-ids)
  - [8. Audit firewall NFTables](#8-test_audit_nftablessh--audit-firewall-nftables)
  - [9. Audit IDS Snort](#9-test_audit_snortsh--audit-ids-snort)
- [Query Splunk per la verifica manuale](#query-splunk-per-la-verifica-manuale)
- [Riepilogo Principi ZTA Coperti](#riepilogo-principi-zta-coperti)
- [Note operative](#note-operative)

---

## Panoramica

La directory `tests/` contiene la suite di test end-to-end per la verifica
della Zero Trust Architecture. I test coprono accessi consentiti e negati,
fallimenti mTLS, risk score dinamico integrato con Splunk e audit completi
di firewall NFTables e IDS Snort. Ogni test verifica uno o più principi
ZTA fondamentali.

---

## Struttura della directory

```text
tests/
├── run_project_tests.sh             # Runner principale (esegue tutte le suite)
├── lib_test_helpers.sh              # Funzioni comuni a tutti i test
├── config_audit.sh                  # Configurazione unificata per audit NFTables e Snort
│
├── test_access_success.sh           # [Test applicativo] Verifica accessi autorizzati
├── test_access_denied.sh            # [Test applicativo] Verifica accessi negati
├── test_mtls_failures.sh            # [Test applicativo] Verifica fallimenti mTLS
├── test_dynamic_risk_score.sh       # [Test applicativo] Verifica risk score dinamico
├── test_audit_nftables.sh           # [Test di audit] Regole firewall NFTables
└── test_audit_snort.sh              # [Test di audit] Regole IDS Snort
```

---

## Esecuzione

### Esecuzione rapida (ambiente già pronto)

Dalla radice del progetto:

```bash
bash tests/run_project_tests.sh
```

### Preparazione ambiente pulito

Per rigenerare certificati e container prima dei test:

```bash
bash scripts/clean_runtime.sh
bash scripts/generate_certs.sh
BINDINGS_FILE="scripts/identity_bindings.testing.conf" bash scripts/generate_device_certs.sh
bash scripts/init_runtime.sh
bash tests/run_project_tests.sh
```

**Nota:** `run_project_tests.sh` deve essere eseguito dalla radice del progetto
o con `bash tests/run_project_tests.sh`.

---

## 1. `run_project_tests.sh` – Runner Principale

### Scopo

Esegue in sequenza le sei suite di test. Se una suite fallisce (exit code 1),
il runner registra l'errore ma continua con le suite successive. Al termine
stampa le query Splunk pronte da copiare e restituisce un errore complessivo
se almeno una suite non è riuscita.

### Ordine di esecuzione

| Passo | Suite                          | Categoria       |
|-------|--------------------------------|-----------------|
| 1     | `test_audit_nftables.sh`      | Audit firewall  |
| 2     | `test_audit_snort.sh`         | Audit IDS       |
| 3     | `test_access_success.sh`      | Policy OPA      |
| 4     | `test_access_denied.sh`       | Policy OPA      |
| 5     | `test_mtls_failures.sh`       | Policy OPA      |
| 6     | `test_dynamic_risk_score.sh`  | Risk dinamico   |

---

## 2. `lib_test_helpers.sh` – Libreria Condivisa

### Scopo

Centralizza tutte le funzioni comuni utilizzate dalle suite di test, eliminando
duplicazione e garantendo coerenza nell'orchestrazione dei container, nelle
attese e nella gestione degli esiti.

### Funzioni principali (raggruppate per area)

#### Orchestrazione container

| Funzione                         | Descrizione                                                              |
|----------------------------------|--------------------------------------------------------------------------|
| `compose`                        | Esegue `docker compose --profile testing` con disabilitazione MSYS       |
| `start_base_services`            | Avvia container essenziali (db, Splunk, API, OPA, Envoy, Snort, FW)     |
| `start_testing_clients`          | Avvia SWTPM e client TPM dimostrativi                                    |

#### Attesa servizi (polling attivo)

| Funzione                         | Descrizione                                                              |
|----------------------------------|--------------------------------------------------------------------------|
| `wait_for_opa`                   | Polling su REST OPA (max 90 s)                                           |
| `wait_for_splunk_hec`            | Polling su Splunk HEC (max 180 s)                                        |
| `wait_for_splunk_search_api`     | Polling su API ricerca Splunk (max 180 s)                                |

#### Invio richieste e verifica esiti

| Funzione                         | Descrizione                                                              |
|----------------------------------|--------------------------------------------------------------------------|
| `run_access_test`                | Richiesta HTTPS mTLS con firma TPM; verifica status HTTP atteso          |
| `run_plain_tls_test`             | Richiesta TLS senza certificato client                                   |
| `run_missing_cert_test`          | Richiesta con percorso certificato inesistente                           |
| `extract_http_status`            | Estrae codice HTTP 3 cifre da output `openssl s_client`                  |
| `identity_for`                   | Cerca nella matrice `identity_bindings.testing.conf` e restituisce `cert_path|tpm_handle` |

#### Integrazione Splunk

| Funzione                         | Descrizione                                                              |
|----------------------------------|--------------------------------------------------------------------------|
| `run_splunk_search_json`         | Esegue query Splunk in modalità export e restituisce JSON                |
| `extract_splunk_stat`            | Estrae valore numerico da risposta Splunk (campo specifico)              |
| `send_splunk_hec_event`          | Invia evento JSON a Splunk HEC con token configurato                     |
| `pause_dynamic_risk_updates`     | Sospende la saved search durante le suite con rischio statico            |
| `resume_dynamic_risk_updates`    | Riattiva la saved search al termine della suite                          |

#### Gestione risk score OPA

| Funzione                         | Descrizione                                                              |
|----------------------------------|--------------------------------------------------------------------------|
| `set_static_risk_scores_baseline`| Ripristina `risk_scores.json`, riavvia OPA e verifica i valori attesi    |
| `get_opa_risk_score`             | Legge risk score corrente di un utente da OPA via REST API               |

#### Registrazione esiti

| Funzione                         | Descrizione                                                              |
|----------------------------------|--------------------------------------------------------------------------|
| `record_pass`, `record_fail`, `record_skip` | Incrementa contatori e stampa esito                          |
| `print_summary`                  | Stampa riepilogo finale OK/FAIL/SKIP                                     |

### Principi ZTA nei test helpers

- **Nessuna assunzione sull'ambiente**: tutti i path e le credenziali sono
  letti da `.env` o ricavati dalla matrice `identity_bindings.testing.conf`.
- **Verifica attiva**: `wait_for_*` effettua polling attivo, non timeout fissi.
- **Test atomici**: ogni invocazione di `run_access_test` è un test indipendente
  con contatori separati.
- **Rischio deterministico**: le suite statiche sospendono temporaneamente la
  saved search Splunk, evitando che gli alert generati dalle suite precedenti
  modifichino la baseline durante le verifiche. La pianificazione viene sempre
  riattivata all'uscita; il test del rischio dinamico la mantiene attiva.

---

## 3. `config_audit.sh` – Configurazione Unificata Audit

### Scopo

Definisce le variabili comuni utilizzate da `test_audit_nftables.sh` e
`test_audit_snort.sh`: IP di tutti i container, porte servizi, path dei
file di log e colori per output.

### Variabili esportate (raggruppate)

#### Indirizzi IP firewall (usati come target nei test)

| Variabile             | IP            | Descrizione                    |
|-----------------------|---------------|--------------------------------|
| `FW_CORPORATE_IP`     | 172.20.10.10  | Firewall su corporate_net      |
| `FW_VPN_IP`           | 172.20.11.10  | Firewall su vpn_net            |
| `FW_SATELLITE_IP`     | 172.20.12.10  | Firewall su satellite_net      |
| `FW_PUBLIC_IP`        | 172.20.13.10  | Firewall su public_net         |

#### Indirizzi IP dei client

| Variabile             | IP            | Descrizione                    |
|-----------------------|---------------|--------------------------------|
| `CLIENT_D001_IP`      | 172.20.11.31  | Client D-001 su vpn_net        |
| `CLIENT_D002_IP`      | 172.20.12.31  | Client D-002 su satellite_net  |
| `CLIENT_DSOC_IP`      | 172.20.10.31  | Client D-SOC su corporate_net  |

#### Indirizzi IP di Envoy (PEP) su ogni rete

| Variabile             | IP            | Descrizione                    |
|-----------------------|---------------|--------------------------------|
| `ENVOY_IP`            | 172.20.2.7    | Envoy su zerotrust_net         |
| `ENVOY_CORPORATE_IP`  | 172.20.10.7   | Envoy su corporate_net         |
| `ENVOY_VPN_IP`        | 172.20.11.7   | Envoy su vpn_net               |
| `ENVOY_SATELLITE_IP`  | 172.20.12.7   | Envoy su satellite_net         |

#### Porte servizi

| Variabile             | Porta | Servizio                       |
|-----------------------|-------|--------------------------------|
| `ENVOY_PORT`          | 8443  | Envoy (PEP) mTLS               |
| `MONGO_PORT`          | 27017 | MongoDB                        |
| `API_PORT`            | 3000  | API backend                    |
| `OPA_PORT`            | 8181  | OPA REST                       |
| `SPLUNK_WEB_PORT`     | 8000  | Splunk Web UI                  |
| `SPLUNK_HEC_PORT`     | 8088  | Splunk HEC                     |

---

## Test applicativi (Policy OPA)

I test applicativi verificano il cuore della Zero Trust Architecture: la
policy ABAC di OPA, il binding utente-dispositivo-rete e il risk score
dinamico.

---

## 4. `test_access_success.sh` – Accessi Consentiti

### Scopo

Verifica che le richieste **autorizzate** dalla policy OPA ricevano risposta
HTTP 200 e arrivino correttamente al backend API. Ogni richiesta è firmata
con la chiave privata TPM del dispositivo.

### Cosa testa

| Test                              | Utente               | Dispositivo | Metodo | Path             | Risultato atteso |
|-----------------------------------|----------------------|-------------|--------|------------------|------------------|
| operatore_ancona legge R-001      | operatore_ancona     | D-001       | GET    | /risorse/R-001   | 200              |
| operatore_ancona da D-002 legge   | operatore_ancona     | D-002       | GET    | /risorse/R-001   | 200              |
| capitano_claudia da D-001 legge   | capitano_claudia     | D-001       | GET    | /risorse/R-001   | 200              |
| capitano_claudia da D-002 legge   | capitano_claudia     | D-002       | GET    | /risorse/R-001   | 200              |
| soc_admin da D-SOC vista completa | soc_admin            | D-SOC       | GET    | /all             | 200              |
| soc_admin da D-001 vista completa | soc_admin            | D-001       | GET    | /all             | 200              |
| soc_admin da D-002 vista completa | soc_admin            | D-002       | GET    | /all             | 200              |
| capitano_claudia da D-002 lista   | capitano_claudia     | D-002       | GET    | /risorse         | 200              |

### Principi ZTA verificati

- **Minimo privilegio**: ogni utente può operare solo sui dispositivi
  associati (binding esplicito).
- **Network‑aware**: `operatore_ancona` può accedere da D-001 solo su
  `vpn_net` e da D-002 su `satellite_net`.
- **Resource‑level ABAC**: `soc_admin` ha `*` accesso, gli altri hanno
  solo `risorse` e `dispositivi`.

---

## 5. `test_access_denied.sh` – Accessi Negati

### Scopo

Verifica che le richieste **non autorizzate** ricevano risposta HTTP 403
con body JSON contenente le motivazioni del diniego (`reason_codes`).

### Cosa testa

| Test                              | Utente               | Dispositivo | Metodo | Path             | Risultato atteso |
|-----------------------------------|----------------------|-------------|--------|------------------|------------------|
| operatore_ancona non può inserire | operatore_ancona     | D-001       | POST   | /risorse         | 403              |
| operatore_ancona non può usare /all| operatore_ancona    | D-001       | GET    | /all             | 403              |
| capitano_claudia non può cancellare| capitano_claudia   | D-002       | DELETE | /risorse/R-001   | 403              |
| capitano_claudia non può usare /all| capitano_claudia   | D-002       | GET    | /all             | 403              |
| soc_admin non può accedere a R-999 | soc_admin           | D-SOC       | GET    | /risorse/R-999   | 403              |

### Principi ZTA verificati

- **Default deny**: anche un utente valido su dispositivo valido può essere
  negato se l'operazione o la risorsa non sono nel profilo.
- **Resource‑level RBAC**: R-999 non esiste in `access_rules.json` quindi
  è negato anche per `soc_admin`.
- **Command‑level ABAC**: `operatore_ancona` non ha `POST`; `capitano_claudia`
  non ha `DELETE`.

---

## 6. `test_mtls_failures.sh` – Fallimenti mTLS

### Scopo

Verifica i casi in cui il canale mTLS stesso fallisce (nessun certificato
o certificato mancante) e i casi in cui mTLS è valido ma OPA nega la
richiesta per policy.

### Cosa testa

| Categoria         | Test                                      | Condizione                          | Risultato atteso |
|-------------------|-------------------------------------------|-------------------------------------|------------------|
| **mTLS fallito** | Richiesta senza certificato client        | `openssl s_client` senza `-cert`   | 000 (connessione rifiutata) |
| **mTLS fallito** | Certificato client mancante nel container | Percorso certificato inesistente   | 000 (connessione rifiutata) |
| **OPA deny**     | mTLS OK + operatore /all                  | Certificato valido, OPA nega       | 403              |
| **OPA deny**     | mTLS OK + capitano DELETE R-001           | Certificato valido, OPA nega       | 403              |

### Principi ZTA verificati

- **Never trust, always verify**: Envoy richiede sempre certificato client
  per stabilire la connessione TLS.
- **Defense in depth**: anche con mTLS valido, OPA può negare l'operazione
  per policy (comando non permesso, risorsa non accessibile).
- **Verifica del certificato**: se il file certificato non esiste, la
  connessione TLS non viene stabilita (errore OpenSSL).

---

## 7. `test_dynamic_risk_score.sh` – Rischio Dinamico

### Scopo

Testa il ciclo completo del risk score dinamico che integra Splunk, OPA e
Snort. Questo è il test più complesso della suite e verifica l'intera
pipeline di **continuous monitoring** e **adaptive access control**.

### Flusso del test

| Passo | Azione                                                                 | Verifica                                          |
|-------|------------------------------------------------------------------------|---------------------------------------------------|
| 1     | Sospensione saved search e ripristino baseline                         | `risk_score = 10` per gli utenti autorizzati      |
| 2     | Invio 8 eventi deny via HEC per `operatore_ancona`                     | Splunk ha indicizzato 8 eventi univoci            |
| 3     | Riattivazione e attesa della saved search Splunk                       | `risk_score >= 80` per `operatore_ancona`         |
| 4     | Richiesta normalmente consentita (`GET /risorse/R-001`)                | HTTP 403 (bloccata dal rischio elevato)           |
| 5     | Genera tentativo diretto a MongoDB da D-SOC per attivare Snort alert   | Alert Snort SID 999904 in Splunk                  |
| 6     | Attesa nuovo aggiornamento risk score per `soc_admin` (da alert Snort) | `risk_score >= 90` per `soc_admin`                |
| 7     | Richiesta normalmente consentita (`GET /all` da soc_admin)             | HTTP 403 (bloccata dal rischio elevato)           |
| 8     | Ripristino baseline e riattivazione della saved search                 | Ambiente lasciato in stato operativo              |

### Principi ZTA verificati

- **Continuous monitoring**: Splunk raccoglie e correla decision log OPA e
  alert IDS Snort, ricalcolando il rischio ogni minuto.
- **Adaptive access control**: OPA blocca richieste che sarebbero consentite
  a rischio basso, dimostrando adattamento in tempo reale.
- **Assume breach**: il test dimostra che anche un utente legittimo può
  essere bloccato se il suo profilo di rischio supera la soglia.

---

## Test di audit (Firewall e IDS)

I test di audit verificano i componenti di sicurezza perimetrale: il
firewall NFTables e l'IDS Snort. Vengono eseguiti prima dei test
applicativi per garantire che i controlli di rete e di rilevamento
siano operativi.

---

## 8. `test_audit_nftables.sh` – Audit Firewall NFTables

### Scopo

Esegue una verifica funzionale completa delle regole NFTables applicate dal
container `firewall_perimeter`. Utilizza connessioni TCP reali e verifica
i contatori del firewall e i file di log.

### Cosa testa

| Categoria                     | Test eseguiti                                                                 | Meccanismo di verifica                     |
|-------------------------------|-------------------------------------------------------------------------------|--------------------------------------------|
| **Permesso DNAT+FORWARD**     | Connessioni TCP da VPN, Satellite e Corporate verso Envoy (8443)             | Contatori FORWARD incrementati             |
| **Blocco INPUT**              | Tentativi connessione a porte interne (Mongo 27017, API 3000, OPA 8181, Splunk 8000) | Log `NFT-INPUT-DROP` nel file ulogd |
| **Movimento laterale**        | Blocco VPN ↔ Satellite (cliente a cliente)                                    | Timeout TCP (nessuna rotta)                |
| **Default FORWARD**           | Blocco VPN → Satellite porta 22                                               | Timeout TCP                                |
| **ICMP permesso**             | Ping verso firewall (diagnostica)                                             | Risposta ICMP positiva                     |
| **Loopback**                  | Connessione a 127.0.0.1 sul firewall                                          | Connessione stabilita o rifiutata dal SO   |

### Output

I risultati sono scritti in `out/report_tests_nftables.txt` con etichette
`[PASS]`, `[FAIL]`, `[WARN]` e dettagli su contatori e log.

### Principi ZTA verificati

- **Segmentazione di rete**: il firewall impedisce movimento laterale tra
  reti client diverse (VPN, Satellite, Corporate, Public).
- **Minimo accesso**: solo la porta 8443 del PEP è aperta in FORWARD; tutte
  le altre porte interne sono bloccate a livello INPUT.
- **Preservazione IP sorgente**: il DNAT non usa SNAT, quindi Envoy e OPA
  possono identificare la rete di provenienza del client.

---

## 9. `test_audit_snort.sh` – Audit IDS Snort

### Scopo

Genera 35 attacchi/eventi per testare tutte le 8 categorie di regole Snort
personalizzate. Ogni attacco viene eseguito dal container client appropriato
simulando l'origine di rete attesa dalla regola.

### Categorie testate

| Categoria          | SIDs            | Attacchi generati                                                       |
|--------------------|-----------------|-------------------------------------------------------------------------|
| **0 – Diagnostica**  | 999901–999904   | Ping ICMP, SQLi test, SYN a MongoDB                                  |
| **1 – Ricognizione** | 1000001–1000005 | Port scan TCP (20 SYN), UDP scan (5 porte), NULL scan, SYN flood (110), Slowloris (50 connessioni) |
| **2 – Bypass PEP**   | 1000006–1000010 | Accessi diretti a MongoDB, API backend, OPA, admin Envoy, Splunk    |
| **3 – Anomalie TLS** | 1000011–1000017 | HTTP GET/POST in chiaro su mTLS, downgrade TLS 1.0/1.1, Heartbeat  |
| **4 – Injection**    | 1000015,1000018,1000019 | SQLi UNION SELECT, DROP TABLE, command injection cat /etc/passwd |
| **5 – Esfiltrazione**| 1000020,1000021 | Opcode MongoDB (wire protocol), 520 connessioni verso esterno         |
| **6 – Laterale**     | 1000022–1000028  | VPN→BACKEND, SATELLITE→BACKEND, SATELLITE→CORPORATE                  |
| **7 – Brute force**  | 1000029–1000031  | SSH (6 connessioni), Splunk (12), OPA (20)                            |
| **8 – Piano controllo**| 1000032–1000035| PUT/DELETE su OPA policies/data, log flooding Splunk HEC (220 richieste) |

### Output

I risultati sono scritti in `out/report_tests_snort.txt` con:
- Timestamp di ogni attacco
- Container coinvolto
- SIDs attesi (possono essere multipli, ad es. `1000032|1000008`)

### Principi ZTA verificati

- **Assume breach**: le regole presuppongono che un attaccante possa agire
  da qualsiasi rete (VPN, Satellite, Corporate).
- **Continuous monitoring**: tutti gli eventi sono loggati e inviati a
  Splunk per correlazione e risk scoring.
- **Defense in depth**: anche se il firewall e OPA bloccano l'attacco a
  livello di rete o applicazione, Snort rileva il tentativo e produce
  evidenza forense.

---

## Query Splunk per la verifica manuale

Aprire Splunk Web su `http://localhost:8000`, accedere con utente `admin` e
la password `SPLUNK_PASSWORD` presente nel file locale `.env`, quindi usare
**Search & Reporting**. Le query seguenti considerano gli ultimi 30 minuti.

### Eventi disponibili per sourcetype

```spl
index=main earliest=-30m
| stats count as eventi by sourcetype
| sort - eventi
```

Verifica rapidamente che Splunk stia ricevendo decisioni OPA, alert Snort e
log Envoy/MongoDB.

### Decisioni OPA per utente

```spl
index=main sourcetype=opa_decision earliest=-30m
| rex field=_raw max_match=1 "\"user_id\":\"(?<user_id>[^\"]+)"
| rex field=_raw max_match=1 "\"allowed\":(?<allowed>true|false)"
| stats count as totale sum(eval(allowed="true")) as consentite sum(eval(allowed="false")) as negate by user_id
| sort user_id
```

Per controllare soltanto il capitano:

```spl
index=main sourcetype=opa_decision "capitano_claudia" earliest=-30m
| table _time source host _raw
| sort - _time
```

### Eventi del test di rischio dinamico

```spl
index=main sourcetype=opa_decision source="dynamic-risk-test" earliest=-30m
| spath path=test_run_id output=test_run_id
| spath path=event_id output=event_id
| stats count as eventi dc(event_id) as eventi_univoci values(test_run_id) as esecuzioni
```

Il test completo deve produrre `eventi=8` ed `eventi_univoci=8` per ogni
esecuzione.

### Risk score correnti nel lookup Splunk

```spl
| inputlookup historical_risk_scores.csv
| table user_id risk_score isAnomaly denied_count unique_sources snort_alert_count snort_critical_count device_id trust_level updated_at
| sort user_id
```

Il lookup deve contenere sempre `operatore_ancona`, `capitano_claudia`,
`soc_admin` e `intruso`. La saved search aggiunge una baseline versionata
prima di calcolare gli eventi degli ultimi cinque minuti, quindi un utente
senza attività recente non scompare più dal CSV.

Per un singolo utente aggiungere, ad esempio:

```spl
| inputlookup historical_risk_scores.csv
| search user_id="capitano_claudia"
```

### Alert Snort recenti

```spl
index=main sourcetype=snort_alert_json earliest=-30m
| spath path=src_ap output=src_ap
| spath path=dst_ap output=dst_ap
| spath path=rule output=rule
| spath path=action output=action
| table _time src_ap dst_ap rule action
| sort - _time
```

Verifica specifica del tentativo diretto a MongoDB usato dal test dinamico:

```spl
index=main sourcetype=snort_alert_json earliest=-30m
| spath path=src_ap output=src_ap
| spath path=dst_ap output=dst_ap
| spath path=rule output=rule
| search rule="1:999904:*"
| table _time src_ap dst_ap rule
| sort - _time
```

### Log Envoy e MongoDB

```spl
index=main sourcetype=envoy_access_json earliest=-30m
| table _time host source _raw
| sort - _time
```

```spl
index=main sourcetype=mongodb_log earliest=-30m
| table _time host source _raw
| sort - _time
```

---

## Riepilogo Principi ZTA Coperti

| Principio                       | Test che lo verificano                                                          |
|---------------------------------|---------------------------------------------------------------------------------|
| **Never trust, always verify**  | `test_access_success`, `test_access_denied`, `test_mtls_failures`               |
| **Minimo privilegio**           | `test_access_success`, `test_access_denied`                                     |
| **Hardware-bound identity**     | `test_access_success` (firma TPM), `test_mtls_failures`                         |
| **Segmentazione di rete**       | `test_audit_nftables` (DNAT, INPUT drop, lateral movement)                      |
| **Continuous monitoring**       | `test_dynamic_risk_score` (Splunk + OPA), `test_audit_snort`, `test_audit_nftables` |
| **Adaptive access control**     | `test_dynamic_risk_score` (risk score che blocca accesso normalmente consentito)|                               |
| **Assume breach**               | `test_audit_snort` (tutte le 8 categorie), `test_audit_nftables`                |
| **Default deny**                | `test_access_denied`, `test_audit_nftables` (INPUT/FORWARD policy drop)         |
| **Defense in depth**            | `test_audit_snort` (IDS oltre a FW e OPA), `test_mtls_failures`                 |

---

## Note operative

- I test richiedono Docker Compose con profilo `testing` e le immagini
  Docker già costruite (`docker compose --profile testing build`).
- `test_dynamic_risk_score.sh` richiede Splunk operativo e può impiegare
  fino a 3 minuti per attendere l'aggiornamento del risk score (saved
  search ogni 60 secondi).
- `test_audit_snort.sh` genera gli attacchi ma non verifica automaticamente
  che gli alert siano effettivamente prodotti da Snort e arrivati a Splunk;
  la verifica incrociata è demandata a `test_dynamic_risk_score.sh`.
- I report prodotti in `tests/out/` sono dati runtime ignorati da Git e
  possono essere rigenerati eseguendo nuovamente le suite di audit.
- Per debug durante l'esecuzione, consultare i log dei container:
  ```bash
  docker compose --profile testing logs -f pep_gateway pdp_engine ids_network_monitor
  ```
