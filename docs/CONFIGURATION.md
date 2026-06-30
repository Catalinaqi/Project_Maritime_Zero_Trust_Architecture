# Configurazioni – Maritime Zero Trust Architecture

La directory `configs/` contiene tutti i file di configurazione necessari per il
funzionamento dello stack ZTA. Ogni sottocartella corrisponde a un componente
dell'architettura e la sua documentazione, qui raccolta, evidenzia il ruolo
specifico all'interno del modello **Never Trust, Always Verify**.

## Struttura generale

```text
configs/
├── identity/                     # Matrice autorevole utente‑dispositivo‑rete
│   └── identity_bindings.conf
├── nftables/                     # Firewall perimetrale NFTables
│   └── rules.nft
├── envoy/                        # Policy Enforcement Point (Envoy)
│   ├── envoy.yaml
│   └── mongo_inspector_active.lua
├── snort/                        # IDS passivo Snort 3
│   ├── snort-zta.lua
│   └── snort-zta.rules
├── opa/                          # Policy Decision Point (OPA)
│   ├── config.yaml               # (non modificabile manualmente)
│   ├── mock_input.json
│   ├── policies/
│   │   └── authorization.rego
│   └── data/
│       ├── roles.json
│       ├── devices.json
│       ├── networks.json
│       ├── access_rules.json
│       └── risk_data/
│           └── risk_scores.json       # Generato a runtime
├── mongodb/                      # Database MongoDB con TLS obbligatorio
│   ├── mongod.conf
│   └── init-scripts/
│       ├── 01-init.js
│       └── 02-seed.js
├── runtime-templates/            # Baseline versionate dei dati mutabili
│   ├── risk_scores.json
│   └── historical_risk_scores.csv
└── splunk/                       # SIEM Splunk Enterprise
    ├── default.yml
    └── apps/
        └── opa_risk_updater/
            ├── app.conf
            ├── bin/
            │   └── opa_risk_updater.py
            ├── default/
            │   ├── transforms.conf
            │   ├── alert_actions.conf
            │   └── savedsearches.conf
            ├── local/
            │   ├── props.conf
            │   └── inputs.conf
            └── lookups/
                ├── snort_device_mapping.csv
                ├── risk_user_baseline.csv
                └── historical_risk_scores.csv  # Generato a runtime
```

---

## 1. `identity/` – Matrice delle identità

### File: `identity_bindings.conf`

```text
USER_ID|DEVICE_ID|CLIENT_SERVICE|TPM_HANDLE|DEVICE_LOCATION|NETWORK_NAME
```

Registra ogni coppia **utente‑dispositivo** autorizzata, con handle TPM dedicato,
posizione fisica e rete di appartenenza. È la **fonte di verità** per il
provisioning dei certificati device e per la generazione delle `access_rules.json`
di OPA.

**Principio ZTA:** *Minimo privilegio* – ogni binding è esplicito; nessun
utente può agire da un dispositivo non associato. *Hardware‑bound identity* –
la chiave privata risiede nel TPM e viene generata su di esso.

---

## 2. `nftables/` – Firewall perimetrale L3/L4

### File: `rules.nft`

Definisce le regole NFTables applicate dal container `firewall_perimeter`:

- **DNAT** (prerouting): redirige il traffico dalle reti client (vpn_net,
  satellite_net, corporate_net, public_net) verso Envoy sulla porta 8443.
  L'IP sorgente originale è preservato per permettere a OPA di identificare
  la rete di provenienza.
- **INPUT policy drop**: blocca tutto tranne traffico locale, connessioni
  stabilite e ICMP diagnostico.
- **FORWARD policy drop**: consente solo il traffico verso Envoy (porta 8443)
  dalle reti autorizzate; blocca esplicitamente il movimento laterale tra reti
  (VPN → satellite, public → VPN, ecc.) con log dedicato.
- **OUTPUT policy accept**: il firewall può inviare log a Splunk HEC.

**Principio ZTA:** *Nessuna fiducia implicita sulla rete* – il firewall non
permette comunicazioni laterali tra reti neppure se le connessioni sono
"interne". *Segmentazione di rete* – ogni rete client ha accesso solo al PEP.

---

## 3. `envoy/` – Policy Enforcement Point (PEP)

### File: `envoy.yaml`

Configura Envoy come **terminatore mTLS** e **gateway di autorizzazione**:

- Listener HTTPS sulla porta 8443 con `require_client_certificate: true`.
- Catena di filtri: **Lua** → **ext_authz (OPA)** → **Router**.
- Il filtro Lua estrae dal certificato client (SAN URI SPIFFE) `user_id` e
  `device_id`, li inserisce negli header `x-zta-*` e li passa a OPA tramite
  dynamic metadata.
- L'access log (JSON) è inviato a Splunk.
- Due cluster upstream: `cluster_backend_api` (API Node.js) e `cluster_opa`
  (OPA gRPC).

### File: `mongo_inspector_active.lua`

Filtro Lua attualmente in uso. Funzioni principali:

- `trim()`, `first_uri_san()`, `peer_subject()`, `peer_common_name()` per
  estrarre identità dal certificato TLS.
- `source_network_from_ip()`: determina la rete di origine in base al CIDR
  dell'IP sorgente.
- `envoy_on_request`: rimuove header non affidabili (`x-user-id`, ecc.),
  estrae SAN URI SPIFFE, soggetto, CN e OU, setta `x-zta-*` e popola il
  metadata contestuale per OPA.

**Principio ZTA:** *Never trust, always verify* – ogni richiesta è autenticata
via mTLS e autorizzata da OPA prima di raggiungere il backend. *Identity‑aware
enforcement* – il filtro estrae identità dal certificato, non da header
controllabili dal client.

---

## 4. `snort/` – IDS passivo (Network Monitoring)

### File: `snort-zta.lua`

Template di configurazione Snort 3 con variabili sostituite da `envsubst`
all'avvio. Definisce:

- DAQ afpacket in modalità **passiva** (non inline).
- Motore di pattern matching `ac_bnfa`.
- Stream TCP con timeout di 60 secondi.
- Ispettori HTTP e binder.
- Output `alert_json` verso file condiviso con Splunk.

### File: `snort-zta.rules`

Regole personalizzate per il progetto, organizzate in categorie:

| Categoria | SID range | Descrizione |
|-----------|-----------|-------------|
| 0 – Diagnostica | 9999xx | ICMP da reti esterne, TCP SYN, SQLi test, tentativi diretti a MongoDB |
| 1 – Ricognizione / DoS | 10000xx | Port scan TCP/UDP, SYN flood, Slowloris |
| 2 – Bypass del PEP | 10000xx | Accessi diretti a MongoDB, API, OPA, admin Envoy, Splunk |
| 3 – Anomalie TLS | 10001xx | HTTP in chiaro su porta mTLS, downgrade SSLv3/TLS1.0/1.1, Heartbeat |
| 4 – Injection | 10001xx | SQLi UNION SELECT, DROP TABLE/COLLECTION, command injection |
| 5 – Esfiltrazione | 10002xx | Wire protocol MongoDB anomalo, volume anomalo in uscita |
| 6 – Movimento laterale | 10002xx | Traffico tra reti non autorizzato (public → vpn, ecc.) |
| 7 – Brute force | 10002xx | SSH, Splunk, OPA |
| 8 – Manipolazione piano di controllo | 10003xx | PUT/DELETE su policy OPA, log flooding Splunk |

**Principio ZTA:** *Continuous monitoring* – Snort osserva passivamente tutto
il traffico client → PEP, rilevando tentativi di bypass, vulnerabilità e
movimento laterale. *Assume breach* – le regole presuppongono che un
attaccante possa agire da qualsiasi rete.

---

## 5. `opa/` – Policy Decision Point (PDP)

### Directory `policies/`

#### `authorization.rego`

Policy ABAC principale. Implementa:

1. **Estrazione del contesto** dai metadata Lua (`user_id`, `device_id`,
   `collection`, `resource_id`, `command`).
2. **Identificazione rete sorgente** tramite CIDR match.
3. **Condizioni elementari**: utente esiste, dispositivo esiste, dispositivo
   trusted, rete conosciuta, regola di accesso (binding utente‑dispositivo‑rete).
4. **Autorizzazione risorsa**: verifica che la collection e il comando siano
   ammessi dal profilo utente; controllo RBAC su risorsa specifica
   (`resource_rules`).
5. **Finestra temporale** con fuso Europe/Rome, gestisce intervalli normali
   e a cavallo della mezzanotte.
6. **Rischio dinamico**: legge `risk_scores.json` e verifica `risk_score <=
   max_risk_score`.
7. **Motivazioni di diniego** (`denial_reasons`) restituite nel body 403.
8. **Risposta** con header `x-zta-*` e `dynamic_metadata`.

Policy di default: **deny**.

### Directory `data/`

#### `roles.json`

Profili utente: `operatore_ancona`, `capitano_claudia`, `soc_admin` più
`intruso` per test. Ogni profilo definisce ruolo, risorse consentite, comandi,
finestra temporale e soglia massima di rischio.

#### `devices.json`

Dispositivi fidati: `D-001` (terminale porto), `D-002` (terminale nave),
`D-SOC` (postazione SOC), tutti con `trusted: true`.

#### `networks.json`

Mappa CIDR → nome rete: `corporate_net`, `vpn_net`, `satellite_net`,
`public_net`.

#### `access_rules.json`

Due sezioni:
- `rules`: binding **utente‑dispositivo‑rete** (6 regole, inclusi utenti
  condivisi su più dispositivi).
- `resource_rules`: RBAC per risorsa specifica (R-001,R-002,R-003,R-004), con
  ruoli e comandi permessi.

#### `risk_data/risk_scores.json`

Stato corrente dei risk score per utente, aggiornato periodicamente da
Splunk tramite `opa_risk_updater`. Include `denied_count`, `is_anomaly`,
`risk_score`, `snort_alert_count`, ecc. Il file non è versionato: viene creato
da `scripts/init_runtime.sh` usando il template pulito in
`configs/runtime-templates/risk_scores.json`.

### File: `mock_input.json`

Input fittizio per testare la policy in isolamento (simula una richiesta
GET di `operatore_ancona` da rete VPN).

**Principio ZTA:** *Unified policy enforcement* – tutte le decisioni di
accesso sono centralizzate in OPA, che valuta identità, dispositivo, rete,
risorsa, orario e rischio prima di consentire qualsiasi operazione.

---

## 6. `mongodb/` – Database con TLS obbligatorio

### File: `mongod.conf`

Configurazione MongoDB:

- `net.tls.mode: requireTLS` – solo connessioni TLS accolte.
- `net.tls.certificateKeyFile` e `CAFile` puntano ai certificati generati.
- `security.authorization: enabled` – autenticazione obbligatoria.
- `net.bindIp: 0.0.0.0` – necessario per il container backend (rete interna
  `backend_net`, non esposta).

### File: `init-scripts/01-init.js`

Crea l'account applicativo `maritime_api_role` con privilegi limitati alle
sole collezioni `utenti` (find), `dispositivi` (find), `risorse` (CRUD).
Nessun utente finale ha accesso diretto a MongoDB.

### File: `init-scripts/02-seed.js`

Popola il database dimostrativo con 3 utenti, 4 risorse, 3 dispositivi.
Gli indici garantiscono univocità degli identificatori applicativi.

**Principio ZTA:** *Minimo privilegio* – l'account API ha solo i permessi
strettamente necessari. *TLS mutuale* – MongoDB verifica il certificato
client, oltre al proprio. *Isolamento di rete* – `backend_net` è una rete
Docker interna non raggiungibile dai client.

---

## 7. `splunk/` – SIEM e Risk Score dinamico

### File: `default.yml`

Configurazione di base Splunk: accetta licenza, abilita HEC su `:8088`
senza TLS (la rete `monitoring_net` è interna).

### App: `opa_risk_updater`

#### `app.conf`

Metadati dell'app: autore, descrizione, versione 1.0, non visibile in UI.

#### `default/transforms.conf`

Registra il lookup runtime `historical_risk_scores.csv` e la baseline
versionata `risk_user_baseline.csv`.

#### `default/alert_actions.conf`

Definisce l'azione `opa_risk_updater` che esegue lo script Python per
scrivere il JSON dei risk score su `/opa_data/risk_data/risk_scores.json`.

#### `default/savedsearches.conf`

Saved search `Calcolo Dinamico Risk Score OPA` eseguita ogni minuto.
Combina decision log OPA (`sourcetype=opa_decision`) e alert Snort
(`sourcetype=snort_alert_json`), calcola `denied_count`, `unique_sources`,
`snort_alert_count`, `snort_critical_count`, determina `isAnomaly` e
`risk_score` (da 10 a 100) e scrive il risultato nel lookup CSV. Prima
dell'aggregazione aggiunge la baseline di tutti gli utenti configurati, così
anche chi non genera eventi negli ultimi cinque minuti rimane nel lookup. Al
termine scatena l'azione `opa_risk_updater`.

#### `local/props.conf`

Configura il parsing dei timestamp Snort (formato `%m/%d-%H:%M:%S.%6N`,
fuso `Europe/Rome`).

#### `local/inputs.conf`

Monitora tre file di log:
- `/var/log/snort/alert_json.txt` → `snort_alert_json`
- `/var/log/mongodb/mongod.log` → `mongodb_log`
- `/var/log/envoy/access.log` → `envoy_access_json`

#### `lookups/snort_device_mapping.csv`

Mappa IP sorgente a `user_id`, `device_id` e `trust_level`, usata dalla
saved search per arricchire gli alert Snort senza firma.

#### `lookups/risk_user_baseline.csv`

Elenca tutti gli utenti che devono comparire nel calcolo del rischio e i loro
valori minimi: rischio 10 per gli utenti autorizzati e rischio 90 per
`intruso`. Impedisce che un utente senza eventi recenti scompaia dal lookup.

#### `lookups/historical_risk_scores.csv`

Storico dei risk score per utente, prodotto dalla saved search e consumato
dallo script Python. Anche questo file è runtime e viene inizializzato dal
template versionato `configs/runtime-templates/historical_risk_scores.csv`.

#### `bin/opa_risk_updater.py`

Script Python eseguito come azione Splunk. Legge il lookup CSV, costruisce
il documento JSON piatto atteso da OPA e lo scrive in modo atomico (tramite
`tempfile.mkstemp` + `os.replace`) nel file `risk_scores.json` montato
dentro OPA.

**Principio ZTA:** *Continuous monitoring* – Splunk raccoglie e correla
decision log OPA, alert Snort, log firewall e log Envoy. Il risk score
dinamico viene ricalcolato ogni minuto e retroalimenta OPA per adattare
le decisioni in tempo reale.

---

## Regole di modifica

- I file in `opa/policies/` richiedono il riavvio di OPA (o `PUT /v1/policies`)
  per essere applicati.
- I file in `opa/data/` vengono ricaricati automaticamente da OPA al
  successivo ciclo di valutazione (polling ogni 60 s di default).
- La modifica di `mongodb/init-scripts/` richiede la rimozione del volume
  MongoDB (`bash scripts/clean_runtime.sh`) prima del riavvio.
- I file in `splunk/` richiedono il riavvio di Splunk per essere riletti.
- `mongod.conf` e `envoy.yaml` richiedono la ricostruzione del container
  (`docker compose up -d --build`).
- `nftables/rules.nft` viene applicato all'avvio del container firewall.
- `identity_bindings.conf` è la matrice autorevole: dopo ogni modifica
  eseguire `bash scripts/generate_certs.sh` e
  `bash scripts/provision_tpm_devices.sh`.
