# Rapporto di revisione — versione finale

## Esito complessivo

Il progetto contiene tutti i componenti richiesti dalla consegna: Envoy (PEP), OPA (PDP),
Splunk (SIEM), NFTables (firewall perimetrale), Snort 3 (IDS), MongoDB (database), mTLS
con certificati hardware-bound via SWTPM, policy ABAC e controllo del rischio dinamico.

---

## Bug critici corretti in questa revisione

### 1. Struttura dati OPA errata (BUG FUNZIONALE BLOCCANTE)

**Problema**: i file JSON dei dati OPA contenevano un livello di wrapper superfluo:
```json
{ "roles": { "operatore_ancona": {...} } }
```
OPA monta `/policies/roles.json` come `data.roles`; il valore risultante era quindi
`data.roles = {"roles": {...}}`, rendendo `data.roles["operatore_ancona"]` sempre
indefinito. La policy avrebbe negato ogni richiesta con `unknown_user`, indipendentemente
dalle credenziali presentate.

**Correzione**: rimosso il wrapper in tutti e cinque i file:
`roles.json`, `devices.json`, `networks.json`, `access_rules.json`, `risk_scores.json`.
La struttura è ora piatta, con i dati direttamente accessibili come `data.roles[user_id]`.

### 2. Finestra temporale intruso sempre aperta a mezzanotte

**Problema**: `intruso` aveva `time_window_start: "00:00"` e `time_window_end: "00:00"`.
La regola `window_start <= window_end` con entrambi i valori a 0 era soddisfatta;
`current_minutes <= 0` era vera a mezzanotte esatta, autorizzando l'accesso.

**Correzione**: finestra impostata a `"00:01"–"00:00"` (inizio > fine, attraversa la
mezzanotte), resa sempre falsa dalla terza clausola `time_allowed`.

### 3. Certificati generati inclusi nello ZIP

**Problema**: lo ZIP conteneva chiavi private (`ca.key`, `server.key`, `mongodb-server.key`)
e certificati generati — dati che non devono essere distribuiti.

**Correzione**: tutti i file nelle directory `certs/` rimossi; rimangono solo `.gitkeep`
e `certs/README.md`. I certificati si generano localmente con `bash scripts/generate_certs.sh`.

---

## Bug minori corretti

### 4. Regole Snort diagnostiche ad ambito illimitato

`ZTA-MVP-001` e `ZTA-MVP-002` generavano alert su qualsiasi ICMP e qualsiasi TCP SYN,
producendo migliaia di eventi durante il normale funzionamento TLS.  
Sostituite con versioni che filtrano su `$EXTERNAL_NET → $HOME_NET` e con soglia
`detection_filter` per ZTA-MVP-002.

### 5. OPA policy — network_known e commenti

La regola `network_known` è stata allineata alla semantica corretta di OPA:
usa la parola chiave `if` senza confronto esplicito con la stringa vuota.
Aggiunti commenti tecnici dettagliati a tutte le sezioni della policy.

### 6. Timeout ext_authz Envoy troppo basso

Il timeout OPA era 1 s. Aumentato a 2 s per ridurre i 503 durante l'avvio a freddo
quando OPA carica le policy.

### 7. Script Python Splunk — formato piatto

`opa_risk_updater.py` aggiornato per scrivere il JSON in formato piatto, coerente
con la struttura attesa dalla policy OPA. Aggiunti commenti professionali.

### 8. historical_risk_scores.csv — riga con user_id vuoto

La riga dati seed aveva `user_id` vuoto, causando un warning nello script Python
a ogni esecuzione. Rimossa.

---

## Verifiche eseguite staticamente

- Parsing YAML: `docker-compose.yml`, `envoy.yaml`, `opa/config.yaml`
- Parsing JSON: tutti i file di dati OPA
- Sintassi Bash: tutti gli script `.sh` con `bash -n`
- Struttura dati OPA vs. percorsi nella policy Rego
- Coerenza volumi Docker Compose vs. percorsi in Envoy, OPA, MongoDB, Snort, Splunk
- Presenza di tutte le variabili d'ambiente richieste in `.env.example`
- Assenza di chiavi private e certificati nello ZIP
- Assenza del file `.env` nello ZIP
- Cross-reference SAN URI nei certificati TPM vs. pattern Lua vs. policy OPA

## Verifiche non eseguibili (ambiente privo di Docker)

- `docker compose config` con il plugin Docker Compose
- Build delle immagini (Snort, API backend, client TPM)
- Avvio end-to-end e healthcheck dei container
- Validazione Rego tramite binario OPA (`opa eval`)
- Verifica Snort in ambiente Linux con namespace di rete
- Ricezione reale degli eventi in Splunk

---

## Limitazioni note

- MongoDB è una singola istanza; la consegna non richiede replica set.
- Snort opera sul percorso client-firewall: il payload mTLS rimane cifrato.
- L'identità hardware è simulata con SWTPM (nessun TPM fisico richiesto).
- Il naming delle interfacce Snort/NFTables richiede Docker Compose ≥ 2.36.0.
- Splunk HEC usa HTTP sulla rete interna Docker (non esposto all'esterno).
