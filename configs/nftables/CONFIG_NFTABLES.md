# 🔥 Firewall Perimetrale (NFTables) - Maritime ZTA

## Scopo
Questo modulo implementa la **Layer 1 Network Security**, agendo come "Muro Perimetrale" per garantire 
l'isolamento dei dati e la protezione dai tentativi di accesso non autorizzato basandosi sui principi della Zero Trust Architecture (ZTA).

---

## Modello di Sicurezza
- **Default DENY:** Tutto il traffico è bloccato per impostazione predefinita.
- **Isolamento MongoDB:** Il database è raggiungibile SOLO attraverso l'API Backend, bloccando ogni accesso diretto.
- **Punto di Ingresso Unico:** Solo Envoy (PEP) è esposto sulla porta `8443`.
- **Visibilità:** Ogni tentativo di violazione viene registrato e inviato a Splunk per l'analisi forense.

---

## Architettura di Rete
Il firewall opera come gateway tra le zone di fiducia (Trust Zones) definite nel `docker-compose.yml`:

| Zona | Rete | Scopo |
| :--- | :--- | :--- |
| **ZTA Backbone** | `zerotrust_net` | Cuore del sistema (Envoy, OPA, Firewall, Snort) |
| **Data Store** | `backend_net` | Isolamento totale del database (MongoDB) |
| **Observability** | `monitoring_net` | Canale sicuro per i log verso Splunk |
| **Client Access** | `corporate/vpn/satellite/public` | Segmentazione in base al profilo utente |

---

## Regole di Sicurezza (Forward Chain)
In sintesi, il firewall applica queste 8 direttive logiche:
1. **Stato:** Permette il traffico di ritorno delle connessioni già autorizzate.
2. **Accesso Pubblico:** Autorizza solo il traffico verso Envoy sulla porta `8443`.
3. **Protezione DB:** Permette solo al `api_backend` di parlare con MongoDB (`27017`).
4. **Isolamento OPA:** Permette solo a Envoy di interrogare le politiche su OPA (`8181/9191`).
5. **Observability:** Permette l'invio dei log di sicurezza verso Splunk (`8088`).
6. **Diagnostica:** Consente il protocollo ICMP (ping) per i test di rete.
7. **Audit:** Registra tutti i tentativi di accesso non autorizzati nei log di sistema.
8. **Drop Finale:** Scarta silenziosamente tutto ciò che non è esplicitamente permesso.

---

## Test e Validazione
Per verificare il corretto funzionamento del firewall:
1. Esegui il test automatizzato dalla cartella principale:
   ```bash
   ./configs/nftables/test_firewall_*.sh
