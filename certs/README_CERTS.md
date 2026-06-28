# Certificati generati localmente

Questa directory viene mantenuta nel repository soltanto tramite file `.gitkeep`.
Le chiavi private e i certificati generati non devono essere versionati né inclusi
nel pacchetto di consegna.

## Struttura della directory `certs/`

```text
certs/
├── ca/                          # CA radice (chiave privata solo su host)
│   ├── ca.crt                   #   Certificato radice (distribuito a tutti)
│   └── ca.key                   #   Chiave privata (MAI montata nei container)
├── server/                      # Certificato server per Envoy (PEP)
│   ├── server.crt               #   Usato da Envoy per terminazione mTLS
│   └── server.key               #   Chiave privata del server
├── mongodb/                     # Certificati per TLS reciproco con MongoDB
│   ├── mongodb-server.crt       #   Certificato server MongoDB
│   ├── mongodb-server.key       #   Chiave privata server MongoDB
│   ├── mongodb-server.pem       #   Combinazione crt+key per MongoDB
│   ├── api-client.crt           #   Certificato client per API backend
│   ├── api-client.key           #   Chiave privata client API backend
│   ├── api-client.pem           #   Combinazione per connessione API→MongoDB
│   ├── healthcheck-client.crt   #   Certificato per healthcheck MongoDB
│   ├── healthcheck-client.key   #   Chiave privata healthcheck
│   └── healthcheck-client.pem   #   Combinazione per healthcheck
└── devices/                     # Certificati utente‑dispositivo (TPM‑bound)
    ├── identity-certificates.tsv#   Indice autorevole: utente, dispositivo, percorso
    ├── D-001/identities/        #   Certificati per dispositivo D-001
    │   ├── operatore_ancona/    #       Utente: operatore_ancona
    │   │   ├── identity.crt     #           Certificato identita (SAN SPIFFE)
    │   │   ├── identity_tpm_public.pem  #     Chiave pubblica TPM
    │   │   └── ca.crt           #           CA radice (per validazione)
    │   ├── capitano_claudia/    #       Utente: capitano_claudia
    │   └── soc_admin/           #       Utente: soc_admin
    ├── D-002/identities/        #   Certificati per dispositivo D-002
    │   ├── operatore_ancona/
    │   ├── capitano_claudia/
    │   └── soc_admin/
    └── D-SOC/identities/        #   Certificati per dispositivo D-SOC
        └── soc_admin/
```

## Ruolo nella Zero Trust Architecture

| File / Directory                 | Ruolo ZTA                                               |
|----------------------------------|---------------------------------------------------------|
| `ca/ca.crt`                      | Trust anchor distribuito a tutti i componenti           |
| `ca/ca.key`                      | Firma offline di tutti i certificati (mai esposta)      |
| `server/server.crt` / `.key`     | Identita del PEP (Envoy) per terminazione mTLS          |
| `mongodb/mongodb-server.*`       | Identita del database; TLS obbligatorio su backend_net  |
| `mongodb/api-client.*`           | Identita del backend (API) verso MongoDB                |
| `mongodb/healthcheck-client.*`   | Identita del container di healthcheck MongoDB           |
| `devices/D-XXX/identities/*/identity.crt` | Certificato client con SAN URI SPIFFE (utente + dispositivo) |
| `devices/D-XXX/identities/*/identity_tpm_public.pem` | Chiave pubblica generata dal TPM per binding hardware |
| `devices/identity-certificates.tsv` | Matrice di provisioning leggibile da script e auditing   |

## Principi ZTA applicati

1.  **Mai fidarsi, sempre verificare**: ogni connessione mTLS richiede un
    certificato valido firmato dalla CA; non esistono eccezioni di rete.
2.  **Minimo privilegio**: ogni certificato contiene un SAN URI che identifica
    univocamente la coppia utente‑dispositivo; OPA abbina tale identita alle
    policy ABAC per decidere l'accesso.
3.  **Hardware‑bound identity**: la chiave privata dei certificati device e
    generata dentro il TPM emulato (SWTPM) e non puo essere estratta; il
    certificato e firmato dalla CA solo dopo aver attestato la corretta
    generazione della key pair.
4.  **Segregazione delle chiavi**: `ca.key` risiede esclusivamente sul filesystem
    host e **non** viene montata in alcun container, neppure durante il
    provisioning.
5.  **Rotazione e revoca**: per sostituire un certificato compromesso e
    sufficiente rigenerare il solo file interessato con gli script dedicati;
    la CA key resta invariata. La revoca e gestita a livello di policy OPA
    (non tramite CRL/OCSP, per semplicita dimostrativa).

## Comandi di generazione

- **PKI infrastrutturale** (CA, server, MongoDB): `bash scripts/generate_certs.sh`
- **Certificati device con TPM**: `bash scripts/provision_tpm_devices.sh`

Dopo ogni modifica alla matrice `configs/identity/identity_bindings.conf`
e necessario rieseguire entrambi gli script per allineare i certificati.
