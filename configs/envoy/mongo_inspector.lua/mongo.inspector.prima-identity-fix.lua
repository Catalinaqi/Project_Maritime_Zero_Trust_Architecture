-- Versione storica del filtro Lua precedente alla correzione delle identita.
function envoy_on_request(request_handle)
    -- Recupera il path della richiesta, ad esempio:
    -- "/risorse"
    -- "/risorse/R-001"
    -- "/dispositivi"
    local path = request_handle:headers():get(":path") or "unknown"

    -- Recupera il metodo HTTP, ad esempio GET, POST, PUT o DELETE.
    local method = request_handle:headers():get(":method") or "unknown"

    -- Rimuove eventuali query string dal path.
    -- Esempio: "/risorse/R-001?debug=true" diventa "/risorse/R-001".
    local clean_path = string.match(path, "^[^?]+") or path

    -- Estrae la collection principale.
    -- Esempio:
    -- "/risorse/R-001" -> "risorse"
    -- "/dispositivi"   -> "dispositivi"
    local collection = string.match(clean_path, "^/([^/]+)") or "unknown"

    -- Estrae l'id specifico della risorsa, se presente.
    -- Esempio:
    -- "/risorse/R-001" -> "R-001"
    -- "/risorse"       -> "unknown"
    local resource_id = string.match(clean_path, "^/[^/]+/([^/]+)") or "unknown"

    -- Mappa il metodo HTTP in un comando logico usato da OPA.
    local command_map = {
        GET    = "find",
        POST   = "insert",
        PUT    = "update",
        DELETE = "delete"
    }

    -- Se il metodo non è riconosciuto, usa "unknown".
    local command = command_map[method] or "unknown"

    -- =========================================================================
    -- ESTRAZIONE user_id DAL CERTIFICATO mTLS
    --
    -- PROBLEMA ORIGINALE:
    --   user_id veniva letto dall'header HTTP X-User-Id, controllato dal client.
    --   Qualsiasi client poteva scrivere X-User-Id: soc_admin e impersonare
    --   un utente privilegiato, rendendo inutile il controllo in OPA.
    --
    -- SOLUZIONE:
    --   user_id viene estratto dal campo CN del certificato client presentato
    --   durante l'handshake mTLS. Envoy espone il subject del certificato
    --   verificato tramite l'header x-forwarded-client-cert (XFCC), che viene
    --   popolato automaticamente da Envoy dopo la validazione TLS e non può
    --   essere falsificato dal client (Envoy sovrascrive qualsiasi XFCC
    --   inviato dal client con il valore reale del certificato verificato).
    --
    -- FORMATO XFCC:
    --   By=spiffe://...;Hash=...;Subject="/O=Org/CN=operatore_ancona"
    --
    -- MAPPING CN -> user_id:
    --   Il CN del certificato device corrisponde direttamente alla chiave
    --   usata in data.roles (es. "operatore_ancona", "soc_admin").
    --   Il generate_certs.sh genera i device cert con CN=<user_id>.
    --   Vedere: certs/devices/D-001 -> CN=D-001, ma il cert client legacy
    --   usa CN=<nome_utente>. Per coerenza con data.roles usiamo il CN
    --   del cert client (il nome della cartella in certs/clients/).
    --
    -- FALLBACK:
    --   Se XFCC non è presente (connessione non mTLS, impossibile in prod
    --   perché Envoy richiede require_client_certificate: true) user_id
    --   rimane "unknown" e OPA nega la richiesta per user_exists = false.
    --
    -- SICUREZZA:
    --   L'header X-User-Id inviato dal client viene rimosso prima della
    --   valutazione, così non può interferire nemmeno come fallback.
    -- =========================================================================

    -- Rimuove l'header X-User-Id inviato dal client per evitare
    -- qualsiasi possibilità di injection o confusione.
    request_handle:headers():remove("x-user-id")

    -- Legge l'header XFCC popolato da Envoy dopo la validazione mTLS.
    local xfcc = request_handle:headers():get("x-forwarded-client-cert") or ""

    -- Estrae il campo Subject dal valore XFCC.
    -- Formato atteso: ...Subject="/O=Maritime_Zero_Trust/CN=operatore_ancona"...
    local subject = string.match(xfcc, 'Subject="([^"]*)"') or ""

    -- Estrae il CN dal Subject.
    -- Supporta sia "CN=valore" che "CN = valore" (con spazi).
    local user_id = string.match(subject, "CN%s*=%s*([^,/]+)") or "unknown"

    -- Rimuove eventuali spazi iniziali e finali dal CN estratto.
    user_id = string.match(user_id, "^%s*(.-)%s*$") or user_id

    -- Salva i metadati che verranno inviati a OPA tramite ext_authz.
    -- Nota: il risk score NON viene letto dagli header HTTP.
    -- Il rischio dinamico viene recuperato da OPA dai dati aggiornati da Splunk.
    request_handle:streamInfo():dynamicMetadata():set(
        "envoy.filters.http.lua",
        "context_extensions",
        {
            command     = command,
            collection  = collection,
            resource_id = resource_id,
            path        = clean_path,
            user_id     = user_id
        }
    )
end

function envoy_on_response(response_handle)
end
