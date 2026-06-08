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
        GET = "find",
        POST = "insert",
        PUT = "update",
        DELETE = "delete"
    }

    -- Se il metodo non è riconosciuto, usa "unknown".
    local command = command_map[method] or "unknown"

    -- Recupera l'utente applicativo.
    -- Il certificato mTLS identifica il dispositivo,
    -- mentre X-User-Id identifica l'utente.
    local user_id = request_handle:headers():get("x-user-id") or "unknown"

    -- Salva i metadati che verranno inviati a OPA tramite ext_authz.
    -- Nota:
    -- il risk score NON viene letto dagli header HTTP.
    -- Il rischio dinamico viene recuperato da OPA dai dati aggiornati da Splunk.
    request_handle:streamInfo():dynamicMetadata():set(
        "envoy.filters.http.lua",
        "context_extensions",
        {
            command = command,
            collection = collection,
            resource_id = resource_id,
            path = clean_path,
            user_id = user_id
        }
    )
end

function envoy_on_response(response_handle)
end