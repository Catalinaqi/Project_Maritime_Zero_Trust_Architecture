function envoy_on_request(request_handle)
    -- Recupera il path della richiesta, ad esempio "/risorse".
    local path = request_handle:headers():get(":path") or "unknown"

    -- Recupera il metodo HTTP, ad esempio GET, POST, PUT o DELETE.
    local method = request_handle:headers():get(":method") or "unknown"

    -- Estrae la risorsa richiesta dal path.
    -- Esempio: "/risorse" diventa "risorse".
    local collection = string.match(path, "^/([^/]+)") or "unknown"

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
    -- Il certificato mTLS identifica il dispositivo, mentre X-User-Id identifica l'utente.
    local user_id = request_handle:headers():get("x-user-id") or "unknown"

    -- Salva solo i metadati necessari a OPA.
    -- Il risk score NON viene letto dagli header HTTP:
    -- viene recuperato da OPA dai dati aggiornati da Splunk.
    request_handle:streamInfo():dynamicMetadata():set(
        "envoy.filters.http.lua",
        "context_extensions",
        {
            command = command,
            collection = collection,
            path = path,
            user_id = user_id
        }
    )
end

function envoy_on_response(response_handle)
end