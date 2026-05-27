function envoy_on_request(request_handle)
    local path = request_handle:headers():get(":path")
    local method = request_handle:headers():get(":method")

    -- Estrae la collection dall'URL: /risorse → "risorse"
    local collection = string.match(path, "^/([^/]+)")

    -- Mappa HTTP method → comando MongoDB
    local command_map = {
        GET = "find",
        POST = "insert",
        PUT = "update",
        DELETE = "delete"
    }

    local command = command_map[method] or "unknown"

    if device_cert_b64 then
        -- Decodifica e cerca il CN del device nel certificato base64
        -- In Lua non possiamo fare crypto, estraiamo il CN come stringa
        local decoded = request_handle:httpCall(
            "local_decoder",
            {
                [":method"] = "POST",
                [":path"] = "/decode-cert",
                [":authority"] = "localhost"
            },
            device_cert_b64,
            1000
        )
        -- Alternativa più semplice: cerca il pattern CN= nel base64 decodificato
        device_cn = string.match(device_cert_b64, "CN=([^,/]+)") or "unknown"
        device_verified = device_cn ~= "unknown"
    end

    -- Scrive tutti i metadati per OPA

    request_handle:streamInfo():dynamicMetadata():set(
        "envoy.filters.http.lua",
        "context_extensions",
        {
            command = command,
            collection = collection or "unknown",
            path = path
            device_cn      = device_cn,
            device_present = device_verified
        }
    )
end

function envoy_on_response(response_handle)
end
