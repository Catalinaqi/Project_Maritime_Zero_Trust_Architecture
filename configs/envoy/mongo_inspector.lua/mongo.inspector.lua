function envoy_on_request(request_handle)
    -- Recupera e normalizza metodo e percorso HTTP.
    local path = request_handle:headers():get(":path") or "unknown"
    local method = request_handle:headers():get(":method") or "unknown"
    local clean_path = string.match(path, "^[^?]+") or path
    local collection = string.match(clean_path, "^/([^/]+)") or "unknown"
    local resource_id = string.match(clean_path, "^/[^/]+/([^/]+)") or "unknown"

    local command_map = {
        GET = "find",
        POST = "insert",
        PUT = "update",
        PATCH = "update",
        DELETE = "delete"
    }

    local command = command_map[method] or "unknown"

    -- Non viene accettata alcuna identità dichiarata dal client via header.
    request_handle:headers():remove("x-user-id")
    request_handle:headers():remove("x-device-id")

    -- Envoy genera XFCC con SANITIZE_SET usando il certificato mTLS verificato.
    -- Subject atteso:
    -- /O=Maritime_Zero_Trust/OU=operatore_ancona/CN=D-001/L=Terminal-Ancona
    local xfcc = request_handle:headers():get("x-forwarded-client-cert") or ""
    local subject = string.match(xfcc, 'Subject="([^"]*)"') or ""

    -- CN identifica il dispositivo TPM-backed.
    local device_id = string.match(subject, "CN%s*=%s*([^,/]+)") or "unknown"

    -- OU identifica l'utente associato al certificato del dispositivo.
    local user_id = string.match(subject, "OU%s*=%s*([^,/]+)") or "unknown"

    device_id = string.match(device_id, "^%s*(.-)%s*$") or device_id
    user_id = string.match(user_id, "^%s*(.-)%s*$") or user_id

    request_handle:streamInfo():dynamicMetadata():set(
        "envoy.filters.http.lua",
        "context_extensions",
        {
            command = command,
            collection = collection,
            resource_id = resource_id,
            path = clean_path,
            user_id = user_id,
            device_id = device_id
        }
    )
end

function envoy_on_response(response_handle)
end
