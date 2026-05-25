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

    request_handle:streamInfo():dynamicMetadata():set(
        "envoy.filters.http.lua",
        "context_extensions",
        {
            command = command,
            collection = collection or "unknown",
            path = path
        }
    )
end

function envoy_on_response(response_handle)
end
