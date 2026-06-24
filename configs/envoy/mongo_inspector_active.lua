-- Estrae identita, rete e risorsa dalla richiesta e prepara il contesto OPA.
local function trim(value)
    return string.match(value or "", "^%s*(.-)%s*$") or value
end

local function first_uri_san(ssl)
    if ssl == nil then
        return nil
    end

    local ok, sans = pcall(function()
        return ssl:uriSanPeerCertificate()
    end)

    if ok and type(sans) == "table" then
        for _, value in ipairs(sans) do
            if value ~= nil and value ~= "" then
                return value
            end
        end
    end

    return nil
end

local function peer_subject(ssl)
    if ssl == nil then
        return nil
    end

    local ok, value = pcall(function()
        return ssl:subjectPeerCertificate()
    end)

    if ok and value ~= nil and value ~= "" then
        return value
    end

    return nil
end

local function peer_common_name(ssl)
    if ssl == nil then
        return nil
    end

    local ok, parsed = pcall(function()
        return ssl:parsedSubjectPeerCertificate()
    end)

    if ok and parsed ~= nil then
        local ok_cn, cn = pcall(function()
            return parsed:commonName()
        end)

        if ok_cn and cn ~= nil and cn ~= "" then
            return cn
        end
    end

    return nil
end

local function source_network_from_ip(source_ip)
    if string.match(source_ip or "", "^172%.20%.10%.") then
        return "corporate_net"
    elseif string.match(source_ip or "", "^172%.20%.11%.") then
        return "vpn_net"
    elseif string.match(source_ip or "", "^172%.20%.12%.") then
        return "satellite_net"
    elseif string.match(source_ip or "", "^172%.20%.13%.") then
        return "public_net"
    end

    return "unknown"
end

function envoy_on_request(request_handle)
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

    request_handle:headers():remove("x-user-id")
    request_handle:headers():remove("x-device-id")
    request_handle:headers():remove("x-zta-user-id")
    request_handle:headers():remove("x-zta-device-id")
    request_handle:headers():remove("x-zta-network")
    request_handle:headers():remove("x-zta-risk-score")

    local ssl = nil
    pcall(function()
        ssl = request_handle:streamInfo():downstreamSslConnection()
    end)

    if ssl == nil then
        pcall(function()
            ssl = request_handle:connection():ssl()
        end)
    end

    local xfcc = request_handle:headers():get("x-forwarded-client-cert") or ""
    local subject = string.match(xfcc, 'Subject="([^"]*)"') or ""
    local uri = string.match(xfcc, 'URI="?([^;,%s"]+)"?') or ""

    local tls_uri = first_uri_san(ssl)
    local tls_subject = peer_subject(ssl)
    local tls_common_name = peer_common_name(ssl)

    if tls_uri ~= nil then
        uri = tls_uri
    end

    if tls_subject ~= nil then
        subject = tls_subject
    end

    local user_id, device_id = string.match(
        uri,
        "^spiffe://[^/]+/users/([^/]+)/devices/([^/]+)$"
    )

    if user_id == nil or device_id == nil then
        user_id, device_id = string.match(
            uri,
            "^spiffe://[^/]+/user/([^/]+)/device/([^/]+)$"
        )
    end

    if user_id == nil then
        user_id = tls_common_name or string.match(subject, "CN%s*=%s*([^,/]+)")
    end

    if device_id == nil then
        device_id = string.match(subject, "OU%s*=%s*([^,/]+)")
    end

    local remote_address = request_handle:streamInfo():downstreamDirectRemoteAddress() or ""
    local source_ip = string.match(remote_address, "^(%d+%.%d+%.%d+%.%d+)") or "unknown"
    local source_network = source_network_from_ip(source_ip)
    local clean_user_id = trim(user_id or "unknown")
    local clean_device_id = trim(device_id or "unknown")

    request_handle:headers():replace("x-zta-user-id", clean_user_id)
    request_handle:headers():replace("x-zta-device-id", clean_device_id)
    request_handle:headers():replace("x-zta-network", source_network)

    request_handle:streamInfo():dynamicMetadata():set(
        "envoy.filters.http.lua",
        "context_extensions",
        {
            command = command,
            collection = collection,
            resource_id = resource_id,
            path = clean_path,
            user_id = clean_user_id,
            device_id = clean_device_id,
            source_ip = source_ip,
            source_network = source_network
        }
    )
end

function envoy_on_response(response_handle)
end
