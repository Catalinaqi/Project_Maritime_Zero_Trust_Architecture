function envoy_on_request(request_handle)
    local payload = request_handle:body()

    if payload then
        local payload_string = tostring(payload:getBytes(0, payload:length()))

        local extracted_command = ""
        local extracted_collection = ""

        if string.find(payload_string, "find") then
            extracted_command = "find"
            extracted_collection = "risorse"
        elseif string.find(payload_string, "insert") then
            extracted_command = "insert"
            extracted_collection = "risorse"
        end

        local metadata_table = {
            command = extracted_command,
            collection = extracted_collection
        }

        request_handle:streamInfo():dynamicMetadata():set(
            "envoy.filters.http.lua",
            "context_extensions",
            metadata_table
        )
    end
end

function envoy_on_response(response_handle)
    -- Necessario per chiudere il ciclo del filtro Lua, anche se vuoto
end
