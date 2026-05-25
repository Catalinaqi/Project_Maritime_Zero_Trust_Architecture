package envoy.authz

import rego.v1

default allow := false

# Lettura metadati con camelCase (protojson)
request_metadata := input.attributes.metadataContext.filterMetadata["envoy.filters.http.lua"].context_extensions

req_collection := request_metadata.collection
req_command    := request_metadata.command

# Identità mTLS
user_principal := input.attributes.source.principal

user_id := "operatore_ancona" if contains(user_principal, "CN=Marco Rossi")
user_id := "capitano_claudia" if contains(user_principal, "CN=Elena Bianchi")
user_id := "soc_admin"        if contains(user_principal, "CN=Admin SOC")

user_profile := data.users[user_id]

allow if {
    resource_allowed(user_profile.allowed_resources, req_collection)
    command_allowed(user_profile.allowed_commands, req_command)
    time_allowed(user_profile)
    risk_allowed(user_profile)
}

resource_allowed(allowed_list, collection) if { allowed_list[_] == "*" }
resource_allowed(allowed_list, collection) if { allowed_list[_] == collection }

command_allowed(allowed_list, command) if { allowed_list[_] == command }

time_allowed(profile) if {
    now   := time.clock([time.now_ns(), "Europe/Rome"])
    current_hour := now[0]
    start := to_number(substring(profile.time_window_start, 0, 2))
    end   := to_number(substring(profile.time_window_end,   0, 2))
    current_hour >= start
    current_hour <= end
}

risk_allowed(profile) if {
    score := request_metadata.risk_score
    score <= profile.max_risk_score
}

risk_allowed(profile) if {
    not request_metadata.risk_score
}
