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

#Check del dispositivio leggendo il l'OU dal certificato
#device_id := dev if {
#    # L'OU del certificato contiene il device ID
#    principal := input.attributes.source.principal
#    dev := regex.find_n("OU=([^,]+)", principal, 1)[0]
#    dev != ""
#}

#evice_allowed(profile) if {
#   profile.allowed_devices[_] == device_id
#}

# Device ID ora viene dall'header HTTP estratto da Lua
# invece che dall'OU del certificato utente
device_id := request_metadata.device_cn

device_allowed(profile) if {
    profile.allowed_devices[_] == device_id
}

# Blocca se il certificato device non è presente
device_present if {
    request_metadata.device_present == true
}


allow if {
    device_present
    resource_allowed(user_profile.allowed_resources, req_collection)
    command_allowed(user_profile.allowed_commands, req_command)
    device_allowed(user_profile)
    time_allowed(user_profile)
    risk_allowed(user_profile)
    network_allowed(user_profile)
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

network_allowed(profile) if {
    src_ip := input.attributes.source.address.socketAddress.address
    subnet := profile.allowed_subnets[_]
    net.cidr_contains(subnet, src_ip)
}
