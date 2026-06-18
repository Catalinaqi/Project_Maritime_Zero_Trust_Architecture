package envoy.authz

import rego.v1

# Di default ogni richiesta è negata.
default allow := false

# ============================================================================
# METADATI DA ENVOY / LUA
# ============================================================================

lua_metadata := object.get(
    input.attributes.metadataContext.filterMetadata,
    "envoy.filters.http.lua",
    {}
)

request_metadata := object.get(lua_metadata, "context_extensions", {})

user_id := object.get(request_metadata, "user_id", "unknown")

req_collection := object.get(request_metadata, "collection", "unknown")

req_resource_id := object.get(request_metadata, "resource_id", "unknown")

req_command := object.get(request_metadata, "command", "unknown")

# ============================================================================
# IDENTITÀ DISPOSITIVO DA CERTIFICATO mTLS
# ============================================================================

device_principal := object.get(input.attributes.source, "principal", "")

device_id := "D-001" if {
    contains(device_principal, "CN=D-001")
}

device_id := "D-001" if {
    contains(device_principal, "CN = D-001")
}

device_id := "D-002" if {
    contains(device_principal, "CN=D-002")
}

device_id := "D-002" if {
    contains(device_principal, "CN = D-002")
}

device_id := "D-SOC" if {
    contains(device_principal, "CN=D-SOC")
}

device_id := "D-SOC" if {
    contains(device_principal, "CN = D-SOC")
}

# ============================================================================
# PROFILI UTENTE E DISPOSITIVO
# ============================================================================

user_profile := data.roles[user_id]

device_profile := data.devices[device_id]

# ============================================================================
# REGOLA PRINCIPALE
# ============================================================================

allow if {
    user_exists
    device_exists
    device_trusted
    network_known
    access_rule_exists
    resource_allowed(user_profile.allowed_resources, req_collection)
    command_allowed(user_profile.allowed_commands, req_command)
    specific_resource_allowed
    time_allowed(user_profile)
    risk_allowed(user_profile)
}

# ============================================================================
# CONTROLLI BASE
# ============================================================================

user_exists if {
    data.roles[user_id]
}

device_exists if {
    data.devices[device_id]
}

device_trusted if {
    device_profile.trusted == true
}

# ============================================================================
# CONTROLLO RETE
# ============================================================================

current_network := network_name if {
    src_ip := input.attributes.source.address.socketAddress.address

    some network_name

    cidr := data.networks[network_name].cidrs[_]
    net.cidr_contains(cidr, src_ip)
}

network_known if {
    current_network
}

access_rule_exists if {
    rule := data.access_rules.rules[_]
    rule.user == user_id
    rule.device == device_id
    rule.networks[_] == current_network
}

# ============================================================================
# CONTROLLO COLLECTION E COMANDI
# ============================================================================

resource_allowed(allowed_resources, collection) if {
    allowed_resources[_] == "*"
}

resource_allowed(allowed_resources, collection) if {
    allowed_resources[_] == collection
}

command_allowed(allowed_commands, command) if {
    allowed_commands[_] == command
}

# ============================================================================
# CONTROLLO RBAC SU RISORSA SPECIFICA
# ============================================================================

# Se non è richiesta una risorsa specifica, ad esempio GET /risorse,
# rimane valido il controllo generale sulla collection.
specific_resource_allowed if {
    req_resource_id == "unknown"
}

# Se la collection non è "risorse", non applico il controllo RBAC specifico.
# Esempio: /dispositivi oppure /all.
specific_resource_allowed if {
    req_collection != "risorse"
}

# Se la richiesta è del tipo /risorse/R-001,
# controllo le regole specifiche dentro data.access_rules.resource_rules.
specific_resource_allowed if {
    req_collection == "risorse"
    req_resource_id != "unknown"

    resource_rule := data.access_rules.resource_rules[req_resource_id]

    resource_rule.allowed_roles[_] == user_profile.role
    resource_rule.allowed_commands[_] == req_command
}

# ============================================================================
# CONTROLLO FASCIA ORARIA
# ============================================================================

time_allowed(profile) if {
    profile.time_window_start
    profile.time_window_end
}

# ============================================================================
# CONTROLLO RISK SCORE DINAMICO
# ============================================================================

#risk_score := score if {
#    score := data.risk_data.risk_scores.risk_scores[user_id].risk_score
#} else := 0

# Recupera il risk score dell'utente corrente.
# Il dato arriva dal file:
# configs/opa/data/risk_data/risk_scores.json
#
# Dentro OPA il path diventa:
# data.risk_data.risk_scores
#
# Esempio:
# data.risk_data.risk_scores["operatore_ancona"].risk_score = 10

risk_score := object.get(
    object.get(data.risk_data.risk_scores, user_id, {}),
    "risk_score",
    0
)

# Controlla se il rischio dell'utente è minore o uguale
# alla soglia massima ammessa dal suo profilo/ruolo.
risk_allowed(profile) if {
    risk_score <= profile.max_risk_score
}
