# Policy di supporto usata per prove e confronto con la policy autorizzativa.
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

# Il filtro Lua ricava device_id dal CN del certificato verificato da Envoy.
# Non vengono usati header controllabili dal client.
device_id := object.get(request_metadata, "device_id", "unknown")

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
#
# L'ora corrente viene ricavata con time.clock(), evitando divisioni
# sui nanosecondi che possono produrre valori non interi e regole undefined.
#
# Le finestre sono espresse nel formato HH:MM.
# Sono gestiti:
# - intervalli normali, ad esempio 06:00-22:00;
# - intervalli che attraversano la mezzanotte, ad esempio 22:00-06:00;
# - start == end come blocco totale, secondo una logica fail-secure.
# ============================================================================

# Restituisce [ora, minuto, secondo] in UTC.
current_clock := time.clock(time.now_ns())

# Ora corrente in minuti dall'inizio della giornata.
current_time_minutes := total if {
    hours := current_clock[0]
    minutes := current_clock[1]
    total := (hours * 60) + minutes
}

# Rappresentazione diagnostica HH:MM.
current_time_str := sprintf("%02d:%02d", [
    current_clock[0],
    current_clock[1],
])

# Converte una stringa HH:MM in minuti dall'inizio della giornata.
time_string_to_minutes(value) := total if {
    parts := split(value, ":")
    count(parts) == 2

    hours := to_number(parts[0])
    minutes := to_number(parts[1])

    hours >= 0
    hours <= 23
    minutes >= 0
    minutes <= 59

    total := (hours * 60) + minutes
}

# Intervallo normale, ad esempio 06:00-22:00.
time_allowed(profile) if {
    start := time_string_to_minutes(profile.time_window_start)
    end := time_string_to_minutes(profile.time_window_end)

    start < end
    current_time_minutes >= start
    current_time_minutes <= end
}

# Intervallo che attraversa la mezzanotte: parte serale.
time_allowed(profile) if {
    start := time_string_to_minutes(profile.time_window_start)
    end := time_string_to_minutes(profile.time_window_end)

    start > end
    current_time_minutes >= start
}

# Intervallo che attraversa la mezzanotte: parte mattutina.
time_allowed(profile) if {
    start := time_string_to_minutes(profile.time_window_start)
    end := time_string_to_minutes(profile.time_window_end)

    start > end
    current_time_minutes <= end
}

# Nessuna regola copre start == end:
# la finestra viene quindi negata in modo fail-secure.

# ============================================================================
# CONTROLLO RISK SCORE DINAMICO
#
# Il risk score viene aggiornato da Splunk tramite opa_risk_updater.py
# e scritto nel file configs/opa/data/risk_data/risk_scores.json,
# montato in OPA come data.risk_data.risk_scores.
# ============================================================================

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
