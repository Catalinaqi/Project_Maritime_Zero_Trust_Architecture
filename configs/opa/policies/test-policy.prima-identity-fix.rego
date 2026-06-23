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
#
# PROBLEMA ORIGINALE:
#   time_allowed controllava solo che i campi time_window_start e
#   time_window_end esistessero nel profilo, non confrontava mai l'ora
#   corrente. La finestra oraria era quindi sempre ignorata.
#
# SOLUZIONE:
#   Viene estratta l'ora corrente UTC tramite time.now_ns() e convertita
#   in formato HH:MM. Viene poi confrontata con time_window_start e
#   time_window_end presenti nel profilo utente in data.roles.
#
#   Il confronto è lessicografico su stringhe "HH:MM", che funziona
#   correttamente per intervalli che non attraversano la mezzanotte
#   (es. "06:00" - "22:00"). Tutti i profili attuali usano "00:00"-"23:59"
#   oppure "00:00"-"00:00" (blocco totale per intruso), quindi il caso
#   mezzanotte non si presenta, ma viene gestito correttamente: se start
#   > end la regola nega sempre (comportamento fail-secure).
# ============================================================================

# Converte i nanosecondi Unix in ore e minuti UTC.
# time.now_ns() restituisce nanosecondi dall'epoch Unix.
# Dividiamo per 1e9 per ottenere i secondi, poi usiamo modulo
# per estrarre ore e minuti nell'arco della giornata.
current_time_minutes := minutes if {
    now_ns   := time.now_ns()
    now_s    := now_ns / 1000000000
    day_s    := now_s % 86400
    hours    := day_s / 3600
    minutes  := (day_s % 3600) / 60
}

# Formatta ore e minuti come stringa "HH:MM" con zero padding.
current_time_str := sprintf("%02d:%02d", [
    current_time_minutes / 60,
    current_time_minutes % 60
])

time_allowed(profile) if {
    # Entrambi i campi devono essere presenti nel profilo.
    start := profile.time_window_start
    end   := profile.time_window_end

    # L'ora corrente deve essere >= start e <= end.
    # Il confronto lessicografico su "HH:MM" è corretto
    # per intervalli che non attraversano la mezzanotte.
    current_time_str >= start
    current_time_str <= end
}

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
