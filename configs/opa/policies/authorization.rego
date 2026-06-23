package envoy.authz

import rego.v1

# La decisione predefinita è negativa: una richiesta viene autorizzata
# soltanto quando tutti i controlli Zero Trust risultano soddisfatti.
default allow := false

# ---------------------------------------------------------------------------
# Estrazione del contesto dalla richiesta
# ---------------------------------------------------------------------------

metadata_context := object.get(input.attributes, "metadataContext", {})
filter_metadata  := object.get(metadata_context, "filterMetadata", {})
lua_metadata     := object.get(filter_metadata, "envoy.filters.http.lua", {})
request_metadata := object.get(lua_metadata, "context_extensions", {})

user_id       := object.get(request_metadata, "user_id",     "unknown")
device_id     := object.get(request_metadata, "device_id",   "unknown")
req_collection := object.get(request_metadata, "collection",  "unknown")
req_resource_id := object.get(request_metadata, "resource_id", "unknown")
req_command   := object.get(request_metadata, "command",     "unknown")

user_profile   := object.get(data.roles,   user_id,   {})
device_profile := object.get(data.devices, device_id, {})

# ---------------------------------------------------------------------------
# Identificazione della rete sorgente
# ---------------------------------------------------------------------------

source_ip := object.get(
    object.get(
        object.get(input.attributes.source, "address", {}),
        "socketAddress",
        {},
    ),
    "address",
    "0.0.0.0",
)

# Restituisce il nome della rete corrispondente all'IP sorgente.
# Se nessun CIDR corrisponde, la variabile rimane indefinita.
current_network := network_name if {
    some network_name
    cidr := data.networks[network_name].cidrs[_]
    net.cidr_contains(cidr, source_ip)
}

# ---------------------------------------------------------------------------
# Condizioni elementari Zero Trust
# ---------------------------------------------------------------------------

user_exists       if data.roles[user_id]
device_exists     if data.devices[device_id]
device_trusted    if device_profile.trusted == true
# network_known è vero se e solo se current_network è stata assegnata.
network_known     if current_network

access_rule_exists if {
    rule := data.access_rules.rules[_]
    rule.user    == user_id
    rule.device  == device_id
    rule.networks[_] == current_network
}

# ---------------------------------------------------------------------------
# Verifica sulla risorsa e sul comando
# ---------------------------------------------------------------------------

# Wildcard: l'utente può accedere a qualsiasi collezione.
resource_allowed if user_profile.allowed_resources[_] == "*"
# Corrispondenza esatta sulla collezione richiesta.
resource_allowed if user_profile.allowed_resources[_] == req_collection

command_allowed if user_profile.allowed_commands[_] == req_command

# L'endpoint /all mappa sulla collezione "all"; viene controllato come le altre.
# L'accesso è consentito solo se l'utente ha wildcard "*" sulle risorse.

# ---------------------------------------------------------------------------
# Verifica sulla specifica risorsa (resource_id)
# ---------------------------------------------------------------------------

# Nessuna restrizione su resource_id se non è stato specificato.
specific_resource_allowed if req_resource_id == "unknown"
# Nessuna restrizione su resource_id per le collezioni diverse da "risorse".
specific_resource_allowed if req_collection != "risorse"
# Verifica la regola specifica della risorsa nella collezione "risorse".
specific_resource_allowed if {
    req_collection == "risorse"
    req_resource_id != "unknown"
    rule := data.access_rules.resource_rules[req_resource_id]
    rule.allowed_roles[_]    == user_profile.role
    rule.allowed_commands[_] == req_command
}

# ---------------------------------------------------------------------------
# Finestra temporale (fuso Europe/Rome)
# ---------------------------------------------------------------------------

# Converte una stringa HH:MM nel numero di minuti dall'inizio del giorno.
time_to_minutes(value) := result if {
    regex.match("^[0-2][0-9]:[0-5][0-9]$", value)
    hours   := to_number(substring(value, 0, 2))
    minutes := to_number(substring(value, 3, 2))
    hours <= 23
    result := hours * 60 + minutes
}

clock           := time.clock([time.now_ns(), "Europe/Rome"])
current_minutes := clock[0] * 60 + clock[1]
window_start    := time_to_minutes(user_profile.time_window_start)
window_end      := time_to_minutes(user_profile.time_window_end)

# Intervallo ordinario (es. 08:00-18:00): inizio < fine.
time_allowed if {
    window_start <= window_end
    current_minutes >= window_start
    current_minutes <= window_end
}

# Intervallo che attraversa la mezzanotte (es. 22:00-06:00): inizio > fine.
time_allowed if {
    window_start > window_end
    current_minutes >= window_start
}

time_allowed if {
    window_start > window_end
    current_minutes <= window_end
}

# ---------------------------------------------------------------------------
# Rischio dinamico
# ---------------------------------------------------------------------------

risk_record := object.get(data.risk_data.risk_scores, user_id, {})
risk_known  if object.get(risk_record, "risk_score", null) != null
risk_score  := object.get(risk_record, "risk_score", 100)
risk_allowed if {
    risk_known
    risk_score <= user_profile.max_risk_score
}

# ---------------------------------------------------------------------------
# Regola di autorizzazione principale
# ---------------------------------------------------------------------------

allow if {
    user_exists
    device_exists
    device_trusted
    network_known
    access_rule_exists
    resource_allowed
    command_allowed
    specific_resource_allowed
    time_allowed
    risk_allowed
}

# ---------------------------------------------------------------------------
# Motivazioni del diniego (incluse nei decision log)
# ---------------------------------------------------------------------------

denial_reasons contains "unknown_user"    if not user_exists
denial_reasons contains "unknown_device"  if not device_exists
denial_reasons contains "untrusted_device" if {
    device_exists
    not device_trusted
}
denial_reasons contains "unknown_network" if not network_known
denial_reasons contains "invalid_user_device_network_binding" if {
    user_exists
    device_exists
    network_known
    not access_rule_exists
}
denial_reasons contains "resource_not_allowed"          if { user_exists; not resource_allowed }
denial_reasons contains "command_not_allowed"           if { user_exists; not command_allowed }
denial_reasons contains "specific_resource_not_allowed" if not specific_resource_allowed
denial_reasons contains "outside_time_window"           if { user_exists; not time_allowed }
denial_reasons contains "risk_score_unavailable"        if { user_exists; not risk_known }
denial_reasons contains "risk_threshold_exceeded"       if { risk_known; not risk_allowed }

reason_list := sort([reason | denial_reasons[reason]])

# ---------------------------------------------------------------------------
# Risposta al plugin OPA-Envoy
# ---------------------------------------------------------------------------

# Caso positivo: OPA autorizza la richiesta e aggiunge gli header ZTA al backend.
decision := {
    "allowed": true,
    "headers": {
        "x-zta-user-id":    user_id,
        "x-zta-device-id":  device_id,
        "x-zta-network":    current_network,
        "x-zta-risk-score": sprintf("%v", [risk_score]),
    },
    "dynamic_metadata": {"reason_codes": []},
} if allow

# Caso negativo: OPA nega la richiesta con HTTP 403 e i codici di diniego.
decision := {
    "allowed":     false,
    "http_status": 403,
    "body": json.marshal({
        "error":        "access_denied",
        "message":      "Richiesta negata dalla policy Zero Trust",
        "reason_codes": reason_list,
    }),
    "dynamic_metadata": {"reason_codes": reason_list},
} if not allow
