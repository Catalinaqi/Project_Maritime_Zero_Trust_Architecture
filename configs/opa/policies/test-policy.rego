package envoy.authz

import rego.v1

# Di default ogni richiesta è negata.
default allow := false

# Recupera i metadati creati dal filtro Lua di Envoy.
lua_metadata := object.get(
    input.attributes.metadataContext.filterMetadata,
    "envoy.filters.http.lua",
    {}
)

request_metadata := object.get(lua_metadata, "context_extensions", {})

# L'utente applicativo arriva dall'header X-User-Id,
# letto dal filtro Lua e passato a OPA.
user_id := object.get(request_metadata, "user_id", "unknown")

# Risorsa richiesta, ad esempio "risorse" o "dispositivi".
req_collection := object.get(request_metadata, "collection", "unknown")

# Comando logico richiesto, ad esempio "find", "insert", "update", "delete".
req_command := object.get(request_metadata, "command", "unknown")

# Principal del certificato mTLS.
# Nella nuova architettura rappresenta il dispositivo.
device_principal := object.get(input.attributes.source, "principal", "")

# Estrae l'identificativo del dispositivo dal subject del certificato mTLS.
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

# Profilo dell'utente letto da roles.json.
# Con i file JSON montati singolarmente:
# roles.json viene esposto come data.roles.
user_profile := data.roles[user_id]

# Profilo del dispositivo letto da devices.json.
# devices.json viene esposto come data.devices.
device_profile := data.devices[device_id]

# Regola principale:
# la richiesta è permessa solo se tutti i controlli sono veri.
allow if {
    user_exists
    device_exists
    device_trusted
    network_known
    access_rule_exists
    resource_allowed(user_profile.allowed_resources, req_collection)
    command_allowed(user_profile.allowed_commands, req_command)
    time_allowed(user_profile)
    risk_allowed(user_profile)
}

# Controlla che l'utente esista in roles.json.
user_exists if {
    data.roles[user_id]
}

# Controlla che il dispositivo esista in devices.json.
device_exists if {
    data.devices[device_id]
}

# Controlla che il dispositivo sia trusted.
device_trusted if {
    device_profile.trusted == true
}

# Identifica la rete sorgente in base all'IP del client.
current_network := network_name if {
    src_ip := input.attributes.source.address.socketAddress.address

    some network_name

    cidr := data.networks[network_name].cidrs[_]
    net.cidr_contains(cidr, src_ip)
}

# Controlla che la rete sorgente sia una rete conosciuta.
network_known if {
    current_network
}

# Controlla che esista una regola che autorizza:
# utente + dispositivo + rete.
access_rule_exists if {
    rule := data.access_rules.rules[_]
    rule.user == user_id
    rule.device == device_id
    rule.networks[_] == current_network
}

# Controlla se la risorsa richiesta è autorizzata.
resource_allowed(allowed_resources, collection) if {
    allowed_resources[_] == "*"
}

resource_allowed(allowed_resources, collection) if {
    allowed_resources[_] == collection
}

# Controlla se il comando richiesto è autorizzato.
command_allowed(allowed_commands, command) if {
    allowed_commands[_] == command
}

# Controllo fascia oraria.
# Per ora il controllo orario è disabilitato per evitare incompatibilità
# con la versione di OPA usata nel container.
# La regola verifica solo che i campi esistano nel profilo utente.
time_allowed(profile) if {
    profile.time_window_start
    profile.time_window_end
}

# Legge il punteggio dinamicamente aggiornato da Splunk.
# Se l'utente non è ancora censito nel file, applica il valore di default 0.

risk_score := score if {
    score := data.risk_data.risk_scores[user_id].risk_score
} else := 0

# Controlla che il rischio sia sotto la soglia massima dell'utente.
risk_allowed(profile) if {
    risk_score <= profile.max_risk_score
}
