package envoy.authz

import rego.v1

default allow := false

# Estrazione dei metadati dinamici iniettati dal filtro Lua
mongo_metadata := input.attributes.metadata_context.filter_metadata["envoy.filters.http.lua"].context_extensions

# Identità estratta dal certificato mTLS
user_principal := input.attributes.source.principal

# REGOLA 1: Accesso alla collezione 'risorse'
allow if {
    contains(user_principal, "CN=Elena Bianchi")
    contains(user_principal, "OU=D-002")
    mongo_metadata.collection == "risorse"
    mongo_metadata.command == "find"
}

# REGOLA 2: Accesso alla collezione 'dispositivi'
allow if {
    contains(user_principal, "CN=Marco Rossi")
    contains(user_principal, "OU=D-001")
    mongo_metadata.collection == "dispositivi"
    mongo_metadata.command == "find"
}
