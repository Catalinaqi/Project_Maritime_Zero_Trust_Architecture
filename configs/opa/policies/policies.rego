package envoy.authz

import input.attributes.request.http as http_request
import input.attributes.metadata_context.filter_metadata["envoy.filters.http.lua"] as envoy_metadata_mongodb

default allow = false

allow {
    http_request.method == "POST"
}

allow if {
    envoy_metadata_mongodb.role == "ruolo_banchina"
    allowed_resources := ["risorse", "dispositivi"]
    allowed_commands := ["find"]
    envoy_metadata_mongodb.resource in allowed_resources
    envoy_metadata_mongodb.command in allowed_commands
}

allow if {
    envoy_metadata_mongodb.role == "ruolo_equipaggio"
    envoy_metadata_mongodb.resource == "risorse"
    allowed_commands := ["find", "insert", "update"]
    envoy_metadata_mongodb.command in allowed_commands
}

allow if {
    envoy_metadata_mongodb.role == "ruolo_equipaggio"
    envoy_metadata_mongodb.resource == "dispositivi"
    allowed_commands := ["find"]
    envoy_metadata_mongodb.command in allowed_commands
}

allow if {
    envoy_metadata_mongodb.role == "ruolo_gestione_flotta"
    allowed_commands := ["find", "insert", "update", "remove"]
    envoy_metadata_mongodb.command in allowed_commands
}

