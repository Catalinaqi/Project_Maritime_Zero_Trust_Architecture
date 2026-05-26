package envoy.authz

import input.attributes.metadata_context.filter_metadata["envoy.filters.http.lua"].context_extensions as envoy_metadata_mongodb

# Grab the URL-encoded certificate from the Envoy input and URL-decode it back into standard PEM format
pem_cert := urlquery.decode(input.attributes.source.certificate)

certs := crypto.x509.parse_certificates(pem_cert)       # Parse the PEM string into an array of certificate objects
client_cert := certs[0]         # Assuming the client certificate is the first one in the array
device_cert := certs[1]         # Assuming the device certificate is the second one in the array

default allow = false

allow {
    http_request.method == "POST"
}


# Policies based on the "ruolo_banchina" role
allow if {
    allowed_resources := ["risorse", "dispositivi"]
    allowed_commands := ["find"]
    envoy_metadata_mongodb.resource in allowed_resources
    envoy_metadata_mongodb.command in allowed_commands
}

# Policies based on the "ruolo_equipaggio" role
allow if {
    envoy_metadata_mongodb.resource == "risorse"
    allowed_commands := ["find", "insert", "update"]
    envoy_metadata_mongodb.command in allowed_commands
}

allow if {
    envoy_metadata_mongodb.resource == "dispositivi"
    allowed_commands := ["find"]
    envoy_metadata_mongodb.command in allowed_commands
}

# Policies based on the "ruolo_gestione_flotta" role
allow if {
    envoy_metadata_mongodb.role == "ruolo_gestione_flotta"
    allowed_commands := ["find", "insert", "update", "remove"]
    envoy_metadata_mongodb.command in allowed_commands
}

