package envoy.authz

import input.attributes.request.http as http_request

default allow = false

# Si permette tutto per adesso, per testare il funzionamento di OPA con Envoy.
allow {
    http_request.method == "GET"
}