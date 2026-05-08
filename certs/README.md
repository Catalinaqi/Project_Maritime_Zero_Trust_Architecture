# PKI Certificates Directory

## ⚠️ SECURITY WARNING

**NEVER commit certificates to version control!**

This directory contains:
- `ca/` - Certificate Authority files
- `server/` - Server certificates (Envoy, MongoDB)
- `clients/` - Client certificates (5 profiles)

## Generate Certificates

```bash
# From project root
poetry run python scripts/generate_certs.py

# Or use Makefile
make init-certs
```

## Certificate Structure

```
certs/
├── ca/
│   ├── ca.crt          # CA certificate (public)
│   └── ca.key          # CA private key (NEVER commit!)
├── server/
│   ├── envoy.crt
│   ├── envoy.key
│   ├── mongodb.crt
│   └── mongodb.key
└── clients/
    ├── corporate/
    ├── vpn_remote/
    ├── satellite/
    ├── foreign_agent/
    └── public_wifi/
```

## Validity

- CA: 10 years
- Server: 1 year
- Client: 1 year

Rotate before expiration!
