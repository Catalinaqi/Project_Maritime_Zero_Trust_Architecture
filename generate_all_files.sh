#!/bin/bash
# Generate all remaining project files

echo "Generating complete Maritime ZTA project files..."

# Create IntelliJ IDEA configuration
mkdir -p .idea
cat > .idea/misc.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project version="4">
  <component name="ProjectRootManager" version="2" project-jdk-name="Python 3.11 (maritime-zta)" project-jdk-type="Python SDK" />
</project>
EOF

cat > .idea/.gitignore << 'EOF'
workspace.xml
tasks.xml
usage.statistics.xml
dictionaries/
shelf/
EOF

# Create LICENSE
cat > LICENSE << 'EOF'
MIT License

Copyright (c) 2026 Maritime ZTA Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF

# Create certs README
cat > certs/README.md << 'EOF'
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
EOF

echo "✓ Core files generated"
echo "✓ IntelliJ IDEA config created"
echo "✓ LICENSE created"
echo "✓ Certs README created"

