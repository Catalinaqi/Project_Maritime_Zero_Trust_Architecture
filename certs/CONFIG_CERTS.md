# 🔐 Maritime ZTA - Public Key Infrastructure (PKI) & mTLS Directory

This directory serves as the local cryptographic repository for the **Maritime Zero Trust Architecture (ZTA)** simulation. It manages the full lifecycle of certificates, serial states, and private keys required to enforce strict mutual TLS (mTLS) authentication across the ecosystem.

## 🛑 Security Guardrail (DevSecOps Policy)
In compliance with **Zero Trust core principles**, this directory is explicitly ignored by version control (except for this documentation file). 
* **NEVER** commit or push `.key` (Private Keys), `.crt` (Certificates), or `.srl` (Tracking files) to GitHub.
* Compromising a private key breaks the cryptographic root of trust for the entire maritime vessel infrastructure.

---

## 📂 PKI Directory Structure & Component Mapping

Once generated locally, the directory structure adheres strictly to the following layout. Each asset is mapped to transient testing containers to enable fine-grained access control:

```
certs/
├── ca/
│   ├── ca.crt               # Root CA Public Certificate
│   ├── ca.key               # Root CA Private Key (The Master Trust Anchor)
│   └── ca.srl               # Certificate Serial Number Tracking File
├── server/
│   ├── server.crt           # PEP Gateway mTLS Public Certificate
│   └── server.key           # PEP Gateway Private Key
├── clients/
│   ├── capitano_claudia/    # Authorized Captain Identity Context
│   │   ├── ca.crt           # CA Certificate for server validation
│   │   ├── client.crt       # User Public Certificate
│   │   └── client.key       # User Private Key
│   ├── operatore_ancona/    # Operator Identity Context
│   │   ├── ca.crt | client.crt | client.key
│   ├── soc_admin/           # Security Operations Center Admin Context
│   │   ├── ca.crt | client.crt | client.key
│   └── intruso/             # Malicious/Untrusted Actor Context
│       └── ca.crt | client.crt | client.key
└── devices/
    ├── D-001/               # Validated Workstation Hardware Bind
    │   ├── ca.crt           # CA Certificate for server validation
    │   ├── device.crt       # Device Public Certificate
    │   └── device.key       # Device Private Key
    ├── D-002/               # Onboard IoT Node Bind
    │   └── ca.crt | device.crt | device.key
    └── D-SOC/               # Secure Monitoring Terminal Bind
        └── ca.crt | device.crt | device.key

```

### 🔍 Detailed Functional Breakdown

#### 1. `ca/` (Certificate Authority Root)

* **`ca.crt`**: The self-signed root certificate shared with the Policy Enforcement Point (PEP) Gateway (`envoy`/`pep_gateway`). Envoy treats this file as its trust anchor to verify that any incoming client connection was genuinely signed by this PKI.
* **`ca.key`**: The cryptographic master key. Used exclusively by OpenSSL on the host machine to sign certificate signing requests (CSRs). It never leaves the host.
* **`ca.srl`**: An automatically updated tracker file containing the sequential serial hexadecimal number for the next certificate to be issued. This prevents duplicate serial bugs within the simulation.

#### 2. `server/` (Gateway Identity Context)

* Contains credentials presented by the Envoy Proxy container to clients during downstream handshakes (`https://localhost:8443`). It establishes TLS termination before forwarding traffic to the OPA Engine and API backend.

#### 3. `clients/` & `devices/` (Distributed Handoff Contexts)

* Every individual subject directory contains its identity credentials along with a localized **`ca.crt`**.
* **The role of local `ca.crt**`: When test suites or transient microservice clients execute a `curl` call, they consume this local `ca.crt` via flags (e.g., `--cacert ca.crt`) to verify the identity of the PEP Gateway server, completing the mutual validation loop (mTLS).
* **Subject-Common-Name Parsing**: The certificate fields (`client.crt`/`device.crt`) are decoded on-the-fly by Envoy, mapping attributes directly to Open Policy Agent (OPA) to compute real-time access decisions.

---

## 🛠️ Complete PKI Re-Initialization & Regeneration

If certificates expire, numbers desynchronize, or Windows-hosted environments experience volume access locks during development, a total cryptographic reset can be cleanly enforced.

Execute the following sequence from the repository root directory using Git Bash (MINGW64):

```bash
# 1. Purge legacy cryptographic material safely to avoid serial mismatch conflicts
rm -rf certs/ca certs/server certs/clients certs/devices

# 2. Reset Windows system & read-only locks on the host directory
attrib -r -s "certs" /s /d 2>/dev/null || true

# 3. Execute the automated generation script to build the PKI tree from scratch
./scripts/generate_certs.sh

```

### 🧠 Operational Purpose of the Reset Sequence

* **`rm -rf`**: Ensures that legacy keys and asymmetric configurations are removed entirely, forcing the generation of uniform expiry timestamps and valid serial counts across all identities.
* **`attrib -r -s`**: Resolves an architectural issue unique to running Docker Desktop on Windows. When Linux-based containers mount host volumes, Windows file-system attributes frequently lock directories as Read-Only (`-r`) or System (`-s`), triggering unexpected `Permission Denied` errors during OpenSSL file writes. This command unlocks the entire tree recursively (`/s` `/d`).
* **`./scripts/generate_certs.sh`**: Re-runs the automated certificate generation blueprint, populating every single client, device, and authority subdirectory instantly.

Once execution finishes, run `docker compose up -d --build` to safely map the newly generated volume configurations into the container runtime.
