# Maritime Zero Trust Architecture (ZTA)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker Desktop](https://img.shields.io/badge/Docker%20Desktop-4.38.0-blue.svg)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3.11+-green.svg)](https://www.python.org/)

**Enterprise-grade Zero Trust Architecture** for maritime operations with mutual TLS, policy-driven access control, real-time monitoring, and intrusion detection.

---

## 📋 **Table of Contents**

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Technologies & Tools](#-technologies--tools)
- [The 12 Services](#-the-12-services)
- [Quick Start](#-quick-start)
- [Project Structure](#-project-structure)
- [Security Features](#-security-features)
- [Documentation](#-documentation)

---

## 🎯 **Overview**

This project implements a production-ready **Zero Trust security model** based on **NIST SP 800-207** with:

- **12 containerized microservices** (7 core + 5 testing clients)
- **mTLS everywhere**: All communication encrypted and mutually authenticated
- **Policy-driven access**: Dynamic authorization via Open Policy Agent (OPA)
- **Real-time SIEM**: Centralized logging and threat correlation with Splunk
- **Network IDS**: Snort with 15+ custom detection rules
- **Defense in depth**: Multi-layer security (firewall → proxy → policy → data)

---

## 🏗️ **Architecture**

### **System Architecture Diagram**

```
  update diagram

LEGEND:
  PEP = Policy Enforcement Point (Envoy)
  PDP = Policy Decision Point (OPA)
  SIEM = Security Information & Event Management (Splunk)
  NIDS = Network Intrusion Detection System (Snort)
  mTLS = Mutual TLS (both sides authenticate with certificates)
  RBAC = Role-Based Access Control
  ABAC = Attribute-Based Access Control
```

### **Traffic Flow**

```
Client Request
    │
    ├─1─► NFTables Firewall (L3/L4 filtering)
    │         │
    │         ├─► Snort IDS (monitors, alerts to Splunk)
    │         │
    ├─2─► Envoy Proxy (mTLS validation)
    │         │
    │         ├─3─► OPA Policy Engine (authorization check)
    │         │         │
    │         │         ├─► Query Splunk (risk score)
    │         │         │
    │         │         └─► Decision: allow/deny
    │         │
    │         ├─4─► If ALLOW → MongoDB (fetch data)
    │         │
    │         └─5─► Return response to client
    │
    └─► All steps logged to Splunk SIEM
```

---

## 🛠️ **Technologies & Tools**

### **Core Technologies**

| Technology | Version | Purpose | Layer |
|-----------|---------|---------|-------|
| **Docker Desktop** | 4.38.0 | Container orchestration & management | Infrastructure |
| **Docker Compose** | v2.30+ (integrated with Docker Desktop) | Multi-container deployment | Infrastructure |
| **Windows 11** | 23H2+ | Host operating system | Infrastructure |
| **Python** | 3.11+ | Automation & testing | Development |
| **Poetry** | 1.7+ | Dependency management | Development |

### **Security & Networking**

| Tool | Purpose | Type | Protocols |
|------|---------|------|-----------|
| **NFTables** | Layer 3/4 firewall | Network Security | TCP/UDP/ICMP |
| **Snort** | Network intrusion detection | NIDS | All IP protocols |
| **Envoy Proxy** | Reverse proxy & PEP | Application Gateway | HTTP/2, gRPC |
| **OpenSSL** | PKI & certificate management | Cryptography | TLS 1.2/1.3 |
| **mTLS** | Mutual authentication | Security Protocol | X.509 certificates |

### **Zero Trust Components**

| Component | Technology | Role | Port |
|-----------|------------|------|------|
| **PEP** (Enforcement) | Envoy Proxy | Intercepts & enforces | 8443 |
| **PDP** (Decision) | Open Policy Agent | Evaluates policies | 8181 |
| **PAP** (Admin) | Rego files | Defines policies | N/A |
| **PIP** (Info) | Splunk SIEM | Provides context | 8088 |

### **Data & Storage**

| Technology | Purpose | Features |
|-----------|---------|----------|
| **MongoDB** 7.0 | Primary database | TLS, RBAC, Audit logging |
| **Splunk** 9.1 | SIEM & log aggregation | HEC, Dashboards, Alerting |

### **Development & Testing**

| Tool | Purpose | Usage |
|------|---------|-------|
| **IntelliJ IDEA Community** | IDE | Code editing & debugging |
| **Pytest** | Testing framework | Unit & integration tests |
| **Black** | Code formatter | Python code style |
| **Ruff** | Linter | Fast Python linting |
| **MyPy** | Type checker | Static type analysis |
| **Bandit** | Security scanner | Python security issues |
| **Trivy** | Container scanner | Docker image vulnerabilities |
| **Make** | Task automation | Build & deploy commands |

### **CI/CD**

| Tool | Purpose |
|------|---------|
| **GitHub Actions** | Automated testing & deployment |
| **Dependabot** | Dependency updates |
| **Pre-commit** | Git hooks for code quality |

---

## 📦 **The 12 Services**

### **CORE Services (7 permanent containers)**

| # | Service Name | Technology | Function | Ports | Networks |
|---|-------------|------------|----------|-------|----------|
| 1 | `firewall_perimeter` | NFTables | L3/L4 packet filtering | - | zerotrust, backend, monitoring, corporate, vpn, satellite, public |
| 2 | `ids_network_monitor` | Snort 3 | Network intrusion detection | - | zerotrust, backend, monitoring, corporate, vpn, satellite, public |
| 3 | `siem_central` | Splunk 9.1 | Security monitoring & correlation | 8000, 8088 | zerotrust, backend, monitoring |
| 4 | `db_primary` | MongoDB 7.0 | Protected database with TLS | 27017 (internal) | backend (internal) |
| 5 | `api_backend` | Node.js (API) | MongoDB data access layer | 3000 (internal) | backend |
| 6 | `pdp_engine` | OPA 0.60 | Policy decision engine | 8181, 9191 | zerotrust, monitoring, corporate, vpn, satellite, public |
| 7 | `pep_gateway` | Envoy 1.29 | mTLS proxy & enforcement | 8443, 9901 | zerotrust, backend, corporate, vpn, satellite, public |

### **TESTING Clients (4 testing containers)**

| # | Client Name | Profile | User Role | Network | Access Level |
|---|------------|---------|-----------|---------|--------------|
| 8 | `client_soc_admin` | Corporate HQ | `ruolo_gestione_flotta` (Fleet Management) | corporate_net | **Full access** |
| 9 | `client_operatore_ancona` | VPN Remote | `ruolo_banchina` (Dock Operator) | vpn_net | **Medium access** |
| 10 | `client_capitano_claudia` | Satellite Office | `ruolo_equipaggio` (Crew) | satellite_net | **Medium access** |
| 11 | `client_intruso` | Public WiFi | `ruolo_non_autorizzato` (Unauthorized) | public_net | **Minimal / Blocked** |

### **Service Dependencies**

```
Start Order (respecting dependencies):

1. siem_central (Splunk) ──┐
                            ├─► Must be healthy first
2. db_primary (MongoDB) ────┘

3. api_backend ────────────► Depends on: MongoDB (healthy)

4. pdp_engine (OPA) ──────► Depends on: Splunk (started)

5. pep_gateway (Envoy) ───► Depends on: OPA, api_backend

6. firewall_perimeter ────► Can start anytime
7. ids_network_monitor ───► Depends on: Splunk (started)

8-11. clients_* ──────────► Depends on: Envoy (testing only, profile: testing)
```

---

## 🚀 **Quick Start**

### **System Requirements**

- **OS**: Windows 11 23H2+ (or Windows 10 22H2+)
- **Docker**: Docker Desktop 4.38.0 (WSL 2 backend recommended)
- **CPU**: 4 cores minimum (8 recommended)
- **RAM**: 8 GB minimum (16 GB recommended)
- **Disk**: 40 GB available space
- **Network**: Internet connectivity for image downloads

### **Prerequisites Installation**

```powershell
# 1. Install Docker Desktop 4.38.0
# Download from https://www.docker.com/products/docker-desktop/
# Enable WSL 2 backend during installation

# 2. Install Python 3.11+ & Poetry
# Download from https://www.python.org/downloads/windows/
# Then install Poetry:
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | python -

# 3. Open a new PowerShell and verify
docker --version
docker compose version
python --version
poetry --version

# 4. Enable WSL 2 integration (if not default)
# Open Docker Desktop → Settings → Resources → WSL Integration
# Ensure your distro is enabled
```

> **Note**: Docker Desktop 4.38.0 includes both Docker Engine and Docker Compose. No separate Linux package installation is needed.

### **Project Setup**

```bash
# 1. Extract project
tar -xzf Project_Maritime_Zero_Trust_Architecture.tar.gz
cd Project_Maritime_Zero_Trust_Architecture

# 2. Install Python dependencies
poetry install

# 3. Configure environment
cp .env.example .env
nano .env  # Update passwords and secrets

# 4. Generate PKI certificates (REQUIRED)
make init-certs
# or: poetry run python scripts/generate_certs.py

# 5. Validate configuration
make validate-config

# 6. Start services
make up

# 7. Verify health
make ps
docker compose ps

# 8. View logs
make logs
```

### **First Test**

```bash
# Start testing clients
docker compose --profile testing up -d

# Test mTLS connection
make test-mtls

# Run full test suite
make test-all
```

### **Access Web Interfaces**

- **Splunk SIEM**: http://localhost:8000
  - Username: `admin`
  - Password: (from `.env` file)

- **Envoy Admin**: http://localhost:9901
  - Stats: http://localhost:9901/stats
  - Clusters: http://localhost:9901/clusters

---

## 📁 **Project Structure**

```
Project_Maritime_Zero_Trust_Architecture/
├── configs/                    # Service configurations
│   ├── envoy/
│   ├── opa/
│   ├── mongodb/
│   ├── splunk/
│   ├── snort/
│   └── nftables/
│
├── services/                   # Docker service definitions
│   ├── envoy/
│   ├── opa/
│   ├── mongodb/
│   ├── splunk/
│   ├── snort/
│   ├── nftables/
│   └── clients/
│
├── scripts/                    # Python automation scripts
│   ├── __init__.py
│   ├── generate_certs.py      # PKI certificate generation
│   ├── validate_config.py     # Configuration validation
│   ├── run_tests.py           # Test orchestration
│   └── security_audit.py      # Security auditing
│
├── tests/                      # Test suite
│   ├── __init__.py
│   ├── test_opa_policies.py   # Policy tests
│   ├── test_network.py        # Network security tests
│   ├── test_mtls.py           # mTLS validation
│   └── test_integration.py    # End-to-end tests
│
├── docs/                       # Documentation
│   ├── architecture.md        # Architecture details
│   ├── security-model.md      # Security implementation
│   ├── deployment.md          # Deployment guide
│   ├── testing.md             # Testing guide
│   └── diagrams/              # Architecture diagrams
│
├── certs/                      # PKI certificates (gitignored)
│
├── docker-compose.yml          # Main orchestration file
├── .env.example                # Environment template
├── .gitignore                  # Git ignore rules
├── .editorconfig               # Code style config
├── pyproject.toml              # Poetry dependencies
├── Makefile                    # Development commands
├── README.md                   # This file
├── SECURITY.md                 # Security policy
└── CHECKLIST.md                # Deployment checklist
```

---

## 🔐 **Security Features**

### **Zero Trust Principles**

1. **Never Trust, Always Verify**: Every request authenticated & authorized
2. **Least Privilege Access**: Minimum permissions per role
3. **Assume Breach**: Continuous monitoring & logging
4. **Explicit Verification**: Context-aware authorization

### **Authentication & Authorization**

- **mTLS**: X.509 certificate-based authentication
- **ABAC**: Attribute-based access control via OPA
- **Risk Scoring**: Dynamic risk calculation based on:
  - User identity & role
  - Device type & posture
  - Geographic location
  - Time of access
  - Behavioral patterns

### **Network Security**

- **NFTables**: L3/L4 firewall blocks direct database access
- **Snort IDS**: 15+ custom rules detect Zero Trust violations
- **Network Segmentation**: 5 isolated Docker networks
- **Rate Limiting**: Per-user and global limits in Envoy

### **Data Protection**

- **TLS Everywhere**: All communication encrypted
- **Database Encryption**: MongoDB with TLS-only mode
- **RBAC**: 4 roles with granular permissions
- **Audit Logging**: All access logged to Splunk

### **Monitoring & Response**

- **Real-time SIEM**: Splunk aggregates all logs
- **Behavioral Analysis**: OPA queries Splunk for anomalies
- **Automated Alerts**: Configured for critical events
- **Dashboards**: Zero Trust metrics & KPIs

---

## 📚 **Documentation**

- **[CHECKLIST.md](CHECKLIST.md)** - Step-by-step deployment guide
- **[SECURITY.md](SECURITY.md)** - Security policy & vulnerability reporting
- **[docs/architecture.md](docs/architecture.md)** - Detailed architecture
- **[docs/security-model.md](docs/security-model.md)** - Security implementation
- **[docs/deployment.md](docs/deployment.md)** - Production deployment
- **[docs/testing.md](docs/testing.md)** - Testing strategies

---

## 🤝 **Contributing**

1. Fork the repository
2. Create a feature branch
3. Run tests: `make test-all`
4. Run security checks: `make security-check`
5. Submit a pull request

---

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 **Acknowledgments**

- **NIST SP 800-207**: Zero Trust Architecture specification
- **Open Policy Agent**: Policy engine framework
- **Envoy Proxy**: Service mesh and API gateway
- **Splunk**: SIEM platform
- **Snort**: Intrusion detection system
- **MongoDB**: Database platform

---

## 📞 **Support**

- **Security Issues**: security@maritime-ops.local
- **Technical Support**: support@maritime-ops.local
- **Documentation**: [GitHub Wiki](https://github.com/your-org/maritime-zta/wiki)

---

**Built with ❤️ for security-first operations** 🔒

**Last Updated**: 2026-05-08  
**Version**: 1.0.0  
**Status**: Production Ready ✅
