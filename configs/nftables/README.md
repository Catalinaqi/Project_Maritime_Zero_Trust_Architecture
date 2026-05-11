# 🔥 NFTables Firewall Configuration

## Purpose
Layer 1 Network Security using NFTables to enforce Zero Trust Architecture principles for Adria Ferries maritime operations.

The firewall serves as the **first line of defense**, ensuring:
- **Default DENY** - No traffic is trusted by default
- **Single entry point** - All traffic must go through Envoy (PEP)
- **MongoDB isolation** - Direct database access is strictly prohibited
- **Defense in depth** - Independent security layer that works even if other layers fail
- **Network segmentation** - Traffic between Docker bridge networks is explicitly controlled

---

## Network Segmentation

### Architecture Decision: Docker Bridge Networks

The `docker-compose.yml` uses **4 separate Docker bridge networks** (not `network_mode: host`) for Docker Desktop compatibility (Windows/Mac) and better network isolation.

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Host                               │
│                                                              │
│  ┌──────────────────┐  ┌──────────────────┐                  │
│  │  zerotrust_net   │  │   backend_net     │                  │
│  │  172.20.2.0/24   │  │   172.20.3.0/24   │                  │
│  │                  │  │                   │                  │
│  │  Envoy (2.7) ────┼──┼──→ MongoDB (3.5)  │                  │
│  │  OPA (2.6)       │  │                   │                  │
│  │  Splunk (2.8)    │  │    INTERNAL       │                  │
│  │  Firewall (2.10) │  │    (no external)  │                  │
│  │  Snort (2.11)    │  │                   │                  │
│  └────────┬─────────┘  └──────────────────┘                  │
│           │                                                   │
│  ┌────────▼─────────┐  ┌──────────────────┐                  │
│  │  monitoring_net   │  │   clients_net     │                  │
│  │  172.20.4.0/24   │  │   172.20.5.0/24   │                  │
│  │                   │  │                   │                  │
│  │  Splunk (4.8)    │  │  Corporate (5.20) │                  │
│  │  Firewall (4.10) │  │  VPN (5.21)       │                  │
│  │  Snort (4.11)    │  │  Satellite (5.22) │                  │
│  └──────────────────┘  │  Foreign (5.23)   │                  │
│                         │  Public (5.24)    │                  │
│                         └──────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
```

### Firewall Network Interfaces

Since the firewall connects to 3 networks, NFTables sees traffic through different virtual Ethernet interfaces:

| Interface | Network | Subnet | Firewall IP | Purpose |
|-----------|---------|--------|-------------|---------|
| `eth0` | `zerotrust_net` | 172.20.2.0/24 | `172.20.2.10` | Public-facing services (Envoy, OPA, Splunk) |
| `eth1` | `backend_net` | 172.20.3.0/24 | `172.20.3.10` | Database backend (MongoDB) |
| `eth2` | `monitoring_net` | 172.20.4.0/24 | `172.20.4.10` | Monitoring and logging |

> **Note**: The firewall acts as a **gateway between these networks**, forwarding allowed traffic between them (e.g., Envoy on zerotrust_net → MongoDB on backend_net via eth0→eth1).

### Service IP Addresses (Static - from docker-compose.yml)

| IP Address | Service | Hostname | Network(s) | Layer |
|------------|---------|----------|------------|-------|
| `172.20.2.8` | `siem_central` | Splunk SIEM | zerotrust_net, monitoring_net | Layer 4 |
| `172.20.3.5` | `db_primary` | MongoDB Database | backend_net **(internal)** | Layer 4 |
| `172.20.2.6` | `pdp_engine` | OPA Policy Engine | zerotrust_net | Layer 3 |
| `172.20.2.7` | `pep_gateway` | Envoy Proxy (PEP) | zerotrust_net, backend_net, clients_net | Layer 2 |
| **`172.20.2.10`** | **`firewall_perimeter`** | **NFTables Firewall** | **zerotrust_net, backend_net, monitoring_net** | **Layer 1** |
| **`172.20.2.11`** | **`ids_network_monitor`** | **Snort IDS** | **zerotrust_net, backend_net, monitoring_net, clients_net** | **Layer 1** |

### Client IPs (--profile testing)

| Client | IP | Network | Certificate Profile |
|--------|----|---------|-------------------|
| Corporate | 172.20.5.20 | clients_net | operations |
| VPN Remote | 172.20.5.21 | clients_net | remote_agent |
| Satellite | 172.20.5.22 | clients_net | branch_ops |
| Foreign Agent | 172.20.5.23 | clients_net | partner |
| Public WiFi | 172.20.5.24 | clients_net | guest |

---

## Security Rules

### INPUT Chain (Traffic TO the firewall container)

| Priority | Rule | Purpose |
|----------|------|---------|
| 1 | `iif lo accept` | Allow localhost for internal processes |
| 2 | `ct state established,related accept` | Allow return traffic for outbound connections |
| 3 | `ip protocol icmp accept` | Allow ping for network diagnostics |
| 4 | `log prefix ... drop` | Default deny - log all rejected input |

### FORWARD Chain (Traffic THROUGH the firewall between networks)

| Rule # | Rule | Purpose | Threat Mitigated |
|--------|------|---------|-----------------|
| **1** | `ct state established,related accept` | Allow established connection return traffic | Performance optimization (~90% of traffic) |
| **2** | `tcp dport 8443 accept` | Allow traffic to Envoy (PEP) | Public entry point for all services |
| **3** | `ip saddr 172.20.2.7 tcp dport 27017 accept` | Allow Envoy ONLY → MongoDB | **Authorized database path** |
| **3b** | `tcp dport 27017 ... log crit ... drop` | BLOCK all other MongoDB access | **Data exfiltration prevention** |
| **4** | `ip saddr 172.20.2.7 tcp dport 8181 accept` | Allow Envoy ONLY → OPA | Authorized policy decision path |
| **4b** | `tcp dport 8181 ... log warn ... drop` | BLOCK other OPA access | Policy bypass prevention |
| **5** | `tcp dport 8088 accept` | Allow Splunk HEC | Log ingestion from all services |
| **5b** | `tcp dport 8089 accept` | Allow Splunk management | SIEM administration |
| **6** | `ip protocol icmp accept` | Allow ICMP | Network diagnostics across networks |
| **7a** | `iif eth0 oif eth1 ip saddr 172.20.2.7 ip daddr 172.20.3.5 dport 27017 accept` | Cross-network: zerotrust→backend | Envoy→MongoDB bridge routing |
| **7b** | `iif eth2 oif eth0 ip saddr 172.20.4.0/24 ip daddr 172.20.2.8 dport 8088 accept` | Cross-network: monitoring→zerotrust | Snort→Splunk log routing |
| **8** | `log prefix ... drop` | Default deny fallback | Catch-all for unmatched traffic |

### OUTPUT Chain (Traffic FROM the firewall)

| Rule | Purpose |
|------|---------|
| `policy accept` | Allow all outbound traffic for DNS lookups, log forwarding, health checks |

---

## Data Flow Diagram

```
                    ╔═════════════════╗
                    ║   CLIENTS_NET   ║
                    ║  172.20.5.0/24  ║
                    ╚═══════╤═════════╝
                            │ (traffic from clients to Envoy:8443)
                            ▼
              ┌────────────────────────────────────┐
              │         zerotrust_net (eth0)        │
              │         172.20.2.10                 │
              │  ┌──────────────────────────────┐  │
              │  │  🛡️  NFTABLES FIREWALL        │  │
              │  │  Default Policy: DROP         │  │
              │  │                               │  │
              │  │  8443:  ACCEPT ───────────────┼──┼──→ Envoy (172.20.2.7)
              │  │  27017: DROP* (log CRITICAL)  │  │
              │  │  8088:  ACCEPT ───────────────┼──┼──→ Splunk (172.20.2.8)
              │  │  8089:  ACCEPT ───────────────┼──┼──→ Splunk Mgmt
              │  │  8181:  DROP** (log WARNING)  │  │
              │  └──────────────────────────────┘  │
              └──────┬─────────────────────────────┘
                     │
          ┌──────────┴──────────┐
          │                     │
   eth1   ▼                     ▼   eth0
  ┌────────────────┐   ┌──────────────────────┐
  │  backend_net   │   │   zerotrust_net       │
  │  172.20.3.0/24 │   │   172.20.2.0/24       │
  │  (internal)    │   │                       │
  │                 │   │  ┌─────────────────┐  │
  │  MongoDB        │   │  │ Envoy Proxy     │  │
  │  172.20.3.5    │◄──┼──│ (PEP - Layer 2)  │  │
  │  :27017        │   │  │ 172.20.2.7:8443  │  │
  │                 │   │  └─────────────────┘  │
  │                 │   │  ┌─────────────────┐  │
  │                 │   │  │ OPA Engine      │  │
  │                 │   │  │ (PDP - Layer 3) │  │
  │                 │   │  │ 172.20.2.6:8181 │  │
  │                 │   │  └─────────────────┘  │
  │                 │   │  ┌─────────────────┐  │
  │                 │   │  │ Splunk SIEM     │  │
  │                 │   │  │ (Layer 4)       │  │
  │                 │   │  │ 172.20.2.8:8088 │  │
  │                 │   │  └─────────────────┘  │
  └────────────────┘   └──────────────────────┘
                               │
                        eth2   ▼
                       ┌──────────────────┐
                       │  monitoring_net   │
                       │  172.20.4.0/24   │
                       │                  │
                       │  Snort IDS       │
                       │  (Layer 1)       │
                       │  172.20.2.11     │
                       │  (also on eth0)  │
                       └──────────────────┘

* Only Envoy (172.20.2.7) can access MongoDB (172.20.3.5)
** Only Envoy (172.20.2.7) can access OPA (172.20.2.6)
```

---

## Threat Model

### Threats Mitigated

| Threat | Attack Vector | Firewall Rule | Additional Defense |
|--------|--------------|---------------|-------------------|
| **Direct Database Access** | Attacker connects to port 27017 | `tcp dport 27017 drop` (unless src=172.20.2.7) | MongoDB TLS + RBAC |
| **Port Scanning** | nmap scan to discover services | Default deny + logging to Splunk | Snort detects scan patterns |
| **Data Exfiltration** | Malicious insider extracts data | Only Envoy→MongoDB path allowed | OPA ABAC policies |
| **Bypass PEP** | Attacker reaches OPA directly | `tcp dport 8181 drop` (non-Envoy) | OPA validates request origin |
| **Lateral Movement** | Compromised container attacks others | Default deny between networks | Docker network segmentation |
| **DDoS / SYN Flood** | Flood of connection requests | Stateful connection tracking | Snort SYN flood detection |
| **Cross-network pivot** | Attacker on clients_net tries backend_net | backend_net is **internal** (no external route) | Docker internal network |

### Attack Scenarios

#### Scenario 1: Public WiFi Hacker
```
1. Hacker connects to ship's public WiFi (clients_net: 172.20.5.0/24)
2. Scans for open ports: $ nmap -p 27017 172.20.3.5
3. FIREWALL: Port 27017 → DROP (unless src=172.20.2.7)
4. backend_net is INTERNAL: clients_net cannot route to backend_net directly
5. SNORT: Port scan detected on zerotrust_net → Alert to Splunk
6. Result: ✅ Double security (Docker isolation + NFTables rules)
```

#### Scenario 2: Compromised Service on zerotrust_net
```
1. Attacker compromises a non-Envoy container (e.g., OPA at 172.20.2.6)
2. Attempts to connect to MongoDB: $ nc -zv 172.20.3.5 27017
3. FIREWALL: Connection DROPPED (IP != 172.20.2.7)
4. FIREWALL: [CRITICAL] DIRECT_DB_ATTEMPT logged to Splunk
5. SNORT: Detects MongoDB wire protocol → Alert to Splunk
6. Result: ✅ Multiple detection layers, source IP traced
```

#### Scenario 3: Data Exfiltration Attempt
```
1. Malicious insider tries to bypass PEP and connect directly to MongoDB
2. FIREWALL: Connection DROPPED (IP != 172.20.2.7)
3. FIREWALL: Critical log sent to Splunk (172.20.2.8:8088)
4. SPLUNK: Real-time alert to SOC team with source IP
5. Result: ✅ Exfiltration prevented, attacker identified
```

---

## Configuration Files

| File | Purpose |
|------|---------|
| `rules.nft` | **Main ruleset** - Active firewall rules deployed to container |
| `README.md` | **Documentation** - Strategy, architecture, and procedures |

### File Locations
- **Host**: `./configs/nftables/rules.nft`
- **Container**: `/etc/nftables/rules.nft`
- **Mount**: Read-only (`:ro`) to prevent runtime tampering
- **Mount in compose**: `./configs/nftables/rules.nft:/etc/nftables/rules.nft:ro`

---

## Environment Variables

The firewall container receives these from `docker-compose.yml`:

| Variable | Value | Purpose |
|----------|-------|---------|
| `ENVOY_IP` | `172.20.2.7` | Envoy PEP IP address |
| `MONGODB_IP` | `172.20.3.5` | MongoDB database IP |
| `SPLUNK_IP` | `172.20.2.8` | Splunk SIEM IP |
| `OPA_IP` | `172.20.2.6` | OPA Policy Engine IP |

> **Note**: Current `rules.nft` uses hardcoded IPs for auditability. Environment variables can be used in entrypoint for dynamic rule generation.

---

## Testing

### Syntax Validation
```bash
# Validate locally (requires nftables)
nft -c -f configs/nftables/rules.nft

# Validate via Docker
docker compose build firewall_perimeter
docker compose run --rm firewall_perimeter nft -c -f /etc/nftables/rules.nft
```

### Rule Verification
```bash
# Start the firewall
docker compose up -d firewall_perimeter

# List all active rules
docker exec firewall_perimeter nft list ruleset

# Show specific table
docker exec firewall_perimeter nft list table inet filter

# Monitor events
docker exec firewall_perimeter nft monitor
```

### Connectivity Tests
```bash
# Test 1: Direct MongoDB access (should FAIL)
docker exec firewall_perimeter timeout 2 bash -c \
  'echo > /dev/tcp/172.20.3.5/27017' && \
  echo "❌ FAIL: MongoDB accessible!" || \
  echo "✅ PASS: MongoDB blocked"

# Test 2: Envoy port (should WORK)
docker exec firewall_perimeter timeout 2 bash -c \
  'echo > /dev/tcp/172.20.2.7/8443' && \
  echo "✅ PASS: Envoy reachable" || \
  echo "❌ FAIL: Envoy not reachable"

# Test 3: Splunk HEC (should WORK)
docker exec firewall_perimeter timeout 2 bash -c \
  'echo > /dev/tcp/172.20.2.8/8088' && \
  echo "✅ PASS: Splunk HEC reachable" || \
  echo "❌ FAIL: Splunk HEC not reachable"

# Test 4: OPA from non-Envoy (should FAIL)
docker exec firewall_perimeter timeout 2 bash -c \
  'echo > /dev/tcp/172.20.2.6/8181' && \
  echo "❌ FAIL: OPA accessible!" || \
  echo "✅ PASS: OPA blocked from unauthorized source"
```

### Integration Tests
```bash
# Run full firewall test suite
cd tests && poetry run pytest test_firewall.py -v

# Specific test
cd tests && poetry run pytest test_firewall.py::test_mongodb_blocked -v
```

---

## Troubleshooting

### Common Issues

| Problem | Symptom | Solution |
|---------|---------|----------|
| **Rules not loading** | Container starts but firewall inactive | Check syntax: `nft -c -f /etc/nftables/rules.nft` |
| **Network broken** | No containers can communicate | Flush rules: `nft flush ruleset` (opens all traffic) |
| **MongoDB unreachable from Envoy** | Envoy cannot connect to DB | Verify Envoy IP is 172.20.2.7: `docker inspect pep_gateway` |
| **Cross-network blocked** | Envoy→MongoDB fails | Check eth0→eth1 forwarding rules in FORWARD chain |
| **Logs not in Splunk** | No firewall logs | Check HEC token: `docker logs siem_central` |
| **Interface name mismatch** | `iif`/`oif` rules not matching | Check interfaces: `docker exec firewall_perimeter ip link` |

### Docker Desktop Specific Issues
- `network_mode: host` does NOT work → removed from compose
- `NET_ADMIN` capability works inside container's network namespace
- Firewall filters traffic on its bridge networks, NOT host traffic
- All services use **static IPs** on Docker bridge networks

### Emergency Recovery
```bash
# If firewall blocks everything:
# 1. Flush all rules (opens all traffic temporarily)
docker exec firewall_perimeter nft flush ruleset

# 2. Verify cleared
docker exec firewall_perimeter nft list ruleset  # Empty = good

# 3. Fix rules locally and reload
nft -c -f configs/nftables/rules.nft  # Validate
docker compose restart firewall_perimeter

# 4. Worst case: stop firewall entirely
docker compose stop firewall_perimeter
```

### Debugging
```bash
# Real-time packet monitoring
docker exec firewall_perimeter nft monitor trace

# Check logs
docker logs firewall_perimeter --tail 100

# Connection tracking
docker exec firewall_perimeter cat /proc/net/nf_conntrack

# Network interfaces
docker exec firewall_perimeter ip addr
docker exec firewall_perimeter ip route
```

---

## Monitoring & Metrics

### Key Metrics for Splunk

| Metric | Alert Threshold | Severity | Action |
|--------|----------------|----------|--------|
| Direct MongoDB attempts | > 0 in 5 min | **CRITICAL** | Investigate source IP immediately |
| Unauthorized OPA access | > 0 in 5 min | **WARNING** | Check for compromised services |
| Drops per minute | > 100/min | **INFO** | Possible scan in progress |
| Port scan sequences | > 10 sources in 1 min | **WARNING** | Correlate with Snort alerts |
| Rule load failures | 1 occurrence | **CRITICAL** | Firewall needs restart |

### Log Format for Splunk
```
[NFTABLES-FWD] DROP: SRC=172.20.X.X DST=172.20.X.X PROTO=TCP DPT=XXXX
[NFTABLES-INPUT] DROP: SRC=172.20.X.X DST=172.20.X.X PROTO=TCP
[CRITICAL] DIRECT_DB_ATTEMPT: SRC=172.20.2.X DST=172.20.3.5 DPT=27017
[WARNING] UNAUTHORIZED_OPA_ACCESS: SRC=172.20.2.X DST=172.20.2.6 DPT=8181
```

---

## Integration Points

| Persona | Component | Integration |
|---------|-----------|-------------|
| **Persona 2** (Giada) | Envoy Proxy (172.20.2.7) | Firewall allows Envoy (8443) as sole entry point; routes Envoy→MongoDB |
| **Persona 3** | OPA Engine (172.20.2.6) | Firewall restricts OPA access (8181) to Envoy only |
| **Persona 4** | Splunk SIEM (172.20.2.8) | Firewall allows log ingestion (8088) for all services |
| **Persona 4** | MongoDB DB (172.20.3.5) | Firewall enforces MongoDB isolation (27017) |
| **All** | Snort IDS (172.20.2.11) | Firewall logs correlate with Snort alerts in Splunk |

### Dependency Chain
```
Before firewall can be tested:
  1. Docker networks must be created (docker compose up)
  2. Splunk must be healthy (firewall needs logging destination)
  
After firewall is running:
  1. Envoy (Persona 2) can safely expose port 8443
  2. OPA (Persona 3) is protected from unauthorized access
  3. MongoDB (Persona 4) is isolated from direct connections
  4. Snort alerts can flow to Splunk securely
```

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-05-11 | Persona 1 | Initial ZTA ruleset with static IPs (172.20.0.x) |
| 1.1.0 | 2026-05-11 | Persona 1 | Updated for Docker Desktop: removed network_mode:host, switched to segmented bridge networks (172.20.2.x/3.x/4.x/5.x), added cross-network forwarding rules (eth0/eth1/eth2), updated all IPs to match new docker-compose.yml |

---

## References

- [NFTables Wiki](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page)
- [NFTables Man Page](https://man7.org/linux/man-pages/man8/nft.8.html)
- [Zero Trust Architecture (NIST SP 800-207)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [Docker Networking Overview](https://docs.docker.com/network/)
- [Docker Compose Networks](https://docs.docker.com/compose/networking/)
