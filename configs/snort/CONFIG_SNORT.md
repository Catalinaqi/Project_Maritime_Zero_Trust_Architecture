# 👁️ Snort 3 IDS - Zero Trust Architecture

## Purpose

Layer 1 Intrusion Detection System (IDS) using **Snort 3** to detect and alert on attack patterns targeting the Adria Ferries maritime Zero Trust Architecture.

Snort serves as the **second pair of eyes** after the firewall, providing:
- **Signature-based detection** — 15 custom rules (SID 1000001–1000015) covering 6 attack categories
- **Protocol anomaly detection** — NULL scans, TLS downgrade, Heartbleed, etc.
- **Threat correlation** — Alerts forwarded to Splunk SIEM for incident response
- **Defense in depth** — Independent detection even if firewall rules are misconfigured
- **Visibility** — Monitoring authorized traffic paths for malicious payloads

---

## Monitored Networks

| Network | CIDR | Container Interface | Purpose |
|---------|------|---------------------|---------|
| `clients_net` | 172.20.5.0/24 | `eth0` | Client workloads – corporate, VPN, satellite, foreign agent, public WiFi |
| `zerotrust_net` | 172.20.2.0/24 | `eth1` | Core ZTA processing – Envoy, OPA, Splunk, Firewall |
| `backend_net` | 172.20.3.0/24 | `eth2` | Isolated data storage – MongoDB, audit logs |
| `monitoring_net` | 172.20.4.0/24 | `eth3` | Security logs & alerts – Splunk SIEM, Firewall |

> **Note**: All four interfaces are monitored to provide full visibility across every trust zone.
> The order `eth0:eth1:eth2:eth3` matches Docker's network attachment order defined in `docker-compose.yml`.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Snort 3 IDS Container                          │
│  ┌────────────┐   ┌──────────────────┐   ┌─────────────────────────┐  │
│  │ eth0 (pcap)│──▶│ Detection Engine  │──▶│ alert_fast (local)     │  │
│  │ clients_net│   │ 15 ZTA rules      │   │ /var/log/snort/alert   │  │
│  ├────────────┤   └────────┬─────────┘   └─────────────────────────┘  │
│  │ eth1 (pcap)│            │                                           │
│  │zerotrust_net│           ▼                                           │
│  ├────────────┤   ┌─────────────────────┐                              │
│  │ eth2 (pcap)│   │ alert_json (HTTP)   │                              │
│  │ backend_net│   │ 172.20.2.8:8088     │──▶ Splunk HEC               │
│  ├────────────┤   └─────────────────────┘                              │
│  │ eth3 (pcap)│                                                        │
│  │monitoring  │                                                        │
│  └────────────┘                                                        │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Alert Flow to Splunk

```
Attack Packet → eth0/eth1/eth2/eth3 → Snort 3 Detection Engine → Rule Match (SID)
    → alert_fast (local: /var/log/snort/alert)
    → alert_json (HTTP POST to 172.20.2.8:8088/services/collector) → Splunk HEC
```

### JSON Payload Format
```json
{
  "event": {
    "sid": 1000001,
    "msg": "[ZTA-001] TCP SYN Port Scan Detected - Reconnaissance in progress",
    "priority": 2,
    "protocol": "TCP",
    "src_ip": "172.20.5.20",
    "src_port": 54321,
    "dst_ip": "172.20.2.7",
    "dst_port": 8443,
    "timestamp": "2026-05-11T14:30:00Z"
  },
  "time": 1746983400,
  "host": "ids_network_monitor"
}
```

---

## Integration Points

| Persona | Component | Port | How Snort Monitors |
|---------|-----------|------|--------------------|
| **P1** | NFTables Firewall | — | Correlates alerts with firewall rejects in Splunk |
| **P2** | Envoy (PEP) | 8443 | Detects SQLi, TLS anomalies, HTTP abuse |
| **P3** | OPA (Policy) | 8181 | Detects unauthorized policy queries (SSH brute) |
| **P4** | Splunk HEC | 8088 | All alerts sent via HTTP JSON to Splunk HEC |
| **P4** | MongoDB | 27017 | Detects direct DB access (SID 1000007–1000008) |
| **P4** | Clients | — | Detects lateral movement (SID 1000012) |

---

## Rule Categories Overview

| Category | SID Range | Rules | Attack Vector | Severity |
|----------|-----------|-------|---------------|----------|
| **1. Port Scanning** | 1000001–1000003 | 3 | Reconnaissance, network mapping | Medium |
| **2. SQL Injection** | 1000004–1000006 | 3 | Web app attacks via Envoy (8443) | Critical |
| **3. Direct Database** | 1000007–1000008 | 2 | MongoDB bypass, data exfiltration | Critical |
| **4. TLS Anomalies** | 1000009–1000011 | 3 | MITM, Heartbleed, downgrade attacks | High |
| **5. Lateral Movement** | 1000012–1000013 | 2 | Client-to-client attack pivot | High |
| **6. DDoS/Resource** | 1000014–1000015 | 2 | SYN flood, Slowloris | High |

**Total: 15 rules** — See [`CONFIG_SNORT_RULES.md`](./rules/CONFIG_SNORT_RULES.md) for detailed rule definitions.

---

## Container Configuration

### Dockerfile
- **Base**: `ubuntu:22.04` runtime stage
- **Snort binary**: Copied from `ghcr.io/snort3/snort3:latest`
- **User**: `snort` (UID 1000) — non-root for security
- **Health check**: Runs `snort -T` every 30s

### Entrypoint (`entrypoint-snort.sh`)
1. Pre-flight checks (binary, config, rules, permissions)
2. Validate config (`snort -T`)
3. Show rules summary
4. Start Snort in IDS mode (`-i eth0:eth2 -A alert_fast`)
5. Monitor alerts (`tail -f /var/log/snort/alert`)

---

## Troubleshooting

| Problem | Symptom | Solution |
|---------|---------|----------|
| Rules not loading | `snort -T` shows errors | Verify syntax and unique SIDs in `.rules` file |
| Splunk not receiving | No alerts in SIEM | Check `SPLUNK_HEC_URL` and `SPLUNK_HEC_TOKEN` environment variables |
| False positives | Alert on legit traffic | Adjust `detection_filter` thresholds |
| HOME_NET not working | Rules fire everywhere | Verify `HOME_NET = 172.20.0.0/16` in `snort.lua` |
| Container exits | Startup failure | Check logs: `docker logs ids_network_monitor` |
| Memory issues | Snort OOM | Reduce `max_sessions` or increase container memory limit |

---

## Testing

```bash
# Validate Snort configuration
docker exec ids_network_monitor snort -c /etc/snort/snort.lua -T --warn-all

# Simulate a port scan (expected: ZTA-001 alert)
docker exec client_corporate nmap -sS 172.20.2.7
docker exec ids_network_monitor tail -5 /var/log/snort/alert

# Simulate a direct MongoDB connection (expected: ZTA-007)
docker exec client_corporate timeout 2 bash -c 'echo > /dev/tcp/172.20.3.5/27017' 2>&1 || true
docker exec ids_network_monitor tail -5 /var/log/snort/alert
```

> For full testing procedures, see [`CONFIG_SNORT_RULES.md`](./rules/CONFIG_SNORT_RULES.md#testing).

---

## References

- [Snort 3 Documentation](https://docs.snort.org/)
- [Snort Rule Writing Guide](https://docs.snort.org/rules/)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CVE-2014-0160 Heartbleed](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160)

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-05-11 | Persona 1 | Initial configuration — 15 rules, 6 categories, Splunk integration |
