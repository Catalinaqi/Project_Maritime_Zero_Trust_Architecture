# 👁️ Snort 3 IDS Custom Rules - Zero Trust Architecture

## Purpose

Layer 1 Intrusion Detection System (IDS) using **Snort 3** to detect and alert on attack patterns targeting the Adria Ferries maritime Zero Trust Architecture.

Snort serves as the **second pair of eyes** after the firewall, providing:
- **Signature-based detection** - Known attack patterns identified by 15 custom rules (SID 1000001-1000015)
- **Protocol anomaly detection** - Abnormal traffic patterns (NULL scans, TLS downgrade, etc.)
- **Threat correlation** - Alerts correlated with firewall logs in Splunk for incident response
- **Defense in depth** - Independent detection layer that works even if firewall rules are misconfigured
- **Visibility** - Monitoring traffic that the firewall allows (authorized paths) for malicious payloads

---

## Rule Classification

The 15 custom rules are organized into **6 categories** covering the Zero Trust threat model:

| Category | SID Range | Rules | Attack Vector | Severity |
|----------|-----------|-------|---------------|----------|
| **1. Port Scanning** | 1000001-1000003 | 3 | Reconnaissance, network mapping | Medium |
| **2. SQL Injection** | 1000004-1000006 | 3 | Web app attacks via Envoy (8443) | Critical |
| **3. Direct Database** | 1000007-1000008 | 2 | MongoDB bypass, data exfiltration | Critical |
| **4. TLS Anomalies** | 1000009-1000011 | 3 | MITM, Heartbleed, downgrade attacks | High |
| **5. Lateral Movement** | 1000012-1000013 | 2 | Client-to-client attack pivot | High |
| **6. DDoS/Resource** | 1000014-1000015 | 2 | SYN flood, Slowloris | High |

**Total: 15 rules**

---

## Category 1: Port Scanning Detection (SID 1000001 - 1000003)

### SID 1000001 - TCP SYN Port Scan
```snort
alert tcp any any -> $HOME_NET any (
    msg:"[ZTA-001] TCP SYN Port Scan Detected - Reconnaissance in progress";
    flags:S;
    detection_filter:track by_src, count 20, seconds 60;
    sid:1000001;
    rev:1;
    priority:2;
)
```

**Detection Logic**: Monitors TCP SYN packets. If a single source IP sends 20+ SYN packets to any destination in HOME_NET within 60 seconds, an alert is generated.

**False Positive Potential**: Low. Network scanners (nmap, masscan) and legitimate health checks may trigger. Exclude known monitoring IPs if needed.

**Response**: Cross-reference source IP with firewall logs. If from clients_net, check for compromised client; if from external, block at firewall and contain.

### SID 1000002 - UDP Port Scan
```snort
alert udp any any -> $HOME_NET any (
    msg:"[ZTA-002] UDP Port Scan Detected - Possible reconnaissance";
    detection_filter:track by_src, count 20, seconds 60;
    sid:1000002;
    rev:1;
    priority:2;
)
```

**Detection Logic**: Monitors UDP packets. 20+ UDP packets from same source to HOME_NET in 60 seconds triggers alert.

### SID 1000003 - Stealth Scan (NULL/FIN/XMAS)
```snort
alert tcp any any -> $HOME_NET any (
    msg:"[ZTA-003] Stealth Scan Detected (NULL/FIN/XMAS) - Advanced reconnaissance";
    flags:!APRSUF12;
    sid:1000003;
    rev:1;
    priority:1;
)
```

**Detection Logic**: Catches TCP packets with abnormal flag combinations that do NOT have any of the SYN, RST, PSH, ACK, URG, FIN flags set.

---

## Category 2: SQL Injection Detection (SID 1000004 - 1000006)

### SID 1000004 - UNION SELECT Injection
```snort
alert tcp any any -> $HOME_NET 8443 (
    msg:"[ZTA-004] SQL Injection Attempt: UNION SELECT";
    flow:to_server,established;
    content:"union"; nocase;
    content:"select"; nocase; distance:0;
    sid:1000004;
    rev:1;
    priority:1;
)
```

### SID 1000005 - OR 1=1 Bypass
```snort
alert tcp any any -> $HOME_NET 8443 (
    msg:"[ZTA-005] SQL Injection Attempt: OR 1=1 Bypass";
    flow:to_server,established;
    pcre:"/(\\%27)|(\\')|(\\-\\-)|(\\%23)|(#)/i";
    content:"or"; nocase;
    content:"1=1"; nocase; distance:0;
    sid:1000005;
    rev:1;
    priority:1;
)
```

### SID 1000006 - DROP TABLE Attacks
```snort
alert tcp any any -> $HOME_NET 8443 (
    msg:"[ZTA-006] SQL Injection Attempt: DROP TABLE/Data Destruction";
    flow:to_server,established;
    content:"drop"; nocase;
    pcre:"/drop\\s+(table|database|index|procedure)/i";
    sid:1000006;
    rev:1;
    priority:1;
)
```

---

## Category 3: Direct Database Access (SID 1000007 - 1000008)

### SID 1000007 - Direct MongoDB Connection
```snort
alert tcp any any -> 172.20.3.5 27017 (
    msg:"[ZTA-007] DIRECT MongoDB Connection Attempt - Firewall bypass suspected";
    flags:S;
    sid:1000007;
    rev:1;
    priority:1;
)
```

### SID 1000008 - MongoDB Wire Protocol
```snort
alert tcp any any -> $HOME_NET any (
    msg:"[ZTA-008] MongoDB Wire Protocol Detected - Possible data exfiltration";
    flow:to_server,established;
    content:"|d4070000|";
    sid:1000008;
    rev:1;
    priority:2;
)
```

---

## Category 4: TLS/Certificate Anomalies (SID 1000009 - 1000011)

### SID 1000009 - Unencrypted HTTP on TLS Port
```snort
alert tcp any any -> $HOME_NET 8443 (
    msg:"[ZTA-009] Unencrypted HTTP on TLS Port - Possible MITM";
    flow:to_server,established;
    content:"GET"; offset:0; depth:3;
    sid:1000009;
    rev:1;
    priority:1;
)
```

### SID 1000010 - TLS Heartbleed Attack
```snort
alert tcp any any -> $HOME_NET 8443 (
    msg:"[ZTA-010] TLS Heartbleed Attack - Memory leakage attempt";
    flow:to_server,established;
    content:"|18 03|"; offset:0; depth:2;
    byte_test:2,>,200,0,relative;
    sid:1000010;
    rev:1;
    priority:1;
)
```

### SID 1000011 - TLS Version Downgrade (SSLv3, TLSv1.0, TLSv1.1)
```snort
alert tcp any any -> $HOME_NET 8443 (
    msg:"[ZTA-011] TLS Version Downgrade Attack - Weak protocol detected";
    flow:to_server,established;
    content:"|16 03|"; offset:0; depth:2;
    pcre:"/\x16\x03[\x00-\x02]/";
    sid:1000011;
    rev:2;
    priority:2;
)
```

**Detection Logic**: Uses PCRE pattern `\x16\x03[\x00-\x02]` to match TLS handshake (content type 0x16) with major version 3 and minor version ≤ 2 (SSLv3, TLS 1.0, TLS 1.1). Replaced the previous `byte_test` with `relative` which was unreliable in Snort 3.

---

## Category 5: Lateral Movement (SID 1000012 - 1000013)

### SID 1000012 - Client-to-Client Connection
```snort
alert tcp 172.20.5.0/24 any -> 172.20.5.0/24 any (
    msg:"[ZTA-012] Lateral Movement: Client-to-client connection";
    flags:S;
    sid:1000012;
    rev:1;
    priority:1;
)
```

### SID 1000013 - SSH Brute Force
```snort
alert tcp any any -> $HOME_NET 22 (
    msg:"[ZTA-013] SSH Brute Force Attack - Possible credential stuffing";
    flow:to_server,established;
    detection_filter:track by_src, count 5, seconds 60;
    sid:1000013;
    rev:1;
    priority:1;
)
```

---

## Category 6: DDoS / Resource Exhaustion (SID 1000014 - 1000015)

### SID 1000014 - SYN Flood
```snort
alert tcp any any -> $HOME_NET any (
    msg:"[ZTA-014] SYN Flood Attack - Possible DDoS in progress";
    flags:S;
    detection_filter:track by_dst, count 100, seconds 10;
    sid:1000014;
    rev:1;
    priority:1;
)
```

### SID 1000015 - HTTP Slowloris
```snort
alert tcp any any -> $HOME_NET 8443 (
    msg:"[ZTA-015] HTTP Slowloris Attack - Resource exhaustion attempt";
    flow:to_server,established;
    content:"POST"; offset:0; depth:4;
    detection_filter:track by_src, count 50, seconds 60;
    sid:1000015;
    rev:1;
    priority:1;
)
```

---

## Detection Matrix

| Rule ID | Name | Protocol | Direction | Threshold | Priority |
|---------|------|----------|-----------|-----------|----------|
| 1000001 | TCP SYN Scan | TCP | -> HOME_NET | 20 SYN/60s | Medium |
| 1000002 | UDP Scan | UDP | -> HOME_NET | 20 pkts/60s | Medium |
| 1000003 | Stealth Scan | TCP | -> HOME_NET | Any | Critical |
| 1000004 | UNION SELECT | TCP | -> :8443 | Any | Critical |
| 1000005 | OR 1=1 | TCP | -> :8443 | Any | Critical |
| 1000006 | DROP TABLE | TCP | -> :8443 | Any | Critical |
| 1000007 | Direct MongoDB | TCP | -> 172.20.3.5:27017 | Any | Critical |
| 1000008 | MongoDB Proto | TCP | -> HOME_NET | Any | Medium |
| 1000009 | HTTP on TLS | TCP | -> :8443 | Any | Critical |
| 1000010 | Heartbleed | TCP | -> :8443 | payload >200 | Critical |
| 1000011 | TLS Downgrade | TCP | -> :8443 | pcre match | High |
| 1000012 | Lateral Move | TCP | clients->clients | Any | Critical |
| 1000013 | SSH Brute | TCP | -> :22 | 5 conn/60s | Critical |
| 1000014 | SYN Flood | TCP | -> HOME_NET | 100 SYN/10s | Critical |
| 1000015 | Slowloris | TCP | -> :8443 | 50 POST/60s | Critical |

---

## Testing

```bash
# Validate Snort configuration
docker exec ids_network_monitor snort -c /etc/snort/snort.lua -T --warn-all

# Simulate port scan
docker exec client_corporate nmap -sS 172.20.2.7
docker exec ids_network_monitor tail -5 /var/log/snort/alert
# Expected: [ZTA-001] TCP SYN Port Scan Detected

# Simulate SQL injection
docker exec client_corporate curl -s "http://172.20.2.7:8443/api?id=1' OR '1'='1"
docker exec ids_network_monitor tail -5 /var/log/snort/alert
# Expected: [ZTA-005] SQL Injection Attempt: OR 1=1 Bypass

# Simulate direct MongoDB
docker exec client_corporate timeout 2 bash -c 'echo > /dev/tcp/172.20.3.5/27017' 2>&1 || true
docker exec ids_network_monitor tail -5 /var/log/snort/alert
# Expected: [ZTA-007] DIRECT MongoDB Connection Attempt

# Simulate lateral movement
docker exec client_corporate timeout 2 bash -c 'echo > /dev/tcp/172.20.5.21/22' 2>&1 || true
docker exec ids_network_monitor tail -5 /var/log/snort/alert
# Expected: [ZTA-012] Lateral Movement

# Simulate SYN flood
docker exec client_corporate nping --tcp -c 200 --flags syn --delay 10ms 172.20.2.7 2>/dev/null || true
docker exec ids_network_monitor tail -5 /var/log/snort/alert
# Expected: [ZTA-014] SYN Flood Attack
```

---

## Alert Flow to Splunk

```
Attack Packet -> eth0/eth1/eth2/eth3 -> Snort Detection Engine -> Rule Match (SID)
    -> alert_fast (local: /var/log/snort/alert)
    -> alert_json (HTTP POST to 172.20.2.8:8088/services/collector) -> Splunk HEC
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

| Persona | Component | Integration |
|---------|-----------|-------------|
| **P1** | NFTables Firewall | Alerts correlate with firewall rejects in Splunk |
| **P2** | Envoy (:8443) | Monitors traffic to Envoy for SQLi, TLS anomalies |
| **P3** | OPA (:8181) | Detects unauthorized OPA access (SID 1000013) |
| **P4** | Splunk HEC (:8088) | All alerts sent via HTTP JSON |
| **P4** | MongoDB (:27017) | Detects direct DB access (SID 1000007) |
| **P4** | Clients (172.20.5.x) | Detects lateral movement (SID 1000012) |

---

## Troubleshooting

| Problem | Symptom | Solution |
|---------|---------|----------|
| Rules not loading | snort -T shows errors | Verify syntax and unique SIDs |
| Splunk not receiving | No alerts in SIEM | Check SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN environment variables |
| False positives | Alert on legit traffic | Adjust detection_filter thresholds |
| HOME_NET not working | Rules fire everywhere | Verify HOME_NET = 172.20.0.0/16 in snort.lua |

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-05-11 | Persona 1 | Initial 15 rules, 6 categories, Splunk integration |

---

## References

- [Snort 3 Documentation](https://docs.snort.org/)
- [Snort Rule Writing Guide](https://docs.snort.org/rules/)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CVE-2014-0160 Heartbleed](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160)
