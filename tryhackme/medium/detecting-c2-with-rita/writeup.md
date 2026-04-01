# Detecting C2 with RITA — TryHackMe AOC2025

## Metadata

| Field | Value |
|-------|-------|
| **Platform** | TryHackMe |
| **Room** | Detecting C2 with RITA (AOC2025) |
| **Difficulty** | Medium |
| **Category** | Threat Hunting / Network Forensics / C2 Detection |
| **MITRE ATT&CK** | T1071 (Application Layer Protocol), T1571 (Non-Standard Port), T1132 (Data Encoding), T1008 (Fallback Channels) |

---

## Objective

Hunt command and control (C2) traffic within captured network data by converting a raw PCAP to structured Zeek logs, importing them into RITA, and identifying beaconing behavior, connection anomalies, and suspicious domains through statistical analysis.

---

## Scenario

A security team suspects adversary activity within their network. A large PCAP (`rita_challenge.pcap`) was collected from a network tap. The objective is to identify any C2 communication by analyzing the traffic for behavioral indicators: periodic beaconing, long-lived connections, unusual ports, and suspicious external destinations.

---

## Tools Used

See [tools.md](./tools.md) for full reference.

| Tool | Version | Purpose |
|------|---------|----------|
| Zeek | Latest | PCAP → structured log conversion |
| RITA | v5.x | Statistical C2 beacon detection |
| VirusTotal | — | IOC validation |

---

## Methodology

### Step 1 — Convert PCAP to Zeek Logs

```bash
zeek readpcap ~/pcaps/rita_challenge.pcap zeek_logs/rita_challenge
```

**Why:** RITA does not accept raw PCAP input. Zeek acts as the parsing layer, converting binary packet data into structured log files (conn.log, ssl.log, dns.log, http.log, etc.). Each log captures specific protocol metadata: connection tuples, timestamps, durations, bytes transferred, and certificates. This structured output is what enables RITA's statistical correlation engine to function.

**Output logs relevant to C2 hunting:**
- `conn.log` — connection 5-tuple, duration, bytes (primary beaconing source)
- `ssl.log` — TLS certificate details (detects self-signed or short-lived certs)
- `dns.log` — DNS query volume and FQDN length (DNS tunneling indicators)
- `http.log` — HTTP headers, user agents, MIME types

![Zeek log output](screenshots/01-zeek-logs.png)

---

### Step 2 — Import Logs into RITA

```bash
rita import --logs ~/zeek_logs/rita_challenge/ --database rita_challenge
```

**Why:** RITA parses the Zeek log directory and runs its full analysis pipeline against the dataset. During import, RITA:
- Ingests `conn.log`, `ssl.log`, `dns.log`, `http.log`
- Computes beacon scores by analyzing inter-arrival times (jitter and periodicity of connections)
- Calculates connection duration averages
- Cross-references external IPs against threat intelligence feeds (e.g., Feodo Tracker)
- Computes prevalence: % of internal hosts communicating with each external destination

---

### Step 3 — Analyze Results

```bash
rita view rita_challenge
```

**Why:** The interactive TUI presents all findings ranked by severity. Each row represents a unique source→destination pair. The analyst uses this view to prioritize investigation based on beacon score, connection duration, and threat modifier flags.

**RITA TUI Search Syntax used:**

```
/dst:malhare.net                                           # Filter by destination domain
/dst:rabbithole.malhare.net                               # Specific subdomain filter
/src:10.0.0.13 dst:rabbithole.malhare.net                 # Source-destination pair
/dst:rabbithole.malhare.net beacon:>70 sort:duration-desc # Beacon > 70% sorted by duration
```

![RITA main view](screenshots/02-rita-main-view.png)

---

## Analysis

### C2 Beaconing Behavior

C2 beaconing is the periodic "check-in" communication between a compromised host and its C2 server. Malware typically calls home at regular intervals to receive commands or exfiltrate data. This regularity creates a statistical pattern: consistent inter-arrival times between connections with low jitter.

RITA detects this by:
1. Collecting all connection timestamps between a source-destination pair from `conn.log`
2. Computing the inter-arrival time (IAT) between consecutive connections
3. Calculating the **skew** (asymmetry) and **dispersion** (spread) of the IAT distribution
4. A low-skew, low-dispersion distribution → high beacon score (close to 100%)

In this lab, `rabbithole.malhare.net` received connections from multiple internal hosts with beacon scores between **64.40% – 97.70%**, confirming periodic automated communication.

![Beaconing results](screenshots/03-beaconing.png)

### Prevalence as a Threat Signal

Prevalence measures what % of internal hosts are communicating with a given external destination. The logic: legitimate services (Google, Microsoft) are contacted by many hosts. C2 infrastructure is typically contacted by only 1-2 compromised hosts.

In this dataset, `rabbithole.malhare.net` showed `6/10 (60%)` prevalence — unusually high for a suspicious domain, suggesting a broader compromise across the internal network.

### Connection Duration Analysis

Long connection durations indicate persistent, interactive sessions — consistent with C2 tunnels, reverse shells, or RAT communication. The top entries showed durations of **17m8s and 21m1s**, which is abnormal for typical HTTP or DNS traffic.

### Port and Protocol Anomalies

Host `10.0.0.13` connected to `rabbithole.malhare.net` over **port 80 (HTTP)** — while not a non-standard port, unencrypted C2 over HTTP allows the malware to blend in with normal web traffic. Combined with high beacon scores, this warrants immediate investigation.

---

## Key Findings

| Indicator | Value | Significance |
|-----------|-------|---------------|
| C2 Domain | `rabbithole.malhare.net` | High beacon scores across multiple hosts |
| C2 Domain | `malhare.net` | Parent domain, 3 internal hosts communicating |
| Secondary Domain | `c2.thm-labs.net` | Additional C2 destination detected |
| Compromised Hosts | 10.0.0.10, 10.0.0.11, 10.0.0.12, 10.0.0.13, 10.0.0.14, 10.0.0.15 | Multiple internal endpoints beaconing |
| Max Connection Count | 40 (to `rabbithole.malhare.net`) | High frequency beaconing |
| Top Beacon Score | 97.70% | Near-perfect periodicity — automated C2 callback |
| Port Used (10.0.0.13) | 80/tcp/http | HTTP-based C2 communication |
| Prevalence | 6/10 (60%) | Broad internal compromise |

---

## Flags

| Question | Answer |
|----------|--------|
| Hosts communicating with malhare.net | 3 |
| Threat Modifier for host count | Prevalence |
| Highest connections to rabbithole.malhare.net | 40 |
| Search filter (beacon >70, sort duration desc) | `/dst:rabbithole.malhare.net beacon:>70 sort:duration-desc` |
| Port used by 10.0.0.13 | 80 |

---

## Real-World Application

### How This Appears in a SIEM (Splunk)

A SOC analyst would look for these Splunk queries to replicate this detection:

```spl
# Detect high-frequency beaconing (same src/dst, multiple connections)
index=network sourcetype=zeek_conn
| stats count AS conn_count, avg(duration) AS avg_duration BY id.orig_h, id.resp_h
| where conn_count > 20 AND avg_duration < 5
| sort -conn_count

# Long connection duration anomaly
index=network sourcetype=zeek_conn
| where duration > 600
| table _time, id.orig_h, id.resp_h, id.resp_p, duration, orig_bytes

# DNS query volume spike (possible DNS tunneling)
index=network sourcetype=zeek_dns
| stats count AS query_count BY query, id.orig_h
| where query_count > 50
| sort -query_count
```

### SOC Investigation Process

1. **Alert triage** — RITA/SIEM flags `rabbithole.malhare.net` as high-severity beacon
2. **Pivot on source IP** — Identify all 10.0.0.x hosts beaconing the same destination
3. **Check threat intel** — Query VirusTotal, Feodo Tracker, Shodan for the C2 domain
4. **Examine endpoint** — Pull Sysmon logs for process creation, network connections on affected hosts
5. **Contain** — Block C2 domains/IPs at firewall/DNS level, isolate endpoints
6. **Eradicate** — Identify malware process, remove persistence mechanisms
7. **Document IOCs** — Add to SIEM watchlist, update firewall blocklist

### Relevant Log Sources for Detection

| Log Source | What to Look For |
|------------|------------------|
| Zeek conn.log | High conn_count, long duration, same dst |
| Zeek ssl.log | Self-signed certs, short validity periods |
| Zeek dns.log | Long FQDNs, high query volume per domain |
| Zeek http.log | Rare user agents, MIME mismatch |
| Sysmon Event ID 3 | Network connections from suspicious processes |
| Windows Event 4688 | Process creation linked to C2 payload |

---

## Lessons Learned

- **Beacon score alone is not enough** — 10.0.0.11 had 64.40% beacon score with no severity flag. Always correlate beacon score with duration, prevalence, and port context.
- **Prevalence is a force multiplier** — Low prevalence (1-2 hosts) is suspicious. High prevalence (6/10) suggests lateral movement or a worm-like C2 implant.
- **HTTP C2 blends in** — Port 80 is rarely blocked. Attackers use HTTP to hide in legitimate-looking traffic. Content inspection or user-agent analysis is needed to differentiate.
- **Small datasets affect scoring** — RITA's `First Seen` modifier is less reliable in short capture windows. In production, continuous log ingestion over days provides more accurate baselines.
- **RITA complements SIEMs** — RITA excels at statistical beaconing detection that rule-based SIEMs miss. Both should be used together in a mature SOC.
