# Detecting C2 with RITA — TryHackMe AOC2025

## Metadata

| Field | Value |
|-------|-------|
| **Platform** | TryHackMe |
| **Room** | Detecting C2 with RITA (AOC2025) |
| **Difficulty** | Medium |
| **Category** | Threat Hunting / Network Forensics / C2 Detection |
| **MITRE ATT&CK** | T1071.001 — C2 over HTTP (observed); T1102 — Web Service used as communication channel |

---

## Objective

Hunt command and control (C2) traffic within captured network data by converting a raw PCAP to structured Zeek logs, importing them into RITA, and identifying beaconing behavior, connection anomalies, and suspicious domains through statistical analysis.

---

## Scenario

An internal alert flagged anomalous outbound traffic patterns from multiple hosts within the 10.0.0.0/24 segment. A PCAP (`rita_challenge.pcap`) was captured at the network perimeter and handed off for analysis. The task is to determine whether the traffic represents active C2 communication — identifying affected hosts, destination infrastructure, beaconing patterns, and communication channels used by the adversary.

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

Prevalence measures what % of internal hosts are communicating with a given external destination. A high prevalence value (~60%) does **not** by itself confirm C2 — legitimate shared infrastructure (CDNs, SaaS endpoints) naturally shows high prevalence. Conversely, a low prevalence value (1–2 hosts) is not automatically suspicious either; targeted intrusions often affect a single endpoint.

Prevalence becomes actionable only when correlated with other indicators. In this dataset, `rabbithole.malhare.net` showed `6/10 (60%)` prevalence **alongside** beacon scores of 64–97%, long connection durations (10–21 minutes), and a domain with no legitimate business purpose. That combination — not prevalence alone — is what elevates the finding to high confidence C2.

The analytical workflow: use prevalence to scope the blast radius (how many hosts are involved), then validate with beaconing patterns, connection intervals, and entropy of communication timing.

### Connection Duration Analysis

Long connection durations indicate persistent, interactive sessions — consistent with C2 tunnels, reverse shells, or RAT communication. The top entries showed durations of **17m8s and 21m1s**, which is abnormal for typical HTTP or DNS traffic.

### Port 80 — HTTP as a C2 Channel

Host `10.0.0.13` connected to `rabbithole.malhare.net` over **port 80/tcp/http**. Attackers use HTTP because it traverses most firewall policies uninspected and blends into baseline web traffic. The pattern observed here — 40 connections with a 97.70% beacon score — is consistent with HTTP short polling: the implant sends a GET/POST at a fixed interval and receives tasking in the response body.

More sophisticated frameworks use **malleable C2 profiles** to customize HTTP headers, URI paths, and user-agent strings to mimic legitimate traffic, or **domain fronting** to route C2 through trusted CDNs. Neither was confirmed here, but both are relevant escalation paths when HTTP C2 is identified.

---

## Key Findings

### Primary Indicators

| Indicator | Value | Why It Matters |
|-----------|-------|----------------|
| C2 Domain | `rabbithole.malhare.net` | Beacon scores 64–97.70% across 6 internal hosts |
| Max Connection Count | 40 | High-frequency automated callback pattern |
| Compromised Hosts | 10.0.0.10–10.0.0.15 | Broad internal compromise confirmed |

### Supporting Indicators

| Indicator | Value | Why It Matters |
|-----------|-------|----------------|
| Connection Duration | 17m8s – 21m1s | Persistent sessions abnormal for HTTP |
| Port / Protocol | 80/tcp/http | HTTP used to blend C2 into normal traffic |
| Secondary Domain | `c2.thm-labs.net` | Additional C2 destination from same network segment |

### Contextual Indicators

| Indicator | Value | Why It Matters |
|-----------|-------|----------------|
| Prevalence | 6/10 (60%) | Scopes blast radius; not C2 confirmation alone |
| Parent Domain | `malhare.net` | 3 hosts communicating — used to map infrastructure |

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

### Beaconing Detection — Splunk

```spl
index=network sourcetype=zeek_conn
| sort _time
| streamstats current=f last(_time) AS prev_time BY id.orig_h, id.resp_h
| eval interval=_time - prev_time
| stats count AS conn_count, stdev(interval) AS interval_stdev
    BY id.orig_h, id.resp_h, id.resp_p
| where conn_count > 15 AND interval_stdev < 30
| sort -conn_count
```

Detects automated callbacks by identifying high connection counts with low inter-arrival time variance — the statistical signature of beaconing.

### Threat Hunting Pivots

1. **Interval analysis** — Extract IAT per source→destination pair from `conn.log`. Stdev < 30s confirms automated periodicity over human browsing.
2. **Endpoint correlation** — Map beaconing hosts to Sysmon Event ID 3 (network connection) and Event ID 1 (process creation) to identify the implant process responsible for the outbound traffic.
3. **User session validation** — Compare beaconing timestamps against authentication logs (Event ID 4624/4634). Callbacks during off-hours or outside active sessions confirm autonomous implant behavior.

---

## Detection Confidence Assessment

| Signal Type | Indicator | Weight |
|-------------|-----------|--------|
| **Primary** | Beacon score up to 97.70% — near-perfect interval regularity | High |
| **Supporting** | 40 connections to single destination | High |
| **Supporting** | 6 internal hosts beaconing the same C2 domain | High |
| **Weak/Contextual** | Prevalence 60% — requires correlation, not standalone | Low |
| **Weak/Contextual** | Port 80 — common port, insufficient alone | Low |

**Overall Confidence: HIGH** — Primary and supporting signals are independently sufficient to confirm C2 activity. Contextual signals provide scope only.

---

## Lessons Learned

- **Beacon score alone is not enough** — 10.0.0.11 had 64.40% beacon score with no severity flag. Always correlate beacon score with duration, prevalence, and port context before escalating.
- **Prevalence requires context** — Low prevalence (1–2 hosts) may indicate targeted activity. High prevalence (6/10) may indicate widespread compromise OR a shared benign service. Neither value is conclusive without correlating against beaconing patterns, domain reputation, and connection metadata.
- **HTTP C2 blends in** — Port 80 is rarely blocked. Without content inspection or user-agent baselining, HTTP C2 traffic is indistinguishable from legitimate web browsing at the firewall level.
- **Small datasets affect scoring** — RITA's `First Seen` modifier is less reliable in short capture windows. In production, continuous log ingestion over days provides more accurate baselines.
- **RITA complements SIEMs** — RITA excels at statistical beaconing detection that rule-based SIEMs miss. Both should be used together in a mature SOC.

---

## Final Assessment

The analyzed traffic is **consistent with active C2 communication**. The convergence of multiple independent indicators eliminates benign explanations:

- Beacon scores of up to **97.70%** indicate near-perfect connection periodicity — a statistical signature of automated malware callbacks, not human-driven browsing
- **40 connections** to a single external domain from one host reflects high-frequency implant check-ins
- **6 of 10 internal hosts** communicating with the same C2 infrastructure confirms a broad compromise, not an isolated incident
- **HTTP on port 80** was deliberately used to blend C2 traffic into normal web activity and avoid firewall-level blocking

**Conclusion:** C2 activity confirmed with high probability. Immediate containment of the 10.0.0.0/24 segment and endpoint forensics on all beaconing hosts is warranted.

**Confidence Level: HIGH**
