# Detecting C2 with RITA — TryHackMe AOC2025

## Metadata

| Field | Value |
|-------|-------|
| **Platform** | TryHackMe |
| **Room** | Detecting C2 with RITA (AOC2025) |
| **Difficulty** | Medium |
| **Category** | Threat Hunting / Network Forensics / C2 Detection |
| **MITRE ATT&CK** | T1071.001 (Application Layer Protocol: Web Protocols), T1102 (Web Service) |

---

## Objective

Hunt C2 traffic within a captured PCAP by converting it to Zeek logs, importing into RITA, and identifying beaconing behavior, connection anomalies, and suspicious external destinations through statistical analysis.

---

## Scenario

An internal alert flagged anomalous outbound traffic from multiple hosts in the 10.0.0.0/24 segment. A PCAP (`rita_challenge.pcap`) was captured at the network perimeter and handed off for analysis. The objective: determine whether traffic represents active C2 communication, identify affected hosts, and map the adversary infrastructure.

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

**Why:** RITA requires Zeek-format logs as input. Zeek parses the binary PCAP and outputs structured per-protocol log files containing connection tuples, timestamps, durations, bytes transferred, and certificate metadata.

**Relevant output logs:**
- `conn.log` — connection 5-tuple, duration, bytes (primary beaconing source)
- `ssl.log` — TLS certificate details (self-signed cert detection)
- `dns.log` — query volume, FQDN length (DNS tunneling indicators)
- `http.log` — headers, user agents, MIME types

![Zeek log output](screenshots/01-zeek-logs.png)

---

### Step 2 — Import Logs into RITA

```bash
rita import --logs ~/zeek_logs/rita_challenge/ --database rita_challenge
```

**Why:** RITA runs its full statistical pipeline on import: computing beacon scores from inter-arrival times (IAT), calculating connection durations, cross-referencing IPs against threat intel feeds (Feodo Tracker), and computing prevalence across internal hosts.

---

### Step 3 — Analyze Results

```bash
rita view rita_challenge
```

**RITA TUI Search Syntax used:**

```
/dst:malhare.net
/dst:rabbithole.malhare.net
/src:10.0.0.13 dst:rabbithole.malhare.net
/dst:rabbithole.malhare.net beacon:>70 sort:duration-desc
```

![RITA main view](screenshots/02-rita-main-view.png)

---

## Analysis

### C2 Beaconing Behavior

RITA detects beaconing by analyzing inter-arrival times (IAT) between connections in `conn.log`:
1. Collects all timestamps for each source→destination pair
2. Computes IAT between consecutive connections
3. Calculates **skew** (asymmetry) and **dispersion** (spread) of the IAT distribution
4. Low skew + low dispersion = high beacon score (automated, periodic communication)

`rabbithole.malhare.net` showed beacon scores of **64.40% – 97.70%** across multiple internal hosts, confirming periodic automated callbacks.

![Beaconing results](screenshots/03-beaconing.png)

### Prevalence as a Threat Signal

Prevalence measures what % of internal hosts contact a given external destination. It is **not a standalone C2 indicator** — CDNs and SaaS platforms naturally show high prevalence. It becomes actionable only when correlated with beacon scores, connection durations, and domain reputation.

Here, `6/10 (60%)` prevalence to `rabbithole.malhare.net` combined with beacon scores of 64–97% and durations of 10–21 minutes confirms broad compromise — prevalence scopes the blast radius, not the verdict.

### Connection Duration

Top entries showed durations of **17m8s and 21m1s** — abnormal for HTTP, consistent with persistent C2 tunnel or RAT keep-alive behavior.

### Port 80 — HTTP as C2 Channel

`10.0.0.13` connected to `rabbithole.malhare.net` over **port 80/tcp/http**. HTTP is deliberately chosen by attackers to blend callbacks into normal web traffic and bypass firewall inspection. The 40 connections with 97.70% beacon score are consistent with HTTP short polling: implant sends GET/POST at fixed intervals, receives tasking in the response body.

---

## Key Findings

### Primary Indicators

| Indicator | Value | Significance |
|-----------|-------|--------------|
| C2 Domain | `rabbithole.malhare.net` | Beacon scores 64–97.70% across 6 internal hosts |
| Connection Count | 40 | High-frequency automated callback pattern |
| Compromised Hosts | 10.0.0.10 – 10.0.0.15 | Broad internal compromise confirmed |

### Supporting Indicators

| Indicator | Value | Significance |
|-----------|-------|--------------|
| Connection Duration | 17m8s – 21m1s | Persistent sessions abnormal for HTTP |
| Port / Protocol | 80/tcp/http | HTTP used to blend C2 into normal traffic |
| Secondary Domain | `c2.thm-labs.net` | Additional C2 destination detected |

### Contextual Indicators

| Indicator | Value | Significance |
|-----------|-------|--------------|
| Prevalence | 6/10 (60%) | Scopes blast radius only — not C2 confirmation |
| Parent Domain | `malhare.net` | 3 hosts communicating — maps adversary infrastructure |

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

Identifies high-frequency connections with low inter-arrival time variance — the statistical signature of automated beaconing.

### Threat Hunting Pivots

1. **Interval analysis** — Compute IAT stdev per source→destination pair. Stdev < 30s confirms automated periodicity.
2. **Endpoint correlation** — Map beaconing hosts to Sysmon Event ID 3 (network connection) and Event ID 1 (process creation) to identify the responsible implant process.
3. **Session validation** — Compare beaconing timestamps against auth logs (Event ID 4624/4634). Callbacks outside active user sessions confirm autonomous implant behavior.

---

## Detection Confidence Assessment

**Primary Signal:**
- High beacon score (64–97%) indicating periodic automated communication

**Supporting Signals:**
- High connection count (40 connections)
- Multiple hosts communicating (6 hosts)

**Weak/Contextual Signals:**
- Prevalence (requires correlation, not standalone)
- Port usage (HTTP is common and not suspicious alone)

**Overall Confidence: HIGH**

---

## Lessons Learned

- **Beacon score alone is not enough** — Always correlate with duration, prevalence, and port context before escalating.
- **Prevalence requires context** — Low prevalence may indicate targeted activity; high prevalence may indicate widespread compromise or a shared benign service. Neither is conclusive alone.
- **HTTP C2 blends in** — Without content inspection or user-agent baselining, HTTP C2 is indistinguishable from normal web traffic at the firewall level.
- **Small datasets affect scoring** — RITA's `First Seen` modifier is less reliable in short capture windows. Production environments require continuous ingestion for accurate baselines.
- **RITA complements SIEMs** — RITA's statistical beaconing detection catches what rule-based SIEMs miss. Both are required in a mature SOC.

---

## Final Assessment

The traffic associated with `rabbithole.malhare.net` demonstrates strong indicators of command-and-control (C2) activity.

**Key reasons:**
- High beacon scores (up to 97.70%) indicating regular automated communication
- High connection count (40 connections)
- Multiple internal hosts involved (6 hosts)
- Use of HTTP (port 80) to blend with normal traffic

**Conclusion:**
The observed behavior is consistent with HTTP-based C2 beaconing across multiple compromised hosts.

**Confidence: HIGH**
