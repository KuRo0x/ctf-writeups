# Detecting C2 with RITA — TryHackMe AOC2025

## Metadata

| Field | Value |
|-------|-------|
| **Platform** | TryHackMe |
| **Room** | Detecting C2 with RITA (AOC2025) |
| **Difficulty** | Medium |
| **Category** | Threat Hunting / Network Forensics / C2 Detection |
| **MITRE ATT&CK** | T1071.001 (Web Protocols), T1571 (Non-Standard Port), T1102 (Web Service) |

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

Host `10.0.0.13` connected to `rabbithole.malhare.net` over **port 80/tcp/http**. Attackers deliberately use HTTP because it traverses most firewall policies without inspection, blends into baseline web traffic volume, and allows the implant to disguise callbacks as normal browsing activity.

HTTP C2 communication typically follows one of two patterns:
- **Short polling** — the implant sends a small HTTP GET/POST at a fixed interval, receives tasking in the response body. This produces the high connection counts and regular IATs observed here (40 connections, 97.70% beacon score).
- **Long polling** — the implant holds an open HTTP connection waiting for tasking, producing long durations with low connection counts.

More sophisticated frameworks (e.g., Cobalt Strike with **malleable C2 profiles**) allow operators to customize every field of the HTTP transaction — URI paths, headers, user-agent strings, response body structure — to mimic legitimate application traffic (e.g., impersonating jQuery requests or Windows Update). **Domain fronting** takes this further: the TLS SNI header points to a trusted CDN (e.g., Cloudflare), while the HTTP Host header routes traffic to the actual C2, bypassing domain-based firewall rules entirely. Neither technique was confirmed here, but both are relevant escalation paths when HTTP C2 is identified.

---

## Key Findings

| Indicator | Value | Significance |
|-----------|-------|--------------|
| C2 Domain | `rabbithole.malhare.net` | High beacon scores across multiple hosts |
| C2 Domain | `malhare.net` | Parent domain, 3 internal hosts communicating |
| Secondary Domain | `c2.thm-labs.net` | Additional C2 destination detected |
| Compromised Hosts | 10.0.0.10, 10.0.0.11, 10.0.0.12, 10.0.0.13, 10.0.0.14, 10.0.0.15 | Multiple internal endpoints beaconing |
| Max Connection Count | 40 (to `rabbithole.malhare.net`) | High frequency beaconing |
| Top Beacon Score | 97.70% | Near-perfect periodicity — automated C2 callback |
| Port Used (10.0.0.13) | 80/tcp/http | HTTP-based C2 communication |
| Prevalence | 6/10 (60%) | Broad scope — requires correlation to confirm C2 |

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

```spl
# Detect beaconing: high connection count to same destination with low interval stdev
index=network sourcetype=zeek_conn
| sort _time
| streamstats current=f last(_time) AS prev_time BY id.orig_h, id.resp_h
| eval interval=_time - prev_time
| stats count AS conn_count, stdev(interval) AS interval_stdev, avg(duration) AS avg_dur
    BY id.orig_h, id.resp_h, id.resp_p
| where conn_count > 15 AND interval_stdev < 30
| sort -conn_count

# Long connection duration anomaly
index=network sourcetype=zeek_conn
| where duration > 600
| table _time, id.orig_h, id.resp_h, id.resp_p, duration, orig_bytes, resp_bytes

# DNS query volume spike (possible DNS tunneling or DGA)
index=network sourcetype=zeek_dns
| rex field=query "(?<domain>[^.]+\.[^.]+)$"
| stats count AS query_count, dc(query) AS unique_subdomains BY domain, id.orig_h
| where query_count > 50 OR unique_subdomains > 20
| sort -unique_subdomains
```

### SOC Threat Hunting Actions

Upon RITA flagging `rabbithole.malhare.net` as high-severity, the investigation pivots as follows:

1. **Pivot on destination across all log sources** — Query `conn.log`, `http.log`, `ssl.log`, and `dns.log` for all traffic to `malhare.net` and subdomains. Identify the full list of source IPs, not just those RITA surfaced.
2. **Analyze connection interval distribution** — Extract timestamps for each source→destination pair and compute IAT. A stdev < 10–30 seconds on intervals confirms automated beaconing versus human-driven browsing.
3. **DNS entropy and query frequency** — Check `dns.log` for query volume to `malhare.net`. Excessive subdomain diversity or high-entropy labels (e.g., `a3f9bc.malhare.net`) would indicate DNS-based C2 or DGA activity.
4. **Correlate with endpoint logs** — Map beaconing hosts (10.0.0.10–0.15) to Sysmon Event ID 3 (network connections) and Event ID 1 (process creation). Identify which process owns the outbound connection — browser vs. system process vs. unknown binary.
5. **User activity correlation** — Compare beaconing timestamps against authentication logs (Event ID 4624/4634). Beaconing during off-hours or outside user session windows confirms autonomous implant behavior.
6. **Certificate analysis** — Query `ssl.log` for connections to `malhare.net`. Check certificate issuer, validity period, and subject. Self-signed or Let's Encrypt certs on C2 infrastructure are common; short-lived certs indicate infrastructure rotation.

### Relevant Log Sources for Detection

| Log Source | What to Look For |
|------------|-----------------|
| Zeek conn.log | High conn_count, low interval stdev, long duration to same dst |
| Zeek ssl.log | Self-signed certs, short validity periods, rare JA3 hashes |
| Zeek dns.log | High query volume, high-entropy subdomains, long FQDNs |
| Zeek http.log | Rare user agents, MIME mismatch, fixed URI patterns |
| Sysmon Event ID 3 | Network connections — identify owning process |
| Sysmon Event ID 1 | Process creation — catch implant execution |
| Windows Event 4688 | Process creation with network activity on same host |

---

## Lessons Learned

- **Beacon score alone is not enough** — 10.0.0.11 had 64.40% beacon score with no severity flag. Always correlate beacon score with duration, prevalence, and port context before escalating.
- **Prevalence requires context** — Low prevalence (1–2 hosts) may indicate targeted activity. High prevalence (6/10) may indicate widespread compromise OR a shared benign service. Neither value is conclusive without correlating against beaconing patterns, domain reputation, and connection metadata.
- **HTTP C2 blends in** — Port 80 is rarely blocked. Without content inspection or user-agent baselining, HTTP C2 traffic is indistinguishable from legitimate web browsing at the firewall level.
- **Small datasets affect scoring** — RITA's `First Seen` modifier is less reliable in short capture windows. In production, continuous log ingestion over days provides more accurate baselines.
- **RITA complements SIEMs** — RITA excels at statistical beaconing detection that rule-based SIEMs miss. Both should be used together in a mature SOC.
