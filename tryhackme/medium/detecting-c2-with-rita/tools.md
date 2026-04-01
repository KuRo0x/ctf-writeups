# Tools Reference — Detecting C2 with RITA

---

## Zeek

**Purpose:** Network Security Monitor (NSM) that converts raw PCAP files into structured, protocol-aware log files. Zeek is not an IDS/IPS — it does not block or alert. It observes and records.

**Why used here:** RITA only accepts Zeek logs as input. Zeek parses the binary PCAP and outputs TSV/JSON logs per protocol, enabling RITA's statistical analysis engine to process connection metadata.

**Key Command:**
```bash
zeek readpcap <pcap_file> <output_directory>
```

**Relevant Output Logs:**

| Log File | Content | C2 Relevance |
|----------|---------|---------------|
| `conn.log` | 5-tuple, duration, bytes | Beaconing intervals, long connections |
| `ssl.log` | TLS certs, JA3 hashes | Self-signed certs, rare TLS fingerprints |
| `dns.log` | Queries, answers, TTLs | DNS tunneling, long FQDNs |
| `http.log` | URIs, user agents, MIME | C2 over HTTP, MIME mismatch |
| `files.log` | File transfers | Payload/exfiltration detection |

**Reference:** https://docs.zeek.org/en/master/logs/index.html

---

## RITA (Real Intelligence Threat Analytics)

**Purpose:** Open-source threat hunting framework by Active Countermeasures. Statistically analyzes Zeek logs to detect C2 beaconing, DNS tunneling, long connections, and data exfiltration.

**Why used here:** RITA's beacon detection algorithm analyzes inter-arrival times (IAT) between connections and computes a beacon score based on periodicity, jitter (skew), and dispersion. This identifies automated malware callbacks that rule-based tools miss.

**Key Commands:**
```bash
# Import Zeek logs into a named dataset
rita import --logs <zeek_log_dir> --database <dataset_name>

# Launch interactive TUI viewer
rita view <dataset_name>
```

**TUI Search Syntax:**

| Filter | Syntax | Example |
|--------|--------|----------|
| Destination host/domain | `dst:<value>` | `dst:malhare.net` |
| Source IP | `src:<value>` | `src:10.0.0.13` |
| Beacon score threshold | `beacon:><value>` | `beacon:>70` |
| Sort by duration descending | `sort:duration-desc` | — |
| Combined filter | `dst:x beacon:>70 sort:duration-desc` | — |
| Show search help | `?` (while in search mode) | — |
| Clear filter | `Ctrl+X` | — |

**Threat Modifiers Explained:**

| Modifier | What it Detects |
|----------|-----------------|
| **Prevalence** | % of internal hosts contacting destination (low = suspicious) |
| **First Seen** | How recently the destination first appeared on the network |
| **Rare Signature** | Uncommon TLS/SSL patterns or user agent strings |
| **MIME Mismatch** | HTTP content type doesn't match URI |
| **Missing Host Header** | HTTP requests without Host header (common in malware) |
| **Large Outgoing Data** | High outbound byte volume (exfiltration indicator) |
| **No Direct Connections** | Hidden/proxied communication path |

**Reference:** https://www.activecountermeasures.com/free-tools/rita/

---

## VirusTotal

**Purpose:** Online threat intelligence aggregator. Cross-references IPs, domains, URLs, and file hashes against 70+ security vendor databases.

**Why used here:** Validate discovered IOCs (IPs and domains from RITA output) against known threat intelligence to confirm malicious classification.

**Usage:** https://www.virustotal.com — search for IP or domain directly.

**What to check:**
- Detection ratio (X/70+ vendors flagging as malicious)
- Community comments and tags
- WHOIS and passive DNS for infrastructure pivoting
- Relations tab for connected domains/IPs
