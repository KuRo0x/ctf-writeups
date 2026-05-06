# Room: Introduction to EDR

| Field | Value |
|-------|-------|
| **Platform** | TryHackMe |
| **Difficulty** | Easy |
| **Category** | Blue Team / SOC / Endpoint Security |
| **Room URL** | https://tryhackme.com/room/introductiontoedrs |
| **Completed** | 2026-05-06 |

---

## 🎯 Objective

Understand how Endpoint Detection and Response (EDR) solutions work, how they differ from traditional antivirus, and how a SOC analyst uses an EDR console to triage and investigate realistic endpoint detections.

---

## 📖 Key Concepts Learned

### EDR vs Antivirus

| Feature | Antivirus (AV) | EDR |
|---------|---------------|-----|
| Detection Method | Signature-based | Behavioral + Signature + ML |
| Visibility | File-level only | Full process tree, network, registry, CLI |
| Threat Coverage | Known threats only | Known + Unknown + Fileless |
| Response | Quarantine/Delete | Isolate, Terminate, Quarantine, Remote Shell |
| Context | Minimal | Full attack chain timeline |
| False Negative Risk | High (advanced threats) | Low (behavioral analysis) |

**Analogy:** AV = immigration check at airport (checks passports against known criminals). EDR = security officers inside the airport (monitors behavior continuously).

---

### EDR Architecture

```
[Endpoint] --> [EDR Agent/Sensor] --> [EDR Console (Cloud/On-Prem)]
                   |                         |
           Collects Telemetry         Correlates + Analyzes
           Sends Alerts               ML + Threat Intel
                                      Triggers Detections
```

- **EDR Agent (Sensor):** Installed on each endpoint; collects all telemetry and sends it to the console in real time
- **EDR Console:** Central brain; correlates data, applies ML algorithms, matches IOCs, and generates alerts

---

### Telemetry Types Collected

| Telemetry | What It Detects |
|-----------|----------------|
| **Process Executions** | Suspicious parent-child relationships, malware payloads |
| **Network Connections** | C2 communications, data exfiltration, lateral movement |
| **Command Line Activity** | Obfuscated PowerShell, malicious commands |
| **File/Folder Modifications** | Malicious file dropping, ransomware, data staging |
| **Registry Modifications** | Persistence mechanisms, configuration tampering |

---

### Detection Techniques

| Technique | How It Works | Example |
|-----------|-------------|--------|
| **Behavioral Detection** | Observes complete behavior, not just signatures | `winword.exe` spawning `powershell.exe` flagged as unusual parent-child |
| **Anomaly Detection** | Detects deviation from baseline behavior | Process modifies auto-start registry key (not normal for that endpoint) |
| **IOC Matching** | Matches activity against threat intel feeds | File hash matches known malware in threat intel feed |
| **MITRE ATT&CK Mapping** | Maps detections to tactics/techniques | Scheduled task creation → Persistence / T1053 |
| **Machine Learning** | Identifies complex multi-step attack patterns | Fileless attacks, multi-staged intrusions |

---

### Response Capabilities

| Action | Use Case |
|--------|----------|
| **Isolate Host** | Contains active malware before lateral movement spreads |
| **Terminate Process** | Stops malicious process without full host isolation |
| **Quarantine File** | Moves malicious file to isolated location for review |
| **Remote Shell Access** | Deep investigation or custom remediation (e.g., CrowdStrike RTR) |
| **Artefact Collection** | Extracts memory dumps, event logs, registry hives for forensics |

---

## 🔍 Attack Scenario Analysis

**Scenario:** Phishing email → Malicious macro → PowerShell → Payload download → Process injection → C2 access

```
Step 1: Phishing email with Word doc (malicious macro)
Step 2: User opens document
Step 3: Macro silently spawns PowerShell  <-- EDR flags unusual parent-child (winword.exe > powershell.exe)
Step 4: Obfuscated PowerShell downloads second-stage payload  <-- EDR flags obfuscated script
Step 5: Payload injected into svchost.exe  <-- EDR detects process injection
Step 6: Attacker gains remote access via svchost.exe C2 beacon  <-- EDR flags unexpected outbound connection
```

**AV result:** May mark as clean (no signature match)
**EDR result:** Full alert with attack chain, MITRE mapping, analyst response options

---

## 🖥️ EDR Triage — Practical Investigation (Task 7)

### Triage Methodology

For every alert in the EDR console, I followed this structured approach:

1. **Identify the hostname and alert severity**
2. **Open the process tree** — trace parent → child relationships
3. **Inspect command-line arguments** — look for obfuscation, download cradles, suspicious flags
4. **Check network connections** — identify C2, exfiltration attempts
5. **Review Threat Intel labels** — hash reputation, known malware families
6. **Map to MITRE ATT&CK** — identify the tactic and technique

### Investigated Endpoints

| Endpoint | Detection Type | Key Finding |
|----------|---------------|-------------|
| `DESKTOP-HR01` | Payload Download via CMD | Tool launched by CMD.exe to download payload; saved to specific local path |
| `WIN-ENG-LAPTOP03` | Credential Dumping + Exfiltration | Suspicious `syncsvc.exe` path; outbound exfiltration URL identified |
| `DESKTOP-DEV01` | Threat Intel Match | `UpdateAgent.exe` labelled by Threat Intel feed |

---

## 🗺️ MITRE ATT&CK Mapping

| Technique | ID | Observed In Scenario |
|-----------|----|---------------------|
| Phishing: Spearphishing Attachment | T1566.001 | Initial Word doc delivery |
| Command & Scripting Interpreter: PowerShell | T1059.001 | Macro spawning PowerShell |
| Obfuscated Files or Information | T1027 | Encoded PowerShell command |
| Ingress Tool Transfer | T1105 | Payload download from remote server |
| Process Injection | T1055 | Payload injected into `svchost.exe` |
| Command and Control | TA0011 | `svchost.exe` making outbound C2 connection |
| Scheduled Task/Job | T1053 | Persistence via scheduled task example |
| OS Credential Dumping | T1003 | LSASS memory access on WIN-ENG-LAPTOP03 |
| Exfiltration Over C2 Channel | T1041 | Exfiltration attempt on WIN-ENG-LAPTOP03 |

---

## 🔵 Detection Opportunities

- **Alert on unusual parent-child process relationships** — e.g., `winword.exe` or `excel.exe` spawning `powershell.exe`, `cmd.exe`, or `wscript.exe`
- **Flag obfuscated PowerShell** — detect `-EncodedCommand`, `-Enc`, `downloadstring`, `IEX`, `bypass` in CLI arguments
- **Monitor LSASS access** — alert on any process (other than known tools) accessing `lsass.exe` memory
- **Detect process injection** — unusual `svchost.exe` instances not spawned by `services.exe`
- **Baseline network behavior** — alert on `svchost.exe` making unexpected outbound connections
- **Hash reputation checks** — integrate threat intel feed for automated IOC matching on newly executed binaries
- **Registry monitoring** — alert on modifications to auto-start registry keys (HKCU/HKLM Run)

> 💡 All of the above can be implemented as **Sigma rules** in your ELK/SOC Detection Lab using Winlogbeat + Sysmon event logs.

---

## 🛠️ Tools Referenced

- CrowdStrike Falcon EDR (demonstrated in room)
- SentinelOne ActiveEDR
- Microsoft Defender for Endpoint
- OpenEDR
- Sysmon (endpoint telemetry — used in personal SOC lab)
- ELK Stack (SIEM integration)

---

## 📚 Lessons Learned

- **EDR is not a replacement for SIEM** — it is host-only and does not detect network-level threats. Both must work together in a SOC ecosystem.
- **Context is everything** — EDR's biggest advantage over AV is providing the full attack chain timeline. A single suspicious event may seem harmless; the full chain reveals the attack.
- **Behavioral detection beats signatures** — advanced attackers craft malware to look clean and abuse legitimate tools (LOLBins). Behavioral analysis catches this.
- **MITRE ATT&CK mapping accelerates triage** — when an EDR maps a detection to a technique, you immediately know what the attacker was attempting without starting from scratch.
- **EDR agents = my Winlogbeat/Sysmon setup** — understanding EDR architecture confirmed that my home lab setup mirrors real EDR telemetry collection pipelines.
