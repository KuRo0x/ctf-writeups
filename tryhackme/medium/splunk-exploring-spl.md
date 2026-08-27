# Splunk: Exploring SPL

**Platform:** TryHackMe  
**Room:** [Splunk: Exploring SPL](https://tryhackme.com/room/splunkexploringspl)  
**Difficulty:** Medium  
**Category:** SIEM / Blue Team / SOC  
**Completed:** 2026-08-27  
**Status:** ✅ Completed

---

## Overview

This room covers Splunk's Search Processing Language (SPL) from the ground up — filters, structuring, transformational commands, and anomaly detection. Index used throughout: `windowslogs` and `vpnlogs`.

---

## Task 1 – Introduction

> No questions. Lab machine started, VPN connected (OpenVPN, Europe Paris server, IP: 192.168.159.86).

---

## Task 2 – Search & Reporting App Overview

**Q1: How many total events does `index=windowslogs` return?**  
```spl
index=windowslogs
```
> **Answer: 12256**

**Q2: Which SourceIP has recorded the most events?**  
> Check the Fields Sidebar → SourceIP → Top values  
> **Answer: 172.90.12.11**

**Q3: How many events appear on 04/15/2022 from 08:05 AM to 08:06 AM?**  
> Use the Time Picker → Date time range → 04/15/2022 08:05:00 to 08:06:00  
> **Answer: 134**

---

## Task 3 – SPL Operators

**Q1: Events with EventID = 4624?**  
```spl
index=windowslogs EventID=4624
```
> **Answer: 26**

**Q2: Events with DestinationIp=172.18.39.6 AND DestinationPort=135?**  
```spl
index=windowslogs DestinationIp=172.18.39.6 DestinationPort=135
```
> **Answer: 4**

**Q3: Highest-count SourceIp for Salena.Adam query?**  
```spl
index=windowslogs Hostname=Salena.Adam DestinationIp=172.18.38.5
```
> **Answer: 172.90.12.11**

**Q4: Events returned by `cyber*`?**  
```spl
index=windowslogs cyber*
```
> **Answer: 12256**

**Q5: Which operator has the lowest priority?**  
> **Answer: AND**

---

## Task 4 – Filtering Commands

**Q1: Highest SourceProcessId using `fields` command?**  
```spl
index=windowslogs | fields Domain SourceProcessId TargetProcessId
```
> Check SourceProcessId values in results.

**Q2: TargetObject with highest count matching `Manager$`?**  
```spl
index=windowslogs | regex TargetObject="Manager$"
```
> Read top value from the TargetObject field.

---

## Task 5 – Structuring Results

**Q1: Which AccountName appears first?**  
```spl
index=windowslogs
| table EventID AccountName AccountType
```
> Read the first row.

**Q2: Which EventID appears first after `reverse`?**  
```spl
index=windowslogs
| table EventID AccountName AccountType
| reverse
```
> **Answer: 800**

**Q3: Password given to user A1berto?**  
```spl
index=windowslogs EventID=1
| table _time ParentProcessId ProcessId ParentCommandLine CommandLine
| reverse
```
> Search for `A1berto` in CommandLine column to find the password set.

---

## Task 6 – Structuring Results (head/tail/sort)

**Q1: Hostname on top after `reverse`?**  
```spl
index=windowslogs
| table _time EventID Hostname SourceName
| reverse
```
> **Answer: James.browne**

**Q2: Last EventID with `tail`?**  
```spl
index=windowslogs
| table _time EventID Hostname SourceName
| tail
```
> **Answer: 4103**

**Q3: Top SourceName after `sort`?**  
```spl
index=windowslogs
| table _time EventID Hostname SourceName
| sort SourceName
```
> **Answer: Microsoft-Windows-Directory-Services-SAM**

---

## Task 7 – Transformational Commands

**Q1: Image field value with most occurrences?**  
```spl
index=windowslogs
| top Image
```
> Read the first row.

**Q2: Which Region do SourceIp addresses originate from?**  
```spl
index=windowslogs
| iplocation SourceIp
| stats count by Region
| sort - count
```
> Read the top Region.

**Q3: Image with highest RiskScore?**  
```spl
index=windowslogs
| lookup image_riskscore Image OUTPUT RiskScore
| stats count by Image RiskScore
| sort - RiskScore
```
> **Answer: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe**

---

## Task 8 – Anomaly Detection

### Country-based outlier detection

```spl
index=vpnlogs
| eventstats count as logins_by_user by user
| eventstats count as logins_by_user_country by user src_country
| eval country_freq=logins_by_user_country/logins_by_user
| where country_freq < 0.1
| table _time user src_ip src_country country_freq
```

**Q1: Other outlier user (besides kbrown)?**  
> **Answer: jsmith**

**Q2: Anomalous country for jsmith?**  
> **Answer: JP**

### Hour-based outlier detection

```spl
index=vpnlogs
| eval hour=tonumber(strftime(_time, "%H")) + tonumber(strftime(_time, "%M"))/60
| eventstats avg(hour) as typical_hour stdev(hour) as stdev_hour by user
| eval zscore=abs(hour - typical_hour) / stdev_hour
| where zscore > 3
| eval hour=round(hour, 2), typical_hour=round(typical_hour, 2)
| eval stdev_hour=round(stdev_hour, 2), zscore=round(zscore, 2)
| table _time user src_ip src_country hour typical_hour stdev_hour zscore
| sort - zscore
```

**Q3: User who suspiciously logged in at 3 AM?**  
> **Answer: njackson**

---

## Key SPL Commands Learned

| Command | Purpose |
|---|---|
| `fields` | Include/exclude specific fields |
| `dedup` | Remove duplicate values |
| `rename` | Rename fields |
| `regex` | Filter using PCRE regex |
| `table` | Display selected fields in table format |
| `head` / `tail` | First / last N events |
| `sort` | Sort results by field |
| `reverse` | Reverse event order |
| `top` / `rare` | Most / least frequent values |
| `stats` | Aggregate statistics |
| `chart` / `timechart` | Visualizations |
| `iplocation` | Enrich IPs with geo data |
| `lookup` | Enrich with external CSV/table |
| `eval` | Create/modify fields with expressions |
| `eventstats` | Stats without collapsing raw events |
| `where` | Filter using expressions (more powerful than `search`) |

---

## MITRE ATT&CK Relevance

- **T1078** – Valid Accounts (logon anomaly detection via EventID 4624)
- **T1059.001** – PowerShell execution (Image = powershell.exe in top risk)
- **T1133** – External Remote Services (VPN login anomalies)

---

## Notes

- Always set the time range to **All time** when working with this dataset.
- The `AND` operator has lower priority than `OR` in SPL — use parentheses to control evaluation order.
- `eventstats` keeps raw events intact while adding aggregate fields; use it over `stats` when you need both the aggregated value and the original event.
- z-score anomaly detection is a powerful pattern for identifying outliers in user behavior (logins by hour, country frequency).
