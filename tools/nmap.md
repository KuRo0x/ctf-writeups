# Nmap

## Purpose
Network scanning and service discovery tool used for port discovery, service detection, and basic vulnerability identification.

---

## ⚡ Common Commands

```bash
# Basic scan
nmap <TARGET-IP>

# Service and script scan
nmap -sC -sV <TARGET-IP>

# Full port scan
nmap -p- <TARGET-IP>

# Aggressive scan
nmap -A <TARGET-IP>

# OS detection
nmap -O <TARGET-IP>

# Output to file
nmap -sC -sV -oN scan.txt <TARGET-IP>
```

---

## 🎯 Used For

- Port discovery
- Service detection
- OS fingerprinting
- Basic vulnerability identification

---

## 🗺️ MITRE ATT&CK

| Technique | ID |
|-----------|----|
| Network Service Scanning | T1046 |
