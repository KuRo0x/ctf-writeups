# Gobuster

## Purpose
Directory and file brute-forcing tool used for web enumeration.

---

## ⚡ Common Commands

```bash
# Directory brute force
gobuster dir -u http://<TARGET-IP> -w /usr/share/wordlists/dirb/common.txt

# With file extensions
gobuster dir -u http://<TARGET-IP> -w /usr/share/wordlists/dirb/common.txt -x php,html,txt

# DNS subdomain enumeration
gobuster dns -d <TARGET-DOMAIN> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Output to file
gobuster dir -u http://<TARGET-IP> -w /usr/share/wordlists/dirb/common.txt -o output.txt
```

---

## 🎯 Used For

- Web directory enumeration
- Hidden file discovery
- DNS subdomain brute forcing

---

## 🗺️ MITRE ATT&CK

| Technique | ID |
|-----------|----|
| Web Service Scanning | T1595.003 |
