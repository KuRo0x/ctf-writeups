# Privilege Escalation Techniques

## Description
Privilege escalation is the act of exploiting a bug, design flaw, or configuration oversight to gain elevated access to resources that are normally protected.

---

## 🔍 Common Vectors

### SUID Binaries
```bash
find / -perm -4000 -type f 2>/dev/null
```

### Sudo Misconfigurations
```bash
sudo -l
```

### Cron Jobs
```bash
cat /etc/crontab
ls -la /etc/cron*
```

### Writable /etc/passwd
```bash
ls -la /etc/passwd
```

---

## 🗺️ MITRE ATT&CK

| Tactic | ID |
|--------|----|
| Privilege Escalation | TA0004 |
| Abuse Elevation Control Mechanism | T1548 |

---

## 🔵 Detection

- Monitor for abnormal SUID binary executions
- Alert on `sudo -l` from non-admin users
- Detect modifications to `/etc/passwd` or `/etc/crontab`

---

## 🛡️ Prevention

- Apply least privilege principle
- Audit SUID binaries regularly
- Restrict sudo permissions
