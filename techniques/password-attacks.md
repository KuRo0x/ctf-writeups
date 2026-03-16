# Password Attacks

## Description
Password attacks involve attempts to obtain, crack, or bypass passwords using various techniques including brute force, dictionary attacks, and credential stuffing.

---

## 🔍 Common Techniques

### Brute Force
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<TARGET-IP>
```

### Hash Cracking
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

---

## 🗺️ MITRE ATT&CK

| Technique | ID |
|-----------|----|
| Brute Force | T1110 |
| Credential Dumping | T1003 |

---

## 🔵 Detection

- Alert on multiple failed authentication attempts
- Monitor for login attempts from unusual IPs
- Detect abnormal credential access patterns

---

## 🛡️ Prevention

- Enforce strong password policies
- Enable multi-factor authentication (MFA)
- Implement account lockout policies
