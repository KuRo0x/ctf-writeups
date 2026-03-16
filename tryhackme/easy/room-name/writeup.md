# Room: ROOM-NAME

| Field | Value |
|-------|-------|
| **Platform** | TryHackMe |
| **Difficulty** | Easy |
| **Category** | Web / Privilege Escalation / Enumeration / Forensics / Crypto |

---

## 🎯 Objective

Brief description of the goal of the challenge.

---

## 🔍 Enumeration

```bash
nmap -sC -sV <TARGET-IP>
```

**Open Ports:**

| Port | State | Service |
|------|-------|---------|
| 22/tcp | open | ssh |
| 80/tcp | open | http |

**Web Enumeration:**

```bash
gobuster dir -u http://<TARGET-IP> -w /usr/share/wordlists/dirb/common.txt
```

Directories discovered:
- `/admin`
- `/login`

---

## 💥 Exploitation

Explain the vulnerability used to gain access.

**Example:** SQL Injection used on login page.

```sql
Payload: ' OR 1=1 --
```

Explain why the attack works.

---

## ⬆️ Privilege Escalation

Describe steps used to escalate privileges.

```bash
find / -perm -4000 -type f 2>/dev/null
```

Explain how the vulnerability allowed privilege escalation.

---

## 🚩 Flag

```
THM{example_flag}
```

---

## 🛠️ Tools Used

- Nmap
- Gobuster
- Burp Suite
- LinPEAS

---

## 🗺️ MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Exploit Public-Facing Application | T1190 |
| Command & Scripting Interpreter | T1059 |
| Privilege Escalation | TA0004 |

---

## 🔵 Detection Opportunities

- Monitor web logs for SQL injection patterns
- Detect repeated failed authentication attempts
- Monitor abnormal SUID binary executions

---

## 📚 Lessons Learned

Explain what security concepts were learned from this challenge.
