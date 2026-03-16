# SQL Injection

## Description
SQL Injection allows attackers to manipulate database queries through unsanitized user input, potentially leaking data or bypassing authentication.

---

## 💥 Example Payloads

```sql
' OR 1=1 --
' OR '1'='1
admin'--
' UNION SELECT null, username, password FROM users--
```

---

## 🗺️ MITRE ATT&CK

| Technique | ID |
|-----------|----|
| Exploit Public-Facing Application | T1190 |

---

## 🔵 Detection

- Monitor web server logs for suspicious query patterns (`'`, `--`, `OR 1=1`)
- Alert on unusual database error messages in HTTP responses
- Use a WAF to detect and block injection attempts

---

## 🛡️ Prevention

- Use parameterized queries / prepared statements
- Implement input validation and sanitization
- Deploy a Web Application Firewall (WAF)
