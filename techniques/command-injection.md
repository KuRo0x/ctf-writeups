# Command Injection

## Description
Command injection occurs when an attacker is able to execute arbitrary OS commands on the server by injecting them through vulnerable input fields.

---

## 💥 Example Payloads

```bash
; ls -la
| whoami
&& cat /etc/passwd
`id`
$(id)
```

---

## 🗺️ MITRE ATT&CK

| Technique | ID |
|-----------|----|
| Command & Scripting Interpreter | T1059 |
| Exploit Public-Facing Application | T1190 |

---

## 🔵 Detection

- Monitor for abnormal process spawning from web services
- Alert on shell commands executed by web server processes
- Detect use of `whoami`, `id`, `cat /etc/passwd` from web processes

---

## 🛡️ Prevention

- Never pass user input directly to OS commands
- Use allowlists for accepted input values
- Implement proper input validation
