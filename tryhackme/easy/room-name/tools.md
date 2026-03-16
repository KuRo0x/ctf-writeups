# Tools Used — ROOM-NAME

| Tool | Purpose |
|------|---------|
| Nmap | Port scanning and service detection |
| Gobuster | Directory enumeration |
| Burp Suite | Web proxy and request manipulation |
| LinPEAS | Privilege escalation enumeration |

## Commands Reference

```bash
# Nmap
nmap -sC -sV <TARGET-IP>

# Gobuster
gobuster dir -u http://<TARGET-IP> -w /usr/share/wordlists/dirb/common.txt

# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```
