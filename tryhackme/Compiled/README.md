# TryHackMe: Compiled
**Category:** Reverse Engineering | **Difficulty:** Easy | **Date:** 2026-05-10  
**Platform:** TryHackMe | **Room:** [Compiled](https://tryhackme.com/room/compiled)

---

## Tools Used
| Tool | Purpose |
|------|---------|
| `file` | Binary type identification |
| `strings` | Extract readable text from binary |
| `objdump` | Disassemble binary (assembly view) |
| `gdb` | Dynamic debugger |

---

## Methodology

### Step 1 — Identify Binary
```bash
file Compiled
# Compiled: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```
**Key info:** 64-bit Linux ELF, PIE enabled (ASLR), **not stripped** (symbols kept = easier RE).

---

### Step 2 — Extract Strings
```bash
strings Compiled | grep -E "init|CTF|dso|pass|try|correct"
```
**Output:**
```
DoYouEven%sCTF   ← scanf format string (KEY!)
__dso_handle     ← strcmp trap (red herring)
_init            ← real password target
```

---

### Step 3 — Understand scanf Format Logic
```
Format:  DoYouEven  %s        CTF
Input:   DoYouEven  _init     (CTF optional)
Buffer:             _init     ← ONLY this gets stored
```
`scanf("DoYouEven%sCTF", buffer)` captures ONLY the `%s` middle part into buffer.  
Buffer is then compared via `strcmp` — NOT the full input string.

---

### Step 4 — Disassembly Proof (objdump)
```bash
objdump -d Compiled | grep -A40 "<main>:"
```
**Key addresses:**
```asm
0x11cc: call scanf        ; buffer stored @ rbp-0x20
0x11e2: call strcmp       ; buffer vs __dso_handle (trap)
0x11e9: js 0x1205         ; <0 → fail
0x11fc: call strcmp       ; buffer vs _init (WIN)
0x1203: jle 0x124b        ; <=0 → Correct!
```

---

### Step 5 — Test Inputs
| Input | Buffer captured | Result |
|-------|----------------|--------|
| `DoYouEven_init` | `_init` | ✅ Correct! |
| `DoYouEven_initCTF` | `_initCTF` | ❌ Try again! |
| `DoYouEven__dso_handleCTF` | `__dso_handle` | ❌ Try again! |
| `randomtext` | scanf mismatch | ❌ Try again! |

---

## Solution
```bash
./Compiled
Password: DoYouEven_init
# → Correct!
```

---

## Key Lesson
> `scanf("DoYouEven%sCTF", buf)` → `buf = "_init"` not `"_initCTF"`  
> The prefix/suffix in the format string are **literal matchers**, not stored. Only `%s` fills the buffer.

---

## MITRE ATT&CK
- **T1027** — Obfuscated Files or Information (format string obfuscation)
- **T1140** — Deobfuscate/Decode Files or Information
