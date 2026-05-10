# TryHackMe — Compiled

> **Category:** Reverse Engineering | **Difficulty:** Easy | **Date:** 2026-05-10
> **Room:** [https://tryhackme.com/room/compiled](https://tryhackme.com/room/compiled)

---

## Introduction

This is a beginner reverse engineering challenge. We are given a compiled Linux binary with no source code. Our goal is to figure out the correct password by analyzing the binary using static and dynamic tools — without ever seeing the original C code.

This writeup is designed so anyone can follow along step by step, even if it's their first time doing reverse engineering.

---

## Environment

- **OS:** Kali Linux (x86-64)
- **Tools:** `file`, `strings`, `objdump`, `gdb`
- **Binary:** `Compiled` (download from the THM room)

---

## Step 1 — What Kind of File Is This?

Before running anything, we always identify the binary type. This tells us what tools to use.

```bash
file Compiled
```

**Output:**
```
Compiled: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
for GNU/Linux 3.2.0, not stripped
```

**What this tells us:**
| Field | Value | Meaning |
|-------|-------|---------|
| Format | ELF 64-bit | Standard Linux executable |
| Architecture | x86-64 | 64-bit Intel/AMD CPU |
| PIE | Yes | Addresses randomize each run (ASLR) |
| Stripped | No | Function names kept → easier to reverse |

> ⚠️ **Linux is case-sensitive.** The file is named `Compiled` (capital C). Running `file compiled` will fail with "No such file or directory".

---

## Step 2 — Extract Readable Strings

Compiled binaries often contain leftover human-readable text: passwords, prompts, error messages, format strings. The `strings` command extracts all of them.

```bash
strings Compiled | grep -E "init|CTF|dso|pass|try|correct"
```

**Output:**
```
DoYouEven%sCTF
__dso_handle
_init
```

**Analyzing what we found:**

- `DoYouEven%sCTF` — This is a **scanf format string**. The `%s` means it reads a string from our input. This is the key to the challenge.
- `__dso_handle` — An ELF loader symbol. The binary uses this as a **strcmp trap** (a fake target to trick brute-forcers).
- `_init` — A short string. This is likely the **real password target** compared by `strcmp`.

---

## Step 3 — Understanding the scanf Format String

This is the core trick of the challenge. Let's break it down.

The binary calls:
```c
scanf("DoYouEven%sCTF", buffer);
```

How `scanf` parses our input:
```
Format string:   D o Y o u E v e n  %s  C T F
Our input:       D o Y o u E v e n  _init
                 ^^^^^^^^^^^^^^^^^ ^^^^^
                 Literal match      Captured into buffer
```

- `scanf` matches the literal prefix `DoYouEven` first.
- Then `%s` captures everything until whitespace (Enter key = `\n`) into `buffer[]`.
- The trailing `CTF` in the format is **never reached** because `%s` already consumed the rest.
- So `buffer` contains **only** `_init` — not `_initCTF`.

**This is why `DoYouEven_initCTF` fails:**
```
Input:   DoYouEven_initCTF
Buffer:            _initCTF   ← strcmp("_initCTF", "_init") = FAIL
```

**And why `DoYouEven_init` works:**
```
Input:   DoYouEven_init
Buffer:            _init      ← strcmp("_init", "_init") = WIN
```

---

## Step 4 — Confirm With Disassembly (objdump)

We can prove the logic by reading the actual assembly code.

```bash
objdump -d Compiled | grep -A40 -B5 "<main>:"
```

**Key lines from the output:**
```asm
11b6: lea -0x20(%rbp),%rax    ; buffer location = rbp-0x20
11cc: call __isoc99_scanf     ; reads our input into buffer
11d5: lea 0xe42(%rip),%rdx    ; loads compare string #1
11e2: call strcmp             ; strcmp(buffer, "__dso_handle") — trap!
11e9: js 1205                 ; if result < 0 → jump to fail
11eb: lea -0x20(%rbp),%rax    ; reload buffer
11f6: call strcmp             ; strcmp(buffer, "_init") — real check
1203: jle 124b                ; if result <= 0 → Correct!
```

**Assembly flow diagram:**
```
[scanf] → buffer
    ↓
[strcmp #1: buffer vs __dso_handle]
    ↓ result < 0?
   YES → Try again!
    ↓ NO
[strcmp #2: buffer vs _init]
    ↓ result <= 0?
   YES → Correct!
    ↓ NO
        → Try again!
```

> 💡 **PIE Note:** The addresses above are relative (from objdump). In GDB with a live process, addresses are randomized by ASLR. Use `b *main+offset` format or disable ASLR with `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`.

---

## Step 5 — Test Different Inputs

Let's verify our understanding:

```bash
./Compiled
```

| Input | Buffer captured | Result |
|-------|----------------|--------|
| `DoYouEven_init` | `_init` | ✅ Correct! |
| `DoYouEven_initCTF` | `_initCTF` | ❌ Try again! |
| `DoYouEven__dso_handleCTF` | `__dso_handle` | ❌ Try again! (trap) |
| `randomtext` | scanf mismatch | ❌ Try again! |
| `DoYouEven_init CTF` | `_init` | ✅ Correct! (space stops %s) |

---

## Solution

```bash
./Compiled
Password: DoYouEven_init
# → Correct!
```

---

## Key Takeaways

1. **Always `file` first** — Know your binary before touching it.
2. **`strings` wins easy RE** — 80% of beginner challenges leak the answer.
3. **`%s` in scanf stops at whitespace** — The buffer only holds the middle part, never the trailing literal.
4. **`__dso_handle` is a red herring** — Common ELF symbol used as a trap.
5. **`not stripped` = easier RE** — Function names like `main`, `strcmp` stay visible.
6. **PIE ≠ protection against static RE** — `objdump` ignores ASLR, reads the binary directly.

---

## MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|-----------|----|-----------|
| Obfuscated Files or Information | T1027 | Format string hides password logic |
| Deobfuscate / Decode Files | T1140 | strings + objdump recovers logic |

---

## Detection Opportunity (Blue Team)

If this binary were malware:
- **Sysmon Event ID 1** — Process creation: unexpected binary execution
- **Sysmon Event ID 7** — Image load: `libthread_db.so.1` (debugger detected)
- **Sigma rule:** Alert on ELF binaries calling `scanf` + `strcmp` with hardcoded format strings

---

*Writeup by [KuRo0x](https://github.com/KuRo0x) — TryHackMe CTF Series*
