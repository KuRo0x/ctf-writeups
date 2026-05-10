# THM: Compiled — Reverse Engineering
**Category:** RE | **Difficulty:** Easy | **Date:** 2026-05-10

## Tools
file, strings, objdump, gdb

## Methodology
1. file Compiled → ELF 64-bit, not stripped, PIE
2. strings → DoYouEven%sCTF, _init, __dso_handle
3. scanf format captures %s middle only into buffer
4. objdump: scanf@0x11cc, strcmp#1@0x11e2, strcmp#2@0x11fc
5. Password: DoYouEven_init → Correct!

## Key Lesson
scanf("DoYouEven%sCTF", buf) → buf="_init" not "_initCTF"
