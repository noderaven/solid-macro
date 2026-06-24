# History

## v1 (preserved at git tag `v1`)

The original solid-macro was authored during OSCP study to demonstrate a
chain of evasion and injection techniques in a single VBA file. v1 is
preserved at git tag `v1` for reference; it was a sketch, not a working
artifact, and a code review surfaced multiple critical issues:

- `CallPointer` relied on `CreateObject("Thread")`, a COM ProgID that does
  not exist on any Windows install; the function short-circuited silently.
- Assembly-stream building used VBA `String` concatenation (UTF-16),
  producing `48 00 B9 00 ...` byte sequences instead of the intended x64
  opcodes.
- `Pack()` read 8 bytes from a `Variant` starting at offset 0 (capturing the
  VT type tag) instead of offset 8 (the value).
- `GetProcAddress` and `GetModuleHandleA` were called but not declared,
  preventing `Option Explicit` compilation.
- The "fresh" ntdll for unhooking was fetched via `LoadLibrary`, which on
  an already-loaded module returns the same hooked base address.
- `AES_Decrypt` was an XOR placeholder; the embedded ciphertext was a
  repeating decorative hex pattern, not real encrypted data.

## v2 (this rewrite)

v2 is a multi-file repo built around a modular VBA project, Python build
tooling, and ISO/LNK delivery wrappers. Technique selection is current to
mid-2026: HellsGate-style indirect syscalls, hardware-breakpoint AMSI
bypass, per-thread ETW kill, PPID-spoofed EarlyBird APC into a `dllhost.exe`
child.

The functional level is "polished sketch": the chain is end-to-end correct,
but the shellcode itself is user-supplied. The repo does not ship a
working weaponized artifact.

The detection profile is documented honestly in
[threat-model.md](threat-model.md): the chain will be caught by a tuned MDE
in 2026, and that is expected. The artifact's value is demonstrating
mastery of modern technique selection, not undetectability against a
defended target.

Design rationale: see `docs/superpowers/specs/2026-06-24-solid-macro-modernization-design.md`.
Implementation plan: see `docs/superpowers/plans/2026-06-24-solid-macro-v2.md`.
