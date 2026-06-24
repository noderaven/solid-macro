# Changelog

## v2 (in progress)

Major rewrite. The v1 single-file artifact had multiple critical bugs that
prevented compilation and runtime execution (see `docs/history.md`); v2 is a
clean break.

Highlights:

- Modular VBA: nine `.bas` files under `macro/`, glued by `macro/build/assemble.py`.
- HellsGate-style indirect syscalls via `\KnownDlls\ntdll.dll`.
- Hardware-breakpoint AMSI bypass via VEH (no in-process patching of amsi.dll).
- TEB.EtwTraceData zeroed per-thread.
- PPID-spoofed EarlyBird APC into a `dllhost.exe` child (replaces v1's
  `werfault.exe` target).
- Real AES-256-CTR payload encryption (`payload/aes.py` + `macro/Aes.bas`).
- ISO and LNK delivery wrappers under `delivery/`.
- Pytest coverage for all Python tooling; NIST KAT vectors pin AES.
- Honest detection-profile documentation in `docs/threat-model.md`.

Breaking changes (relative to v1):

- v1 artifact removed from `main`; preserved at git tag `v1`.
- No backwards-compatible code path.
- New repo layout under `macro/`, `payload/`, `delivery/`, `tests/`, `docs/`.

## v1

Original OSCP-era single-file VBA. See git tag `v1` and `docs/history.md`.
