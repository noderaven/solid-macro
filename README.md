# solid-macro

VBA macro chain demonstrating modern EDR-evasion techniques, originally
authored during OSCP study and modernized in v2 for the Windows 11 24H2 /
Microsoft Defender for Endpoint era.

> **Educational artifact, not a weapon.** v2 is a polished sketch of a
> credible OSEP-grade chain. The repo does not ship working shellcode; you
> supply your own. The detection profile is documented honestly in
> [docs/threat-model.md](docs/threat-model.md) -- a tuned MDE will catch
> the chain, and that is expected.

## Status

- **v2** is the current head of `main`. Modular VBA (9 source files plus a
  generated `Payload.bas`), Python build tooling, ISO + LNK delivery
  wrappers, CI on every push.
- **v1** is preserved at git tag `v1`. See [docs/history.md](docs/history.md)
  for the v1 narrative and review findings (the v1 file had a number of
  bugs that prevented it from compiling or running -- the rewrite was a
  clean break, not a refactor).

## What the chain does

When the assembled `.docm` is opened in Word with macros enabled, `AutoOpen`
fires and walks an eight-phase pipeline:

```
Phase 0  AMSI scans macro source           pre-runtime; defeated by source obfuscation
Phase 1  AutoOpen + ValidateEnvironment    sandbox/uptime/domain keying
Phase 2  Engine bootstrap                  DispCallFunc resolved; RW page allocated
Phase 3  ResolveSyscalls                   map \KnownDlls\ntdll.dll; build SSN table
Phase 4  Sensor blinding                   HWBP AMSI bypass + TEB ETW zero
Phase 5  Payload decryption                AES-256-CTR in pure VBA
Phase 6  Injection                         dllhost-spoofed PPID + EarlyBird APC
Phase 7  Schedule Cleanup                  Application.OnTime Now + 2s
Phase 8  Cleanup (deferred)                best-effort VBProject self-erase
```

Each technique is covered in detail in
[docs/techniques.md](docs/techniques.md). The phase boundaries are
intentional: each phase returns a status, a failure bails the chain cleanly,
and `Debug.bas` provides phase-by-phase telemetry via `OutputDebugStringA`
for lab walkthroughs.

## Repo layout

```
macro/
  Strings.bas        MkStr / MkAStr / HexToBytes (no flat sensitive literals)
  Structs.bas        PE, NT, CONTEXT64, exception, Toolhelp32 types
  Engine.bas         DispCallFunc shim, RWX hygiene, Call0..Call12
  Aes.bas            AES-256-CTR (mirror of payload/aes.py)
  Syscalls.bas       HellsGate SSN extraction; SysCall0..SysCall12
  Evasion.bas        HWBP AMSI bypass via VEH; TEB.EtwTraceData zero
  Injection.bas      PPID-spoofed CreateProcessW; NtAllocate/Write/Protect/Queue/Resume
  SolidMacro.bas     AutoOpen, RunExploit, ValidateEnvironment, Cleanup
  Debug.bas          DbgPrint / DbgAssert gated by DEBUG_ENABLED
  build/
    assemble.py      glues .bas files into a .docm-ready VBA project

payload/
  aes.py             pure-Python AES-256-CTR (no third-party deps)
  build.py           CLI: shellcode.bin -> macro/Payload.bas
  __init__.py

delivery/
  lnk/build_lnk.py   pure-Python MS-SHLLINK builder
  iso/build_iso.py   pycdlib-based ISO 9660 + Joliet builder
  xll/README.md      future-work placeholder for the native twin

tests/                 pytest covering all Python tooling (43 tests)
docs/
  README files plus techniques / threat-model / delivery / development /
  history and the superpowers/ design spec + implementation plan.

.github/workflows/ci.yml   pytest + assemble --check on push/PR
```

## Quickstart

```bash
# 1. Generate Payload.bas from your shellcode (encrypted with AES-256-CTR)
python payload/build.py path/to/shellcode.bin --out macro/Payload.bas

# 2. Static-check the assembled VBA project
python macro/build/assemble.py --check

# 3. Assemble the module set ready for Word VBA editor import
python macro/build/assemble.py
# Wrote macro/build/dist/Strings.bas
# Wrote macro/build/dist/Structs.bas
# ... (10 files total)

# 4. (Optional) bundle for delivery past Mark-of-the-Web
python delivery/lnk/build_lnk.py --target "data\\report.docm" --out report.lnk
python delivery/iso/build_iso.py report.lnk data/report.docm --out report.iso
```

`assemble.py --flatten` produces one combined `Module1.bas` if you prefer a
single-paste workflow over module-by-module import.

If `python` isn't on your PATH, use `python3` -- everything in this repo
targets Python 3.10+.

## Testing

Python side runs automatically via pytest:

```bash
pip install pytest pycdlib==1.14.0
python -m pytest tests/ -v
```

Expected: 43 tests pass.

- `test_aes.py` pins the AES-256-CTR implementation to NIST FIPS 197 (single
  block KAT) and NIST SP 800-38A Section F.5.5 (4-block CTR KAT). The VBA
  twin (`Aes.bas`) is built to mirror this byte-for-byte; if the Word-side
  decryption produces wrong output, the bug is in `Aes.bas` because Python
  is pinned to the standard.
- `test_assemble.py` covers the static-check rules: balanced `Sub/Function`,
  no orphan line continuations, no flat sensitive API name literals.
- `test_build.py` round-trips `payload/build.py` output through the regex
  parser and back through AES.
- `test_lnk.py` and `test_iso.py` byte-parse the emitted LNK and ISO files
  to confirm the on-disk layout matches what Windows expects.

GitHub Actions runs this matrix across Python 3.10 / 3.11 / 3.12 on every
push and pull request -- see [.github/workflows/ci.yml](.github/workflows/ci.yml).

VBA side requires a lab VM. See
[docs/development.md](docs/development.md) for the manual workflow:
import to Word VBA editor, `Debug > Compile VBAProject`, then walk the
phase telemetry via DebugView with the `winword.exe` filter.

## Scope and limitations

This is an OSEP-grade study artifact. Every technique it uses is publicly
documented -- HellsGate is from late 2020, hardware-breakpoint AMSI bypass
is well-known since 2022, PPID spoofing via `UpdateProcThreadAttribute` has
been public since 2011. Detection rules for the combination exist in
publicly-shipped YARA / Sigma / EDR-vendor signature feeds.

The [threat model](docs/threat-model.md) lays out exactly what each
technique beats and what catches it. A representative summary:

| Stage | Beats | Caught by |
|---|---|---|
| HellsGate indirect syscalls | NTDLL user-mode hooks | MDE "syscall from non-image-backed memory" (~2024) |
| HWBP AMSI bypass | byte-patch scans on amsi.dll | VEH installation + DR0/DR7 mutation from Office |
| PPID spoof | forward process-tree heuristics | kernel callback comparing creator PID to attribute PID |
| EarlyBird APC | user-mode hook racing | cross-process write + QueueUserAPC kernel callback |
| ISO-wrapped LNK delivery | default Mark-of-the-Web | `BlockDownloadsOfAllSamples` GPO, OOXMLFileSandboxAttachments |

If you are looking for a production-grade red-team tool, this is not it. If
you are studying for OSEP or want to understand how a modern Office-macro
evasion chain is actually built, the code is here and the rationale is
documented.

## Build / run requirements

- Python 3.10+
- `pip install pytest pycdlib==1.14.0` for the test suite
- Lab VM with x64 Windows 11 24H2 + x64 Microsoft Office 2016+ for the
  manual VBA verification path

There are no third-party Python dependencies in the *core* build path
(`payload/aes.py` is pure standard library). `pycdlib` is only used by the
ISO delivery wrapper; `pytest` is dev-only.

## Documentation

| File | Purpose |
|---|---|
| [README.md](README.md) | this file |
| [CHANGELOG.md](CHANGELOG.md) | v1 -> v2 entry |
| [docs/techniques.md](docs/techniques.md) | per-stage technique deep-dive |
| [docs/threat-model.md](docs/threat-model.md) | honest detection profile |
| [docs/delivery.md](docs/delivery.md) | MotW story, ISO/LNK reasoning |
| [docs/development.md](docs/development.md) | build, test, lab workflow |
| [docs/history.md](docs/history.md) | v1 review findings, v2 narrative |
| [docs/superpowers/specs/2026-06-24-solid-macro-modernization-design.md](docs/superpowers/specs/2026-06-24-solid-macro-modernization-design.md) | v2 design spec |
| [docs/superpowers/plans/2026-06-24-solid-macro-v2.md](docs/superpowers/plans/2026-06-24-solid-macro-v2.md) | v2 implementation plan |

## Authorization and use

Use of these techniques is appropriate only with explicit authorization in
contexts such as authorized penetration testing engagements, CTF
competitions, educational study (e.g. OSEP / PEN-300 coursework), and
defensive security research. Do not deploy this against systems you do not
own or do not have written permission to test.

## License

MIT. See [LICENSE](LICENSE).

## Author

[noderaven](https://github.com/noderaven). Contributions accepted via PR --
keep them ASCII-only (no em-dashes / curly quotes / emoji) per repo
convention; commits should be attributable to a single person.
