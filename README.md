# solid-macro

VBA macro chain demonstrating modern EDR-evasion techniques, originally
authored during OSCP study and modernized in v2 for the Windows 11 24H2 /
Microsoft Defender for Endpoint era.

## Status

- **v2** is the current head of `main`. Modular VBA, Python build tooling,
  ISO/LNK delivery wrappers, indirect syscalls, hardware-breakpoint AMSI
  bypass, PPID-spoofed EarlyBird APC.
- **v1** is preserved at git tag `v1`. See `docs/history.md` for the v1
  narrative and review findings.

## Quickstart

```
# Encrypt your shellcode
python payload/build.py path/to/shellcode.bin --out macro/Payload.bas

# Assemble the macro source
python macro/build/assemble.py

# Import macro/build/dist/*.bas into Word's VBA editor and save as .docm

# (Optional) bundle for delivery past Mark-of-the-Web
python delivery/lnk/build_lnk.py --target "data\\report.docm" --out report.lnk
python delivery/iso/build_iso.py report.lnk data/report.docm --out report.iso
```

See [docs/development.md](docs/development.md) for the full build / test
workflow.

## Scope

This is an educational artifact. It uses techniques that are publicly
documented and detected to some degree by every modern EDR. The
[threat model](docs/threat-model.md) documents exactly what each technique
beats and what catches it. A tuned MDE will catch the chain; that is
expected and documented.

If you are looking for a production-grade red-team tool, this is not it.
If you are studying for OSEP or want to understand how modern Office-macro
evasion is built, this should be useful.

## Repo layout

```
macro/         <- VBA source modules (.bas) + build glue
payload/       <- shellcode encryption (Python AES-256-CTR)
delivery/      <- ISO and LNK delivery wrappers
tests/         <- pytest covering the Python tooling
docs/          <- techniques, threat model, delivery, development, history
```

## License

MIT. See `LICENSE`.

## Author

[noderaven](https://github.com/noderaven). Contributions accepted via PR --
keep them ASCII-only (no em-dashes / curly quotes / emoji) per repo
convention.
