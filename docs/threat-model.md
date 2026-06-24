# Threat model

Scope: v2 is an OSEP-grade study artifact. Every technique used is publicly
documented; YARA, Sigma, and behavioral detection rules exist for each. The
chain is designed to demonstrate understanding of modern evasion, not to
defeat a tuned Microsoft Defender for Endpoint deployment.

## Detection profile

| Stage | Beats | Caught by |
|---|---|---|
| Source-level obfuscation (`MkStr` byte-built names) | Static AMSI string-pattern signatures for known sensitive API names in macro source | Behavioral AMSI on VBA execution patterns; high-entropy literal heuristics |
| DispCallFunc dispatch (no static `Declare` for Nt*) | Static analysis identifying `Declare PtrSafe Function NtAllocateVirtualMemory` and friends in source | Behavioral hook on `DispCallFunc(0, ...)` from Office (rarely-used API combination) |
| HellsGate indirect syscalls via `\KnownDlls\ntdll.dll` | NTDLL user-mode hooks; file-system telemetry from reading ntdll.dll off disk | MDE "syscall instruction issued from non-image-backed memory" rule (added ~2024) |
| HWBP AMSI bypass | Static scans for byte-patches of `AmsiScanBuffer`; RWX hygiene checks on amsi.dll | VEH installation telemetry from Office; DR0+DR7 mutation pattern via `NtSetContextThread` |
| TEB.EtwTraceData zero | User-mode ETW providers consuming the per-thread `EtwTraceData` | ETW-Ti (kernel-mode); TEB scanning by kernel-resident agents |
| PPID spoof | Forward process-tree analysis from WINWORD.EXE | MDE kernel callback comparing creator PID to `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` value |
| EarlyBird APC | User-mode hook racing on the new thread's first wakeup | Cross-process `WriteProcessMemory` + `QueueUserAPC` kernel-callback combination |
| Delivery via ISO-wrapped LNK | Default Mark-of-the-Web on `.docm` downloaded from internet zone | `BlockDownloadsOfAllSamples` GPO; `OOXMLFileSandboxAttachments` Office policy; Smart App Control on Win11 22H2+ |

A determined, well-tuned MDE deployment will catch the v2 chain. This is
expected, documented, and aligned with v2's stated scope (OSEP study artifact,
public repo, polished sketch).

## Out-of-scope detection vectors

These are present in real-world environments but v2 makes no attempt to
defeat them:

- Kernel-mode ETW-Threat-Intelligence
- Hardware-Stack-Protection (CET) shadow-stack enforcement on supported CPUs
- AppLocker / WDAC enforcement
- Office Cloud-Based AMSI scanning (newer than per-process AMSI)
- Memory scanners (signature scans of process address space)
- Patchguard / Kernel Patch Protection

## If a researcher wanted to push this further

Beyond v2 scope, the natural next techniques to layer in (each is also
publicly documented and detected by something):

- **RecycledGate / Tartarus Gate**: call ntdll's own `syscall;ret` gadgets
  instead of writing custom stubs in private memory. Beats the 2024
  non-image-backed-memory rule.
- **Module stomping** for shellcode hosting: overwrite a benign loaded
  DLL's RX section instead of allocating a private RX page. No RWX in any
  private region.
- **Phantom DLL hollowing**: map a real DLL, decommit, refill with
  shellcode -- inherits disk-backed appearance.
- **KiUserApcDispatcher callback abuse**: hijack the user-mode APC
  dispatcher instead of `QueueUserAPC` + `ResumeThread`.

All of these are 2022-2024 era and detected by some EDR config.
