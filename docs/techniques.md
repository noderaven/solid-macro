# Techniques

A per-stage walkthrough of the v2 evasion chain. See
[threat-model.md](threat-model.md) for the honest detection table.

## Source-level obfuscation (`Strings.bas`)

Office VBA-AMSI scans the macro source before `AutoOpen` runs. There is no
runtime bypass that fires early enough; the only defense is making the source
look benign to static AMSI signatures.

`Strings.bas` provides `MkStr(b1, b2, ...)` and `MkAStr(b1, b2, ...)` helpers
that build VBA strings and ANSI byte buffers from numeric code-point arrays.
Every sensitive API name (e.g. `NtAllocateVirtualMemory`, `AmsiScanBuffer`,
`CreateProcessW`) is constructed via these helpers; no flat literal appears in
source.

The `assemble.py --check` static analyzer enforces this by failing the build
if any blocklisted literal appears in source.

## DispCallFunc dispatch shim (`Engine.bas`)

VBA's classic `Declare PtrSafe Function` pattern requires a static API name in
source, which AMSI scans. To call APIs dynamically, the engine resolves
function pointers at runtime (`GetMod` / `GetProc` wrappers) and dispatches via
`oleaut32!DispCallFunc`.

`DispCallFunc` is the OLE primitive that ships with COM; it handles the x64
calling convention (registers, shadow space, stack alignment) correctly. No
inline assembly needed for ordinary API calls.

Fixed-arity public surface (`Call0..Call12`) avoids ParamArray + Variant
unpacking foot-guns that bit v1's home-grown shim.

## HellsGate indirect syscalls (`Syscalls.bas`)

EDR user-mode hooks live in `ntdll.dll`. The standard syscall stub is:

```
4c 8b d1                mov r10, rcx
b8 XX XX XX XX          mov eax, <SSN>
0f 05                   syscall
c3                      ret
```

`ResolveSyscalls` opens `\KnownDlls\ntdll.dll` as a section object via
`NtOpenSection` + `NtMapViewOfSection` (using the in-process pointers we
resolve through Win32 `GetProcAddress`, which we tolerate getting hooked
because it just returns the address; we never *call* the hooked stub for the
actual syscall). The mapped section is the canonical clean ntdll bytes -- no
user-mode hooks because the mapping is read-only and pristine.

For each needed `Nt*` export, we extract the SSN from bytes 4-7 of the
function's clean stub, write a fresh 12-byte stub into our own RX page, and
dispatch via `Engine.Call*`. No syscall instruction ever runs from `ntdll`'s
.text; no hook is touched.

**What this beats:** EDR user-mode hooks on Nt* APIs; file-system telemetry
from reading ntdll off disk.

**What catches it (MDE, ~2024):** the "syscall instruction issued from
non-image-backed memory" rule. MDE's kernel callback sees the syscall came
from a private (non-image-backed) RX page and alerts.

## Hardware-breakpoint AMSI bypass (`Evasion.bas`)

A 62-byte VEH handler is written into an RX page and registered via
`RtlAddVectoredExceptionHandler(1, handler)`. `DR0` is set to the address of
`AmsiScanBuffer`, `DR7` enables Local Exec breakpoint on DR0 via syscalled
`NtSetContextThread` on the current thread.

When Office calls `AmsiScanBuffer` for any VBA / late-bound content scan, the
breakpoint fires. The handler:

1. Reads the saved return address from RSP.
2. Sets `ctx->Rip` to that return address.
3. Advances `ctx->Rsp` by 8 (popping the consumed return address).
4. Sets `ctx->Rax = 0` (`AMSI_RESULT_CLEAN`).
5. Returns `EXCEPTION_CONTINUE_EXECUTION`.

AmsiScanBuffer never executes a single one of its own instructions; the
caller sees a clean scan with no in-process memory modifications to amsi.dll.

**What this beats:** static scans for byte-patches of `AmsiScanBuffer`;
RWX hygiene checks on amsi.dll's .text.

**What catches it:** behavioral telemetry on VEH installation from Office
processes combined with `DR0+DR7` mutation via `NtSetContextThread`. MDE
flags this combination.

## TEB ETW kill (`Evasion.bas`)

`TEB.EtwTraceData` (offset `0x2C0` on Win11 x64) is a per-thread pointer used
by the EtwEventWrite chain. Zeroing it on the current thread silences
user-mode ETW provider chains for this thread without modifying any system
DLL.

`CurrentTeb()` returns the TEB via a 10-byte stub: `mov rax, gs:[0x30]; ret`.
We then write 8 bytes of zero to `TEB + 0x2C0`.

**Limitation:** ETW-Threat-Intelligence (`ETW-Ti`) operates in kernel mode
and cannot be silenced from user-mode. The ETW kill applies to per-process /
per-thread userland ETW only.

## PPID-spoofed EarlyBird APC (`Injection.bas`)

Two techniques combined:

1. **PPID spoofing.** `InitializeProcThreadAttributeList` +
   `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, hParent)`
   set the new process's reported parent to a `dllhost.exe` we located via
   Toolhelp32. `CreateProcessW(CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT)`
   spawns the target with the spoofed parent.

2. **EarlyBird APC.** With the new process suspended, we allocate RW memory
   (`NtAllocateVirtualMemory`), write the shellcode (`NtWriteVirtualMemory`),
   flip to RX (`NtProtectVirtualMemory`), queue an APC pointing at the
   shellcode (`NtQueueApcThread`), and resume the thread
   (`NtResumeThread`). The APC dispatches on first wakeup before EDR has
   fully attached its own per-thread instrumentation.

**Target choice:** `notepad.exe` in `System32` (Microsoft-signed, low
behavioral footprint). Originally v1 used `werfault.exe`, which is heavily
watched and is the wrong choice.

**What catches PPID spoof:** MDE has a kernel callback that compares the
creator process PID (which is recorded by the kernel) against the
attribute-list PID (which the caller sets) and alerts on mismatch.

**What catches EarlyBird APC:** kernel callback on `QueueUserAPC` from a
cross-process context targeting a freshly-created suspended thread.

## AES-256-CTR payload encryption (`Aes.bas` + `payload/aes.py`)

Shellcode is encrypted client-side with the Python AES (`payload/build.py`)
and decrypted in-process by the VBA twin. Both sides implement FIPS 197
AES-256 with CTR mode using the same convention:

- 32-byte key
- 16-byte nonce treated as the initial 128-bit counter (big-endian)
- Counter incremented by 1 per block, mod 2^128

The plaintext shellcode never touches disk and only exists in memory
post-decryption, immediately consumed by `Inject`.

Key/nonce reuse is catastrophic (CTR is a stream cipher); `build.py` generates
random keys and nonces per build by default.
