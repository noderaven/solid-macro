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
