# Overall Architecture and Execution Flow
The macro is designed to execute a multi-stage attack chain entirely from within the memory of the host Office application (e.g., WINWORD.EXE). The execution flow is orchestrated by the `AutoOpen` and `RunExploit` subroutines and follows these strategic steps:

- **Environment Validation**: The script first performs several checks to ensure it is not running in an analysis sandbox and is within the intended target environment.
- **Dynamic API Resolution**: To evade static analysis and certain ASR rules, all necessary Windows API functions are resolved dynamically at runtime.
- **EDR Evasion**: Before executing the main payload, the script attempts to blind EDR solutions by unhooking `ntdll.dll` and patching functions for AMSI (Antimalware Scan Interface) and ETW (Event Tracing for Windows).
- **Payload Preparation**: A shellcode payload, stored in an encrypted format within the script, is decrypted in memory.
- **Stealthy Injection**: The decrypted shellcode is injected into a newly created, legitimate process using a combination of PPID Spoofing and EarlyBird APC Injection to mask its origin and execute before EDR hooks are fully initialized.
- **Self-Destruction**: As a final step, the macro attempts to erase itself from the host document to hinder forensic analysis.

## Key Sections and Techniques

### 1. `ValidateEnvironment()`
This function acts as a guardrail, preventing the payload from executing in unintended environments.

- **`GetTickCount()`**: Checks the system uptime. A very low uptime (< 10 minutes) is often characteristic of a sandbox environment that has just been spun up for analysis.
- **`GetCursorPos()`**: Checks for mouse cursor movement over a 3-second interval. A static cursor suggests no human user is present, indicating a likely sandbox.
- **`Environ("USERDOMAIN")`**: Performs "environmental keying" by checking if the machine is part of a specific domain (LAB-DOMAIN). This ensures the payload only runs on the intended target.

### 2. `ResolveAPIs()` and `CallPointer()`
This is the core of the dynamic API resolution mechanism, designed to bypass the ASR rule that blocks Win32 API calls from Office macros.

- **How it Works**: Instead of using static `Declare` statements for all APIs (which are easily flagged), the script uses `GetProcAddress` to find the memory addresses of required functions (like `VirtualAllocEx`, `CreateProcessA`, etc.) at runtime.
- **`CallPointer` Function**: This is a crucial helper function that was not fully implemented in the provided code but is conceptually necessary for a real-world scenario. It would typically use a mechanism like `CreateObject("Thread")` or a custom assembly stub to execute a function via its memory address (`LongPtr`). This dynamic invocation is much harder for static analysis tools to trace.
- **Obfuscation**: All function and DLL names are stored as concatenated strings (e.g., `"ke" & "rn" & "el" & "32"`) to avoid simple signature-based detection of these sensitive strings in the macro code.

### 3. Evasion Techniques (`BypassAMSIETW` and `UnhookModule`)
This section focuses on actively disabling defensive sensors within the process.

- **`UnhookModule("ntdll.dll")`**: This is a powerful EDR evasion technique.
  - It loads a fresh, clean copy of `ntdll.dll` from disk into memory.
  - It identifies the `.text` section (which contains the executable code) of both the hooked `ntdll.dll` in the current process and the fresh copy.
  - It uses `VirtualProtect` to make the hooked `.text` section writable.
  - It then uses `CopyMemory` to overwrite the EDR's hooks with the original, clean code from the fresh DLL.
  - This effectively "blinds" the EDR to subsequent API calls made by the macro.
- **`BypassAMSIETW()`**: This subroutine patches two key security logging functions in memory.
  - **AMSI Patch**: It finds the address of `AmsiScanBuffer` and overwrites its starting bytes with instructions that force it to immediately return a "clean" result (`AMSI_RESULT_CLEAN`), effectively preventing any further script or memory content from being scanned by AMSI.
  - **ETW Patch**: It finds `EtwEventWrite` and overwrites it with a single `RET` instruction, preventing the process from writing any telemetry data via this function.

### 4. Payload Injection (`InjectPayload` and `GetExplorerHandle`)
This is the most sophisticated part of the exploit chain, combining two advanced techniques.

- **PPID Spoofing**:
  - The macro gets a handle to a running `explorer.exe` process using `GetExplorerHandle`.
  - It uses `InitializeProcThreadAttributeList` and `UpdateProcThreadAttribute` to create a special attribute that designates `explorer.exe` as the parent for a new process.
  - When `CreateProcessA` is called with the `EXTENDED_STARTUPINFO_PRESENT` flag, the new process (`werfault.exe`) is created with `explorer.exe` as its parent, breaking the suspicious process chain from `WINWORD.EXE`.
- **EarlyBird APC Injection**:
  - The target process (`werfault.exe`) is created in a suspended state.
  - The script allocates memory (`VirtualAllocEx`), writes the shellcode (`WriteProcessMemory`), and makes it executable (`VirtualProtectEx`) in the suspended process.
  - It then uses `QueueUserAPC` to queue the shellcode for execution on the process's main thread.
  - Finally, `ResumeThread` is called. The Asynchronous Procedure Call (APC) is one of the first things to execute when the thread wakes up, often before EDR hooks are fully placed on the new process.

### 5. Payload Decryption (`GetDecryptedPayload`)
To evade static analysis of the payload itself, the shellcode is not stored in plaintext.

- **AES-256 Placeholder**: The script includes a placeholder function for AES-256 decryption. In a real scenario, this would contain a full VBA implementation of the AES algorithm.
- **In-Memory Decryption**: The encrypted shellcode string is converted from hex to a byte array and decrypted entirely in memory right before injection. The decrypted payload never touches the disk.

### 6. `SelfDestruct()`
This function attempts to remove the macro from the document to clean up forensic evidence.

- **VBA Project Model**: It uses the `ThisDocument.VBProject` object model to access its own code.
- **Code Deletion**: It iterates through its components, deleting all lines of code from the modules using `CodeModule.DeleteLines`.
- **Caveat**: This technique has a major dependency: it requires "Trust access to the VBA project object model" to be enabled in Word's Trust Center. In most secure environments, this is disabled by default, meaning this part of the script will likely fail.
