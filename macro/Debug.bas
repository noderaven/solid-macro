Option Explicit

' Set DEBUG_ENABLED = False before assembling a release build to silence
' all DbgPrint/DbgAssert calls. The functions remain present so SolidMacro
' and other modules compile in both configurations.
Private Const DEBUG_ENABLED As Boolean = True

Private Declare PtrSafe Sub OutputDebugStringA Lib "kernel32" ( _
    ByVal lpOutputString As LongPtr)

Public Sub DbgPrint(msg As String)
    If Not DEBUG_ENABLED Then Exit Sub
    Dim n As Long, i As Long, ansi() As Byte
    n = Len(msg)
    ReDim ansi(0 To n + 1) As Byte
    For i = 1 To n
        ansi(i - 1) = Asc(Mid$(msg, i, 1)) And &HFF
    Next i
    ansi(n) = 13      ' CR
    ansi(n + 1) = 0   ' null
    OutputDebugStringA VarPtr(ansi(0))
End Sub

Public Sub DbgAssert(cond As Boolean, msg As String)
    If Not DEBUG_ENABLED Then Exit Sub
    If Not cond Then DbgPrint "ASSERT FAILED: " & msg
End Sub
