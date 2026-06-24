Option Explicit

' MkStr: build a VBA String (UTF-16) from a list of code-point byte values.
' Used to avoid flat string literals for sensitive names in source.
'   Example: MkStr(86, 105, 114, 116) = "Virt"
Public Function MkStr(ParamArray bytes() As Variant) As String
    Dim i As Long, s As String
    For i = LBound(bytes) To UBound(bytes)
        s = s & ChrW$(CLng(bytes(i)))
    Next i
    MkStr = s
End Function

' MkAStr: build a null-terminated ANSI Byte() from a list of byte values.
' Pass VarPtr(arr(0)) to APIs that expect CHAR*.
Public Function MkAStr(ParamArray bytes() As Variant) As Byte()
    Dim i As Long, n As Long
    n = UBound(bytes) - LBound(bytes) + 1
    Dim out() As Byte
    ReDim out(0 To n) As Byte    ' +1 for null terminator
    For i = 0 To n - 1
        out(i) = CByte(bytes(LBound(bytes) + i))
    Next i
    out(n) = 0
    MkAStr = out
End Function

' HexToBytes: decode a hex string into a Byte() array.
' Permits whitespace and CR/LF; case-insensitive. Raises on empty
' or odd-length input.
Public Function HexToBytes(ByVal hex As String) As Byte()
    Dim clean As String, i As Long, ch As String * 1
    For i = 1 To Len(hex)
        ch = Mid$(hex, i, 1)
        Select Case Asc(ch)
            Case 32, 9, 13, 10   ' space, tab, CR, LF
                ' skip
            Case Else
                clean = clean & ch
        End Select
    Next i
    If Len(clean) = 0 Then
        Err.Raise 5, "HexToBytes", "Empty hex input"
    End If
    If Len(clean) Mod 2 <> 0 Then
        Err.Raise 5, "HexToBytes", "Odd-length hex input"
    End If
    Dim n As Long, out() As Byte
    n = Len(clean) \ 2
    ReDim out(0 To n - 1) As Byte
    For i = 0 To n - 1
        out(i) = CByte("&H" & Mid$(clean, i * 2 + 1, 2))
    Next i
    HexToBytes = out
End Function
