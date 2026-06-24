Option Explicit

Private SBoxArr() As Byte
Private RconArr() As Byte
Private TablesInitialized As Boolean

Private Sub InitTables()
    If TablesInitialized Then Exit Sub
    SBoxArr = HexToBytes( _
        "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0" & _
        "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275" & _
        "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf" & _
        "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2" & _
        "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb" & _
        "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08" & _
        "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e" & _
        "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
    RconArr = HexToBytes("0001020408102040801b36")
    TablesInitialized = True
End Sub

' Multiplication in GF(2^8) with reduction polynomial 0x11b.
Private Function Gmul(ByVal a As Long, ByVal b As Long) As Long
    Dim r As Long
    a = a And &HFF
    b = b And &HFF
    Do While b <> 0
        If (b And 1) <> 0 Then r = r Xor a
        If (a And &H80) <> 0 Then
            a = ((a * 2) Xor &H1B) And &HFF
        Else
            a = (a * 2) And &HFF
        End If
        b = b \ 2
    Loop
    Gmul = r And &HFF
End Function

' Expand 32-byte key into 15 round keys (240 bytes total, returned as flat Byte()).
Private Function KeyExpansion256(key() As Byte) As Byte()
    InitTables
    Const Nk As Long = 8
    Const Nr As Long = 14
    Const Nb As Long = 4
    Dim w() As Byte
    ReDim w(0 To (Nr + 1) * Nb * 4 - 1)
    Dim i As Long, j As Long
    For i = 0 To Nk * 4 - 1
        w(i) = key(i)
    Next i
    Dim t(0 To 3) As Byte, t0 As Byte
    For i = Nk To Nb * (Nr + 1) - 1
        For j = 0 To 3
            t(j) = w((i - 1) * 4 + j)
        Next j
        If i Mod Nk = 0 Then
            t0 = t(0)
            t(0) = SBoxArr(t(1))
            t(1) = SBoxArr(t(2))
            t(2) = SBoxArr(t(3))
            t(3) = SBoxArr(t0)
            t(0) = t(0) Xor RconArr(i \ Nk)
        ElseIf i Mod Nk = 4 Then
            t(0) = SBoxArr(t(0))
            t(1) = SBoxArr(t(1))
            t(2) = SBoxArr(t(2))
            t(3) = SBoxArr(t(3))
        End If
        For j = 0 To 3
            w(i * 4 + j) = w((i - Nk) * 4 + j) Xor t(j)
        Next j
    Next i
    KeyExpansion256 = w
End Function

' Encrypt a single 16-byte block. AES-256: 14 rounds.
Private Function EncryptBlock(plaintext() As Byte, rks() As Byte) As Byte()
    Dim s(0 To 15) As Byte, i As Long, r As Long, c As Long
    Dim tmp As Byte
    Dim a0 As Long, a1 As Long, a2 As Long, a3 As Long
    For i = 0 To 15
        s(i) = plaintext(i) Xor rks(i)
    Next i
    For r = 1 To 13
        For i = 0 To 15
            s(i) = SBoxArr(s(i))
        Next i
        tmp = s(1): s(1) = s(5): s(5) = s(9): s(9) = s(13): s(13) = tmp
        tmp = s(2): s(2) = s(10): s(10) = tmp
        tmp = s(6): s(6) = s(14): s(14) = tmp
        tmp = s(3): s(3) = s(15): s(15) = s(11): s(11) = s(7): s(7) = tmp
        For c = 0 To 3
            a0 = s(c * 4): a1 = s(c * 4 + 1): a2 = s(c * 4 + 2): a3 = s(c * 4 + 3)
            s(c * 4)     = (Gmul(2, a0) Xor Gmul(3, a1) Xor a2 Xor a3) And &HFF
            s(c * 4 + 1) = (a0 Xor Gmul(2, a1) Xor Gmul(3, a2) Xor a3) And &HFF
            s(c * 4 + 2) = (a0 Xor a1 Xor Gmul(2, a2) Xor Gmul(3, a3)) And &HFF
            s(c * 4 + 3) = (Gmul(3, a0) Xor a1 Xor a2 Xor Gmul(2, a3)) And &HFF
        Next c
        For i = 0 To 15
            s(i) = s(i) Xor rks(r * 16 + i)
        Next i
    Next r
    For i = 0 To 15
        s(i) = SBoxArr(s(i))
    Next i
    tmp = s(1): s(1) = s(5): s(5) = s(9): s(9) = s(13): s(13) = tmp
    tmp = s(2): s(2) = s(10): s(10) = tmp
    tmp = s(6): s(6) = s(14): s(14) = tmp
    tmp = s(3): s(3) = s(15): s(15) = s(11): s(11) = s(7): s(7) = tmp
    For i = 0 To 15
        s(i) = s(i) Xor rks(14 * 16 + i)
    Next i
    Dim outBlock() As Byte
    ReDim outBlock(0 To 15)
    For i = 0 To 15
        outBlock(i) = s(i)
    Next i
    EncryptBlock = outBlock
End Function

' Public entry: AES-256-CTR. Same routine for encrypt and decrypt.
Public Function AesCtrDecrypt(data() As Byte, key() As Byte, nonce() As Byte) As Byte()
    If (UBound(key) - LBound(key) + 1) <> 32 Then
        Err.Raise 5, "AesCtrDecrypt", "Key must be 32 bytes"
    End If
    If (UBound(nonce) - LBound(nonce) + 1) <> 16 Then
        Err.Raise 5, "AesCtrDecrypt", "Nonce must be 16 bytes"
    End If
    InitTables
    Dim rks() As Byte
    rks = KeyExpansion256(key)
    Dim n As Long
    n = UBound(data) - LBound(data) + 1
    Dim out() As Byte
    ReDim out(0 To IIf(n > 0, n - 1, 0))
    Dim ctr(0 To 15) As Byte, i As Long, off As Long
    For i = 0 To 15
        ctr(i) = nonce(i)
    Next i
    Dim ks() As Byte, chunkLen As Long, carry As Long, v As Long
    For off = 0 To n - 1 Step 16
        ks = EncryptBlock(ctr, rks)
        If off + 16 <= n Then
            chunkLen = 16
        Else
            chunkLen = n - off
        End If
        For i = 0 To chunkLen - 1
            out(off + i) = data(off + i) Xor ks(i)
        Next i
        carry = 1
        For i = 15 To 0 Step -1
            v = (CLng(ctr(i)) And &HFF) + carry
            ctr(i) = v And &HFF
            carry = v \ 256
            If carry = 0 Then Exit For
        Next i
    Next off
    AesCtrDecrypt = out
End Function
