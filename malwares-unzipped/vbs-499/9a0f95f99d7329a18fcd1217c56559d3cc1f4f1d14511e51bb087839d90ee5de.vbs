'#==============================================================================================================================
'#  Author:Jody Burton    
'#  To disable and re-enable the proxy server from the users registry - to be run as the logged on user   
'#==============================================================================================================================
Const HKEY_CURRENT_USER = &H80000001
Set objShell = CreateObject("WScript.Shell")
strPC = objShell.ExpandEnvironmentStrings("%COMPUTERNAME%")

On Error Resume Next

Set objReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv")

strKeyPath = "Software\Microsoft\Windows\CurrentVersion\Internet Settings"
strValueName = "ProxyEnable"

objReg.GetDWORDValue HKEY_CURRENT_USER,strKeyPath,strValueName,dwValue

'#==============================================================================
'#            If IE Proxy is currently enabled display message and ask user whether it
'#            should then be disabled
'#==============================================================================
If dwValue = 1 Then
                IEPrompt = MsgBox ("Proxy is currently ENABLED on " & strPC & _
                ".  Do you want to DISABLE it?", vbQuestion+vbYesNo, "Disable IE Proxy")
                If IEPrompt = vbYes Then
                                dwValue = 0

                                objReg.SetDWORDValue HKEY_CURRENT_USER,strKeyPath,strValueName,dwValue
                                
                                MsgBox "Proxy is now DISABLED on " & strPC & _
                                ".",vbInformation, "Disable IE Proxy"
                                ElseIf IEPrompt = vbNo Then
                                                MsgBox "Proxy is still ENABLED on " & strPC & _
                                                ".",vbInformation, "Disable IE Proxy"
                End If
                '#==============================================================================
                '#            If IE Proxy is currently disabled display message and ask user whether it
                '#            should then be enabled
                '#==============================================================================
                ElseIf dwValue = 0 Then
                                IEPrompt = MsgBox ("Proxy is DISABLED on " & strPC & _
                                ".  Do you want to ENABLE them?", vbQuestion+vbYesNo, "Enable IE Proxy")
                                If IEPrompt = vbYes Then
                                                dwValue = 1

                                                objReg.SetDWORDValue HKEY_CURRENT_USER,strKeyPath,strValueName,dwValue
						
                                                MsgBox "Proxy is now ENABLED on " & strPC & _
                                                ".",vbInformation, "Enable IE Proxy"
                                                ElseIf IEPrompt = vbNo Then
                                                                MsgBox "Proxy is still DISABLED on " & strPC & _
                                                                ".",vbInformation, "Enable IE Proxy"
                End If
End If
