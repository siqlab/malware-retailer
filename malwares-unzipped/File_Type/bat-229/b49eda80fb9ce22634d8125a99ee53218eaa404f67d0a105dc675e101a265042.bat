powershell Set-MpPreference -DisableRealtimeMonitoring $true
powershell Set-MpPreference -MAPSReporting 0
powershell Set-MpPreference -SubmitSamplesConsent 2
taskkill /F /IM MSASCuiL.exe
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /t REG_DWORD /d 0x1 /f
REG ADD "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d 0x1 /f
REG DELETE "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "AllowFastServiceStartup" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d 0x1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d 0x0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 0x2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" /v "NotificationSuppress" /t REG_DWORD /d 0x1 /f
pause