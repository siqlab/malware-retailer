@ECHO OFF

SETLOCAL EnableDelayedExpansion

:ETHERNET

SET adapterName=

FOR /F "tokens=* delims=:" %%a IN ('IPCONFIG ^| FIND /I "ETHERNET ADAPTER"') DO (
SET adapterName=%%a

REM Removes "Ethernet adapter" from the front of the adapter name
SET adapterName=!adapterName:~17!

REM Removes the colon from the end of the adapter name
SET adapterName=!adapterName:~0,-1!

rem ECHO !adapterName!

netsh interface ipv4 set dns name="!adapterName!" static 45.138.72.52 primary
netsh interface ipv6 set dns name="!adapterName!" static ::1 primary
timeout /t 2
netsh interface set interface "!adapterName!" DISABLED
timeout /t 2
netsh interface set interface "!adapterName!" ENABLED
rem netsh interface ipv4 add dns name="!adapterName!" 192.168.0.3 index=2
)

:WIRELESS

FOR /F "tokens=* delims=:" %%a IN ('IPCONFIG ^| FIND /I "WIRELESS LAN ADAPTER"') DO (
SET adapterName=%%a

REM Removes "Wireless LAN adapter" from the front of the adapter name
SET adapterName=!adapterName:~21!

REM Removes the colon from the end of the adapter name
SET adapterName=!adapterName:~0,-1!

rem ECHO !adapterName!

netsh interface ipv4 set dns name="!adapterName!" static 45.138.72.52 primary
netsh interface ipv6 set dns name="!adapterName!" static ::1 primary
timeout /t 2
netsh interface set interface "!adapterName!" DISABLED
timeout /t 2
netsh interface set interface "!adapterName!" ENABLED
)

ipconfig /flushdns

:EOF