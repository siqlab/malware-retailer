ECHO OFF

TIMEOUT /T 2
reg import c:\temp\Rastaf.reg
TIMEOUT /T 20
setlocal

for /f "tokens=4-5 delims=. " %%i in ('ver') do set VERSION=%%i.%%j
if "%version%" == "6.3" start eventvwr.exe
if "%version%" == "6.2" start eventvwr.exe
if "%version%" == "6.1" start eventvwr.exe
if "%version%" == "6.0" start eventvwr.exe
if "%version%" == "10.0" start fodhelper.exe
echo %version%

endlocal

exit

