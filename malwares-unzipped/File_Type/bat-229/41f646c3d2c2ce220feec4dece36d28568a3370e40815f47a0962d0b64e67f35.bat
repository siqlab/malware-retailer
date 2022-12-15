@echo off
for /f "delims=" %%i in ('"C:\ProgramData\anydesk\AnyDesk-d8631d26.exe" --get-id') do set CID=%%i 
echo AnyDesk ID is: %CID%
pause