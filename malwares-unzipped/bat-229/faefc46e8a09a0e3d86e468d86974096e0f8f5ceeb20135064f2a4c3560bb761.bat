@echo off

taskkill /f /im AIO.exe
timeout /t 2 /nobreak > NUL

del C:\Users\Public\AIO.exe

timeout /t 2 /nobreak > NUL

DEL "%~f0">NUL

