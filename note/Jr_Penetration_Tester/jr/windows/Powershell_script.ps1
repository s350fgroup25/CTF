# run : .\file.ps1
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# waiting-ports.ps1 : 

$system_ports = Get-NetTCPConnection -State Listen

$text_port = Get-Content -Path C:\Users\Administrator\Desktop\ports.txt

foreach($port in $text_port){

    if($port -in $system_ports.LocalPort){
        echo $port
     }

}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# password.ps1 : 

$path = "C:\Users\Administrator\Desktop\emails\*"
$string_pattern = "password"
$command = Get-ChildItem -Path $path -Recurse | Select-String -Pattern $String_pattern 
echo $command

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# html_link.ps1

$path = "C:\Users\Administrator\Desktop\emails\*"
$string_pattern = "https://"
$command = Get-ChildItem -Path $path -Recurse | Select-String -Pattern $String_pattern 
echo $command
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# port_scan.ps1

for($i=130; $i -le 140; $i++){
    Test-NetConnection localhost -Port $i
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# port_scan.ps2

$ErrorActionPreference -eq "SilentlyContinue"
$Target -eq "localhost"
$LowEnd = 130
$HighEnd = 140
$X = 0

Do
{
$CurrentPort = $LowEnd + $X
if((Test-NetConnection -ErrorAction SilentlyContinue $Target -Port $CurrentPort).PingSucceeded -or (Test-NetConnection -ErrorAction SilentlyContinue $Target -Port $CurrentPort).TcpTestSucceeded)
{$CurrentPort | Out-File .\OpenPorts.txt -Append}
$X = $X + 1
}
While($CurrentPort -lt 140)

(Get-Content .\OpenPorts.txt).Count
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
