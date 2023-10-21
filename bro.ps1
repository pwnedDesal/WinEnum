
param (
	[string]$DomainName
)

$text = "#POWERSHELL VERSION"
$filePath = "output.txt"
# Use Out-File to append the text to the file
$text | Out-File -FilePath $filePath -Append
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowershellEngine /v PowershellVersion |  Out-File -FilePath $filePath -Append
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowershellEngine /v PowershellVersion |  Out-File -FilePath $filePath -Append
$text = "Accessing Reg keys to find powershell version....."
$text |  Out-File -FilePath $filePath -Append
Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PowerShell\*\PowerShellEngine -Name PowerShellVersion |  Out-File -FilePath $filePath -Append
$text = "#IDENTIFYING POWERSHELL LOGGING"
$text |  Out-File -FilePath $filePath -Append
$text = "Accessing Reg keys to find powershell version....."
$text |  Out-File -FilePath $filePath -Append
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription |  Out-File -FilePath $filePath -Append
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging |  Out-File -FilePath $filePath -Append
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging |  Out-File -FilePath $filePath -Append
$text = "#IDENTIFYING AVAILABLE COMMON LANGUAGE RUNTIME(CLR) VERSIONS"
$text |  Out-File -FilePath $filePath -Append
$text = "# checking if the value is TRUE"
$text |  Out-File -FilePath $filePath -Append
$flag = [System.IO.File]::Exists("$env:windir\Microsoft.Net\Framework\v2.0.50727\System.dll")
if ($flag) {
	$text = "CLR version v2.0.50727 is available" |  Out-File -FilePath $filePath -Append
}
else {
	$text = "CLR version v2.0.50727 not available" |  Out-File -FilePath $filePath -Append
}
$flag = [System.IO.File]::Exists("$env:windir\Microsoft.Net\Framework\v4.0.30319\System.dll")
if ($flag) {
	$text = "CLR version v4.0.30319 is available" |  Out-File -FilePath $filePath -Append
}
else {
	$text = "CLR version v4.0.30319 not available" |  Out-File -FilePath $filePath -Append
}
$text = "#USING WMI TO GATHER INFORMATION SUCH AS ANTIVIRUS, LIST UPDATE, PASSWORD IN TEXT FILES, AND USER ACCOUNT" |  Out-File -FilePath $filePath -Append

wmic /namespace:\\root\securitycenter2 path antivirusproduct GET displayName,productState,pathToSignedProductExe |  Out-File -FilePath $filePath -Append
wmic qfe list brief |  Out-File -FilePath $filePath -Append
wmic DATAFILE where "drive='C:' AND Name like '%password%'" GET Name,readable,size /VALUE |  Out-File -FilePath $filePath -Append
wmic useraccount list |  Out-File -FilePath $filePath -Append

$text = "#GATHERING INFORMATION ON WMIC. Domain Information, list all users, groups, member of domain admins groups, and list all computer" |  Out-File -FilePath $filePath -Append
$text = "Domains" |  Out-File -FilePath $filePath -Append
wmic NTDOMAIN GET DomainControllerAddress,DomainName,Roles |  Out-File -FilePath $filePath -Append
$text = "list domain users" |  Out-File -FilePath $filePath -Append
wmic /NAMESPACE:\\root\directory\ldap PATH ds_user GET ds_samaccountname |  Out-File -FilePath $filePath -Append
$text = "list domain groups" |  Out-File -FilePath $filePath -Append
wmic /NAMESPACE:\\root\directory\ldap PATH ds_group GET ds_samaccountname 

Get-WmiObject -Query "SELECT * FROM Win32_GroupUser WHERE GroupComponent=`"Win32_Group.Domain='$DomainName',Name='Administrator'`"" | ForEach-Object {
	$_.PartComponent
} |  Out-File -FilePath $filePath -Append

wmic /NAMESPACE:\\root\directory\ldap PATH ds_computer GET ds_samaccountname | Out-File -FilePath $filePath -Append
$text = "#CHECKING FOR VMWARE THING" |  Out-File -FilePath $filePath -Append

$VMAdapter = Get-WmiObject Win32_NetworkAdapter -Filter 'Manufacturer LIKE "VMware%" OR Name LIKE "VMware%"'
$VMBios = Get-WmiObject Win32_BIOS -Filter 'SerialNumber LIKE
"%VMware%"'
$VMToolsRunning = Get-WmiObject Win32_Process -Filter 'Name="vmtoolsd.exe"'
if([Bool] ($VMAdapter -or $VMBios -or $VMToolsRunning)){
	$text = "you are inside of vmware thing " |  Out-File -FilePath $filePath -Append
}