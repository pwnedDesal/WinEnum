
param (
	[string]$DomainName,
	[string]$adsiURL
)
<# 
				#############
				FORMAT HERE
				#############
$text = "TXT HERE(COMMENT)" |  Out-File -FilePath $filePath -Append
$text = "ADITIONAL TEXT HERE" |  Out-File -FilePath $filePath -Append
COMMAND TO EXECUTE FOR EXZMPLE
`wmic NTDOMAIN GET DomainControllerAddress,DomainName,Roles |  Out-File -FilePath $filePath -Append`

THE `#` IN THE LOGS IS HEADER OR SECTION FOR DIFFERENT GROUPS OF COMMANDS

#>
$text = "# POWERSHELL VERSION"
$filePath = "output.txt"
# Use Out-File to append the text to the file
$text | Out-File -FilePath $filePath -Append
echo "Reading Registry(PowershellVersion)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowershellEngine /v PowershellVersion |  Out-File -FilePath $filePath -Append
echo "Reading Registry"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowershellEngine /v PowershellVersion |  Out-File -FilePath $filePath -Append
$text = "Accessing Reg keys to find powershell version....."
$text |  Out-File -FilePath $filePath -Append
Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PowerShell\*\PowerShellEngine -Name PowerShellVersion |  Out-File -FilePath $filePath -Append
$text = "#IDENTIFYING POWERSHELL LOGGING"
$text |  Out-File -FilePath $filePath -Append
$text = "Accessing Reg keys to find powershell version....."
$text |  Out-File -FilePath $filePath -Append
echo "Reading Registry(Transcription)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription |  Out-File -FilePath $filePath -Append
echo "Reading Registry(ModuleLogging)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging |  Out-File -FilePath $filePath -Append
echo "Reading Registry(ScriptBlockLogging)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging |  Out-File -FilePath $filePath -Append
$text = "# IDENTIFYING AVAILABLE COMMON LANGUAGE RUNTIME(CLR) VERSIONS"
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
$text = "# RECON USING ADSI"
$text | Out-File -FilePath $filePath -Append

# Define the URL to download the DLL
$downloadUrl = $adsiURL

# Define the destination path for the downloaded DLL
$destinationPath = "Microsoft.ActiveDirectory.Management.dll"

# Check if the module is already loaded
if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
	# Module is not loaded, download and import it
	Write-Host "Downloading Microsoft.ActiveDirectory.Management.dll..."
	Invoke-WebRequest -Uri $downloadUrl -OutFile $destinationPath -UseBasicParsing
    
	# Import the downloaded module
	Import-Module $destinationPath

	# Check if the module is now loaded
	if (Get-Module -Name ActiveDirectory -ListAvailable) {
		Write-Host "Microsoft.ActiveDirectory.Management.dll has been successfully imported."
	}
 else {
		Write-Host "Failed to import Microsoft.ActiveDirectory.Management.dll."
	}
}
else {
	Write-Host "Microsoft.ActiveDirectory.Management.dll is already loaded."
	$user=Get-DomainObject("User")
	Write-host $user |  Out-File -FilePath $filePath -Append
	$computer = Get-DomainObject("Computer")
	Write-host $computer |  Out-File -FilePath $filePath -Append
	Write-Host "#List Delegation vulnerabilities" | Out-File -FilePath $filePath -Append
	$text = "List computer that is trusted for delegation, UNconstrained Delegation" |  Out-File -FilePath $filePath -Append
	Get-ADObject -Filter { TrustedForDelegation -eq $True } |  Out-File -FilePath $filePath -Append
	$text = "List User that is trusted for delegation, constrained Delegation(checking the SPN(msDS-AllowedToDelegateTo))" |  Out-File -FilePath $filePath -Append
	Get-ADObject -Filter { msDS-AllowedToDelegateTo -ne "$null" } -Properties msDS-AllowedToDelegateTo | Out-File -FilePath $filePath -Append
	#check for local admin privs
	# Check if the current user is a member of the local administrators group
	$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
	if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
		$text = "Current user has local administrator privileges."
		Write-Host $text
		$text |  Out-File -FilePath $filePath -Append
	}
	else {
		$text = "Current user does not have local administrator privileges."
		Write-Host $text
		$text |  Out-File -FilePath $filePath -Append
	}
	$text = "Resource Based Delegation" |  Out-File -FilePath $filePath -Append
	#list user that has write permission on resource based pc using dc  dsacls "CN=BOB-PC-1,CN=Computers,DC=nukesec,DC=lab" > output.txt
	#then check if `msDS-AllowedToActOnBehalfOfOtherIdentity` property of resource based pc is null


}
function Get-DomainObject {
	param(
		[string]$ObjectType
	)
	$objects = @()
	if ($ObjectType -eq "User") {
		Write-Host "List all Domain users"
		Write-host "# List all Domain users" |  Out-File -FilePath $filePath -Append
		$users = Get-ADUser -Filter * | Select-Object Name
		foreach ($user in $users) {
			$name = $user.Name
			$name | Out-File -Append -FilePath domainUsers.txt
			$objects += $name
		}
	}
 elseif ($ObjectType -eq "Computer") {
		Write-Host "List all Domain Computers"
		Write-host "# List all Domain Computers" |  Out-File -FilePath $filePath -Append
		$computers = Get-ADComputer -Filter * | Select-Object Name
		foreach ($user in $computers) {
			$name = $computer.Name
			$name | Out-File -Append -FilePath domainComputers.txt
			$objects += $name
		}
	}
 else {
		Write-Host "Invalid object type. Please specify 'User' or 'Computer'."
	}
 return $objects
}