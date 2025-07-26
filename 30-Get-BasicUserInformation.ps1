#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-BasicUserInformation.ps1 - By Bitpusher/The Digital Fox
# v3.1 last updated 2025-07-26
# Script to get the rolls and permissions (send as, send on behalf, full access)
# of specified user.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-BasicUserInformation.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell, MSOnline commands.
#
#comp #m365 #security #bec #script #irscript #powershell #roles #permissions #sendas #fullaccess #sendonbehalf

#Requires -Version 5.1

param(
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Get-BasicUserInformation",
    [string]$Priority = "Normal",
    [string]$DebugPreference = "SilentlyContinue",
    [string]$VerbosePreference = "SilentlyContinue",
    [string]$InformationPreference = "Continue",
    [string]$logFileFolderPath = "C:\temp\log",
    [string]$ComputerName = $env:computername,
    [string]$ScriptUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
    [string]$logFilePrefix = "$scriptName" + "_" + "$ComputerName" + "_",
    [string]$logFileDateFormat = "yyyyMMdd_HHmmss",
    [int]$logFileRetentionDays = 30,
    [string]$Encoding = "utf8NoBOM" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
)

#region initialization
if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }

function Get-TimeStamp {
    param(
        [switch]$NoWrap,
        [switch]$Utc
    )
    $dt = Get-Date
    if ($Utc -eq $true) {
        $dt = $dt.ToUniversalTime()
    }
    $str = "{0:yyyy-MM-dd} {0:HH:mm:ss}" -f $dt

    if ($NoWrap -ne $true) {
        $str = "[$str]"
    }
    return $str
}

if ($logFileFolderPath -ne "") {
    if (!(Test-Path -PathType Container -Path $logFileFolderPath)) {
        Write-Output "$(Get-TimeStamp) Creating directory $logFileFolderPath" | Out-Null
        New-Item -ItemType Directory -Force -Path $logFileFolderPath | Out-Null
    } else {
        $DatetoDelete = $(Get-Date).AddDays(- $logFileRetentionDays)
        Get-ChildItem $logFileFolderPath | Where-Object { $_.Name -like "*$logFilePrefix*" -and $_.LastWriteTime -lt $DatetoDelete } | Remove-Item | Out-Null
    }
    $logFilePath = $logFileFolderPath + "\$logFilePrefix" + (Get-Date -Format $logFileDateFormat) + ".LOG"
}

$sw = [Diagnostics.StopWatch]::StartNew()
Write-Output "$scriptName started on $ComputerName by $ScriptUserName at  $(Get-TimeStamp)" | Tee-Object -FilePath $logFilePath -Append

$process = Get-Process -Id $pid
Write-Output "Setting process priority to `"$Priority`"" | Tee-Object -FilePath $logFilePath -Append
$process.PriorityClass = $Priority

#endregion initialization

$date = Get-Date -Format "yyyyMMddHHmmss"

## If OutputPath variable is not defined, prompt for it
if (!$OutputPath) {
    Write-Output ""
    $OutputPath = Read-Host "Enter the output base path, e.g. $($env:userprofile)\Desktop\Investigation (default)" | Tee-Object -FilePath $logFilePath -Append
    If ($OutputPath -eq '') { $OutputPath = "$($env:userprofile)\Desktop\Investigation" }
    Write-Output "Output base path will be in $OutputPath" | Tee-Object -FilePath $logFilePath -Append
} elseif ($OutputPath -eq 'Default') {
    Write-Output ""
    $OutputPath = "$($env:userprofile)\Desktop\Investigation"
    Write-Output "Output base path will be in $OutputPath" | Tee-Object -FilePath $logFilePath -Append
}

## If OutputPath does not exist, create it
$CheckOutputPath = Get-Item $OutputPath -ErrorAction SilentlyContinue
if (!$CheckOutputPath) {
    Write-Output ""
    Write-Output "Output path does not exist. Directory will be created." | Tee-Object -FilePath $logFilePath -Append
    mkdir $OutputPath
}

## Get Primary Domain Name for output subfolder
# $PrimaryDomain = Get-AcceptedDomain | Where-Object Default -eq $true
# $DomainName = $PrimaryDomain.DomainName
$PrimaryDomain = Get-MgDomain | Where-Object { $_.isdefault -eq $True } | Select-Object -Property ID
if ($PrimaryDomain) {
    $DomainName = $PrimaryDomain.ID
} else {
    $DomainName = "DefaultOutput"
}

$CheckSubDir = Get-Item $OutputPath\$DomainName -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
    Write-Output ""
    Write-Output "Domain sub-directory does not exist. Sub-directory `"$DomainName`" will be created." | Tee-Object -FilePath $logFilePath -Append
    mkdir $OutputPath\$DomainName
}
Write-Output "Domain sub-directory will be `"$DomainName`"" | Tee-Object -FilePath $logFilePath -Append


Write-Output "Script will get rolls & permissions on all tenant mailboxes (send as, send on behalf, full access) of specified user."
$User = Read-Host "Enter the user's primary email address (UPN)"


Write-Output "`nUser Information:"
$UserStatus = Get-MgUser -UserID $User -Property GivenName, Surname, DisplayName, userPrincipalName, SignInSessionsValidFromDateTime, OnPremisesSyncEnabled, AccountEnabled, createdDateTime |  Select-Object GivenName, Surname, DisplayName, userPrincipalName, SignInSessionsValidFromDateTime, OnPremisesSyncEnabled, AccountEnabled, createdDateTime
$UserStatus
$UserStatus | Export-Csv -Path "$OutputPath\$DomainName\Account_info_$($User)_$($date).csv" -Encoding $Encoding -NoTypeInformation

Write-Output "`nUser authentication information:"
 
$Details = Get-MgReportAuthenticationMethodUserRegistrationDetail -user (get-mguser -userid $User).id
if ($Details) {
    $Details | fl
    $Details | Export-Csv -Path "$OutputPath\$DomainName\Authentication_Details_$($User)_$($date).csv" -Encoding $Encoding -NoTypeInformation
} else {
    "No authentication information found for $user"
}

Write-Output "`nUser's app roles:"
$Roles = Get-MgUserAppRoleAssignment -UserId $User -CountVariable CountVar  -ConsistencyLevel eventual 
if ($Roles) {
    $Roles | Select-Object PrincipalDisplayName, PrincipalType, ResourceDisplayName
    $Roles | Export-Csv -Path "$OutputPath\$DomainName\App_Roles_$($User)_$($date).csv" -Encoding $Encoding -NoTypeInformation
} else {
    "No app roles assigned to $user"
}

# All permissions on a mailbox:
# Get-MailboxPermission -Identity $User | Export-CSV -Path "$OutputPath\$DomainName\PermissionsOnMailbox_$($User)_$($date).csv" -Encoding $Encoding -NoTypeInformation

$mailboxes = Get-Mailbox -ResultSize Unlimited -Filter ('RecipientTypeDetails -eq "UserMailbox"')


Write-Output "`nUser's Send As permissions:"
$SendAs = foreach ($mailbox in $mailboxes) { get-recipientpermission -Identity $mailbox.DistinguishedName | Where-Object { $_.AccessRights -like "*send*" -and -not ($_.Trustee -match "NT AUTHORITY") -and ($_.IsInherited -eq $false) -and ($_.Trustee -eq "$User") } }
if ($SendAs) {
    $SendAs
    Get-Mailbox -Identity "xxxx" | Select-Object userprincipalname, displayname, name, alias
    $SendAs | Export-Csv -Path "$OutputPath\$DomainName\SendAs_By_$($User)_$($date).csv" -Encoding $Encoding -NoTypeInformation
} else {
    Write-Output "No Send As permissions assigned to $user"
}

# Send as on Mailbox: Get-Mailbox | Get-ADPermission | Where-Object { $_.ExtendedRights -like "*send*" -and ($_.User -match "Accent")} | ft User,Identity
# Send as for All mailboxes:
# $mailboxes = Get-Mailbox -ResultSize Unlimited -Filter ('RecipientTypeDetails -eq "UserMailbox"')
# foreach ($mailbox in $mailboxes) { get-recipientpermission  -Identity $mailbox.alias | ? { $_.AccessRights -like "*send*" -and -not ($_.Trustee -match "NT AUTHORITY") -and ($_.IsInherited -eq $false)} } # alias not unique sometimes
# foreach ($mailbox in $mailboxes) { get-recipientpermission  -Identity $mailbox.guid | ? { $_.AccessRights -like "*send*" -and -not ($_.Trustee -match "NT AUTHORITY") -and ($_.IsInherited -eq $false)} }
# foreach ($mailbox in $mailboxes) { get-recipientpermission  -Identity $mailbox.DistinguishedName | ? { $_.AccessRights -like "*send*" -and -not ($_.Trustee -match "NT AUTHORITY") -and ($_.IsInherited -eq $false)} }


Write-Output "`nUser's Send On Behalf permissions:"
$SendOnBehalf = $mailboxes | Where-Object { $_.GrantSendOnBehalfTo } | Select-Object *, @{ Name = 'grantsendonbehalftoUPN'; Expression = { $_.GrantSendOnBehalfTo | get-user | Select-Object -ExpandProperty userprincipalname } } | Where-Object { "$User" -in $_.grantsendonbehalftoUPN } | Format-Table Name, DistinguishedName, alias, userprincipalname, displayname, GrantSendOnBehalfTo, grantsendonbehalftoUPN
if ($SendOnBehalf) {
    $SendOnBehalf
    $SendOnBehalf | Export-Csv -Path "$OutputPath\$DomainName\SendOnBehalf_By_$($User)_$($date).csv" -Encoding $Encoding -NoTypeInformation
} else {
    Write-Output "No Send On Behalf permissions assigned to $user"
}

# Send on behalf on Mailbox: Get-Mailbox "$User" | select *,@{ Name = 'grantsendonbehalftoUPN';  Expression = { $_.grantsendonbehalfto | get-user | select -expandproperty userprincipalname }}
# Send On Behalf for All mailboxes:
# Get-Mailbox -ResultSize Unlimited | Where-Object {$_.GrantSendOnBehalfTo}
# $mailboxes | Where-Object {$_.GrantSendOnBehalfTo}
# $mailboxes | ? { $_.GrantSendOnBehalfTo }
# Get-Mailbox -ResultSize Unlimited -Filter ('RecipientTypeDetails -eq "UserMailbox"') | select Alias, GrantSendOnBehalfTo
# $mailboxes | ? { $_.GrantSendOnBehalfTo } | fl GrantSendOnBehalfTo,Name,DistinguishedName,alias,userprincipalname,displayname


Write-Output "`nUser's Full Access permissions:"
$FullAccess = foreach ($mailbox in $mailboxes) { Get-MailboxPermission -Identity $mailbox.DistinguishedName -ResultSize Unlimited | Where-Object { ($_.IsInherited -eq $false) -and ($_.User -ne "NT AUTHORITY\SELF") -and ($_.AccessRights -like "FullAccess") -and ($_.User -eq "$User") } }
if ($FullAccess) {
    $FullAccess
    $FullAccess | Export-Csv -Path "$OutputPath\$DomainName\FullAccess_By_$($User)_$($date).csv" -Encoding $Encoding -NoTypeInformation
} else {
    Write-Output "No Full Access permissions assigned to $user"
}

# Full Access on mailbox: Get-Mailbox -ResultSize Unlimited | Get-MailboxPermission -User "$user" | ft User,Identity,AccessRights
# Full Access for All mailboxes:
# $mailboxes = Get-Mailbox -ResultSize Unlimited -Filter ('RecipientTypeDetails -eq "UserMailbox"')
# foreach ($mailbox in $mailboxes) { Get-MailboxPermission -Identity $mailbox.alias -ResultSize Unlimited | ?{ ($_.IsInherited -eq $false) -and ($_.User -ne "NT AUTHORITY\SELF") -and ($_.AccessRights -like "FullAccess") } } # alias not unique sometimes
# foreach ($mailbox in $mailboxes) { Get-MailboxPermission -Identity $mailbox.guid -ResultSize Unlimited | ?{ ($_.IsInherited -eq $false) -and ($_.User -ne "NT AUTHORITY\SELF") -and ($_.AccessRights -like "FullAccess") } }
# foreach ($mailbox in $mailboxes) { Get-MailboxPermission -Identity $mailbox.DistinguishedName -ResultSize Unlimited | ?{ ($_.IsInherited -eq $false) -and ($_.User -ne "NT AUTHORITY\SELF") -and ($_.AccessRights -like "FullAccess") } }


# All mailbox permissions report:
# Get-Mailbox -ResultSize Unlimited | ForEach-Object { Get-MailboxPermission -Identity $_.DistinguishedName }
# Get-Mailbox -resultsize unlimited | Foreach-Object { $_.guid.guid } | Get-MailboxPermission
# Get-Mailbox | Get-MailboxPermission | where {$_.user.tostring() -ne "NT AUTHORITY\SELF" -and $_.IsInherited -eq $false}
# Get-Mailbox | Get-MailboxPermission | where {$_.user.tostring() -ne "NT AUTHORITY\SELF" -and $_.IsInherited -eq $false} | Select Identity,User,@{Name='Access Rights';Expression={[string]::join(', ', $_.AccessRights)}} | Export-Csv -NoTypeInformation mailboxpermissions.csv

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"

exit
