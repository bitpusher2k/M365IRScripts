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
# v2.7 last updated 2024-02-26
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
    [string]$OutputPath,
    [string]$Encoding = "utf8bom" # "ascii","ansi","bigendianunicode","unicode","utf8","utf8","utf8NoBOM","utf32"
)

if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }

$date = Get-Date -Format "yyyyMMddHHmmss"

## If OutputPath variable is not defined, prompt for it
if (!$OutputPath) {
    Write-Output ""
    $OutputPath = Read-Host "Enter the output base path, e.g. $($env:userprofile)\Desktop\Investigation (default)"
    if ($OutputPath -eq '') { $OutputPath = "$($env:userprofile)\Desktop\Investigation" }
    Write-Output "Output base path will be in $OutputPath"
} elseif ($OutputPath -eq 'Default') {
    Write-Output ""
    $OutputPath = "$($env:userprofile)\Desktop\Investigation"
    Write-Output "Output base path will be in $OutputPath"
}

## If OutputPath does not exist, create it
$CheckOutputPath = Get-Item $OutputPath -ErrorAction SilentlyContinue
if (!$CheckOutputPath) {
    Write-Output ""
    Write-Output "Output path does not exist. Directory will be created."
    mkdir $OutputPath
}

## Get Primary Domain Name for output subfolder
$PrimaryDomain = Get-AcceptedDomain | Where-Object Default -EQ $true
$DomainName = $PrimaryDomain.DomainName

$CheckSubDir = Get-Item $OutputPath\$DomainName -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
    Write-Output ""
    Write-Output "Domain sub-directory does not exist. Sub-directory `"$DomainName`" will be created."
    mkdir $OutputPath\$DomainName
}

Write-Output "Script will get rolls & permissions on all tenant mailboxes (send as, send on behalf, full access) of specified user."
$User = Read-Host "Enter the user's primary email address (UPN)"


Write-Output "`nUser Information:"
$UserStatus = Get-MgUser -UserID $User -Property GivenName, Surname, DisplayName, userPrincipalName, SignInSessionsValidFromDateTime, OnPremisesSyncEnabled, AccountEnabled, createdDateTime |  Select-Object GivenName, Surname, DisplayName, userPrincipalName, SignInSessionsValidFromDateTime, OnPremisesSyncEnabled, AccountEnabled, createdDateTime
$UserStatus
$UserStatus | Export-Csv -Path "$OutputPath\$DomainName\Account_info_$($User)_$($date).csv" -Encoding $Encoding -NoTypeInformation

Write-Output "`nUser's roles:"
$Roles = Get-MsolUserRole -UserPrincipalName $User
if ($Roles) {
    $Roles | Select-Object name, isenabled, issystem
    $Roles | Export-Csv -Path "$OutputPath\$DomainName\Roles_Of_$($User)_$($date).csv" -Encoding $Encoding -NoTypeInformation
} else {
    "No special roles assigned to $user"
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


Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

exit
