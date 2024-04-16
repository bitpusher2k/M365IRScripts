#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Lockdown-Account.ps1 - By Bitpusher/The Digital Fox
# vX.X last updated 2024-XX-XX
# Script to lockdown M365 accounts that are suspected of being compromised.
#
# Usage:
# powershell -executionpolicy bypass -f .\Lockdown-Account.ps1 -OutputPath "Default" -UserIds "compromisedaccount@contoso.com"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell, Microsoft Graph commands.
#
# If not connected:
# Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.AccessAsUser.All", "UserAuthenticationMethod.Read.All", "AuditLog.Read.All"
#
#comp #m365 #security #bec #script #irscript #powershell

#Requires -Version 5.1

Param (
    [string]$OutputPath,
    [string]$UserIds,
    [string]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$Encoding = "utf8bom" # "ascii","ansi","bigendianunicode","unicode","utf8","utf8","utf8NoBOM","utf32"
)

if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }

$date = Get-Date -Format "yyyyMMddHHmmss"

## If OutputPath variable is not defined, prompt for it
if (!$OutputPath) {
    Write-Output ""
    $OutputPath = Read-Host "Enter the output base path, e.g. $($env:userprofile)\Desktop\Investigation (default)"
    If ($OutputPath -eq '') { $OutputPath = "$($env:userprofile)\Desktop\Investigation" }
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
# $PrimaryDomain = Get-AcceptedDomain | Where-Object Default -eq $true
# $DomainName = $PrimaryDomain.DomainName
$PrimaryDomain = Get-MgDomain | Where-Object { $_.isdefault -eq $True } | Select-Object -Property ID
$DomainName = $PrimaryDomain.ID

$CheckSubDir = Get-Item $OutputPath\$DomainName -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
    Write-Output ""
    Write-Output "Domain sub-directory does not exist. Sub-directory `"$DomainName`" will be created."
    mkdir $OutputPath\$DomainName
}

$OutputCSV = "$OutputPath\$DomainName\AccountsBlocked_$($date).csv"


## If UserIds variable is not defined, prompt for it
if (!$UserIds) {
    Write-Output ""
    $UserIds = Read-Host 'Enter the user ID(s) (email address/UPN or object ID) of accounts to lock down (revoke sessions, set random password, block sign-in), comma seaparated'
}

Write-Output "Attempting to block access and revoke sessions for $UserIds..."
foreach ($User in $UserIds) {
    Update-MgUser -UserId $User -AccountEnabled:$False
    $NewPassword = @{}
    $RandomString = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 20 | ForEach-Object {[char]$_})
    $NewPassword["Password"] = $RandomString
    # $NewPassword["ForceChangePasswordNextSignIn"] = $True # Not helpful if they need PW reset through AD
    Update-MgUser -UserId $User -PasswordProfile $NewPassword
    # $InvalidateStatus = Invoke-MgInvalidateUserRefreshToken -UserId $User # Deprecated
    $RevokeStatus = Revoke-MgUserSignInSession -UserId $User
    If ($RevokeStatus.Value -eq $true) {
       Write-Host ("Access revoked for user {0}" -f $User.DisplayName)
    }
    # Disable user's registered devices - more useful for termination than compromise
    # [array]$UserDevices = Get-MgUserRegisteredDevice -UserId $User.Id
    # If ($UserDevices) {
    # ForEach ($Device in $UserDevices) {
    #     Update-MgDevice -DeviceId $Device.Id -AccountEnabled $False}
    #     Write-Output "Disabled $Device.Id"
    # }
    $UserStatus = Get-MgUser -UserID $User -Property GivenName, Surname, DisplayName, userPrincipalName, SignInSessionsValidFromDateTime, OnPremisesSyncEnabled, AccountEnabled, createdDateTime |  Select-Object GivenName, Surname, DisplayName, userPrincipalName, SignInSessionsValidFromDateTime, OnPremisesSyncEnabled, AccountEnabled, createdDateTime
    $UserStatus
    $UserStatus | Export-Csv -Path $OutputCSV -NoTypeInformation -Append -Encoding $Encoding
}

Write-Output "Account(s) blocked & passwords reset. Note that if AD sync is configured it may revert the password and re-enable the account."
Write-Output "If this happens you must disable account/reset password from AD."
Write-Output "Manually reset account password with: $NewPassword[`"Password`"] = 'XXXXXXXX'; Update-MgUser -UserId XXXXXXXX -PasswordProfile $NewPassword"
Write-Output "Manually re-enable the account with: Update-MgUser -UserId XXXXXXX -AccountEnabled:$True"
Write-Output "Or from M365 Admin Console > Users > Active Users"

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:"
    Write-Output $OutputCSV
    $Prompt = New-Object -ComObject wscript.shell
    $UserInput = $Prompt.popup("Do you want to open output file?", 0, "Open Output File", 4)
    If ($UserInput -eq 6) {
        Invoke-Item "$OutputCSV"
    }
}

Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

Exit
