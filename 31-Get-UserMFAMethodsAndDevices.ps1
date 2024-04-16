#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-UserMFAMethodsAndDevices.ps1 - By Bitpusher/The Digital Fox
# v2.7 last updated 2024-02-26
# Script to list the registered authentication methods and devices of the specified user.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-UserMFAMethodsAndDevices.ps1 -OutputPath "Default" -UserIds "compromisedaccount@contoso.com"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses (ExchangePowerShell), Azure AD, Microsoft Graph commands.
#
#comp #m365 #security #bec #script #irscript #powershell #authentication #methods #devices

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$UserIds,
    [string]$StartDate,
    [string]$EndDate,
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

## If UserIds variable is not defined, prompt for it
if (!$UserIds) {
    Write-Output ""
    $UserIds = Read-Host 'Enter the userPrincipalName (email address) of the user to list authentication methods/devices'
}

Write-Output "Collecting all user authentication methods and devices..."

# get-mguser -userid (get-mguser -UserId "$UserIds").id -property signinactivity | Select-Object -expandproperty signinactivity

# Get-MgUserAuthenticationMethod -UserId $UserIds | fl *
# Get-MgUserAuthenticationPhoneMethod -UserId $UserIds | fl *
# Get-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $UserIds | fl *
# Get-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $UserIds | Select-Object -expandproperty additionalproperties

$authMethod = Get-MgUserAuthenticationMethod -UserId $UserIds
# $authMethod.additionalProperties
# $authMethod.Id

(Get-MsolUser -UserPrincipalName $UserIds).StrongAuthenticationMethods | Format-List * | Out-File -FilePath "$OutputPath\$DomainName\AllUserAuthenticationMethods_$($UserIds)_$($date).txt" -Append -Encoding $Encoding
$authMethod | Format-List * | Out-File -FilePath "$OutputPath\$DomainName\AllUserAuthenticationMethods_$($UserIds)_$($date).txt" -Append -Encoding $Encoding

$AzUser = Get-AzureADUser -ObjectId "$UserIds"
$User_ObjectID = $AzUser.ObjectID
$Get_User_Devices = (Get-AzureADUserRegisteredDevice -ObjectId $User_ObjectID)
$Count_User_Devices = $Get_User_Devices.count
Write-Output "`n"
Write-Output "User has $Count_User_Devices devices in Azure AD/Entra ID"

$Get_User_Devices | Export-Csv "$OutputPath\$DomainName\AllUserDevices_$($UserIds)_$($date).csv" -Append -NoTypeInformation -Encoding $Encoding
Write-Output "`n"

Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

exit
