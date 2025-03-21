#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-UserJunkMailSettings.ps1 - By Bitpusher/The Digital Fox
# v2.8 last updated 2024-05-12
# Script to look up the junk mail settings of specified user
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-UserJunkMailSettings.ps1 -OutputPath "Default" -UserIds "compromisedaccount@contoso.com"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
#
#comp #m365 #security #bec #script #irscript #powershell #mailbox #junk #mail

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$UserIds,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$Encoding = "utf8bom" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
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

## If UserIds variable is not defined, prompt for it
if (!$UserIds) {
    Write-Output ""
    $UserIds = Read-Host 'Enter the UserPrincipalName (email address)'
}

$OutputCSV = "$OutputPath\$DomainName\JunkMailSettings_$($UserIds)_$($date).csv"

Write-Output "Listing user's junk mail settings..."

# https://support.microsoft.com/en-us/office/change-the-level-of-protection-in-the-junk-email-filter-e89c12d8-9d61-4320-8c57-d982c8d52f6b?ui=en-us&rs=en-us&ad=us

$JunkSettings = Get-MailboxJunkEMailConfiguration -Identity $UserIds
$JunkSettings | Format-List
$JunkSettings | Export-Csv $OutputCSV -Append -NoTypeInformation -Encoding $Encoding
Write-Output "`n`nExample commands to update the above settings if needed:"
Write-Output "Set-MailboxJunkEMailConfiguration –Identity $UserIds –BlockedSendersAndDomains @{Add=`"JunkMailEmailOrDomain@spam.online`"}"
Write-Output "Set-MailboxJunkEmailConfiguration –Identity $UserIds -BlockedSendersAndDomains @{remove=`"name@domain.com`"}"
Write-Output "Set-MailboxJunkEmailConfiguration –Identity $UserIds -TrustedSendersAndDomains @{remove=`"name@domain.com`"}"
Write-Output "`nTo completely erase & recreate the junk mail settings:"
Write-Output "Set-MailboxJunkEmailConfiguration $UserIds -Enabled $false"
Write-Output "Set-MailboxJunkEmailConfiguration $UserIds -Enabled $true"
Write-Output "`n"

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:"
    Write-Output $OutputCSV
    $Prompt = New-Object -ComObject wscript.shell
    $UserInput = $Prompt.popup("Do you want to open output file?", 0, "Open Output File", 4)
    if ($UserInput -eq 6) {
        Invoke-Item "$OutputCSV"
    }
}

Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

exit
