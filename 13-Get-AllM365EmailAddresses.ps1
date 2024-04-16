#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-AllM365EmailAddresses.ps1
# Created by m365scripts.com
# modified by Bitpusher/The Digital Fox
# v2.7 last updated 2024-02-26
# Script to generate report of all email addresses on tenant.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-AllM365EmailAddresses.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
#
#comp #m365 #security #bec #script #mailbox #report #powershell #irscript

#Requires -Version 5.1

<#
=============================================================================================
Name:           List all Office 365 email address using PowerShell
Version:        1.0
Website:        m365scripts.com
Script by:      M365Scripts Team
For detailed script execution: https://m365scripts.com/microsoft365/get-all-office-365-email-address-and-alias-using-powershell
============================================================================================
#>
#comp #m365 #security #bec #script
param(
    [string]$OutputPath,
    [Parameter(Mandatory = $false)]
    [switch]$UserMailboxOnly,
    [switch]$SharedMailboxOnly,
    [switch]$DistributionGroupOnly,
    [switch]$DynamicDistributionGroupOnly,
    [switch]$GroupMailboxOnly,
    [switch]$GuestOnly,
    [switch]$ContactOnly,
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


if ($UserMailboxOnly.IsPresent) {
    $RecipientType = "UserMailbox"
} elseif ($SharedMailboxOnly.IsPresent) {
    $RecipientType = "SharedMailbox"
} elseif ($DistributionGroupOnly.IsPresent) {
    $RecipientType = "MailUniversalDistributionGroup"
} elseif ($GroupMailboxOnly.IsPresent) {
    $RecipientType = "GroupMailbox"
} elseif ($DynamicDistributionGroupOnly.IsPresent) {
    $RecipientType = "DynamicDistributionGroup"
} elseif ($GuestOnly.IsPresent) {
    $RecipientType = "GuestMailUser"
} elseif ($ContactOnly.IsPresent) {
    $RecipientType = "MailContact"
} else {
    $RecipientType = 'RoomMailbox', 'LinkedRoomMailbox', 'EquipmentMailbox', 'SchedulingMailbox',
    'LegacyMailbox', 'LinkedMailbox', 'UserMailbox', 'MailContact', 'DynamicDistributionGroup', 'MailForestContact', 'MailNonUniversalGroup', 'MailUniversalDistributionGroup', 'MailUniversalSecurityGroup',
    'RoomList', 'MailUser', 'GuestMailUser', 'GroupMailbox', 'DiscoveryMailbox', 'PublicFolder', 'TeamMailbox', 'SharedMailbox', 'RemoteUserMailbox', 'RemoteRoomMailbox', 'RemoteEquipmentMailbox',
    'RemoteTeamMailbox', 'RemoteSharedMailbox', 'PublicFolderMailbox', 'SharedWithMailUser'
}

$ExportResult = ""
$ExportResults = @()
$OutputCSV = "$OutputPath\$DomainName\M365EmailAddressesReport_$($date).csv"
$Count = 0

#Get all Email addresses in Microsoft 365
Get-Recipient -ResultSize Unlimited -RecipientTypeDetails $RecipientType | ForEach-Object {
    $Count++
    $DisplayName = $_.DisplayName
    Write-Progress -Activity "`n     Retrieving email addresses of $DisplayName.." `n" Processed count: $Count"
    $RecipientTypeDetails = $_.RecipientTypeDetails
    $PrimarySMTPAddress = $_.PrimarySMTPAddress
    $Alias = ($_.EmailAddresses | Where-Object { $_ -clike "smtp:*" } | ForEach-Object { $_ -replace "smtp:", "" }) -join ","
    if ($Alias -eq "") {
        $Alias = "-"
    }

    #Export result to CSV file
    $ExportResult = @{ 'Display Name' = $DisplayName; 'Recipient Type Details' = $RecipientTypeDetails; 'Primary SMTP Address' = $PrimarySMTPAddress; 'Alias' = $Alias }
    $ExportResults = New-Object PSObject -Property $ExportResult
    $ExportResults | Select-Object 'Display Name', 'Recipient Type Details', 'Primary SMTP Address', 'Alias' | Export-Csv -Path $OutputCSV -Notype -Append -Encoding $Encoding
}

#Open output file after execution
if ($Count -eq 0) {
    Write-Output "No objects found"
} else {
    Write-Output "`nThe output file contains $Count records"
    if ((Test-Path -Path $OutputCSV) -eq "True") {
        Write-Output `n" The Output file is available at:"
        Write-Output $OutputCSV
        $Prompt = New-Object -ComObject wscript.shell
        $UserInput = $Prompt.popup("Do you want to open output file?", 0, "Open Output File", 4)
        if ($UserInput -eq 6) {
            Invoke-Item "$OutputCSV"
        }
    }
}

Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

exit
