﻿#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Search-UALActivityByIPAddress.ps1 - By Bitpusher/The Digital Fox
# v2.7 last updated 2024-02-26
# Script to exports data from the Unified Audit Log for specified IP addresses.
#
# Usage:
# powershell -executionpolicy bypass -f .\Search-UALActivityByIPAddress.ps1 -OutputPath "Default" -IPs "1.1.1.1,8.8.8.8" -DaysAgo "10"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
#
#comp #m365 #security #bec #script #irscript #powershell #unified #audit #log #search #ip

#Requires -Version 5.1

param(
    [string]$OutputPath,
    [string]$IPs,
    [string]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$Encoding = "utf8bom" # "ascii","ansi","bigendianunicode","unicode","utf8","utf8","utf8NoBOM","utf32"
)

if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }

$date = Get-Date -Format "yyyyMMddHHmmss"

$CheckLog = (Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled
if (!$CheckLog) {
    Write-Output "The Unified Audit Log does not appear to be enabled on this tenant. Export of UAL activities may fail. Try running 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true' if export fails."
}

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

# If OutputPath does not exist, create it
$CheckOutputPath = Get-Item $OutputPath -ErrorAction SilentlyContinue
if (!$CheckOutputPath) {
    Write-Output ""
    Write-Output "`nOutput path does not exist. Directory will be created."
    mkdir $OutputPath
}

# Get Primary Domain Name for output subfolder
$PrimaryDomain = Get-AcceptedDomain | Where-Object Default -EQ $true
$DomainName = $PrimaryDomain.DomainName

$CheckSubDir = Get-Item $OutputPath\$DomainName -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
    Write-Output "`nDomain sub-directory does not exist. Sub-directory will be created."
    mkdir $OutputPath\$DomainName
}

## If IPs variable is not defined, prompt for it
if (!$IPs) {
    Write-Output ""
    $IPs = Read-Host "Enter the IP address(s) of interest (comma-separated, wildcards are supported)"
}

## If DaysAgo variable is not defined, prompt for it
if (!$DaysAgo) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to retrieve ALL available UAL entries associated with these IP addresses (default: 10, maximum: 90)'
    if ($DaysAgo -eq '') { $DaysAgo = "10" } elseif ($DaysAgo -gt 90) { $DaysAgo = "90" }
}
if ($DaysAgo -gt 90) { $DaysAgo = "90" }
Write-Output "Will search UAC $DaysAgo days back from today for relevant events."
Write-Output "This script does not currently loop through UAC results - Maximum records retrieved is limited to 5000."

$StartDate = (Get-Date).AddDays(- $DaysAgo)
$EndDate = (Get-Date).AddDays(1)

$OutputCSV = "$OutputPath\$DomainName\UnifiedAuditLogEntries_IPaddress_going_back_$($DaysAgo)_days_from_$($date).csv"

Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -IPAddresses $IPs -SessionCommand ReturnLargeSet -ResultSize 5000`n"
$History = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -IPAddresses $IPs -SessionCommand ReturnLargeSet -ResultSize 5000


if (!$History) {
    Write-Output "`nThere are no activities in the audit log for the time period specified`n"
} else {
    $History | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding $Encoding
    Write-Output "`nSee IP address activities report in the output path.`n"
}

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:"
    Write-Output $OutputCSV
    # $Prompt = New-Object -ComObject wscript.shell
    # $UserInput = $Prompt.popup("Do you want to open output file?",0,"Open Output File",4)
    # If ($UserInput -eq 6) {
    # 	Invoke-Item "$OutputCSV"
    # }
}
Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

exit
