#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-EntraIDRisk.ps1 - By Bitpusher/The Digital Fox
# v2.7 last updated 2024-02-26
# Script to list risk detections by Entra ID and generate report.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-EntraIDRisk.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses (ExchangePowerShell), Microsoft Graph commands.
#
#comp #m365 #security #bec #script #irscript #powershell #entraid #risk

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

$OutputCSVDetection = "$OutputPath\$DomainName\EntraRiskDetection_$($date).csv"
$OutputCSVUsers = "$OutputPath\$DomainName\EntraRiskyUsers_$($date).csv"


# List all risk detections
# Get-MgRiskDetection -Filter "RiskType eq 'anonymizedIPAddress'" | Format-Table UserDisplayName, RiskType, RiskLevel, DetectedDateTime
$RiskDetection = Get-MgRiskDetection
$RiskDetection | Format-List UserDisplayName, RiskState, RiskType, RiskLevel, DetectedDateTime, Activity, IPAddress, ID
$RiskDetection | Export-Csv -Path $OutputCSVDetection -NoTypeInformation -Encoding $Encoding

Write-Output "`nTo remove a risk detection: Remove-MgRiskDetection -RiskDetectionID XXXX"
Write-Output "or go to https://portal.azure.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskDetections and https://portal.azure.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskySignIns"

# # List all high risk detections for the user 'User01'
# Get-MgRiskDetection -Filter "UserDisplayName eq 'User01' and Risklevel eq 'high'" | Format-Table UserDisplayName, RiskType, RiskLevel, DetectedDateTime

# List all high risk users (if licensed)
try {
    $RiskyUserCount = Get-MgRiskyUserCount -ErrorAction:Stop
    Write-Output "Risky user count: $RiskyUserCount"
    $RiskyUser = Get-MgRiskyUser
    $RiskyUser | Format-Table UserDisplayName, RiskDetail, RiskLevel, RiskLastUpdatedDateTime
    $RiskyUser | Export-Csv -Path $OutputCSVUsers -NoTypeInformation -Encoding $Encoding
    Write-Output "`nTo list history: Get-MgRiskyUserHistory -RiskyUserId $riskyUserId"
    Write-Output "`nTo dismiss risk for all users: Get-MgRiskyUser | Invoke-MgDismissRiskyUser"
    Write-Output "`nTo dismiss risk for users with risk older than 90 days:"
    Write-Output "`$riskyUsers = Get-MgRiskyUser -Filter `"RiskLevel eq 'high'`" | where RiskLastUpdatedDateTime -LT (Get-Date).AddDays(-90) | Invoke-MgDismissRiskyUser -UserIds `$riskyUsers.Id"
    Write-Output "or go to https://portal.azure.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskyUsers to view/manage"
} catch {
    Write-Output "`n`nTenant does not appear to be licensed to retrieve risky user information through Graph - Go to https://portal.azure.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskyUsers to view/manage"
}

Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

exit
