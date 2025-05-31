#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Hydra-Collect.ps1 - By Bitpusher/The Digital Fox
# v3.0 last updated 2025-05-31
# Script to trigger set of oft-used investigation scripts with default options at the outset of an investigation.
# "Hydra" because each sub-script "head" is independent (a failure of one will not impact others), and because it's memorable.
#
# Sets output to default "investigation" desktop folder and sets scope to past seven days by default.
#
# Runs:
# * 10-Get-BasicTenantInformation.ps1
# * 11-Get-EntraIDAuditAndSignInLogs30-P1.ps1
# * 12-Search-UnifiedAuditLogSignIn.ps1
# * 13-Get-AllM365EmailAddresses.ps1
# * 14-Get-AllUserPasswordReport.ps1
# * 17-Search-MailboxSuspiciousRules.ps1
# * 18-Search-InboxRuleChanges.ps1
# * 19-Get-AllInboxRules.ps1
# * 22-Get-EnterpriseApplications.ps1
# * 23-Get-DefenderInformation.ps1
# * 24-Get-EntraIDRisk.ps1
# * 90-Get-MFAReport.ps1
# * 91-Get-CAPReport-P1.ps1
# * 93-Get-SecureScoreInformation.ps1
# * OPTIONALLY: Get-UnifiedAuditLogEntries.ps1
#
# Usage:
# powershell -executionpolicy bypass -f .\Hydra-Collect.ps1
#
# powershell -executionpolicy bypass -f .\Hydra-Collect.ps1 -OutputPath "Default" -DaysAgo 7
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell, AzureAD, Microsoft Graph commands. 
#
#comp #m365 #security #bec #script #info #hydra #collect #tenant

#Requires -Version 5.1

param(
    [string]$OutputPath = "Default",
    [string]$DaysAgo = 7,
    [string]$scriptName = "Hydra-Collect",
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
    [string]$Encoding = "utf8bom" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
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

Write-Output "`nRunning 10-Get-BasicTenantInformation.ps1..."
& "$PSScriptRoot\10-Get-BasicTenantInformation.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 11-Get-EntraIDAuditAndSignInLogs30-P1.ps1..."
& "$PSScriptRoot\11-Get-EntraIDAuditAndSignInLogs30-P1.ps1" -OutputPath $OutputPath -DaysAgo $DaysAgo

Write-Output "`nRunning 12-Search-UnifiedAuditLogSignIn.ps1..."
& "$PSScriptRoot\12-Search-UnifiedAuditLogSignIn.ps1" -OutputPath $OutputPath -DaysAgo $DaysAgo -UserIds "ALL"

Write-Output "`nRunning 13-Get-AllM365EmailAddresses.ps1..."
& "$PSScriptRoot\13-Get-AllM365EmailAddresses.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 14-Get-AllUserPasswordReport.ps1..."
& "$PSScriptRoot\14-Get-AllUserPasswordReport.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 17-Search-MailboxSuspiciousRules.ps1..."
& "$PSScriptRoot\17-Search-MailboxSuspiciousRules.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 18-Search-InboxRuleChanges.ps1..."
& "$PSScriptRoot\18-Search-InboxRuleChanges.ps1" -OutputPath $OutputPath -DaysAgo $DaysAgo

Write-Output "`nRunning 19-Get-AllInboxRules.ps1..."
& "$PSScriptRoot\19-Get-AllInboxRules.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 22-Get-EnterpriseApplications.ps1..."
& "$PSScriptRoot\22-Get-EnterpriseApplications.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 23-Get-DefenderInformation.ps1..."
& "$PSScriptRoot\23-Get-DefenderInformation.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 24-Get-EntraIDRisk.ps1..."
& "$PSScriptRoot\24-Get-EntraIDRisk.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 90-Get-MFAReport.ps1..."
& "$PSScriptRoot\90-Get-MFAReport.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 91-Get-CAPReport-P1.ps1..."
& "$PSScriptRoot\91-Get-CAPReport-P1.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 93-Get-SecureScoreInformation.ps1..."
& "$PSScriptRoot\93-Get-SecureScoreInformation.ps1" -OutputPath $OutputPath

$UAL = Read-Host 'Retrieve all available UAL entries for past $DaysAgo days? (Y/N)'
if ($UAL -eq 'Y') {
    Write-Output "`nRunning Get-UnifiedAuditLogEntries.ps1..."
    & "$PSScriptRoot\Get-UnifiedAuditLogEntries.ps1" -OutputPath $OutputPath -DaysAgo $DaysAgo
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"

exit
