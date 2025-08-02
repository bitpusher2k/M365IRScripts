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
# v3.1 last updated 2025-07-26
# Script to trigger set of oft-used investigation scripts with default options at the outset of an investigation.
# "Hydra" because each sub-script "head" is independent (a failure of one will not impact others), and because it's memorable.
#
# Sets output to default "investigation" desktop folder and sets scope to past seven days by default.
#
# Runs:
# * 10-Get-BasicTenantInformation.ps1
# * 18-Search-InboxRuleChanges.ps1 (first pass)
# * 11-Get-EntraIDAuditAndSignInLogs30-P1.ps1
# * 12-Search-UnifiedAuditLogSignIn.ps1
# * 13-Get-AllM365EmailAddresses.ps1
# * 14-Get-AllUserPasswordReport.ps1
# * 17-Search-MailboxSuspiciousRules.ps1
# * 19-Get-AllInboxRules.ps1
# * 22-Get-EnterpriseApplications.ps1
# * 20-Get-ForwardingSettings.ps1
# * 21-Get-MailboxPermissions.ps1
# * 23-Get-DefenderInformation.ps1
# * 24-Get-EntraIDRisk.ps1
# * 90-Get-MFAReport.ps1
# * 91-Get-CAPReport-P1.ps1
# * 93-Get-SecureScoreInformation.ps1
# * OPTIONALLY: 15-Search-UnifiedAuditLogIR.ps1
# * OPTIONALLY: Get-UnifiedAuditLogEntries.ps1
# * 18-Search-InboxRuleChanges.ps1 (second pass)
# * OPTIONALLY: Run several Invictus IR Microsoft Extractor Suite cmdlets for additional reports
# * OPTIONALLY: Run CrowdStrike Reporting Tool for Azure (Get-CRTReport.ps1) for additional reports
#
# Usage:
# powershell -executionpolicy bypass -f .\Hydra-Collect.ps1
#
# powershell -executionpolicy bypass -f .\Hydra-Collect.ps1 -OutputPath "Default" -DaysAgo 7
#
# powershell -executionpolicy bypass -f .\Hydra-Collect.ps1 -OutputPath "Default" -StartDate "2025-06-01" -EndDate "2025-06-10"
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
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
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

$modules = @("Microsoft.Graph", "Microsoft.Graph.Beta", "ExchangeOnlineManagement", "Microsoft-Extractor-Suite")

foreach ($module in $modules) {
    if (Get-Module -ListAvailable -Name $module) {
        Write-Output "$(Get-TimeStamp) $module already installed"
    } else {
        Write-Output "$(Get-TimeStamp) Installing $module"
        Install-Module $module -Force -SkipPublisherCheck -Scope CurrentUser -ErrorAction Stop | Out-Null
    }
}

$modules = @("Microsoft.Graph", "ExchangeOnlineManagement", "Microsoft-Extractor-Suite")

foreach ($module in $modules) {
    if (Get-Module -Name $module) {
        Write-Output "$(Get-TimeStamp) $module already loaded"
    } else {
        Write-Output "$(Get-TimeStamp) Loading $module"
        Import-Module $module -Force -Scope Local | Out-Null
    }
}

#endregion initialization

$date = Get-Date -Format "yyyyMMddHHmmss"

$EXOInfo = Get-ConnectionInformation
$GraphInfo = Get-MgContext

if ($EXOInfo) {
    Write-Output "Exchange Online connection status:" | Tee-Object -FilePath $logFilePath -Append
    $EXOInfo.State | Tee-Object -FilePath $logFilePath -Append
    $EXOInfo.TenantID | Tee-Object -FilePath $logFilePath -Append
    $EXOInfo.UserPrincipalName | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "Exchange Online Management module not connected." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Run .\01-Connect-M365Modules.ps1 or Connect-ExchangeOnline to connect." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Ending." | Tee-Object -FilePath $logFilePath -Append
    exit
}

if ($GraphInfo) {
    Write-Output "Graph connection status:" | Tee-Object -FilePath $logFilePath -Append
    $GraphInfo.AuthType | Tee-Object -FilePath $logFilePath -Append
    $GraphInfo.TenantID | Tee-Object -FilePath $logFilePath -Append
    $GraphInfo.Account | Tee-Object -FilePath $logFilePath -Append
    $GraphInfo.Scopes | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "Exchange Online Management module not connected." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Run .\01-Connect-M365Modules.ps1 or Connect-MgGraph with proper scopes to connect." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Ending." | Tee-Object -FilePath $logFilePath -Append
    exit
}


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

## Get valid starting end ending dates
if (!$DaysAgo -and (!$StartDate -or !$EndDate)) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to retrieve relevant UAL entries (default: 10, maximum: 180)'
    if ($DaysAgo -eq '') { $DaysAgo = "10" } elseif ($DaysAgo -gt 180) { $DaysAgo = "180" }
}

if ($DaysAgo) {
    if ($DaysAgo -gt 180) { $DaysAgo = "180" }
    Write-Output "`nScript will search UAC $DaysAgo days back from today for relevant events." | Tee-Object -FilePath $logFilePath -Append
    $StartDate = (Get-Date).touniversaltime().AddDays(-$DaysAgo)
    $EndDate = (Get-Date).touniversaltime()
    Write-Output "StartDate: $StartDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "EndDate: $EndDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
} elseif ($StartDate -and $EndDate) {
    $StartDate = ($StartDate).touniversaltime()
    $EndDate = ($EndDate).touniversaltime()
    if ($StartDate -lt (Get-Date).touniversaltime().AddDays(-180)) { $StartDate = (Get-Date).touniversaltime().AddDays(-180) }
    if ($StartDate -ge $EndDate) { $EndDate = ($StartDate).AddDays(1) }
    Write-Output "`nScript will search UAC between StartDate and EndDate for relevant events." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "StartDate: $StartDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "EndDate: $EndDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "Neither DaysAgo nor StartDate/EndDate specified. Ending." | Tee-Object -FilePath $logFilePath -Append
    exit
}

Write-Output "`nRunning 10-Get-BasicTenantInformation.ps1..." | Tee-Object -FilePath $logFilePath -Append
& "$PSScriptRoot\10-Get-BasicTenantInformation.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 18-Search-InboxRuleChanges.ps1... First pass..." | Tee-Object -FilePath $logFilePath -Append
& "$PSScriptRoot\18-Search-InboxRuleChanges.ps1" -OutputPath $OutputPath -StartDate $StartDate -EndDate $EndDate

Write-Output "`nRunning 11-Get-EntraIDAuditAndSignInLogs30-P1.ps1..." | Tee-Object -FilePath $logFilePath -Append
& "$PSScriptRoot\11-Get-EntraIDAuditAndSignInLogs30-P1.ps1" -OutputPath $OutputPath -StartDate $StartDate -EndDate $EndDate

Write-Output "`nRunning 12-Search-UnifiedAuditLogSignIn.ps1..." | Tee-Object -FilePath $logFilePath -Append
& "$PSScriptRoot\12-Search-UnifiedAuditLogSignIn.ps1" -OutputPath $OutputPath -StartDate $StartDate -EndDate $EndDate -UserIds "ALL"

Write-Output "`nRunning 13-Get-AllM365EmailAddresses.ps1..." | Tee-Object -FilePath $logFilePath -Append
& "$PSScriptRoot\13-Get-AllM365EmailAddresses.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 14-Get-AllUserPasswordReport.ps1..." | Tee-Object -FilePath $logFilePath -Append
& "$PSScriptRoot\14-Get-AllUserPasswordReport.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 17-Search-MailboxSuspiciousRules.ps1..." | Tee-Object -FilePath $logFilePath -Append
& "$PSScriptRoot\17-Search-MailboxSuspiciousRules.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 19-Get-AllInboxRules.ps1..." | Tee-Object -FilePath $logFilePath -Append
& "$PSScriptRoot\19-Get-AllInboxRules.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 22-Get-EnterpriseApplications.ps1..." | Tee-Object -FilePath $logFilePath -Append
& "$PSScriptRoot\22-Get-EnterpriseApplications.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 20-Get-ForwardingSettings.ps1..." | Tee-Object -FilePath $logFilePath -Append
& "$PSScriptRoot\20-Get-ForwardingSettings.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 21-Get-MailboxPermissions.ps1..." | Tee-Object -FilePath $logFilePath -Append
& "$PSScriptRoot\21-Get-MailboxPermissions.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 23-Get-DefenderInformation.ps1..." | Tee-Object -FilePath $logFilePath -Append
& "$PSScriptRoot\23-Get-DefenderInformation.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 24-Get-EntraIDRisk.ps1..." | Tee-Object -FilePath $logFilePath -Append
& "$PSScriptRoot\24-Get-EntraIDRisk.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 90-Get-MFAReport.ps1..." | Tee-Object -FilePath $logFilePath -Append
& "$PSScriptRoot\90-Get-MFAReport.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 91-Get-CAPReport-P1.ps1..." | Tee-Object -FilePath $logFilePath -Append
& "$PSScriptRoot\91-Get-CAPReport-P1.ps1" -OutputPath $OutputPath

Write-Output "`nRunning 93-Get-SecureScoreInformation.ps1..." | Tee-Object -FilePath $logFilePath -Append
& "$PSScriptRoot\93-Get-SecureScoreInformation.ps1" -OutputPath $OutputPath

$Response = Read-Host "`nRetrieve often relevant UAL entries between StartDate and EndDate? (Y/N - default N)"
if ($Response -eq 'Y') {
    Write-Output "`nRunning 15-Search-UnifiedAuditLogIR.ps1..." | Tee-Object -FilePath $logFilePath -Append
    & "$PSScriptRoot\15-Search-UnifiedAuditLogIR.ps1" -OutputPath $OutputPath -StartDate $StartDate -EndDate $EndDate
}

$Response = Read-Host "`nRetrieve all available UAL entries for between StartDate and EndDate? (Y/N - default N)"
if ($Response -eq 'Y') {
    Write-Output "`nRunning Get-UnifiedAuditLogEntries.ps1..." | Tee-Object -FilePath $logFilePath -Append
    & "$PSScriptRoot\16-Get-UnifiedAuditLogEntries.ps1" -OutputPath $OutputPath -StartDate $StartDate -EndDate $EndDate
}

Write-Output "`nRunning 18-Search-InboxRuleChanges.ps1... Second pass (often gets info when first is blank)..." | Tee-Object -FilePath $logFilePath -Append
& "$PSScriptRoot\18-Search-InboxRuleChanges.ps1" -OutputPath $OutputPath -StartDate $StartDate -EndDate $EndDate

Write-Output "`nRun a set of Invictus IR Microsoft Extractor Suite cmdlets to:"
Write-Output "* Generate CSV report Security Defaults settings"
Write-Output "* Generate CSV report of transport rules"
Write-Output "* Generate CSV report of security alerts"
Write-Output "* Generate reports of Admin users"
Write-Output "* Generate CSV report of mailbox audit status"
Write-Output "* Generate CSV report of OAuth permissions"
Write-Output "* Generate CSV report of user's MFA settings"
$Response = Read-Host "Run cmdlets? (Y/N - default N)"
if ($Response -eq 'Y') {
    Write-Output "`nRunning Invictus IR cmdlets..." | Tee-Object -FilePath $logFilePath -Append
    Get-EntraSecurityDefaults -OutputDir $IRoutput
    Get-TransportRules -OutputDir $IRoutput
    Get-SecurityAlerts -OutputDir $IRoutput -DaysBack $DaysAgo
    Get-AdminUsers -OutputDir $IRoutput
    Get-MailboxAuditStatus -OutputDir $IRoutput
    Get-OAuthPermissionsGraph -OutputDir $IRoutput
    Get-MFA -OutputDir $IRoutput
    # Get-ConditionalAccessPolicies -OutputDir $IRoutput
    # Get-MailboxPermissions -OutputDir $IRoutput
}

Write-Output "`nRun CrowdStrike Reporting Tool for Azure to generate reports related to:"
Write-Output "* Federation Configuration"
Write-Output "* Federation Trust"
Write-Output "* Client Access Settings Configured on Mailboxes"
Write-Output "* Mail Forwarding Rules for Remote Domains"
Write-Output "* Mailbox SMTP Forwarding Rules"
Write-Output "* Mail Transport Rules"
Write-Output "* Delegates with 'Full Access' and those with Any Permissions Granted"
Write-Output "* Delegates with 'Send As' or 'SendOnBehalf' Permissions"
Write-Output "* Exchange Online PowerShell Enabled Users"
Write-Output "* Users with 'Audit Bypass' Enabled"
Write-Output "* Mailboxes Hidden from the Global Address List (GAL)"
Write-Output "* Administrator audit logging configuration settings"
$Response = Read-Host "`nRun CrowdStrike Reporting Tool for Azure (CRT - will prompt for Exchange Online and Azure AD auth and disconnect after)? (Y/N - default N)"
if ($Response -eq 'Y') {
    Write-Output "`nDownloading and Running Get-CRTReport.ps1..." | Tee-Object -FilePath $logFilePath -Append
    Invoke-WebRequest "https://github.com/CrowdStrike/CRT/raw/refs/heads/main/Get-CRTReport.ps1" -OutFile $PSScriptRoot\Get-CRTReport.ps1
    & "$PSScriptRoot\Get-CRTReport.ps1" -WorkingDirectory $IRoutput -Interactive
}

Write-Output "`nScript complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append


Write-Output "After identifying suspect IP addresses recommend pulling all logged actions with:" | Tee-Object -FilePath $logFilePath -Append
Write-Output ".\36-Search-UALActivityByIPAddress.ps1" | Tee-Object -FilePath $logFilePath -Append


Invoke-Item "$OutputPath\$DomainName"

exit
