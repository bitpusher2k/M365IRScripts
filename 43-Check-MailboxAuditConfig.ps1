#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#          @VinceVulpes
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Check-MailboxAuditConfig.ps1 - By Bitpusher/The Digital Fox
# v4.0.0 last updated 2026-04-27
# Script to verify mailbox audit configuration across a tenant.
# Checks that AuditEnabled is $true and that AuditLogAgeLimit is adequate
# for each mailbox. Mailbox audit logging is enabled by default,
# and threat actors have been known to disable mailbox
# auditing (Set-Mailbox -AuditEnabled $false) as an anti-forensics
# technique to prevent their activity from being logged.
#
# Also checks the organization-level audit configuration to verify
# that auditing is enabled at the tenant level.
#
# Reports:
# - All mailboxes with auditing disabled
# - Mailboxes with audit log age limits below a specified threshold
# - Mailboxes where AuditBypassEnabled is set (audit bypass)
# - Organization-level audit configuration summary
#
# Usage:
# powershell -executionpolicy bypass -f .\Check-MailboxAuditConfig.ps1 -OutputPath "Default"
# powershell -executionpolicy bypass -f .\Check-MailboxAuditConfig.ps1 -OutputPath "Default" -MinAuditAge 180
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
# Minimally required tenant role(s): Exchange RBAC "View-Only Org Mgmt"
#
# References:
# https://learn.microsoft.com/en-us/purview/audit-mailboxes
# https://learn.microsoft.com/en-us/powershell/module/exchange/set-mailbox
# https://learn.microsoft.com/en-us/purview/audit-log-enable-disable
# https://learn.microsoft.com/en-us/microsoft-365/compliance/enable-mailbox-auditing
#
#comp #m365 #security #bec #script #irscript #powershell #audit #mailbox #forensics #configuration

#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement, Microsoft.Graph.Identity.DirectoryManagement

param(
    [string]$OutputPath = "Default",
    [int]$MinAuditAge = 90,
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Check-MailboxAuditConfig",
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
    [string]$Encoding = "utf8NoBOM",
    [switch]$NoExplorer
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


function Assert-M365Connection {
    <#
    .SYNOPSIS
    Checks for active Exchange Online and/or MS Graph connections and attempts to connect if missing.
    Scoped to the minimum permissions required by this script.
    #>
    param(
        [switch]$RequireEXO,
        [switch]$RequireGraph,
        [switch]$RequireIPPS,
        [string[]]$GraphScopes
    )

    if ($RequireEXO) {
        $exoConnected = $false
        try { $exoConnected = [bool](Get-ConnectionInformation -ErrorAction SilentlyContinue) } catch {}
        if (-not $exoConnected) {
            Write-Output "Exchange Online not connected. Attempting connection..."
            try {
                Connect-ExchangeOnline -ShowBanner:$false
                Write-Output "Exchange Online connected."
            } catch {
                Write-Error "Failed to connect to Exchange Online: $_"
                exit 1
            }
        } else {
            Write-Output "Exchange Online connection verified."
        }
    }

    if ($RequireIPPS) {
        $ippsConnected = $false
        try { $ippsConnected = [bool](Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionUri -match "compliance" }) } catch {}
        if (-not $ippsConnected) {
            Write-Output "Security & Compliance (IPPS) not connected. Attempting connection..."
            try {
                Connect-IPPSSession -ShowBanner:$false
                Write-Output "IPPS connected."
            } catch {
                Write-Error "Failed to connect to IPPS: $_"
                exit 1
            }
        } else {
            Write-Output "IPPS connection verified."
        }
    }

    if ($RequireGraph) {
        $graphContext = $null
        try { $graphContext = Get-MgContext -ErrorAction SilentlyContinue } catch {}
        if (-not $graphContext) {
            Write-Output "MS Graph not connected. Attempting connection with scopes: $($GraphScopes -join ', ')..."
            try {
                Connect-MgGraph -Scopes $GraphScopes -NoWelcome
                Write-Output "MS Graph connected."
            } catch {
                Write-Error "Failed to connect to MS Graph: $_"
                exit 1
            }
        } else {
            # Verify required scopes are present
            $currentScopes = $graphContext.Scopes
            $missingScopes = $GraphScopes | Where-Object { $_ -notin $currentScopes }
            if ($missingScopes) {
                Write-Output "MS Graph connected but missing scopes: $($missingScopes -join ', '). Reconnecting..."
                try {
                    Connect-MgGraph -Scopes $GraphScopes -NoWelcome
                    Write-Output "MS Graph reconnected with required scopes."
                } catch {
                    Write-Warning "Could not reconnect with required scopes. Some operations may fail."
                }
            } else {
                Write-Output "MS Graph connection verified with required scopes."
            }
        }
    }
}

$sw = [Diagnostics.StopWatch]::StartNew()

Assert-M365Connection -RequireEXO

Write-Output "$scriptName started on $ComputerName by $ScriptUserName at $(Get-TimeStamp)" | Tee-Object -FilePath $logFilePath -Append
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
$PrimaryDomain = Get-AcceptedDomain | Where-Object Default -EQ $true
$DomainName = $PrimaryDomain.DomainName

$CheckSubDir = Get-Item $OutputPath\$DomainName -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
    Write-Output ""
    Write-Output "Domain sub-directory does not exist. Sub-directory `"$DomainName`" will be created." | Tee-Object -FilePath $logFilePath -Append
    mkdir $OutputPath\$DomainName
}
Write-Output "Domain sub-directory will be `"$DomainName`"" | Tee-Object -FilePath $logFilePath -Append

$OutputCSV = "$OutputPath\$DomainName\MailboxAuditConfig_$($date).csv"
$OutputCSVIssues = "$OutputPath\$DomainName\MailboxAuditConfigIssues_$($date).csv"

## Phase 1: Check organization-level audit configuration
Write-Output "`n===== ORGANIZATION AUDIT CONFIGURATION =====" | Tee-Object -FilePath $logFilePath -Append

try {
    $orgConfig = Get-OrganizationConfig | Select-Object AuditDisabled, Name, DisplayName
    if ($orgConfig.AuditDisabled -eq $true) {
        Write-Output "WARNING: Organization-level auditing is DISABLED! (AuditDisabled = True)" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "Enable with: Set-OrganizationConfig -AuditDisabled `$false" | Tee-Object -FilePath $logFilePath -Append
    } else {
        Write-Output "Organization-level auditing is enabled. (AuditDisabled = False)" | Tee-Object -FilePath $logFilePath -Append
    }
} catch {
    Write-Output "Could not retrieve Organization Config: $_" | Tee-Object -FilePath $logFilePath -Append
}

## Phase 2: Check admin audit log configuration
try {
    $adminAuditConfig = Get-AdminAuditLogConfig | Select-Object AdminAuditLogEnabled, AdminAuditLogAgeLimit, UnifiedAuditLogIngestionEnabled
    Write-Output "Admin Audit Log Enabled: $($adminAuditConfig.AdminAuditLogEnabled)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Admin Audit Log Age Limit: $($adminAuditConfig.AdminAuditLogAgeLimit)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Unified Audit Log Ingestion Enabled: $($adminAuditConfig.UnifiedAuditLogIngestionEnabled)" | Tee-Object -FilePath $logFilePath -Append
    if ($adminAuditConfig.UnifiedAuditLogIngestionEnabled -ne $true) {
        Write-Output "WARNING: Unified Audit Log ingestion is not enabled!" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "Enable with: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled `$true" | Tee-Object -FilePath $logFilePath -Append
    }
} catch {
    Write-Output "Could not retrieve Admin Audit Log Config: $_" | Tee-Object -FilePath $logFilePath -Append
}

## Phase 3: Check per-mailbox audit configuration
Write-Output "`n===== PER-MAILBOX AUDIT CONFIGURATION =====" | Tee-Object -FilePath $logFilePath -Append
Write-Output "Minimum acceptable audit age: $MinAuditAge days" | Tee-Object -FilePath $logFilePath -Append
Write-Output "Retrieving mailbox audit settings for all mailboxes (this may take a while)..." | Tee-Object -FilePath $logFilePath -Append

$mailboxes = Get-Mailbox -ResultSize Unlimited | Select-Object DisplayName, PrimarySmtpAddress, GUID, AuditEnabled, AuditLogAgeLimit, AuditBypassEnabled, RecipientTypeDetails, DefaultAuditSet

$allResults = @()
$issueResults = @()

foreach ($mbx in $mailboxes) {
    $issues = @()

    # Check if auditing is disabled
    if ($mbx.AuditEnabled -ne $true) {
        $issues += "AuditDisabled"
    }

    # Check audit log age limit
    $ageLimit = $mbx.AuditLogAgeLimit
    $ageLimitDays = 0
    if ($ageLimit) {
        $ageLimitDays = $ageLimit.Days
    }
    if ($ageLimitDays -lt $MinAuditAge) {
        $issues += "AuditAgeTooShort($($ageLimitDays)d)"
    }

    # Check if audit bypass is enabled
    if ($mbx.AuditBypassEnabled -eq $true) {
        $issues += "AuditBypassEnabled"
    }

    # Check if using default audit set (which may not cover all needed actions)
    $defaultAuditSet = ""
    if ($mbx.DefaultAuditSet) {
        $defaultAuditSet = ($mbx.DefaultAuditSet -join ", ")
    }

    $mbxHash = [ordered]@{
        DisplayName           = $mbx.DisplayName
        PrimarySmtpAddress    = $mbx.PrimarySmtpAddress
        RecipientTypeDetails  = $mbx.RecipientTypeDetails
        AuditEnabled          = $mbx.AuditEnabled
        AuditLogAgeLimitDays  = $ageLimitDays
        AuditBypassEnabled    = $mbx.AuditBypassEnabled
        DefaultAuditSet       = $defaultAuditSet
        Issues                = ($issues -join ", ")
        GUID                  = $mbx.GUID
    }

    $mbxObject = New-Object PSObject -Property $mbxHash
    $allResults += $mbxObject

    if ($issues.Count -gt 0) {
        $issueResults += $mbxObject
    }
}

# Export all mailbox audit configs
$allResults | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding $Encoding
Write-Output "`nTotal mailboxes checked: $($allResults.Count)" | Tee-Object -FilePath $logFilePath -Append

# Summary
$disabledCount = ($allResults | Where-Object { $_.AuditEnabled -ne $true }).Count
$shortAgeCount = ($allResults | Where-Object { $_.AuditLogAgeLimitDays -lt $MinAuditAge -and $_.AuditEnabled -eq $true }).Count
$bypassCount = ($allResults | Where-Object { $_.AuditBypassEnabled -eq $true }).Count

Write-Output "`n===== MAILBOX AUDIT HEALTH SUMMARY =====" | Tee-Object -FilePath $logFilePath -Append
Write-Output "Mailboxes with auditing disabled: $disabledCount" | Tee-Object -FilePath $logFilePath -Append
Write-Output "Mailboxes with audit age < $MinAuditAge days: $shortAgeCount" | Tee-Object -FilePath $logFilePath -Append
Write-Output "Mailboxes with audit bypass enabled: $bypassCount" | Tee-Object -FilePath $logFilePath -Append
Write-Output "Mailboxes with no issues: $($allResults.Count - $issueResults.Count)" | Tee-Object -FilePath $logFilePath -Append

if ($issueResults.Count -gt 0) {
    Write-Output "`n===== MAILBOXES WITH AUDIT ISSUES =====" | Tee-Object -FilePath $logFilePath -Append
    $issueResults | Format-Table DisplayName, PrimarySmtpAddress, AuditEnabled, AuditLogAgeLimitDays, AuditBypassEnabled, Issues -AutoSize
    $issueResults | Export-Csv -Path $OutputCSVIssues -NoTypeInformation -Encoding $Encoding

    Write-Output "`nRemediation commands:" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "  Enable auditing:    Set-Mailbox -Identity '<email>' -AuditEnabled `$true" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "  Set audit age:      Set-Mailbox -Identity '<email>' -AuditLogAgeLimit 180" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "  Disable bypass:     Set-MailboxAuditBypassAssociation -Identity '<email>' -AuditBypassEnabled `$false" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "  Enable all (bulk):  Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled `$true -AuditLogAgeLimit 180" | Tee-Object -FilePath $logFilePath -Append

    Write-Output "`nNOTE: Since January 2019, Microsoft enables mailbox auditing by default for all" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "M365 organizations. If auditing is explicitly disabled on a mailbox, this may" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "indicate an anti-forensics action by a threat actor and should be investigated." | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "`nAll mailbox audit configurations appear healthy." | Tee-Object -FilePath $logFilePath -Append
}

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:" | Tee-Object -FilePath $logFilePath -Append
    Write-Output $OutputCSV | Tee-Object -FilePath $logFilePath -Append
}
if ((Test-Path -Path $OutputCSVIssues) -eq "True") {
    Write-Output " Issues report:" | Tee-Object -FilePath $logFilePath -Append
    Write-Output $OutputCSVIssues | Tee-Object -FilePath $logFilePath -Append
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append
Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
if (-not $NoExplorer) { Invoke-Item "$OutputPath\$DomainName" }
Exit
