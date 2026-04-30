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
# Get-AdminAuditLog.ps1 - By Bitpusher/The Digital Fox
# v4.0.0 last updated 2026-04-27
# Script to search the Unified Audit Log specifically for administrative
# operations that could indicate privilege escalation, persistence, or
# lateral movement by a threat actor. Focuses on:
# - Role/group membership changes (Global Admin, Exchange Admin, etc.)
# - Domain additions/modifications/federation changes
# - Conditional Access Policy modifications
# - Password resets performed by admins (not self-service)
# - Service principal/app registration changes
# - Mailbox delegation changes
# - Organization configuration changes
#
# This supplements script 15 (Search-UnifiedAuditLogIR) by focusing
# exclusively on admin-tier operations for scoping privilege escalation.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-AdminAuditLog.ps1 -OutputPath "Default" -DaysAgo "30"
# powershell -executionpolicy bypass -f .\Get-AdminAuditLog.ps1 -OutputPath "Default" -UserIds "admin@contoso.com" -DaysAgo "90"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell (Search-UnifiedAuditLog) commands.
# Minimally required tenant role(s): Exchange RBAC "View-Only Org Mgmt"
#
# References:
# https://learn.microsoft.com/en-us/purview/audit-log-activities#directory-administration-activities
# https://learn.microsoft.com/en-us/purview/audit-log-activities#role-administration-activities
# https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-compromised-malicious-app
# https://www.microsoft.com/en-us/security/blog/2024/01/17/new-microsoft-incident-response-guides-help-security-teams-analyze-suspicious-activity/
#
#comp #m365 #security #bec #script #irscript #powershell #admin #audit #privilege #escalation #ual

#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement, Microsoft.Graph.Identity.DirectoryManagement

param(
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Get-AdminAuditLog",
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

Assert-M365Connection -RequireEXO -RequireGraph -GraphScopes @("Domain.Read.All")

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
Write-Output "Domain sub-directory will be `"$DomainName`"" | Tee-Object -FilePath $logFilePath -Append

## Get valid starting and ending dates
if (!$DaysAgo -and (!$StartDate -or !$EndDate)) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to search for admin events (default: 30, maximum: 180)'
    if ($DaysAgo -eq '') { $DaysAgo = "30" } elseif ($DaysAgo -gt 180) { $DaysAgo = "180" }
}

if ($DaysAgo) {
    if ($DaysAgo -gt 180) { $DaysAgo = "180" }
    Write-Output "`nScript will search $DaysAgo days back from today for admin events." | Tee-Object -FilePath $logFilePath -Append
    $StartDate = (Get-Date).ToUniversalTime().AddDays(-$DaysAgo)
    $EndDate = (Get-Date).ToUniversalTime()
    Write-Output "StartDate: $StartDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "EndDate: $EndDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
} elseif ($StartDate -and $EndDate) {
    $StartDate = ($StartDate).ToUniversalTime()
    $EndDate = ($EndDate).ToUniversalTime()
    if ($StartDate -lt (Get-Date).ToUniversalTime().AddDays(-180)) { $StartDate = (Get-Date).ToUniversalTime().AddDays(-180) }
    if ($StartDate -ge $EndDate) { $EndDate = ($StartDate).AddDays(1) }
    Write-Output "`nScript will search between StartDate and EndDate for admin events." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "StartDate: $StartDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "EndDate: $EndDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "Neither DaysAgo nor StartDate/EndDate specified. Ending." | Tee-Object -FilePath $logFilePath -Append
    exit
}

$OutputCSV = "$OutputPath\$DomainName\AdminAuditLog_$($date).csv"

## Admin-tier operations to search for
$adminOperations = @(
    # Role and group membership changes
    "Add member to role.",
    "Remove member from role.",
    "Add member to group.",
    "Remove member from group.",
    "Add eligible member to role.",
    "Remove eligible member from role.",
    # Domain operations
    "Add domain to company.",
    "Remove domain from company.",
    "Set domain authentication.",
    "Set federation settings on domain.",
    "Set company information.",
    "Update domain.",
    "Verify domain.",
    # Conditional Access Policy operations
    "Add policy.",
    "Update policy.",
    "Delete policy.",
    # Password operations (admin-initiated)
    "Reset user password.",
    "Change user password.",
    "Set force change user password.",
    # Service principal/app operations
    "Add service principal.",
    "Remove service principal.",
    "Add service principal credentials.",
    "Remove service principal credentials.",
    "Add app role assignment grant to user.",
    "Add application.",
    "Update application.",
    "Remove application.",
    # Mailbox delegation
    "Add-MailboxPermission",
    "Remove-MailboxPermission",
    "Add-RecipientPermission",
    "Remove-RecipientPermission",
    "Set-Mailbox",
    # Organization settings
    "Set-OrganizationConfig",
    "Set-AdminAuditLogConfig",
    "Set-TransportRule",
    "New-TransportRule",
    "Remove-TransportRule",
    # User management
    "Add user.",
    "Delete user.",
    "Update user.",
    "Disable account.",
    # Elevated access
    "Elevate Access."
)

Write-Output "`nSearching Unified Audit Log for administrative operations..." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Searching for $($adminOperations.Count) operation types." | Tee-Object -FilePath $logFilePath -Append

$allResults = @()
$sessionID = "AdminAudit_$date"

## Search in batches since we have many operations
$batchSize = 10
for ($i = 0; $i -lt $adminOperations.Count; $i += $batchSize) {
    $batch = $adminOperations[$i..([Math]::Min($i + $batchSize - 1, $adminOperations.Count - 1))]
    $batchNum = [Math]::Floor($i / $batchSize) + 1
    Write-Output "  Searching batch $batchNum (operations $($i+1)-$([Math]::Min($i + $batchSize, $adminOperations.Count)))..." | Tee-Object -FilePath $logFilePath -Append

    $batchSessionID = "${sessionID}_B${batchNum}"

    do {
        try {
            $searchParams = @{
                StartDate      = $StartDate
                EndDate        = $EndDate
                Operations     = $batch
                SessionId      = $batchSessionID
                SessionCommand = "ReturnLargeSet"
                ResultSize     = 5000
            }
            if ($UserIds) {
                $searchParams.Add("UserIds", $UserIds)
            }

            $results = Search-UnifiedAuditLog @searchParams

            if ($results) {
                $allResults += $results
                Write-Output "    Retrieved $($allResults.Count) total records so far..." | Tee-Object -FilePath $logFilePath -Append
            }
        } catch {
            Write-Output "  Error searching batch $batchNum`: $_" | Tee-Object -FilePath $logFilePath -Append
            break
        }
    } while ($results -and $results.Count -ge 5000)
}

Write-Output "`nTotal admin audit records found: $($allResults.Count)" | Tee-Object -FilePath $logFilePath -Append

if ($allResults.Count -eq 0) {
    Write-Output "No admin-level audit events found in the specified date range." | Tee-Object -FilePath $logFilePath -Append
} else {
    ## Parse and flatten results
    $parsedResults = @()
    foreach ($record in $allResults) {
        $auditData = $record.AuditData | ConvertFrom-Json

        # Extract target resources
        $targetResources = ""
        if ($auditData.Target) {
            $targetResources = ($auditData.Target | ForEach-Object {
                $targetId = $_.ID
                $targetType = $_.Type
                "$targetType`:$targetId"
            }) -join " | "
        }

        # Extract modified properties summary
        $modifiedProps = ""
        if ($auditData.ModifiedProperties) {
            $modifiedProps = ($auditData.ModifiedProperties | ForEach-Object {
                "$($_.Name)"
            }) -join ", "
        }

        # Categorize the operation for easier filtering
        $category = "Other"
        switch -Wildcard ($record.Operations) {
            "*role*"                { $category = "RoleChange" }
            "*member*group*"        { $category = "GroupChange" }
            "*domain*"              { $category = "DomainChange" }
            "*federation*"          { $category = "FederationChange" }
            "*policy*"              { $category = "PolicyChange" }
            "*password*"            { $category = "PasswordChange" }
            "*service principal*"   { $category = "ServicePrincipal" }
            "*application*"         { $category = "Application" }
            "*MailboxPermission*"   { $category = "MailboxDelegation" }
            "*RecipientPermission*" { $category = "MailboxDelegation" }
            "*TransportRule*"       { $category = "TransportRule" }
            "*OrganizationConfig*"  { $category = "OrgConfig" }
            "*AdminAuditLog*"       { $category = "AuditConfig" }
            "*user*"                { $category = "UserManagement" }
            "*Elevate*"             { $category = "ElevateAccess" }
            "Set-Mailbox"           { $category = "MailboxConfig" }
        }

        $parsedHash = [ordered]@{
            CreationDate       = $record.CreationDate
            Category           = $category
            UserIds            = $record.UserIds
            Operations         = $record.Operations
            ObjectId           = $auditData.ObjectId
            ClientIP           = $auditData.ClientIP
            TargetResources    = $targetResources
            ModifiedProperties = $modifiedProps
            ResultStatus       = $auditData.ResultStatus
            UserAgent          = $auditData.UserAgent
            AuditData          = $record.AuditData
        }

        $parsedResults += New-Object PSObject -Property $parsedHash
    }

    # Sort by date and display
    $parsedResults = $parsedResults | Sort-Object CreationDate -Descending
    $parsedResults | Format-Table CreationDate, Category, UserIds, Operations, ObjectId -AutoSize
    $parsedResults | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding $Encoding

    # Summary by category
    Write-Output "`n===== ADMIN EVENT SUMMARY BY CATEGORY =====" | Tee-Object -FilePath $logFilePath -Append
    $parsedResults | Group-Object Category | Sort-Object Count -Descending | Format-Table Name, Count -AutoSize
    Write-Output "" | Tee-Object -FilePath $logFilePath -Append

    # Highlight critical events
    $criticalCategories = @("RoleChange", "DomainChange", "FederationChange", "ElevateAccess", "AuditConfig")
    $criticalEvents = $parsedResults | Where-Object { $criticalCategories -contains $_.Category }
    if ($criticalEvents.Count -gt 0) {
        Write-Output "===== CRITICAL EVENTS (require immediate review) =====" | Tee-Object -FilePath $logFilePath -Append
        $criticalEvents | Format-Table CreationDate, Category, UserIds, Operations, ObjectId -AutoSize
        Write-Output "$($criticalEvents.Count) critical admin event(s) found." | Tee-Object -FilePath $logFilePath -Append
    }

    Write-Output "Use 05-ProcessUnifiedAuditLogFlatten to further process/flatten the AuditData column." | Tee-Object -FilePath $logFilePath -Append
}

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:" | Tee-Object -FilePath $logFilePath -Append
    Write-Output $OutputCSV | Tee-Object -FilePath $logFilePath -Append
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append
Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
if (-not $NoExplorer) { Invoke-Item "$OutputPath\$DomainName" }
Exit
