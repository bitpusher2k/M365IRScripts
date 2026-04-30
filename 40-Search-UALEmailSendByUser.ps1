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
# Search-UALEmailSendByUser.ps1 - By Bitpusher/The Digital Fox
# v4.0.0 last updated 2026-04-27
# Script to search the Unified Audit Log for all email send operations
# (Send, SendAs, SendOnBehalf) by specified user(s) to quantify the
# blast radius of outbound phishing/fraud emails sent from compromised
# accounts during a BEC incident.
#
# This supplements script 33 (Get-UserMessageTrace) by providing send
# events from the UAL perspective which can be correlated with sign-in
# logs to identify which send operations were performed by the threat
# actor vs. the legitimate user.
#
# Usage:
# powershell -executionpolicy bypass -f .\Search-UALEmailSendByUser.ps1 -OutputPath "Default" -UserIds "compromised@contoso.com" -DaysAgo "30"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell (Search-UnifiedAuditLog) commands.
# Minimally required tenant role(s): Exchange RBAC "View-Only Org Mgmt"
#
# References:
# https://learn.microsoft.com/en-us/purview/audit-log-activities#exchange-mailbox-activities
# https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account
# https://learn.microsoft.com/en-us/purview/audit-mailboxes
#
#comp #m365 #security #bec #script #irscript #powershell #email #send #blast #radius #phishing #spam #sendas #sendonbehalf

#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement, Microsoft.Graph.Identity.DirectoryManagement

param(
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Search-UALEmailSendByUser",
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

## If UserIds variable is not defined, prompt for it
if (!$UserIds) {
    Write-Output ""
    $UserIds = Read-Host 'Enter the user ID(s) (email address) of compromised account(s) to investigate, comma separated'
}

## Get valid starting and ending dates
if (!$DaysAgo -and (!$StartDate -or !$EndDate)) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to search for email send events (default: 30, maximum: 180)'
    if ($DaysAgo -eq '') { $DaysAgo = "30" } elseif ($DaysAgo -gt 180) { $DaysAgo = "180" }
}

if ($DaysAgo) {
    if ($DaysAgo -gt 180) { $DaysAgo = "180" }
    Write-Output "`nScript will search $DaysAgo days back from today for email send events." | Tee-Object -FilePath $logFilePath -Append
    $StartDate = (Get-Date).ToUniversalTime().AddDays(-$DaysAgo)
    $EndDate = (Get-Date).ToUniversalTime()
    Write-Output "StartDate: $StartDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "EndDate: $EndDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
} elseif ($StartDate -and $EndDate) {
    $StartDate = ($StartDate).ToUniversalTime()
    $EndDate = ($EndDate).ToUniversalTime()
    if ($StartDate -lt (Get-Date).ToUniversalTime().AddDays(-180)) { $StartDate = (Get-Date).ToUniversalTime().AddDays(-180) }
    if ($StartDate -ge $EndDate) { $EndDate = ($StartDate).AddDays(1) }
    Write-Output "`nScript will search between StartDate and EndDate for email send events." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "StartDate: $StartDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "EndDate: $EndDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "Neither DaysAgo nor StartDate/EndDate specified. Ending." | Tee-Object -FilePath $logFilePath -Append
    exit
}

$OutputCSV = "$OutputPath\$DomainName\EmailSendActivity_$($date).csv"

## Email send operations in the UAL
$sendOperations = @(
    "Send",
    "SendAs",
    "SendOnBehalf"
)

Write-Output "`nSearching Unified Audit Log for email send events by: $UserIds" | Tee-Object -FilePath $logFilePath -Append
Write-Output "Operations: $($sendOperations -join ', ')" | Tee-Object -FilePath $logFilePath -Append

$allResults = @()
$sessionID = "EmailSend_$date"

do {
    try {
        $results = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $UserIds -Operations $sendOperations -SessionId $sessionID -SessionCommand ReturnLargeSet -ResultSize 5000
        if ($results) {
            $allResults += $results
            Write-Output "Retrieved $($allResults.Count) records so far..." | Tee-Object -FilePath $logFilePath -Append
        }
    } catch {
        Write-Output "Error searching UAL for send events: $_" | Tee-Object -FilePath $logFilePath -Append
        break
    }
} while ($results -and $results.Count -ge 5000)

Write-Output "`nTotal email send records found: $($allResults.Count)" | Tee-Object -FilePath $logFilePath -Append

if ($allResults.Count -eq 0) {
    Write-Output "No email send events found for specified user(s) in the date range." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Note: 'Send' events require E5 or Audit (Premium) / MailItemsAccessed logging in most cases." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "SendAs and SendOnBehalf are logged at all license levels when performed by delegates." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Consider also using script 33-Get-UserMessageTrace for SMTP-level send data." | Tee-Object -FilePath $logFilePath -Append
} else {
    ## Parse and flatten results
    $parsedResults = @()
    foreach ($record in $allResults) {
        $auditData = $record.AuditData | ConvertFrom-Json

        $subject = $auditData.Subject
        $internetMessageId = $auditData.InternetMessageId
        $clientIP = $auditData.ClientIPAddress
        if (!$clientIP) { $clientIP = $auditData.ClientIP }
        $sessionId = $auditData.SessionId

        # Extract recipient information from Item.Recipients or other fields
        $recipients = ""
        if ($auditData.Item -and $auditData.Item.Recipients) {
            $recipients = ($auditData.Item.Recipients | ForEach-Object { $_.SmtpAddress }) -join "; "
        }

        $parsedHash = [ordered]@{
            CreationDate       = $record.CreationDate
            UserIds            = $record.UserIds
            Operations         = $record.Operations
            Subject            = $subject
            Recipients         = $recipients
            InternetMessageId  = $internetMessageId
            ClientIP           = $clientIP
            SessionId          = $sessionId
            ClientInfoString   = $auditData.ClientInfoString
            MailboxOwnerUPN    = $auditData.MailboxOwnerUPN
            LogonType          = $auditData.LogonType
            AuditData          = $record.AuditData
        }

        $parsedResults += New-Object PSObject -Property $parsedHash
    }

    # Sort by date and display
    $parsedResults = $parsedResults | Sort-Object CreationDate -Descending
    $parsedResults | Format-Table CreationDate, Operations, Subject, Recipients, ClientIP -AutoSize
    $parsedResults | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding $Encoding

    # Summary statistics
    $sendCount = ($parsedResults | Where-Object { $_.Operations -eq "Send" }).Count
    $sendAsCount = ($parsedResults | Where-Object { $_.Operations -eq "SendAs" }).Count
    $sendOnBehalfCount = ($parsedResults | Where-Object { $_.Operations -eq "SendOnBehalf" }).Count

    # Unique recipient count
    $allRecipients = @()
    foreach ($r in $parsedResults) {
        if ($r.Recipients) {
            $allRecipients += $r.Recipients -split "; "
        }
    }
    $uniqueRecipientCount = ($allRecipients | Sort-Object -Unique).Count

    # Unique IP count
    $uniqueIPs = ($parsedResults | Where-Object { $_.ClientIP } | Select-Object -ExpandProperty ClientIP -Unique)

    Write-Output "`n===== BLAST RADIUS SUMMARY =====" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Total send events: $($parsedResults.Count)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "  Send: $sendCount" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "  SendAs: $sendAsCount" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "  SendOnBehalf: $sendOnBehalfCount" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Unique recipients: $uniqueRecipientCount" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Unique source IPs: $($uniqueIPs.Count)" | Tee-Object -FilePath $logFilePath -Append
    if ($uniqueIPs.Count -gt 0) {
        Write-Output "Source IPs: $($uniqueIPs -join ', ')" | Tee-Object -FilePath $logFilePath -Append
    }
    Write-Output "" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Cross-reference source IPs with sign-in log analysis to identify sends by threat actor." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Use InternetMessageId values with script 44 or 45 for message content retrieval." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Use 06-Lookup-IPInfoCSV to enrich IP addresses in the exported CSV." | Tee-Object -FilePath $logFilePath -Append
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
