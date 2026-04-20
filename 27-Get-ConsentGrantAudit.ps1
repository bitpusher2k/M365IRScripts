#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-ConsentGrantAudit.ps1 - By Bitpusher/The Digital Fox
# v3.2 last updated 2026-03-29
# Script to search the Unified Audit Log for all "Consent to application"
# events, building a timeline of when OAuth apps were authorized, by whom,
# and with what permissions. Useful for identifying when a malicious OAuth
# application was consented to during a BEC incident.
#
# Searches for UAL operations:
# - "Consent to application." (user and admin consent grants)
# - "Add app role assignment grant to user." (app role assignments)
# - "Add delegated permission grant." (delegated permission grants)
# - "Add app role assignment to service principal." (application permissions)
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-ConsentGrantAudit.ps1 -OutputPath "Default" -DaysAgo "30"
# powershell -executionpolicy bypass -f .\Get-ConsentGrantAudit.ps1 -OutputPath "Default" -UserIds "compromised@contoso.com" -DaysAgo "90"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell (Search-UnifiedAuditLog) commands.
#
# References:
# https://learn.microsoft.com/en-us/purview/audit-log-activities#application-administration-activities
# https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account
# https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-consent-requests
#
#comp #m365 #security #bec #script #irscript #powershell #oauth #consent #audit #timeline

#Requires -Version 5.1

param(
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Get-ConsentGrantAudit",
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
    [string]$Encoding = "utf8NoBOM" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
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
    $DaysAgo = Read-Host 'Enter how many days back to search for consent events (default: 90, maximum: 180)'
    if ($DaysAgo -eq '') { $DaysAgo = "90" } elseif ($DaysAgo -gt 180) { $DaysAgo = "180" }
}

if ($DaysAgo) {
    if ($DaysAgo -gt 180) { $DaysAgo = "180" }
    Write-Output "`nScript will search $DaysAgo days back from today for consent events." | Tee-Object -FilePath $logFilePath -Append
    $StartDate = (Get-Date).ToUniversalTime().AddDays(-$DaysAgo)
    $EndDate = (Get-Date).ToUniversalTime()
    Write-Output "StartDate: $StartDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "EndDate: $EndDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
} elseif ($StartDate -and $EndDate) {
    $StartDate = ($StartDate).ToUniversalTime()
    $EndDate = ($EndDate).ToUniversalTime()
    if ($StartDate -lt (Get-Date).ToUniversalTime().AddDays(-180)) { $StartDate = (Get-Date).ToUniversalTime().AddDays(-180) }
    if ($StartDate -ge $EndDate) { $EndDate = ($StartDate).AddDays(1) }
    Write-Output "`nScript will search between StartDate and EndDate for consent events." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "StartDate: $StartDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "EndDate: $EndDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "Neither DaysAgo nor StartDate/EndDate specified. Ending." | Tee-Object -FilePath $logFilePath -Append
    exit
}

$OutputCSV = "$OutputPath\$DomainName\ConsentGrantAudit_$($date).csv"

## Operations related to OAuth/application consent
$consentOperations = @(
    "Consent to application.",
    "Add delegated permission grant.",
    "Add app role assignment grant to user.",
    "Add app role assignment to service principal.",
    "Add OAuth2PermissionGrant.",
    "Update application."
)

$operationsString = $consentOperations -join ","

Write-Output "`nSearching Unified Audit Log for application consent events..." | Tee-Object -FilePath $logFilePath -Append

$allResults = @()
$resultCount = 0
$sessionID = "ConsentAudit_$date"
$retryCount = 0
$maxRetries = 3

## Search UAL with pagination (Search-UnifiedAuditLog returns max 5000 per call)
do {
    try {
        $searchParams = @{
            StartDate     = $StartDate
            EndDate       = $EndDate
            Operations    = $consentOperations
            SessionId     = $sessionID
            SessionCommand = "ReturnLargeSet"
            ResultSize    = 5000
        }
        if ($UserIds) {
            $searchParams.Add("UserIds", $UserIds)
        }

        $results = Search-UnifiedAuditLog @searchParams

        if ($results) {
            $allResults += $results
            $resultCount = $allResults.Count
            Write-Output "Retrieved $resultCount records so far..." | Tee-Object -FilePath $logFilePath -Append
        }
        $retryCount = 0
    } catch {
        $retryCount++
        Write-Output "Error searching UAL (attempt $retryCount of $maxRetries): $_" | Tee-Object -FilePath $logFilePath -Append
        if ($retryCount -ge $maxRetries) {
            Write-Output "Max retries reached. Proceeding with $resultCount records collected." | Tee-Object -FilePath $logFilePath -Append
            break
        }
        Start-Sleep -Seconds 5
    }
} while ($results -and $results.Count -ge 5000)

Write-Output "`nTotal consent-related audit records found: $($allResults.Count)" | Tee-Object -FilePath $logFilePath -Append

if ($allResults.Count -eq 0) {
    Write-Output "No consent grant events found in the specified date range." | Tee-Object -FilePath $logFilePath -Append
} else {
    ## Parse and flatten results
    $parsedResults = @()
    foreach ($record in $allResults) {
        $auditData = $record.AuditData | ConvertFrom-Json

        # Extract target resources (application name, permissions granted, etc.)
        $targetApp = ""
        $targetPermissions = ""
        $modifiedProperties = @()
        if ($auditData.Target) {
            foreach ($target in $auditData.Target) {
                if ($target.Type -eq 1 -or $target.Type -eq "ServicePrincipal") {
                    $targetApp = $target.ID
                }
            }
        }
        if ($auditData.ModifiedProperties) {
            foreach ($prop in $auditData.ModifiedProperties) {
                $modifiedProperties += "$($prop.Name): $($prop.NewValue)"
            }
        }

        $parsedHash = [ordered]@{
            CreationDate         = $record.CreationDate
            UserIds              = $record.UserIds
            Operations           = $record.Operations
            ClientIP             = $auditData.ClientIP
            ObjectId             = $auditData.ObjectId
            TargetApp            = $targetApp
            ResultStatus         = $auditData.ResultStatus
            ModifiedProperties   = ($modifiedProperties -join " | ")
            AuditData            = $record.AuditData
        }

        $parsedResults += New-Object PSObject -Property $parsedHash
    }

    $parsedResults | Sort-Object CreationDate -Descending | Format-Table CreationDate, UserIds, Operations, TargetApp -AutoSize
    $parsedResults | Sort-Object CreationDate -Descending | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding $Encoding

    Write-Output "`nExported $($parsedResults.Count) consent audit record(s)." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Use 05-ProcessUnifiedAuditLogFlatten to further process/flatten the AuditData column if needed." | Tee-Object -FilePath $logFilePath -Append
}

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:" | Tee-Object -FilePath $logFilePath -Append
    Write-Output $OutputCSV | Tee-Object -FilePath $logFilePath -Append
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append
Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"
Exit
