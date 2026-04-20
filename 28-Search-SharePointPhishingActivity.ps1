#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Search-SharePointPhishingActivity.ps1 - By Bitpusher/The Digital Fox
# v3.2 last updated 2026-03-29
# Script to search the Unified Audit Log for SharePoint/OneDrive activity
# commonly associated with BEC phishing campaigns: file uploads followed by
# anonymous link creation, sharing invitations to external recipients, and
# related operations that may indicate lure document distribution.
#
# Modern BEC attacks increasingly leverage SharePoint sharing notifications
# as phishing vectors because they come from a trusted Microsoft domain and
# bypass many email security filters.
#
# Searched operations include:
# - FileUploaded, FileModified (lure document staging)
# - AnonymousLinkCreated, AnonymousLinkUpdated (open sharing)
# - SharingInvitationCreated, AddedToSecureLink (targeted sharing)
# - CompanyLinkCreated (org-wide sharing)
# - SharingSet, SecureLinkCreated
#
# Usage:
# powershell -executionpolicy bypass -f .\Search-SharePointPhishingActivity.ps1 -OutputPath "Default" -UserIds "compromised@contoso.com" -DaysAgo "30"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell (Search-UnifiedAuditLog) commands.
#
# References:
# https://learn.microsoft.com/en-us/purview/audit-log-activities#sharepoint-file-activities
# https://learn.microsoft.com/en-us/purview/audit-log-activities#sharing-and-access-request-activities
# https://www.invictus-ir.com/news/sharepoint-phishing-investigation
# https://www.proofpoint.com/us/blog/cloud-security/revisiting-mact-malicious-applications-credible-cloud-tenants
#
#comp #m365 #security #bec #script #irscript #powershell #sharepoint #phishing #onedrive #sharing

#Requires -Version 5.1

param(
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Search-SharePointPhishingActivity",
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
    [string]$Encoding = "utf8NoBOM"
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

## If UserIds variable is not defined, prompt for it
if (!$UserIds) {
    Write-Output ""
    $UserIds = Read-Host 'Enter the user ID(s) (email address) of compromised account(s) to investigate, comma separated'
}

## Get valid starting and ending dates
if (!$DaysAgo -and (!$StartDate -or !$EndDate)) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to search for SharePoint activity (default: 30, maximum: 180)'
    if ($DaysAgo -eq '') { $DaysAgo = "30" } elseif ($DaysAgo -gt 180) { $DaysAgo = "180" }
}

if ($DaysAgo) {
    if ($DaysAgo -gt 180) { $DaysAgo = "180" }
    Write-Output "`nScript will search $DaysAgo days back from today for SharePoint phishing activity." | Tee-Object -FilePath $logFilePath -Append
    $StartDate = (Get-Date).ToUniversalTime().AddDays(-$DaysAgo)
    $EndDate = (Get-Date).ToUniversalTime()
    Write-Output "StartDate: $StartDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "EndDate: $EndDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
} elseif ($StartDate -and $EndDate) {
    $StartDate = ($StartDate).ToUniversalTime()
    $EndDate = ($EndDate).ToUniversalTime()
    if ($StartDate -lt (Get-Date).ToUniversalTime().AddDays(-180)) { $StartDate = (Get-Date).ToUniversalTime().AddDays(-180) }
    if ($StartDate -ge $EndDate) { $EndDate = ($StartDate).AddDays(1) }
    Write-Output "`nScript will search between StartDate and EndDate." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "StartDate: $StartDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "EndDate: $EndDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "Neither DaysAgo nor StartDate/EndDate specified. Ending." | Tee-Object -FilePath $logFilePath -Append
    exit
}

$OutputCSV = "$OutputPath\$DomainName\SharePointPhishingActivity_$($date).csv"

## SharePoint/OneDrive operations associated with phishing lure distribution
$sharingOperations = @(
    "AnonymousLinkCreated",
    "AnonymousLinkUpdated",
    "SharingInvitationCreated",
    "AddedToSecureLink",
    "SecureLinkCreated",
    "CompanyLinkCreated",
    "SharingSet",
    "SharingLinkCreated"
)

$fileOperations = @(
    "FileUploaded",
    "FileModified",
    "FileCopied"
)

Write-Output "`nPhase 1: Searching for sharing activity by specified user(s)..." | Tee-Object -FilePath $logFilePath -Append

$allResults = @()
$sessionID = "SPPhish_Share_$date"

do {
    try {
        $results = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $UserIds -Operations $sharingOperations -SessionId $sessionID -SessionCommand ReturnLargeSet -ResultSize 5000
        if ($results) {
            $allResults += $results
            Write-Output "Retrieved $($allResults.Count) sharing records so far..." | Tee-Object -FilePath $logFilePath -Append
        }
    } catch {
        Write-Output "Error searching UAL for sharing activity: $_" | Tee-Object -FilePath $logFilePath -Append
        break
    }
} while ($results -and $results.Count -ge 5000)

Write-Output "Total sharing records found: $($allResults.Count)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nPhase 2: Searching for file upload activity by specified user(s)..." | Tee-Object -FilePath $logFilePath -Append

$sessionID2 = "SPPhish_File_$date"

do {
    try {
        $results = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $UserIds -Operations $fileOperations -SessionId $sessionID2 -SessionCommand ReturnLargeSet -ResultSize 5000
        if ($results) {
            $allResults += $results
            Write-Output "Retrieved $($allResults.Count) total records so far..." | Tee-Object -FilePath $logFilePath -Append
        }
    } catch {
        Write-Output "Error searching UAL for file activity: $_" | Tee-Object -FilePath $logFilePath -Append
        break
    }
} while ($results -and $results.Count -ge 5000)

Write-Output "`nTotal combined records found: $($allResults.Count)" | Tee-Object -FilePath $logFilePath -Append

if ($allResults.Count -eq 0) {
    Write-Output "No SharePoint/OneDrive sharing or file upload events found for specified user(s) in the date range." | Tee-Object -FilePath $logFilePath -Append
} else {
    ## Parse and flatten results
    $parsedResults = @()
    foreach ($record in $allResults) {
        $auditData = $record.AuditData | ConvertFrom-Json

        # Determine if sharing target is external
        $isExternal = $false
        $targetUser = ""
        if ($auditData.TargetUserOrGroupName) {
            $targetUser = $auditData.TargetUserOrGroupName
        }
        if ($auditData.EventData) {
            $targetUser = $auditData.EventData
        }
        # Anonymous links are inherently external
        if ($record.Operations -like "AnonymousLink*") {
            $isExternal = $true
        }

        $parsedHash = [ordered]@{
            CreationDate       = $record.CreationDate
            UserIds            = $record.UserIds
            Operations         = $record.Operations
            ObjectId           = $auditData.ObjectId
            SourceFileName     = $auditData.SourceFileName
            SourceFileExtension = $auditData.SourceFileExtension
            SiteUrl            = $auditData.SiteUrl
            SourceRelativeUrl  = $auditData.SourceRelativeUrl
            ClientIP           = $auditData.ClientIP
            TargetUser         = $targetUser
            IsExternalSharing  = $isExternal
            UserAgent          = $auditData.UserAgent
            ItemType           = $auditData.ItemType
            AuditData          = $record.AuditData
        }

        $parsedResults += New-Object PSObject -Property $parsedHash
    }

    # Sort by date and display summary
    $parsedResults = $parsedResults | Sort-Object CreationDate -Descending
    $parsedResults | Format-Table CreationDate, UserIds, Operations, SourceFileName, TargetUser, IsExternalSharing -AutoSize
    $parsedResults | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding $Encoding

    # Summary statistics
    $sharingCount = ($parsedResults | Where-Object { $sharingOperations -contains $_.Operations }).Count
    $uploadCount = ($parsedResults | Where-Object { $fileOperations -contains $_.Operations }).Count
    $externalCount = ($parsedResults | Where-Object { $_.IsExternalSharing -eq $true }).Count
    $anonLinkCount = ($parsedResults | Where-Object { $_.Operations -like "AnonymousLink*" }).Count

    Write-Output "`n===== SUMMARY =====" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "File upload/modify events: $uploadCount" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Sharing events: $sharingCount" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "External sharing events: $externalCount" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Anonymous link creation events: $anonLinkCount" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Review results for patterns of lure document upload followed by sharing." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "High suspicion indicators:" | Tee-Object -FilePath $logFilePath -Append
    Write-Output " - File uploaded then immediately shared externally or via anonymous link" | Tee-Object -FilePath $logFilePath -Append
    Write-Output " - Files with names containing: invoice, payment, document, review, secure, shared" | Tee-Object -FilePath $logFilePath -Append
    Write-Output " - Sharing to external recipients not in normal business contact patterns" | Tee-Object -FilePath $logFilePath -Append
    Write-Output " - Activity from IP addresses identified as malicious in sign-in log review" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Use 05-ProcessUnifiedAuditLogFlatten to further process/flatten the AuditData column." | Tee-Object -FilePath $logFilePath -Append
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
