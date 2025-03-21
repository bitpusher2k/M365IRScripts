﻿#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Search-InboxRuleChanges.ps1
# Created by https://github.com/JeremyTBradshaw/
# modified by Bitpusher/The Digital Fox
# v2.8 last updated 2024-05-03
# Script to search UAC for inbox rule changes on all accounts
# made recently (max past 180 days).
#
# Usage:
# powershell -executionpolicy bypass -f .\Search-InboxRuleChanges.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
#
#comp #m365 #security #bec #script #unified #audit #log

#Requires -Version 5.1

<#
    .Synopsis
    Search the Office 365 unified audit log for suspicious inbox rule activity.

    .Description
    For OWA-based user acitvity and PowerShell-based admin activity, we can
    search for the New-/Set-InboxRule operations.

    For Outlook client based activity, we can search for the UpdateInboxRules
    activity.

    .Parameter StartDate
    Provide a start date (and optionally time) in a System.DateTime-recognized
    format.  Default is to search back 30 days (i.e. (Get-Date).AddDays(-30)).

    .Parameter EndDate
    Provide an end date (and optionally time) in a System.DateTime-
    recognized format.  Default is current date/time (i.e. (Get-Date)).

    .Parameter ResultSize
    By default, the maximum (5000) is specified.  Valid range is 1-5000

    .Parameter UseClientIPExcludedRanges
    This bool is $true by default.  Update the section of the script:

        if ($UseClientIPExcludedRanges -eq $true) {}

    This allows us to filter output to only changes made from outside the
    corporate network.  The common use case of this script case is to detect
    when an account has been compromised and the attacker creates a rule to
    hide NDR backscatter, allowing them to send spam while delaying the mailbox
    owner becoming aware.

    .Notes
    I have decided to have the script process all results of the search then
    output all entries at the end, rather than outputting each log entry
    individually, directly after processing.  This allows for the discovery of
    all audit log entries' list of properties so that a common PS custom object
    can be output for every log entry.  This helps with ensuring down the line
    cmdlets (e.g. Export-Csv) will work predictably.  There could be more
    efficient ways to accomplish this, but I've settled on this one until I
    find a more favorable method.

    Note that this dynamic list of properties challenge is also felt by Excel,
    as is noted in the following article:
    https://docs.microsoft.com/en-us/microsoft-365/compliance/export-view-audit-log-records

    The method of dealing with nested multi-valued properties (sometimes in
    JSON format) in this script results in many properties (i.e. columns) in
    the output.  This is hoped to be superior to how the same data will be
    presented in Excel if the process from the link above is followed instead.

    .Link
    https://github.com/JeremyTBradshaw/PowerShell/blob/main/Search-InboxRuleChanges.ps1 -OutputPath "Default"

    .Link
    # [Unified audit log] Audited Activities:
    https://docs.microsoft.com/en-us/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance#audited-activities

    .Link
    # [Unified audit log] Detailed Properties
    https://docs.microsoft.com/en-us/microsoft-365/compliance/detailed-properties-in-the-office-365-audit-log

    .Example
    .\Search-InboxRuleChanges.ps1

    .Example
    .\Search-InboxRuleChanges.ps1 -UseClientIPExcludedRanges $false -ResultSize 100 -StartDate (Get-Date).AddHours(-4)
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [ValidateRange(1, 5000)] [int]$ResultSize = 5000,
    [bool]$UseClientIPExcludedRanges = $false,
    [string]$Encoding = "utf8bom" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
)

if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }


$date = Get-Date -Format "yyyyMMddHHmmss"

# Write-Verbose -Message "Determining the connected Exchange environment."

# Could update to use Get-ConnectionInformation instead of Get-PSSession
# and check Unified Audit Logging is enabled with Get-AdminAuditLogConfig

# $ExPSSession = @()
# $ExPSSession += Get-PSSession |
# Where-Object { $_.ComputerName -eq 'outlook.office365.com' }

# if ($ExPSSession.Count -ne 1) {
#    Write-Warning -Message "Requires a *single* remote session to Exchange Online."
#    break
# }

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


if ($UseClientIPExcludedRanges -eq $true) {
    Write-Warning -Message 'Using predefined ClientIP excluded IPRanges.'
    Write-Warning -Message 'To avoid this, use -UseClientIPExcludedRanges $false'
    # Ensure to use outside-facing IP's (e.g. NAT'd, external).
    # Since we're searching in EXO, all ClientIP's will be public IP addresses.
    $ClientIPExcludedIPRanges = @()
    foreach ($i in (1..254)) { $ClientIPExcludedIPRanges += "192.168.1.$i" } # <--: Example (but don't actually use private/internal IP's).
    foreach ($i in (1..254)) { $ClientIPExcludedIPRanges += "192.168.2.$i" }
    foreach ($i in (80..90)) { $ClientIPExcludedIPRanges += "10.10.10.$i" }
}

## If DaysAgo variable is not defined, prompt for it
if (!$DaysAgo) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to retrieve ALL available inbox rule change events (default: 30, maximum: 180)'
    if ($DaysAgo -eq '') { $DaysAgo = "30" }
}
if ($DaysAgo -gt 180) { $DaysAgo = "180" }
Write-Output "Will attempt to retrieve all UAC entries going back $DaysAgo days from today."
Write-Output "NOTE: Recently it has taken multiple runs before all email rule change events are properly grabbed and parsed by this script. Reason unknown."
Write-Output "NOTE: Run. Wait 10 minutes. Run again."

$StartDate = (Get-Date).AddDays(- $DaysAgo)
$EndDate = (Get-Date).AddDays(1)
$SearchResultsProcessed = @()

$StartDate
$EndDate

$sesid = Get-Random # Get random session number
Write-Output "Search-UnifiedAuditLog -Operations New-InboxRule, Set-InboxRule, UpdateInboxRules, Remove-InboxRule, Disable-InboxRule -StartDate $StartDate -EndDate $EndDate -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize:$ResultSize"
$count = 1
do {
    Write-Output "Getting unified audit logs page $count - Please wait"
    try {
        $currentOutput = Search-UnifiedAuditLog -Operations New-InboxRule, Set-InboxRule, UpdateInboxRules, Remove-InboxRule, Disable-InboxRule -StartDate $StartDate -EndDate $EndDate -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize:$ResultSize
    } catch {
        Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n"
        Write-Output "Exception message:", $_.Exception.Message, "`n"
        exit 2 # Terminate script
    }
    $SearchResults += $currentoutput # Build total results array
    ++ $count # Increment page count
} until ($currentoutput.count -eq 0) # Until there are no more logs in range to get

Write-Output "$($SearchResults.Count) New-InboxRule/Set-InboxRule/UpdateInboxRules/Remove-InboxRule/Disable-InboxRule records found in logs..."

$sesid = Get-Random # Get random session number
Write-Output "Search-UnifiedAuditLog -Operations Set-Mailbox -StartDate $StartDate -EndDate $EndDate -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize:$ResultSize"
$count = 1
do {
    Write-Output "Getting unified audit logs page $count - Please wait"
    try {
        $currentOutput = Search-UnifiedAuditLog -Operations Set-Mailbox -StartDate $StartDate -EndDate $EndDate -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize:$ResultSize
    } catch {
        Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n"
        Write-Output "Exception message:", $_.Exception.Message, "`n"
        exit 2 # Terminate script
    }
    $SearchResultsSetMailbox += $currentoutput # Build total results array
    ++ $count # Increment page count
} until ($currentoutput.count -eq 0) # Until there are no more logs in range to get

Write-Output "$($SearchResultsSetMailbox.Count) Set-Mailbox records found in logs..."

if ($SearchResultsSetMailbox.Count -ge 1) {
    Write-Output "Writing Set-Mailbox UAL log output..."
    $SearchResultsSetMailbox | Export-Csv "$OutputPath\$DomainName\InboxRuleChangesSetMailbox_going_back_$($DaysAgo)_days_from_$($date).csv" -NoTypeInformation -Encoding $Encoding
}

# The New-InboxRule, Set-InboxRule, Remove-InboxRule, or Disable-InboxRule Operations typically show up when someone is using the PowerShell cmdlet or Outlook on the Web.
# UpdateInboxRules is typically seen when rules are created or modified via an Outlook Desktop client using the Exchange Web Services (EWS) API and has a slightly different log format, which we’ll provide in detail below.
# Set-Mailbox is also seen in PowerShell and OWA usage. Some of the mailbox settings include options to externally forward emails.
# https://redcanary.com/blog/email-forwarding-rules/

foreach ($sr in $SearchResults) {

    Write-Verbose -Message "Processing log entry $($sr.ResultIndex) of $($sr.ResultCount)"

    $AuditData = $null
    $AuditData = $sr.AuditData | ConvertFrom-Json

    if ($UseClientIPExcludedRanges -eq $true) {
        if ($ClientIPExcludedIPRanges -notcontains "$($AuditData.ClientIP -replace '\[' -replace '\].*' -replace ':.*')") { $ContinueProcessing = $true }
        else { $ContinueProcessing = $false }
    } else {
        $ContinueProcessing = $true
    }

    if ($ContinueProcessing -eq $true) {
        $ProcessedLogEntry = $null
        $ProcessedLogEntry = [pscustomobject]@{

            RecordType      = $sr.RecordType
            CreationDateUTC = $sr.CreationDate.ToString('yyyy-MM-dd hh:mm:ss tt')
            UserIds         = $sr.UserIds
            Operations      = $sr.Operations
            ResultIndex     = $sr.ResultIndex
            ResultCount     = $sr.ResultCount
            ClientIP        = $AuditData.ClientIP
            UserId          = $AuditData.UserId
            ExternalAccess  = $AuditData.ExternalAccess
        }
        $InboxRule = @()
        if ($sr.Operations -eq 'UpdateInboxRules') {
            $ProcessedLogEntry |
                Add-Member -NotePropertyName ClientInfoString -NotePropertyValue $AuditData.ClientInfoString -PassThru |
                Add-Member -NotePropertyName ClientProcessName -NotePropertyValue $AuditData.ClientProcessName -PassThru |
                Add-Member -NotePropertyName ClientVersion -NotePropertyValue $AuditData.ClientVersion -PassThru |
                Add-Member -NotePropertyName LogonUserSid -NotePropertyValue $AuditData.LogonUserSid -PassThru |
                Add-Member -NotePropertyName MailboxOwnerSid -NotePropertyValue $AuditData.MailboxOwnerSid -PassThru |
                Add-Member -NotePropertyName MailboxOwnerUPN -NotePropertyValue $AuditData.MailboxOwnerUPN -PassThru |
                Add-Member -NotePropertyName MailboxGuid -NotePropertyValue $AuditData.MailboxGuid

            $OperationProperties = $null
            $OperationProperties = $AuditData | Select-Object -ExpandProperty OperationProperties

            foreach ($opn in $OperationProperties.Name) {
                if ($opn -match 'RuleActions') {
                    $RuleActions = $null
                    $RuleActions = $OperationProperties.Value[$OperationProperties.Name.IndexOf($opn)] | ConvertFrom-Json
                    if ($Null -ne $RuleActions) {
                        $RAProps = Get-Member -InputObject $RuleActions -MemberType NoteProperty
                        foreach ($rap in $RAProps.Name) {

                            $ProcessedLogEntry |
                                Add-Member -NotePropertyName "RuleAction_$($rap)" -NotePropertyValue $RuleActions.$rap
                        }
                    }
                } else {
                    $ProcessedLogEntry |
                        Add-Member -NotePropertyName $opn -NotePropertyValue $OperationProperties.Value[$OperationProperties.Name.IndexOf($opn)]
                }
            }

            if (($ProcessedLogEntry.RuleOperation -notmatch 'RemoveMailboxRule') -and ($ProcessedLogEntry.RuleName)) {

                $InboxRule += Get-InboxRule "$($AuditData.UserId)\$($ProcessedLogEntry.RuleName)" -ErrorAction:SilentlyContinue
            }
        } elseif ($sr.Operations -like '*-InboxRule') {
            $ProcessedLogEntry |
                Add-Member -NotePropertyName ResultStatus -NotePropertyValue $AuditData.ResultStatus -PassThru |
                Add-Member -NotePropertyName ObjectId -NotePropertyValue $AuditData.ObjectId

            $ParametersProperties = $null
            $ParametersProperties = $AuditData | Select-Object -ExpandProperty Parameters

            foreach ($ppn in $ParametersProperties.Name) {

                Write-Debug "Inspect `$ppn, `$ParametersProperties(.name)"
                $ProcessedLogEntry |
                    Add-Member -NotePropertyName CmdletParameter_$ppn -NotePropertyValue $ParametersProperties.Value[$ParametersProperties.Name.IndexOf($ppn)]
            }

            $InboxRule += Get-InboxRule $AuditData.ObjectId -ErrorAction:SilentlyContinue
        } else {
            $ProcessedLogEntry |
                Add-Member -NotePropertyName LogEntryProblem -NotePropertyValue "'Operations' is not one of New-InboxRule, Set-InboxRule, or UpdateInboxRules"
        }

        if ($ProcessedLogEntry.RuleOperation -notmatch 'RemoveMailboxRule') {
            if ($InboxRule.Count -eq 1) {
                $ProcessedLogEntry |
                    Add-Member -NotePropertyName InboxRule_Description -NotePropertyValue $InboxRule.Description
            } elseif ($InboxRule.Count -gt 1) {
                $ProcessedLogEntry |
                    Add-Member -NotePropertyName InboxRule_Description -NotePropertyValue "Multiple matching rules found - check manually."
            } else {
                $ProcessedLogEntry |
                    Add-Member -NotePropertyName InboxRule_Description -NotePropertyValue "Rule not found - check manually."
            }
        }
        $SearchResultsProcessed += $ProcessedLogEntry
    } # end: if ($ContinueProcessing -eq $true) {}
} # end: foreach ($sr in $SearchResults) {}

Write-Debug "`$SearchResultsProcessed <--: Results"

if ($SearchResults.Count -ge 1) {
    Write-Output "Writing New-InboxRule/Set-InboxRule/UpdateInboxRules/Remove-InboxRule/Disable-InboxRule UAL RAW output..."
    $SearchResultsSetMailbox | Export-Csv "$OutputPath\$DomainName\InboxRuleChanges_going_back_$($DaysAgo)_days_from_$($date).csv" -NoTypeInformation -Encoding $Encoding
}

if ($SearchResultsProcessed.Count -ge 1) {
    Write-Output "Writing New-InboxRule/Set-InboxRule/UpdateInboxRules/Remove-InboxRule/Disable-InboxRule UAL processed output..."
    $FinalOutputProperties = @()
    $FinalOutputProperties += $SearchResultsProcessed[0] | Get-Member -MemberType NoteProperty

    foreach ($srp in $SearchResultsProcessed[1..$SearchResultsProcessed.Count]) {
        $FinalOutputProperties += $srp |
            Get-Member -MemberType NoteProperty |
            Where-Object { $FinalOutputProperties.Name -notcontains $_.Name }
    }
    $SearchResultsProcessed | Export-Csv "$OutputPath\$DomainName\InboxRuleChanges_going_back_$($DaysAgo)_days_from_$($date)_Processed.csv" -NoTypeInformation -Encoding $Encoding
}

Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

exit
