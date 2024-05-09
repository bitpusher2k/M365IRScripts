#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-UnifiedAuditLogEntries.ps1 - By Bitpusher/The Digital Fox
# v2.7 last updated 2024-02-26
# Script to export all available UAC entries going back
# the specified number of days (max 90).
#
# UAC retention is 90 days.
#
# NOTE: Retrieving all log entries for a broad swath of time
# and/or on a busy tenant can take a long time.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-UnifiedAuditLogEntries.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
#
#comp #m365 #security #bec #script #unified #audit #log #bulk

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$UserIds,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [int]$DaysAgo,
    [string]$OutputPath,
    [string]$Encoding = "utf8bom" # "ascii","ansi","bigendianunicode","unicode","utf8","utf8","utf8NoBOM","utf32"
)

if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }

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

## If DaysAgo variable is not defined, prompt for it
if (!$DaysAgo) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to retrieve ALL available Unified Audit Log entries for tenant (default: 10, maximum: 90)'
    if ($DaysAgo -eq '') { $DaysAgo = "10" } elseif ($DaysAgo -gt "90") { $DaysAgo = "90" }
    Write-Output "Will attempt to retrieve all UAC entries going back $DaysAgo days from today."
}

$date = Get-Date -Format "yyyyMMddHHmmss"
$logFile = "$OutputPath\$DomainName\UnifiedAuditLog_Past_$($DaysAgo)_days_LOG_$($date).txt"
$OutputCSV = "$OutputPath\$DomainName\UnifiedAuditLog_Past_$($DaysAgo)_days_$($date).csv"

# $StartDate = (Get-Date).AddDays(-$DaysAgo)
# $EndDate = (Get-Date).AddDays(1)
[datetime]$start = [datetime]::UtcNow.AddDays(- $DaysAgo)
[datetime]$end = [datetime]::UtcNow
#$record = "AzureActiveDirectory" https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#auditlogrecordtype
$record = "ALL"
$resultSize = 5000 #Maximum number of records that can be retrieved per query
$intervalMinutes = 30

#Start script
[datetime]$currentStart = $start
[datetime]$currentEnd = $end

function Write-LogFile ([string]$Message) {
    $final = [datetime]::Now.ToUniversalTime().ToString("s") + ":" + $Message
    $final | Out-File $logFile -Append
}

Write-LogFile "BEGIN: Retrieving audit records between $($start) and $($end), RecordType=$record, PageSize=$resultSize."
Write-Output "Retrieving audit records for the date range between $($start) and $($end), RecordType=$record, ResultsSize=$resultSize"

$totalCount = 0
while ($true) {
    $currentEnd = $currentStart.AddMinutes($intervalMinutes)
    if ($currentEnd -gt $end) {
        $currentEnd = $end
    }

    if ($currentStart -eq $currentEnd) {
        break
    }

    $sessionID = [guid]::NewGuid().ToString() + "_" + "ExtractLogs" + (Get-Date).ToString("yyyyMMddHHmmssfff")
    Write-LogFile "INFO: Retrieving audit records for activities performed between $($currentStart) and $($currentEnd)"
    Write-Output "Retrieving audit records for activities performed between $($currentStart) and $($currentEnd)"
    $currentCount = 0

    $sw = [Diagnostics.StopWatch]::StartNew()
    do {
        #$results = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -RecordType $record -SessionId $sessionID -SessionCommand ReturnLargeSet -ResultSize $resultSize
        $results = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -SessionId $sessionID -SessionCommand ReturnLargeSet -ResultSize $resultSize

        if (($results | Measure-Object).Count -ne 0) {
            $results | Export-Csv -Path $OutputCSV -Append -NoTypeInformation -Encoding $Encoding

            $currentTotal = $results[0].ResultCount
            $totalCount += $results.Count
            $currentCount += $results.Count
            Write-LogFile "INFO: Retrieved $($currentCount) audit records out of the total $($currentTotal)"

            if ($currentTotal -eq $results[$results.Count - 1].ResultIndex) {
                $message = "INFO: Successfully retrieved $($currentTotal) audit records for the current time range. Moving on!"
                Write-LogFile $message
                Write-Output "Successfully retrieved $($currentTotal) audit records for the current time range. Moving on to the next interval."
                ""
                break
            }
        }
    } while (($results | Measure-Object).Count -ne 0)
    
    Write-Output "Seconds elapsed for query: $sw.elapsed.totalseconds"

    $currentStart = $currentEnd
}

Write-LogFile "END: Retrieving audit records between $($start) and $($end), RecordType=$record, PageSize=$resultSize, total count: $totalCount."
Write-Output "Script complete! Finished retrieving audit records for the date range between $($start) and $($end). Total count: $totalCount"

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:"
    Write-Output $OutputCSV
    $Prompt = New-Object -ComObject wscript.shell
    $UserInput = $Prompt.popup("Do you want to open output file?", 0, "Open Output File", 4)
    if ($UserInput -eq 6) {
        Invoke-Item "$OutputCSV"
    }
}
Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

exit
