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
# v3.1 last updated 2025-07-26
# Script to export all available UAC entries going back
# the specified number of days (max 180).
#
# UAC retention is 180 days.
#
# NOTE: Retrieving all log entries for a broad swath of time
# and/or on a busy tenant can take a long time.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-UnifiedAuditLogEntries.ps1 -OutputPath "Default" -DaysAgo "10"
#
# powershell -executionpolicy bypass -f .\Get-UnifiedAuditLogEntries.ps1 -OutputPath "Default" -StartDate "2025-07-12" -EndDate "2025-07-20"
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
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Get-UnifiedAuditLogEntries",
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
$PrimaryDomain = Get-AcceptedDomain | Where-Object Default -EQ $true
$DomainName = $PrimaryDomain.DomainName

$CheckSubDir = Get-Item $OutputPath\$DomainName -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
    Write-Output ""
    Write-Output "Domain sub-directory does not exist. Sub-directory `"$DomainName`" will be created." | Tee-Object -FilePath $logFilePath -Append
    mkdir $OutputPath\$DomainName
}
Write-Output "Domain sub-directory will be `"$DomainName`"" | Tee-Object -FilePath $logFilePath -Append

## Get valid starting end ending dates
if (!$DaysAgo -and (!$StartDate -or !$EndDate)) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to retrieve ALL UAL entries (default: 10, maximum: 180)'
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


$date = Get-Date -Format "yyyyMMddHHmmss"
$logFile = "$OutputPath\$DomainName\UnifiedAuditLog_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_LOG_$($date).txt"
$OutputCSV = "$OutputPath\$DomainName\UnifiedAuditLog_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv"

#$record = "AzureActiveDirectory" https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#auditlogrecordtype
$record = "ALL"
$resultSize = 5000 #Maximum number of records that can be retrieved per query
$intervalMinutes = 30

#Start script
[datetime]$currentStart = $StartDate
[datetime]$currentEnd = $EndDate

function Write-LogFile ([string]$Message) {
    $final = [datetime]::Now.ToUniversalTime().ToString("s") + ":" + $Message
    $final | Out-File $logFile -Append
}

Write-LogFile "BEGIN: Retrieving audit records between $($StartDate) and $($EndDate), RecordType=$record, PageSize=$resultSize."
Write-Output "Retrieving audit records for the date range between $($StartDate) and $($EndDate), RecordType=$record, ResultsSize=$resultSize" | Tee-Object -FilePath $logFilePath -Append

$totalCount = 0
while ($true) {
    $currentEnd = $currentStart.AddMinutes($intervalMinutes)
    if ($currentEnd -gt $EndDate) {
        $currentEnd = $EndDate
    }

    if ($currentStart -eq $currentEnd) {
        break
    }

    $sessionID = [guid]::NewGuid().ToString() + "_" + "ExtractLogs" + (Get-Date).ToString("yyyyMMddHHmmssfff")
    Write-LogFile "INFO: Retrieving audit records for activities performed between $($currentStart) and $($currentEnd)"
    Write-Output "Retrieving audit records for activities performed between $($currentStart) and $($currentEnd)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -SessionId $sessionID -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $currentCount = 0

    $sw = [Diagnostics.StopWatch]::StartNew()
    do {
        #$results = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -RecordType $record -SessionId $sessionID -SessionCommand ReturnLargeSet -ResultSize $resultSize
        Write-Output "Test query:" ; Search-UnifiedAuditLog -StartDate $EndDate -EndDate $EndDate -resultsize 1 # Test query to show warning if present
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
                Write-Output "Successfully retrieved $($currentTotal) audit records for the current time range. Moving on to the next interval." | Tee-Object -FilePath $logFilePath -Append
                ""
                break
            }
        }
    } while (($results | Measure-Object).Count -ne 0)
    
    Write-Output "Seconds elapsed for query: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

    $currentStart = $currentEnd
}

Write-LogFile "END: Retrieving audit records between $($StartDate) and $($EndDate), RecordType=$record, PageSize=$resultSize, total count: $totalCount."
Write-Output "Script complete! Finished retrieving audit records for the date range between $($StartDate) and $($EndDate). Total count: $totalCount"

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:" | Tee-Object -FilePath $logFilePath -Append
    Write-Output $OutputCSV | Tee-Object -FilePath $logFilePath -Append
    # $Prompt = New-Object -ComObject wscript.shell
    # $UserInput = $Prompt.popup("Do you want to open output file?", 0, "Open Output File", 4)
    # if ($UserInput -eq 6) {
    #     Invoke-Item "$OutputCSV"
    # }
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"

exit
