#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-UserMessageTrace.ps1 - By Bitpusher/The Digital Fox
# v3.1.1 last updated 2025-10-09
# Script to get message trace report of recent incoming & outgoing email for given user(s) or IP address.
#
# Updated to use Get-MessageTraceV2
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-UserMessageTrace.ps1 -OutputPath "Default" -UserIds "compromisedaccount@contoso.com" -DaysAgo "10"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
#
#comp #m365 #security #bec #script #irscript #powershell #email #message #trace  #exchange #online

#Requires -Version 5.1

param(
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Get-UserMessageTrace",
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

## If UserIds variable is not defined, prompt for it
if (!$UserIds) {
    Write-Output ""
    $UserIds = Read-Host 'Enter the email address(s) or IP address to perform message trace on (seaparate multiple email addresses with commas, maximum result size is 5000)'
}

$IPv4regex = '\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
$IPv6Regex = '^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::|^(?:[0-9a-fA-F]{1,4}:){1,7}:|^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$|^:(?::[0-9a-fA-F]{1,4}){1,7}[0-9a-fA-F]{1,4}$'

$TypeParam = "UPN"
if ($UserIds -match $IPv4regex -or $UserIds -match $IPv6regex) {
    $TypeParam = "IP"
    Write-Output "Will search for IP: $UserIds"
}

## If DaysAgo variable is not defined and StartDate/EndDate were also not defined, prompt for it
if (!$DaysAgo -and (!$StartDate -or !$EndtDate)) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to retrieve ALL available message trace entries for specified account (default: 10, maximum: 90 - entries past 10 days ago will be in 10-day increment reports)' # https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/message-trace-faq, https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/start-historicalsearch?view=exchange-ps, https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-messagetracev2?view=exchange-ps
    if ($DaysAgo -eq '') { $DaysAgo = "10" } elseif ($DaysAgo -gt 90) { $DaysAgo = "90" }
    Write-Output "Will attempt to retrieve message trace entries going back $DaysAgo days from today."
} elseif ($DaysAgo) {
    if ($DaysAgo -gt 90) { $DaysAgo = "90" }
    Write-Output "Will attempt to retrieve message trace entries going back $DaysAgo days from today."
} elseif ($StartDate -and $EndtDate) {
    Write-Output "Will attempt to retrieve message trace entries between $StartDate and $EndDate."
} else {
    Write-Output "Missing date range information - Try running again with -DaysAgo or -StartDate and -EndDate parameters."
    exit
}

if ($StartDate -and $EndtDate) {
    Write-Output "Starting Get-MessageTraceV2..."
    if ($TypeParam -eq "IP") {
        Get-MessageTraceV2 -FromIP $UserIds -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Export-Csv "$OutputPath\$DomainName\TraceSent_$($UserIds)_between_$($StartDate.ToString("yyyyMMddHHmmss"))_and_$($EndtDate.ToString("yyyyMMddHHmmss")).csv" -NoTypeInformation -Encoding $Encoding
        Get-MessageTraceV2 -ToIP $UserIds -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Export-Csv "$OutputPath\$DomainName\TraceReceived_$($UserIds)_between_$($StartDate.ToString("yyyyMMddHHmmss"))_and_$($EndtDate.ToString("yyyyMMddHHmmss")).csv" -NoTypeInformation -Encoding $Encoding
    } else {
        Get-MessageTraceV2 -SenderAddress $UserIds -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Export-Csv "$OutputPath\$DomainName\TraceSent_$($UserIds)_between_$($StartDate.ToString("yyyyMMddHHmmss"))_and_$($EndtDate.ToString("yyyyMMddHHmmss")).csv" -NoTypeInformation -Encoding $Encoding
        Get-MessageTraceV2 -RecipientAddress $UserIds -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Export-Csv "$OutputPath\$DomainName\TraceReceived_$($UserIds)_between_$($StartDate.ToString("yyyyMMddHHmmss"))_and_$($EndtDate.ToString("yyyyMMddHHmmss")).csv" -NoTypeInformation -Encoding $Encoding
    }

    # Write-Output "Starting historical search to retrieve traces of messages older than 10 days..."
    # Start-HistoricalSearch -SenderAddress $UserIds -StartDate $StartDate -EndDate $EndDate -reporttitle "Sender $UserIds historical search between $($StartDate.ToString('yyyyMMddHHmmss')) and $($EndtDate.ToString('yyyyMMddHHmmss'))" -ReportType messagetrace
    # Start-HistoricalSearch -RecipientAddress $UserIds -StartDate $StartDate -EndDate $EndDate -reporttitle "Recipient $UserIds historical search between $($StartDate.ToString('yyyyMMddHHmmss')) and $($EndtDate.ToString('yyyyMMddHHmmss'))" -ReportType messagetrace
    # Write-Output "Historical searches queued. Use 'Get-HistoricalSearch | Select ReportTitle,Status' to check the search status, then when complete download the reports from https://admin.exchange.microsoft.com/#/messagetrace"
    # Write-Output "Use 'Stop-HistoricalSearch -JobId <Guid>' to cancel."
} elseif ($DaysAgo -gt 10) {
    $StartDate = (Get-Date).AddDays(-10)
    $EndDate = (Get-Date).AddDays(1)

    while ($DaysAgo -gt 0) {
        Write-Output "Starting Get-MessageTraceV2..."
        if ($TypeParam -eq "IP") {
            Get-MessageTraceV2 -FromIP $UserIds -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Export-Csv "$OutputPath\$DomainName\TraceSent_$($UserIds)_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
            Get-MessageTraceV2 -ToIP $UserIds -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Export-Csv "$OutputPath\$DomainName\TraceReceived_$($UserIds)_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        } else {
            Get-MessageTraceV2 -SenderAddress $UserIds -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Export-Csv "$OutputPath\$DomainName\TraceSent_$($UserIds)_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
            Get-MessageTraceV2 -RecipientAddress $UserIds -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Export-Csv "$OutputPath\$DomainName\TraceReceived_$($UserIds)_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        }

        $EndDate = ($StartDate)
        $DaysAgo = $DaysAgo - 10
        if ($DaysAgo -gt 10) {
            $StartDate = ($StartDate).AddDays(-10)
        } elseif ($DaysAgo -gt 0) {
            $StartDate = ($StartDate).AddDays(-$DaysAgo)
        }
    }

    # Write-Output "Starting historical search to retrieve traces of messages older than 10 days..."
    # $StartDate = (Get-Date).AddDays(- $DaysAgo)
    # $EndDate = (Get-Date).AddDays(1)
    # Start-HistoricalSearch -SenderAddress $UserIds -StartDate $StartDate -EndDate $EndDate -reporttitle "Sender $UserIds historical search $DaysAgo days ago from $EndDate" -ReportType messagetrace
    # Start-HistoricalSearch -RecipientAddress $UserIds -StartDate $StartDate -EndDate $EndDate -reporttitle "Recipient $UserIds historical search $DaysAgo days ago from $EndDate" -ReportType messagetrace
    # Write-Output "Historical searches queued. Use 'Get-HistoricalSearch | Select ReportTitle,Status' to check the search status, then when complete download the reports from https://admin.exchange.microsoft.com/#/messagetrace"
    # Write-Output "Use 'Stop-HistoricalSearch -JobId <Guid>' to cancel."
} else {
    $StartDate = (Get-Date).AddDays(- $DaysAgo)
    $EndDate = (Get-Date).AddDays(1)

    Write-Output "Starting Get-MessageTraceV2..."
    if ($TypeParam -eq "IP") {
        Get-MessageTraceV2 -FromIP $UserIds -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Export-Csv "$OutputPath\$DomainName\TraceSent_$($UserIds)_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC.csv" -NoTypeInformation -Encoding $Encoding
        Get-MessageTraceV2 -ToIP $UserIds -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Export-Csv "$OutputPath\$DomainName\TraceReceived_$($UserIds)_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC.csv" -NoTypeInformation -Encoding $Encoding
    } else {
        Get-MessageTraceV2 -SenderAddress $UserIds -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Export-Csv "$OutputPath\$DomainName\TraceSent_$($UserIds)_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC.csv" -NoTypeInformation -Encoding $Encoding
        Get-MessageTraceV2 -RecipientAddress $UserIds -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Export-Csv "$OutputPath\$DomainName\TraceReceived_$($UserIds)_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC.csv" -NoTypeInformation -Encoding $Encoding
    }
}

## Potential additions:

# https://docs.microsoft.com/en-us/graph/api/resources/office-365-groups-activity-reports?view=graph-rest-1.0
# Get-MgReportOffice365GroupActivityDetail -OutFile
# https://docs.microsoft.com/en-us/powershell/module/microsoft.graph.reports/get-mgreportoffice365groupactivitydetail?view=graph-powershell-1.0
# Get-MgReportMailboxUsageDetail -OutFile

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"

exit
