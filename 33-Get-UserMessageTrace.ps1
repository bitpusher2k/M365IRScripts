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
# v2.7 last updated 2024-02-26
# Script to get message trace report of recent incoming & outgoing email for a given user.
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
    [string]$OutputPath,
    [string]$UserIds,
    [string]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$Encoding = "utf8bom" # "ascii","ansi","bigendianunicode","unicode","utf8","utf8","utf8NoBOM","utf32"
)

if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }

$date = Get-Date -Format "yyyyMMddHHmmss"

## If OutputPath variable is not defined, prompt for it
if (!$OutputPath) {
    Write-Output ""
    $OutputPath = Read-Host "Enter the output base path, e.g. $($env:userprofile)\Desktop\Investigation (default)"
    If ($OutputPath -eq '') { $OutputPath = "$($env:userprofile)\Desktop\Investigation" }
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

## If UserIds variable is not defined, prompt for it
if (!$UserIds) {
    Write-Output ""
    $UserIds = Read-Host 'Enter the email address of account for message trace'
}

## If DaysAgo variable is not defined and StartDate/EndDate were also not defined, prompt for it
if (!$DaysAgo -and (!$StartDate -or !$EndtDate)) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to retrieve ALL available message trace entries for specified account (default: 10, maximum: 90 - entries past 10 days ago will be in "historical" report)'
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
    Write-Output "Starting Get-MessageTrace..."
    Get-MessageTrace -SenderAddress $UserIds -StartDate $StartDate -EndDate $EndDate | Export-Csv "$OutputPath\$DomainName\TraceSent_$($UserIds)_between_$($StartDate.ToString("yyyyMMddHHmmss"))_and_$($EndtDate.ToString("yyyyMMddHHmmss")).csv" -NoTypeInformation -Encoding $Encoding
    Get-MessageTrace -RecipientAddress $UserIds -StartDate $StartDate -EndDate $EndDate | Export-Csv "$OutputPath\$DomainName\TraceReceived_$($UserIds)_between_$($StartDate.ToString("yyyyMMddHHmmss"))_and_$($EndtDate.ToString("yyyyMMddHHmmss")).csv" -NoTypeInformation -Encoding $Encoding

    Write-Output "Starting historical search to retrieve traces of messages older than 10 days..."
    Start-HistoricalSearch -SenderAddress $UserIds -StartDate $StartDate -EndDate $EndDate -reporttitle "Sender $UserIds historical search between $($StartDate.ToString('yyyyMMddHHmmss')) and $($EndtDate.ToString('yyyyMMddHHmmss'))" -ReportType messagetrace
    Start-HistoricalSearch -RecipientAddress $UserIds -StartDate $StartDate -EndDate $EndDate -reporttitle "Recipient $UserIds historical search between $($StartDate.ToString('yyyyMMddHHmmss')) and $($EndtDate.ToString('yyyyMMddHHmmss'))" -ReportType messagetrace
    Write-Output "Historical searches queued. Use 'Get-HistoricalSearch | Select ReportTitle,Status' to check the search status, then when complete download the reports from https://admin.exchange.microsoft.com/#/messagetrace"
    Write-Output "Use 'Stop-HistoricalSearch -JobId <Guid>' to cancel."
} elseif ($DaysAgo -gt 10) {
    $StartDate = (Get-Date).AddDays(-10)
    $EndDate = (Get-Date).AddDays(1)

    Write-Output "Starting Get-MessageTrace..."
    Get-MessageTrace -SenderAddress $UserIds -StartDate $StartDate -EndDate $EndDate | Export-Csv "$OutputPath\$DomainName\TraceSent_$($UserIds)_going_back_10_days_from_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Get-MessageTrace -RecipientAddress $UserIds -StartDate $StartDate -EndDate $EndDate | Export-Csv "$OutputPath\$DomainName\TraceReceived_$($UserIds)_going_back_10_days_from_$($date).csv" -NoTypeInformation -Encoding $Encoding

    $StartDate = (Get-Date).AddDays(- $DaysAgo)
    $EndDate = (Get-Date).AddDays(1)

    Write-Output "Starting historical search to retrieve traces of messages older than 10 days..."
    Start-HistoricalSearch -SenderAddress $UserIds -StartDate $StartDate -EndDate $EndDate -reporttitle "Sender $UserIds historical search $DaysAgo days ago from $EndDate" -ReportType messagetrace
    Start-HistoricalSearch -RecipientAddress $UserIds -StartDate $StartDate -EndDate $EndDate -reporttitle "Recipient $UserIds historical search $DaysAgo days ago from $EndDate" -ReportType messagetrace
    Write-Output "Historical searches queued. Use 'Get-HistoricalSearch | Select ReportTitle,Status' to check the search status, then when complete download the reports from https://admin.exchange.microsoft.com/#/messagetrace"
    Write-Output "Use 'Stop-HistoricalSearch -JobId <Guid>' to cancel."
} else {
    $StartDate = (Get-Date).AddDays(- $DaysAgo)
    $EndDate = (Get-Date).AddDays(1)

    Write-Output "Starting Get-MessageTrace..."
    Get-MessageTrace -SenderAddress $UserIds -StartDate $StartDate -EndDate $EndDate | Export-Csv "$OutputPath\$DomainName\TraceSent_$($UserIds)_going_back_$($DaysAgo)_days_from_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Get-MessageTrace -RecipientAddress $UserIds -StartDate $StartDate -EndDate $EndDate | Export-Csv "$OutputPath\$DomainName\TraceReceived_$($UserIds)_going_back_$($DaysAgo)_days_from_$($date).csv" -NoTypeInformation -Encoding $Encoding
}

## Potential additions:

# https://docs.microsoft.com/en-us/graph/api/resources/office-365-groups-activity-reports?view=graph-rest-1.0
# Get-MgReportOffice365GroupActivityDetail -OutFile
# https://docs.microsoft.com/en-us/powershell/module/microsoft.graph.reports/get-mgreportoffice365groupactivitydetail?view=graph-powershell-1.0
# Get-MgReportMailboxUsageDetail -OutFile

Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

exit
