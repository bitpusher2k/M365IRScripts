#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Search-UALMailItemsAccessedByUser.ps1 - By Bitpusher/The Digital Fox
# v3.0 last updated 2025-05-31
# Script to export all "MailItemsAccessed" records from the Unified Audit Log for specified users.
#
# For more information see:
# https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts
# https://office365itpros.com/2019/01/07/using-exchange-session-identifiers-audit-log/
#
# Usage:
# powershell -executionpolicy bypass -f .\Search-UALActivityByUser.ps1 -OutputPath "Default" -UserIds "compromisedaccount@contoso.com" -DaysAgo "10"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
#
#comp #m365 #security #bec #script #irscript #powershell #unified #audit #log #search #user

#Requires -Version 5.1

param(
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Search-UALMailItemsAccessedByUser",
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

$CheckLog = (Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled
if (!$CheckLog) {
    Write-Output "The Unified Audit Log does not appear to be enabled on this tenant. Export of UAL activities may fail. Try running 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true' if export fails."
}

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
# $PrimaryDomain = Get-AcceptedDomain | Where-Object Default -eq $true
# $DomainName = $PrimaryDomain.DomainName
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
    $UserIds = Read-Host "Enter the user's primary email address (UPN). Comma-separated to search for entries from multiple users"
}

## If DaysAgo variable is not defined, prompt for it
if (!$DaysAgo) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to retrieve mailitemsaccessed UAL entries associated with these user(s) (default: 10, maximum: 180)'
    if ($DaysAgo -eq '') { $DaysAgo = "10" } elseif ($DaysAgo -gt 180) { $DaysAgo = "180" }
}
if ($DaysAgo -gt 180) { $DaysAgo = "180" }
Write-Output "`nWill search UAC $DaysAgo days back from today for relevant events."

$StartDate = (Get-Date).AddDays(- $DaysAgo)
$EndDate = (Get-Date).AddDays(1)
$resultSize = 5000 #Maximum number of records that can be retrieved per query

$OutputCSV = "$OutputPath\$DomainName\MailItemsAccessedUALEntries_$($UserIds.Replace(',','-'))_going_back_$($DaysAgo)_days_from_$($date).csv"

$amountResults = (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $UserIds -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount)
$throttledResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $UserIds -Operations MailItemsAccessed -ResultSize 1000 | Where {$_.AuditData -like '*"IsThrottled","Value":"True"*'}
$syncResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $UserIds -Operations MailItemsAccessed -ResultSize 1000 | Where {$_.AuditData -like '*"MailAccessType","Value":"Sync"*'}

Write-Output "`nNumber of MailItemsAccessed events logged for specified user(s) during time range: $amountResults.`n"

if ($throttledResults) {
    Write-Output "`nWARNING: MailItemsAccessed events THROTTLED for specified user(s) during search range - Not all events were logged.`n"
}

if ($syncResults) {
    Write-Output "`nWARNING: MailItemsAccessed SYNC events for specified user(s) logged during search range - Desktop Outlook client used and only FOLDER level operations are logged - ALL items in synced folder must be assumed accessed.`n"
}

$sesid = Get-Random # Get random session number
Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $UserIds -Operations `"MailItemsAccessed`" -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize"
$count = 1
do {
    Write-Output "Getting unified audit logs page $count - Please wait"
    try {
        $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $UserIds -Operations "MailItemsAccessed" -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
    } catch {
        Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n"
        Write-Output "Exception message:", $_.Exception.Message, "`n"
        exit 2 # Terminate script
    }
    $AuditOutput += $currentoutput # Build total results array
    ++ $count # Increment page count
} until ($currentoutput.count -eq 0) # Until there are no more logs in range to get

if (!$AuditOutput) {
    Write-Output "`nThere are no activities in the audit log for the time period specified`n"
} else {
    $AuditOutput | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding $Encoding
    Write-Output "`nSee user activities report in the output path.`n"
    Write-Output "Pivot through MailItemsAccessed logs searching by date/time of suspect events, by suspect IP ('ClientIPAddress'), and by associated suspect Session ID ('SessionId')."
}

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:"
    Write-Output $OutputCSV
    # $Prompt = New-Object -ComObject wscript.shell
    # $UserIdsInput = $Prompt.popup("Do you want to open output file?",0,"Open Output File",4)
    # If ($UserIdsInput -eq 6) {
    # 	Invoke-Item "$OutputCSV"
    # }
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"

exit
