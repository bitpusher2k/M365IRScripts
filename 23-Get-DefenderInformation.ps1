#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-DefenderInformation.ps1 - By Bitpusher/The Digital Fox
# v3.0 last updated 2025-05-31
# Script to export reports of MS Defender settings & status, including:
# alert configuration, threat detections, blocked senders (restricted entities),
# quarantine policy, and quarantined messages.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-DefenderInformation.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
#
#comp #m365 #security #bec #script #irscript #powershell

#Requires -Version 5.1

param(
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Get-DefenderInformation",
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


Write-Output "`nScript will export Defender alert configuration, threat detections, blocked senders (restricted entities), quarantine policy, and quarantined messages to csv files..."

Write-Output "`nExporting alert configuration..."
Get-ProtectionAlert | Export-Csv -Path "$OutputPath\$DomainName\DefenderAlertConfiguration_$($date).csv" -Encoding $Encoding -NoTypeInformation

Write-Output "`nExporting threat detections..."
Get-MpThreatDetection | Export-Csv -Path "$OutputPath\$DomainName\DefenderThreatDetections_$($date).csv" -Encoding $Encoding -NoTypeInformation

Write-Output "`nExporting blocked senders..."
$BlockedSenders = Get-BlockedSenderAddress
if ($BlockedSenders) {
    $BlockedSenders
    Write-Output "When accounts are secured un-block with: Remove-BlockedSenderAddress -SenderAddress <emailaddress>"
    Write-Output "Note that it can take 24 hours to fully un-block an account."
    $BlockedSenders | Export-Csv -Path "$OutputPath\$DomainName\BlockedSenders_$($date).csv" -Encoding $Encoding -NoTypeInformation
} else {
    Write-Output "No entities currently restricted on tenant."
}

Write-Output "`nExporting quarantine policy..."
Get-QuarantinePolicy | Export-Csv -Path "$OutputPath\$DomainName\DefenderAlertConfiguration_$($date).csv" -Encoding $Encoding -NoTypeInformation

Write-Output "`nExporting quarantined message list..."
$QuarantinedMessages = Get-QuarantineMessage
if ($QuarantinedMessages) {
    Write-Output "First 10 messages in quarantine:"
    $QuarantinedMessages | Select-Object -First 10
    Write-Output "`nUseful quarantined message operations: "
    Write-Output "Get-QuarantineMessageHeader -Identity <QuarantineMessageIdentity>"
    Write-Output "Preview-QuarantineMessage -Identity <QuarantineMessageIdentity>"
    Write-Output "Delete-QuarantineMessage -Identity <QuarantineMessageIdentity>"
    Write-Output "Release-QuarantineMessage -Identity <QuarantineMessageIdentity>"
    Write-Output "And to export (if you have permissions):"
    Write-Output "`$base64message = Export-QuarantineMessage -Identity <QuarantineMessageIdentity> "
    Write-Output "`$bytesMessage = [Convert]::FromBase64String($base64message.eml)"
    Write-Output "[IO.File]::WriteAllBytes(`"`$OutputPath\`$DomainName\Quarantined Message with Attachments.eml`", `$bytesMessage)"
    $QuarantinedMessages | Export-Csv -Path "$OutputPath\$DomainName\QuarantinedMessages_$($date).csv" -Encoding $Encoding -NoTypeInformation
} else {
    Write-Output "No messages currently in quarantine on tenant."
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"

exit
