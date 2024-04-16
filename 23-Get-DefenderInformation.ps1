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
# v2.7 last updated 2024-02-26
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
    [string]$OutputPath,
    [string]$Encoding = "utf8bom" # "ascii","ansi","bigendianunicode","unicode","utf8","utf8","utf8NoBOM","utf32"
)

if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }

$date = Get-Date -Format "yyyyMMddHHmmss"

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

Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

exit
