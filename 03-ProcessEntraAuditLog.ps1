#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#          @VinceVulpes
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# ProcessEntraAuditLog.ps1 - By Bitpusher/The Digital Fox
# v2.8 last updated 2024-05-12
# Processes an exported CSV of Entra ID Audit log from the admin center,
# removing columns not needed for manual review and reordering for ease of review.
# Not the most efficient way to process CSV files - Not recommended for use on CSV files with more than 100,000 lines.
#
# Usage:
# powershell -executionpolicy bypass -f .\ProcessEntraAuditLog.ps1 -inputFile "Path\to\input\log.csv"
#
# Use with DropShim.bat to allow drag-and-drop processing of downloaded logs.
#
#comp #m365 #security #bec #script #entraid #asuread #audit #csv #log #irscript #powershell

#Requires -Version 5.1

param(
    [string]$inputFile = "EntraAudit.csv",
    [string]$outputFile = "EntraAuditProcessed.csv",
    [string]$scriptName = "ProcessEntraAuditLog",
    [string]$Priority = "Normal",
    [int]$RandMax = "500",
    [string]$DebugPreference = "SilentlyContinue",
    [string]$VerbosePreference = "SilentlyContinue",
    [string]$InformationPreference = "Continue",
    [string]$logFileFolderPath = "C:\Temp\log",
    [string]$ComputerName = $env:computername,
    [string]$ScriptUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
    [string]$logFilePrefix = "$scriptName" + "_" + "$ComputerName" + "_",
    [string]$logFileDateFormat = "yyyyMMdd_HHmmss",
    [int]$logFileRetentionDays = 30
)

$InputHeaders = ("Date", "CorrelationId", "Service", "Category", "Activity", "Result", "ResultReason", "UserAgent", "ActorType", "ActorDisplayName", "ActorObjectId", "ActorUserPrincipalName", "IPAddress", "ActorHomeTenantId", "ActorHomeTenantName", "ActorServicePrincipalId", "ActorServicePrincipalName", "Target1Type", "Target1DisplayName", "Target1ObjectId", "Target1UserPrincipalName", "Target1ModifiedProperty1Name", "Target1ModifiedProperty1OldValue", "Target1ModifiedProperty1NewValue", "Target1ModifiedProperty2Name", "Target1ModifiedProperty2OldValue", "Target1ModifiedProperty2NewValue", "Target1ModifiedProperty3Name", "Target1ModifiedProperty3OldValue", "Target1ModifiedProperty3NewValue", "Target1ModifiedProperty4Name", "Target1ModifiedProperty4OldValue", "Target1ModifiedProperty4NewValue", "Target1ModifiedProperty5Name", "Target1ModifiedProperty5OldValue", "Target1ModifiedProperty5NewValue", "Target2Type", "Target2DisplayName", "Target2ObjectId", "Target2UserPrincipalName", "Target2ModifiedProperty1Name", "Target2ModifiedProperty1OldValue", "Target2ModifiedProperty1NewValue", "Target2ModifiedProperty2Name", "Target2ModifiedProperty2OldValue", "Target2ModifiedProperty2NewValue", "Target2ModifiedProperty3Name", "Target2ModifiedProperty3OldValue", "Target2ModifiedProperty3NewValue", "Target2ModifiedProperty4Name", "Target2ModifiedProperty4OldValue", "Target2ModifiedProperty4NewValue", "Target2ModifiedProperty5Name", "Target2ModifiedProperty5OldValue", "Target2ModifiedProperty5NewValue", "Target3Type", "Target3DisplayName", "Target3ObjectId", "Target3UserPrincipalName", "Target3ModifiedProperty1Name", "Target3ModifiedProperty1OldValue", "Target3ModifiedProperty1NewValue", "Target3ModifiedProperty2Name", "Target3ModifiedProperty2OldValue", "Target3ModifiedProperty2NewValue", "Target3ModifiedProperty3Name", "Target3ModifiedProperty3OldValue", "Target3ModifiedProperty3NewValue", "Target3ModifiedProperty4Name", "Target3ModifiedProperty4OldValue", "Target3ModifiedProperty4NewValue", "Target3ModifiedProperty5Name", "Target3ModifiedProperty5OldValue", "Target3ModifiedProperty5NewValue", "AdditionalDetail1Key", "AdditionalDetail1Value", "AdditionalDetail2Key", "AdditionalDetail2Value", "AdditionalDetail3Key", "AdditionalDetail3Value", "AdditionalDetail4Key", "AdditionalDetail4Value", "AdditionalDetail5Key", "AdditionalDetail5Value", "AdditionalDetail6Key", "AdditionalDetail6Value")

$EntraLog = Import-Csv $inputFile -Header $InputHeaders | Select-Object -Skip 1

$OutputHeaders = ("Date", "ActorUserPrincipalName", "IPAddress", "Activity", "Result", "Target1UserPrincipalName", "Target1ModifiedProperty1Name", "Service", "Category", "ResultReason", "ActorType", "ActorDisplayName", "Target1Type", "Target1DisplayName", "Target1ModifiedProperty1OldValue", "Target1ModifiedProperty1NewValue", "Target1ModifiedProperty2Name", "Target1ModifiedProperty2OldValue", "Target1ModifiedProperty2NewValue", "Target1ModifiedProperty3Name", "Target1ModifiedProperty3OldValue", "Target1ModifiedProperty3NewValue", "Target1ModifiedProperty4Name", "Target1ModifiedProperty4OldValue", "Target1ModifiedProperty4NewValue", "Target1ModifiedProperty5Name", "Target1ModifiedProperty5OldValue", "Target1ModifiedProperty5NewValue")

[string]$outputFolder = Split-Path -Path $inputFile -Parent
[string]$outputFile = (Get-Item $inputFile).BaseName
[string]$outputPath = $outputFolder + "\" + $outputFile + "_Processed.csv"

$EntraLog | Select-Object $OutputHeaders | Export-Csv -Path "$outputPath" -NoTypeInformation

exit
