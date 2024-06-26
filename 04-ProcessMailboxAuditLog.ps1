﻿#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#          @VinceVulpes
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# ProcessMailboxAuditLog.ps1 - By Bitpusher/The Digital Fox
# v2.8 last updated 2024-05-12
# Processes an exported CSV of Exchange Online Mailbox Audit log,
# removing columns not needed for manual review and reordering for ease of review.
# Not the most efficient way to process CSV files - Not recommended for use on CSV files with more than 100,000 lines.
#
# Usage:
# powershell -executionpolicy bypass -f .\ProcessMailboxAuditLog.ps1 -inputFile "Path\to\input\log.csv"
#
# Use with DropShim.bat to allow drag-and-drop processing of downloaded logs.
#
#comp #m365 #security #bec #script #exchange #online #mailbox #audit #csv #log #irscript #powershell

#Requires -Version 5.1

param(
    [string]$inputFile = "MailboxAudit.csv",
    [string]$outputFile = "MailboxAudit_Processed.csv",
    [string]$scriptName = "ProcessMailboxAuditLog",
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


$sw = [Diagnostics.StopWatch]::StartNew()

$headerRow = Get-Content $inputFile | ConvertFrom-String -Delimiter "," | Select-Object -First 1 
$headerRow

$InputHeaders = ("Operation", "OperationResult", "LogonType", "ExternalAccess", "DestFolderId", "DestFolderPathName", "FolderId", "FolderPathName", "FolderName", "MemberRights", "MemberSid", "MemberUpn", "ClientInfoString", "ClientIPAddress", "ClientIP", "ClientMachineName", "ClientProcessName", "ClientVersion", "InternalLogonType", "MailboxOwnerUPN", "MailboxOwnerSid", "DestMailboxOwnerUPN", "DestMailboxOwnerSid", "DestMailboxGuid", "CrossMailboxOperation", "LogonUserDisplayName", "LogonUserSid", "SourceItems", "SourceFolders", "SourceItemIdsList", "SourceItemSubjectsList", "SourceItemAttachmentsList", "SourceItemFolderPathNamesList", "SourceFolderPathNamesList", "SourceItemInternetMessageIdsList", "ItemId", "ItemSubject", "ItemAttachments", "ItemInternetMessageId", "DirtyProperties", "OriginatingServer", "SessionId", "OperationProperties", "AuditOperationsCountInAggregatedRecord", "AggregatedRecordFoldersData", "AppId", "ClientAppId", "ItemIsRecord", "ItemComplianceLabel", "MailboxGuid", "MailboxResolvedOwnerName", "LastAccessed", "Identity", "IsValid", "ObjectState")

$Log = Import-Csv $inputFile -Header $InputHeaders | Select-Object -Skip 1

$OutputHeaders = ("LastAccessed", "ClientIPAddress", "ClientIP", "FolderPathName", "DestFolderPathName", "Operation", "OperationResult", "SourceItemSubjectsList", "SourceItemAttachmentsList", "SourceItemFolderPathNamesList", "SourceFolderPathNamesList", "ItemSubject", "ItemAttachments", "ItemInternetMessageId", "LogonType", "ExternalAccess", "MailboxOwnerUPN", "CrossMailboxOperation", "DirtyProperties", "OriginatingServer", "ItemIsRecord")

[string]$outputFolder = Split-Path -Path $inputFile -Parent
[string]$outputFile = (Get-Item $inputFile).BaseName
[string]$outputPath = $outputFolder + "\" + $outputFile + "_Processed.csv"

$Log | Select-Object $OutputHeaders | Export-Csv -Path "$outputPath" -NoTypeInformation

Write-Output "Seconds elapsed for CSV processing: $($sw.elapsed.totalseconds)"

exit
