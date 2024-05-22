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
# ProcessEntraSignInLog.ps1 - By Bitpusher/The Digital Fox
# v2.8 last updated 2024-05-12
# Processes an exported CSV of Entra ID Sign-in log from admin center
# (https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/SignIns),
# removing columns not needed for manual review, reordering for ease of review,
# and splitting "Location" into three columns.
# Not the most efficient way to process CSV files - Not recommended for use on CSV files with more than 100,000 lines.
#
# Usage:
# powershell -executionpolicy bypass -f .\ProcessEntraSignInLog.ps1 -inputFile "Path\to\input\log.csv"
#
# Use with DropShim.bat to allow drag-and-drop processing of downloaded logs.
#
#comp #m365 #security #bec #script #entraid #asuread #signin #sign-in #csv #log #irscript #powershell

#Requires -Version 5.1

param(
    [string]$inputFile = "EntraSignIn.csv",
    [string]$outputFile = "EntraSignInProcessed.csv",
    [string]$scriptName = "ProcessEntraSignInLog",
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


$headerRow = Get-Content $inputFile | ConvertFrom-String -Delimiter "," | Select-Object -First 1 
$headerRow

$InputHeaders = ("Date", "RequestID", "UserAgent", "CorrelationID", "UserID", "User", "Username", "UserType", "CrossTenantAccess", "TokenType", "AuthenticationProtocol", "UniqueToken", "TransferMethod", "ClientCredential", "TokenProtection", "Application", "ApplicationID ", "Resource", "ResourceID", "ResourceTenantID", "HomeTenantID", "HomeTenantName", "IPaddress", "Location", "Status", "SignInError", "FailureReason", "ClientApp", "DeviceID", "Browser", "OS", "Compliant", "Managed", "JoinType", "MFAResult", "MFAMethod", "MFADetail", "AuthRequirement", "SignInIdentifier", "IPAddressSeen", "AutonomousSysNumber", "Flagged", "TokenIssuerType", "IncomingTokenType", "TokenIssuerName", "Latency", "ConditionalAccess", "ManagedIdentityType", "AssociatedResourceId")

$EntraLog = Import-Csv $inputFile -Header $InputHeaders | Select-Object -Skip 1 | Select-Object *, @{ n = 'City'; e = { $_.Location.Split(',')[0] } }, @{ n = 'Region'; e = { $_.Location.Split(',')[1] } }, @{ n = 'Country'; e = { $_.Location.Split(',')[2] } }, @{ n = 'DateOnly'; e = { $_.Date.Split('T')[0] } }, @{ n = 'TimeOnly'; e = { $_.Date.Split('T')[1].Remove(8) } }

$OutputHeaders = ("Date", "DateOnly", "TimeOnly", "User", "Username", "IPaddress", "City", "Region", "Country", "Status", "UserType", "AuthRequirement", "ConditionalAccess", "TokenType", "Application", "Resource", "ResourceID", "FailureReason", "ClientApp", "Browser", "OS", "Compliant", "Managed", "JoinType", "Latency", "MFAResult", "MFAMethod", "MFADetail")

# $OutputHeaders = ("IPaddress")

[string]$outputFolder = Split-Path -Path $inputFile -Parent
[string]$outputFile = (Get-Item $inputFile).BaseName
[string]$outputPath = $outputFolder + "\" + $outputFile + "_Processed.csv"

$EntraLog | Select-Object $OutputHeaders | Export-Csv -Path "$outputPath" -NoTypeInformation

exit
