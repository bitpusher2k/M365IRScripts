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
# v2.9 last updated 2024-10-14
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


$sw = [Diagnostics.StopWatch]::StartNew()

$headerText = Get-Content $inputFile | Select-Object -First 1 
# $headerText ; pause
$headerRow = Get-Content $inputFile | ConvertFrom-String -Delimiter "," | Select-Object -First 1 
$headerRow

If ($headerText -eq '"Date (UTC)","Request ID","User agent","Correlation ID","User ID","User","Username","User type","Cross tenant access type","Incoming token type","Authentication Protocol","Unique token identifier","Original transfer method","Client credential type","Token Protection - Sign In Session","Token Protection - Sign In Session StatusCode","Application","Application ID ","Resource","Resource ID ","Resource tenant ID","Home tenant ID","Home tenant name","IP address","Location","Status","Sign-in error code","Failure reason","Client app","Device ID","Browser","Operating System","Compliant","Managed","Join Type","Multifactor authentication result","Multifactor authentication auth method","Multifactor authentication auth detail","Authentication requirement","Sign-in identifier","Session ID","IP address (seen by resource)","Through Global Secure Access","Global Secure Access IP address","Autonomous system  number","Flagged for review","Token issuer type","Incoming token type","Token issuer name","Latency","Conditional Access","Managed Identity type","Associated Resource Id","Federated Token Id","Federated Token Issuer"') {
    $InputHeaders = ("DateUTC", "RequestID", "UserAgent", "CorrelationID", "UserID", "User", "Username", "UserType", "CrossTenantAccess", "TokenType", "AuthenticationProtocol", "UniqueToken", "TransferMethod", "ClientCredential", "TokenProtectionSession", "TokenProtectionStatusCode", "Application", "ApplicationID ", "Resource", "ResourceID", "ResourceTenantID", "HomeTenantID", "HomeTenantName", "IPaddress", "Location", "Status", "SignInErrorCode", "FailureReason", "ClientApp", "DeviceID", "Browser", "OS", "Compliant", "Managed", "JoinType", "MFAResult", "MFAMethod", "MFADetail", "AuthRequirement", "SignInIdentifier","SessionID", "IPAddressSeen", "ThroughGlobalSecureAccess", "GSAIPAddress", "AutonomousSysNumber", "Flagged", "TokenIssuerType", "IncomingTokenType", "TokenIssuerName", "Latency", "ConditionalAccess", "ManagedIdentityType", "AssociatedResourceId", "FederatedTokenID", "FederatedTokenIssuer")
} else {
    Write-Output "Header format has changed since script was updated - please update input header definition and try again"
    end
}

$EntraLog = Import-Csv $inputFile -Header $InputHeaders | Select-Object -Skip 1 | Select-Object *, @{ n = 'City'; e = { $_.Location.Split(',')[0] } }, @{ n = 'Region'; e = { $_.Location.Split(',')[1] } }, @{ n = 'Country'; e = { $_.Location.Split(',')[2] } }, @{ n = 'DateOnly'; e = { $_.DateUTC.Split('T')[0] } }, @{ n = 'TimeOnly'; e = { $_.DateUTC.Split('T')[1].Remove(8) } }

$OutputHeaders = ("DateUTC", "DateOnly", "TimeOnly", "User", "Username", "IPaddress", "City", "Region", "Country", "Status", "UserType", "AuthRequirement", "ConditionalAccess", "TokenType", "Application", "Resource", "ResourceID", "FailureReason", "ClientApp", "Browser", "OS", "UserAgent", "Compliant", "Managed", "JoinType", "Latency", "MFAResult", "MFAMethod", "MFADetail","SessionID")

# $OutputHeaders = ("IPaddress")

[string]$outputFolder = Split-Path -Path $inputFile -Parent
[string]$outputFile = (Get-Item $inputFile).BaseName
[string]$outputPath = $outputFolder + "\" + $outputFile + "_Processed.csv"

$EntraLog | Select-Object $OutputHeaders | Export-Csv -Path "$outputPath" -NoTypeInformation

Write-Output "Seconds elapsed for CSV processing: $($sw.elapsed.totalseconds)"

exit
