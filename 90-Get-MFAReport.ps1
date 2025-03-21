﻿#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-MFAReport.ps1
# Original report function created by o365reports.com - https://o365reports.com/2022/04/27/get-mfa-status-of-office-365-users-using-microsoft-graph-powershell
# modified by Bitpusher/The Digital Fox
# v2.8 last updated 2024-05-12
# Script to Export M365 MFA settings of each account using Microsoft Graph.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-MFAReport.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses (ExchangePowerShell), Microsoft Graph commands.
#
#comp #m365 #security #bec #script #irscript #powershell #mfa #report

#Requires -Version 5.1

param(
    [string]$OutputPath,
    [Parameter(Mandatory = $false)]
    [switch]$CreateSession,
    [switch]$MFAEnabled,
    [switch]$MFADisabled,
    [switch]$LicensedUsersOnly,
    [switch]$SignInAllowedUsersOnly,
    [string]$Encoding = "utf8bom" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
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
# $PrimaryDomain = Get-AcceptedDomain | Where-Object Default -eq $true
# $DomainName = $PrimaryDomain.DomainName
$PrimaryDomain = Get-MgDomain | Where-Object { $_.isdefault -eq $True } | Select-Object -Property ID
$DomainName = $PrimaryDomain.ID

$CheckSubDir = Get-Item $OutputPath\$DomainName -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
    Write-Output ""
    Write-Output "Domain sub-directory does not exist. Sub-directory `"$DomainName`" will be created."
    mkdir $OutputPath\$DomainName
}

if ((Get-MgContext) -ne "") {
    Write-Output "Connected to Microsoft Graph PowerShell using $((Get-MgContext).Account) account"
}

$ProcessedUserCount = 0
$ExportCount = 0
#Set output file
$OutputCSV = "$OutputPath\$DomainName\MfaAccountSettingsReport_$($date).csv"
$Result = ""
$Results = @()

Write-Output "Will now retrieve & process the MFA settings of each account on tenant..."
#Get all users
# Get-MgUser -All -Filter "UserType eq 'Member'" | ForEach-Object {
Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled, AssignedLicenses, Department | ForEach-Object {
    $ProcessedUserCount++
    $Name = $_.DisplayName
    $UPN = $_.UserPrincipalName
    $Department = $_.Department
    if ($_.AccountEnabled -eq $true) {
        $SigninStatus = "Allowed"
    } else {
        $SigninStatus = "Blocked"
    }
    if (($_.AssignedLicenses).Count -ne 0) {
        $LicenseStatus = "Licensed"
    } else {
        $LicenseStatus = "Unlicensed"
    }
    $Is3rdPartyAuthenticatorUsed = "False"
    $MFAPhone = "-"
    $MicrosoftAuthenticatorDevice = "-"
    Write-Progress -Activity "Processed users count: $ProcessedUserCount - Currently reviewing: $Name"
    [array]$MFAData = Get-MgUserAuthenticationMethod -UserId $UPN
    $AuthenticationMethod = @()
    $AdditionalDetails = @()

    foreach ($MFA in $MFAData) {
        switch ($MFA.AdditionalProperties["@odata.type"]) {
            "#microsoft.graph.passwordAuthenticationMethod" {
                $AuthMethod = 'PasswordAuthentication'
                $AuthMethodDetails = $MFA.AdditionalProperties["displayName"]
            }
            "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" {
                # Microsoft Authenticator App
                $AuthMethod = 'AuthenticatorApp'
                $AuthMethodDetails = $MFA.AdditionalProperties["displayName"]
                $MicrosoftAuthenticatorDevice = $MFA.AdditionalProperties["displayName"]
            }
            "#microsoft.graph.phoneAuthenticationMethod" {
                # Phone authentication
                $AuthMethod = 'PhoneAuthentication'
                $AuthMethodDetails = $MFA.AdditionalProperties["phoneType", "phoneNumber"] -join ' '
                $MFAPhone = $MFA.AdditionalProperties["phoneNumber"]
            }
            "#microsoft.graph.fido2AuthenticationMethod" {
                # FIDO2 key
                $AuthMethod = 'Fido2'
                $AuthMethodDetails = $MFA.AdditionalProperties["model"]
            }
            "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" {
                # Windows Hello
                $AuthMethod = 'WindowsHelloForBusiness'
                $AuthMethodDetails = $MFA.AdditionalProperties["displayName"]
            }
            "#microsoft.graph.emailAuthenticationMethod" {
                # Email Authentication
                $AuthMethod = 'EmailAuthentication'
                $AuthMethodDetails = $MFA.AdditionalProperties["emailAddress"]
            }
            "microsoft.graph.temporaryAccessPassAuthenticationMethod" {
                # Temporary Access pass
                $AuthMethod = 'TemporaryAccessPass'
                $AuthMethodDetails = 'Access pass lifetime (minutes): ' + $MFA.AdditionalProperties["lifetimeInMinutes"]
            }
            "#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod" {
                # Passwordless
                $AuthMethod = 'PasswordlessMSAuthenticator'
                $AuthMethodDetails = $MFA.AdditionalProperties["displayName"]
            }
            "#microsoft.graph.softwareOathAuthenticationMethod" {
                $AuthMethod = 'SoftwareOath'
                $Is3rdPartyAuthenticatorUsed = "True"
            }
        }
        $AuthenticationMethod += $AuthMethod
        if ($AuthMethodDetails -ne $null) {
            $AdditionalDetails += "$AuthMethod : $AuthMethodDetails"
        }
    }
    #Remove duplicate authentication methods
    $AuthenticationMethod = $AuthenticationMethod | Sort-Object | Get-Unique
    $AuthenticationMethods = $AuthenticationMethod -join ","
    $AdditionalDetail = $AdditionalDetails -join ", "
    $Print = 1
    #Determine MFA status
    [array]$StrongMFAMethods = ("Fido2", "PhoneAuthentication", "PasswordlessMSAuthenticator", "AuthenticatorApp", "WindowsHelloForBusiness")
    $MFAStatus = "Disabled"

    foreach ($StrongMFAMethod in $StrongMFAMethods) {
        if ($AuthenticationMethod -contains $StrongMFAMethod) {
            $MFAStatus = "Strong"
            break
        }
    }

    if (($MFAStatus -ne "Strong") -and ($AuthenticationMethod -contains "SoftwareOath")) {
        $MFAStatus = "Weak"
    }

    # #Filter result based on MFA status
    # if ($MFADisabled.IsPresent -and $MFAStatus -ne "Disabled") {
    #     $Print = 0
    # }
    # if ($MFAEnabled.IsPresent -and $MFAStatus -eq "Disabled") {
    #     $Print = 0
    # }
    # 
    # #Filter result based on license status
    # if ($LicensedUsersOnly.IsPresent -and ($LicenseStatus -eq "Unlicensed")) {
    #     $Print = 0
    # }
    # 
    # #Filter result based on signin status
    # if ($SignInAllowedUsersOnly.IsPresent -and ($SigninStatus -eq "Blocked")) {
    #     $Print = 0
    # }

    if ($Print -eq 1) {
        $ExportCount++
        $Result = @{ 'Name' = $Name; 'UPN' = $UPN; 'Department' = $Department; 'License Status' = $LicenseStatus; 'SignIn Status' = $SigninStatus; 'Authentication Methods' = $AuthenticationMethods; 'MFA Status' = $MFAStatus; 'MFA Phone' = $MFAPhone; 'Microsoft Authenticator Configured Device' = $MicrosoftAuthenticatorDevice; 'Is 3rd-Party Authenticator Used' = $Is3rdPartyAuthenticatorUsed; 'Additional Details' = $AdditionalDetail }
        $Results = New-Object PSObject -Property $Result
        $Results | Select-Object Name, UPN, Department, 'License Status', 'SignIn Status', 'Authentication Methods', 'MFA Status', 'MFA Phone', 'Microsoft Authenticator Configured Device', 'Is 3rd-Party Authenticator Used', 'Additional Details' | Export-Csv -Path $OutputCSV -NoTypeInformation -Append -Encoding $Encoding
    }
}

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:"
    Write-Output $OutputCSV
    # $Prompt = New-Object -ComObject wscript.shell
    # $UserInput = $Prompt.popup("Do you want to open output file?", 0, "Open Output File", 4)
    # if ($UserInput -eq 6) {
    #     Invoke-Item "$OutputCSV"
    # }
} else {
    Write-Output "No users found"
}

Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

exit
