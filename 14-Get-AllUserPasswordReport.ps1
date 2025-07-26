#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-AllUserPasswordReport.ps1 - By Bitpusher/The Digital Fox
# v3.1 last updated 2025-07-26
# Script to report of M365 users' accounts and last password change.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-AllUserPasswordReport.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell, MsGraph commands (obsolete MSOnline/MSOL versions commented out).
#
#comp #m365 #security #bec #script #password #report

#Requires -Version 5.1

param(
    [string]$OutputPath = "Default",
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Get-AllUserPasswordReport",
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
    [string]$Encoding = "utf8bom" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
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

$OutputCSV = "$OutputPath\$DomainName\AccountPasswordReport_$($date).csv"
$OutputCSVGraph = "$OutputPath\$DomainName\AccountPasswordReport_Graph_$($date).csv"

Invoke-WebRequest -Uri "https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv" -OutFile "$($env:temp)\LicenseNames.csv"
$translationTable = Import-Csv "$($env:temp)\LicenseNames.csv"

Write-Output "Generating report of all M365 users and their last password change date..."

# Obsolete MSOL command versions:
# Get-MsolUser -All | Select-Object -Property DisplayName, UserPrincipalName, UserType, WhenCreated, IsLicensed, LastDirSyncTime, BlockCredential, PasswordNeverExpires, LastPasswordChangeTimeStamp, @{ Name = "LastPasswordChangeTimeStampISO"; Expression = { $_.LastPasswordChangeTimeStamp.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffK") } } | Export-Csv $OutputCSV -NoTypeInformation -Encoding $Encoding
# Get-MsolUser -All | select-object -property DisplayName,LastPasswordChangeTimeStamp,@{Name="LastPasswordChangeTimeStampISO"; Expression={$_.LastPasswordChangeTimeStamp.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffK")}} | ft

Get-MgUser -all -property ID, DisplayName, UserPrincipalName, Mail, ProxyAddresses, UserType, CreatedDateTime, CreationType, EmployeeType, MemberOf, AssignedLicenses, LicenseDetails, OnPremisesSyncEnabled, OnPremisesSamAccountName, ManagedDevices, AccountEnabled, PasswordPolicies, SignInActivity, lastPasswordChangeDateTime | Select-Object -Property ID, DisplayName, UserPrincipalName, Mail, @{ Name = "ProxyAddresses"; Expression = { $_.ProxyAddresses -join ';' } }, UserType, CreatedDateTime, CreationType, EmployeeType, MemberOf, @{ Name = "AssignedLicensesName"; Expression = { $_.AssignedLicenses.skuid | Foreach-Object {$sku=$_ ; $translationtable | where-object guid -eq $sku | Select -expandproperty product_display_name -first 1} ; $list -join ',' } }, LicenseDetails, OnPremisesSyncEnabled, OnPremisesSamAccountName, ManagedDevices, AccountEnabled, PasswordPolicies, @{N='LastSignInDate';E={$_.SignInActivity.LastSignInDateTime}}, lastPasswordChangeDateTime, @{ Name = "LastPasswordChangeTimeStampISO"; Expression = { $_.lastPasswordChangeDateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffK") } } | Export-Csv $OutputCSVGraph -NoTypeInformation -Encoding $Encoding

# * To allow users to reset passwords see (will also require AD writeback to be enabled if accounts are synced from AD):
# https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/let-users-reset-passwords?
# https://admin.cloud.microsoft/?#/Settings/SecurityPrivacy/:/Settings/L1/SelfServiceReset
# https://entra.microsoft.com/#view/Microsoft_AAD_IAM/PasswordResetMenuBlade/~/Properties

# * To reset M365 password in PowerShell using MsGraph:
# $password = @{ Password = "PASSWORD" ; ForceChangePasswordNextSignIn = $false } ; Update-MgUser -UserId "USERID OR UPN" -PasswordProfile $password 
# * To force reset on next logon (if SSPR is enabled):
# $password = @{ ForceChangePasswordNextSignIn = $false } ; Update-MgUser -UserId "USERID OR UPN" -PasswordProfile $password 
# * Using a CSV with UPN and NewPassword columns:
# Import-CSV "FILENAME" | ForEach-Object { $password = @{ Password = $_.NewPassword ; ForceChangePasswordNextSignIn = $false } ; $UPN = $_.UPN ; try { Update-MgUser -UserId $UPN -PasswordProfile $password -ErrorAction Stop ; Write-Output "Password updated for $($UPN)" } catch { $errorMessage = $_.Exception.Message ; Write-Output "Failed to update the password for $($UPN): $($_.Exception.Message)" } } 
# * Disable password complexity requirements:
# Update-MgUser -UserId "USERID OR UPN" -PasswordPolicies DisableStrongPassword 
# * Disable password expiration:
# Update-MgUser -UserId "USERID OR UPN" -PasswordPolicies DisablePasswordExpiration 
# * Revert:
# Update-MgUser -UserId "USERID OR UPN" -PasswordPolicies None 
# * Send email notification to all users active non-guest users:
# $AllUsers = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, Mail, UserType, AccountEnabled, PasswordPolicies, lastPasswordChangeDateTime
# ForEach ($User in $AllUsers) {
#    If (!$User.AccountEnabled -or $User.userType -eq "Guest") {
#        continue
#    }
#    $EmailBody = "
#        Hello $($User.DisplayName),
#        <br/><br/>
#        Your M365 password will need to be reset upon the next login.
#        <br/><br/>
#        Thank you,<br/>
#        IT Dept
#    "
#$MailParams = @{
#    Message = @{
#        Subject = "Your M365 password needs to be reset."
#        Importance = "High"
#        Body = @{
#            ContentType = "html"
#            Content = $EmailBody
#        }
#        ToRecipients = @(
#            @{
#                EmailAddress = @{
#                    Address = $User.Mail
#                }
#            }
#        )
#    }
#    Send-MgUserMail -UserId $User.Mail -BodyParameter $MailParams
#    }
#}

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:" | Tee-Object -FilePath $logFilePath -Append
    Write-Output $OutputCSV | Tee-Object -FilePath $logFilePath -Append
    # $Prompt = New-Object -ComObject wscript.shell
    # $UserInput = $Prompt.popup("Do you want to open output file?", 0, "Open Output File", 4)
    # if ($UserInput -eq 6) {
    #     Invoke-Item "$OutputCSV"
    # }
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"

exit
