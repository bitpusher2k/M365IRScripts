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
# v2.8 last updated 2024-05-12
# Script to report of M365 users' accounts and last password change.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-AllUserPasswordReport.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell, MSOnline commands.
#
#comp #m365 #security #bec #script #password #report

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

$OutputCSV = "$OutputPath\$DomainName\AccountPasswordReport_$($date).csv"

Write-Output "Generating report of all M365 users and their last password change date..."

Get-MsolUser -All | Select-Object -Property DisplayName, UserPrincipalName, UserType, WhenCreated, IsLicensed, LastDirSyncTime, BlockCredential, PasswordNeverExpires, LastPasswordChangeTimeStamp, @{ Name = "LastPasswordChangeTimeStampISO"; Expression = { $_.LastPasswordChangeTimeStamp.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffK") } } | Export-Csv $OutputCSV -NoTypeInformation -Encoding $Encoding
#Get-MsolUser -All | select-object -property DisplayName,LastPasswordChangeTimeStamp,@{Name="LastPasswordChangeTimeStampISO"; Expression={$_.LastPasswordChangeTimeStamp.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffK")}} | ft

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:"
    Write-Output $OutputCSV
    $Prompt = New-Object -ComObject wscript.shell
    $UserInput = $Prompt.popup("Do you want to open output file?", 0, "Open Output File", 4)
    if ($UserInput -eq 6) {
        Invoke-Item "$OutputCSV"
    }
}

Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

exit
