#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-MailboxPermissions.ps1 - By Bitpusher/The Digital Fox
# v2.8 last updated 2024-05-12
# Script to generate a report of non-standard permissions applied to Exchange Online user and shared mailboxes.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-MailboxPermissions.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
#
#comp #m365 #security #bec #script #irscript #powershell #mailbox #permissions

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

$OutputCSV = "$OutputPath\$DomainName\MailboxPermissions_$($date).csv"

Write-Output "Checking mailbox permissions..."
$Mbx = Get-Mailbox -RecipientTypeDetails UserMailbox, SharedMailbox -ResultSize Unlimited | Select-Object DisplayName, UserPrincipalName, RecipientTypeDetails
# REST version:
# $Mbx = Get-ExoMailbox -RecipientTypeDetails UserMailbox, SharedMailbox -Properties RecipientTypeDetails -ResultSize Unlimited

if ($Mbx.Count -eq 0) { Write-Error "No mailboxes found. Ending..." -ErrorAction Stop }

# Process found mailboxes...
$Report = [System.Collections.Generic.List[Object]]::new() # Create output file
$ProgressDelta = 100 / ($Mbx.Count); $PercentComplete = 0; $MbxNumber = 0
foreach ($M in $Mbx) {
    $MbxNumber++
    $MbxStatus = $M.DisplayName + " [" + $MbxNumber + "/" + $Mbx.Count + "]"
    Write-Progress -Activity "Processing mailbox" -Status $MbxStatus -PercentComplete $PercentComplete
    $PercentComplete += $ProgressDelta
    # REST equivalent:
    # $Permissions = Get-ExoMailboxPermission -Identity $M.UserPrincipalName | ?  {$_.User -Like "*@*" }
    $Permissions = Get-MailboxPermission -Identity $M.UserPrincipalName | Where-Object { $_.User -like "*@*" }
    if ($Null -ne $Permissions) {
        # Grab each permission and add it into the report
        foreach ($Permission in $Permissions) {
            $ReportLine = [pscustomobject]@{
                Mailbox     = $M.DisplayName
                UPN         = $M.UserPrincipalName
                Permission  = $Permission | Select-Object -ExpandProperty AccessRights
                AssignedTo  = $Permission.User
                MailboxType = $M.RecipientTypeDetails
            }
            $Report.Add($ReportLine)
        }
    }
}
$Report | Sort-Object -Property @{ Expression = { $_.MailboxType }; Ascending = $False }, Mailbox | Export-Csv $OutputCSV -NoTypeInformation -Encoding $Encoding
Write-Output "$Mbx.Count mailboxes scanned."

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
