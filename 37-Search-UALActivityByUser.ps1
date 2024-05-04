#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Search-UALActivityByUser.ps1 - By Bitpusher/The Digital Fox
# v2.8 last updated 2024-05-03
# Script to exports data from the Unified Audit Log for specified users.
#
# Usage:
# powershell -executionpolicy bypass -f .\Search-UALActivityByUser.ps1 -OutputPath "Default" -UserIds "compromisedaccount@contoso.com" -DaysAgo "10"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
#
#comp #m365 #security #bec #script #irscript #powershell #unified #audit #log #search #user

#Requires -Version 5.1

param(
    [string]$OutputPath,
    [string]$UserIds,
    [string]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$Encoding = "utf8bom" # "ascii","ansi","bigendianunicode","unicode","utf8","utf8","utf8NoBOM","utf32"
)

if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }

$date = Get-Date -Format "yyyyMMddHHmmss"

$CheckLog = (Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled
if (!$CheckLog) {
    Write-Output "The Unified Audit Log does not appear to be enabled on this tenant. Export of UAL activities may fail. Try running 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true' if export fails."
}

## If OutputPath variable is not defined, prompt for it
if (!$OutputPath) {
    Write-Output ""
    $OutputPath = Read-Host "Enter the output base path, e.g. $($env:userprofile)\Desktop\Investigation (default)"
    If ($OutputPath -eq '') { $OutputPath = "$($env:userprofile)\Desktop\Investigation" }
    Write-Output "Output base path will be in $OutputPath"
} elseif ($OutputPath -eq 'Default') {
    Write-Output ""
    $OutputPath = "$($env:userprofile)\Desktop\Investigation"
    Write-Output "Output base path will be in $OutputPath"
}

# If OutputPath does not exist, create it
$CheckOutputPath = Get-Item $OutputPath -ErrorAction SilentlyContinue
if (!$CheckOutputPath) {
    Write-Output ""
    Write-Output "`nOutput path does not exist. Directory will be created."
    mkdir $OutputPath
}

# Get Primary Domain Name for output subfolder
$PrimaryDomain = Get-AcceptedDomain | Where-Object Default -EQ $true
$DomainName = $PrimaryDomain.DomainName

$CheckSubDir = Get-Item $OutputPath\$DomainName -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
    Write-Output "`nDomain sub-directory does not exist. Sub-directory will be created."
    mkdir $OutputPath\$DomainName
}

## If UserIds variable is not defined, prompt for it
if (!$UserIds) {
    Write-Output ""
    $UserIds = Read-Host "Enter the user's primary email address (UPN). Comma-separated to search for entries from multiple users"
}

## If DaysAgo variable is not defined, prompt for it
if (!$DaysAgo) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to retrieve ALL available UAL entries associated with these user(s) (default: 10, maximum: 90)'
    if ($DaysAgo -eq '') { $DaysAgo = "10" } elseif ($DaysAgo -gt 90) { $DaysAgo = "90" }
}
if ($DaysAgo -gt 90) { $DaysAgo = "90" }
Write-Output "`nWill search UAC $DaysAgo days back from today for relevant events."

$StartDate = (Get-Date).AddDays(- $DaysAgo)
$EndDate = (Get-Date).AddDays(1)

$OutputCSV = "$OutputPath\$DomainName\UnifiedAuditLogEntries_$($UserIds)_going_back_$($DaysAgo)_days_from_$($date).csv"

$sesid = Get-Random # Get random session number
$count = 1
do {
    Write-Output "Getting unified audit logs page $count - Please wait"
    try {
        $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $UserIds -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize 5000
    } catch {
        Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n"
        Write-Output "Exception message:", $_.Exception.Message, "`n"
        exit 2 # Terminate script
    }
    $AuditOutput += $currentoutput # Build total results array
    ++ $count # Increment page count
} until ($currentoutput.count -eq 0) # Until there are no more logs in range to get

if (!$AuditOutput) {
    Write-Output "`nThere are no activities in the audit log for the time period specified`n"
} else {
    $AuditOutput | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding $Encoding
    Write-Output "`nSee user activities report in the output path.`n"
}

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:"
    Write-Output $OutputCSV
    # $Prompt = New-Object -ComObject wscript.shell
    # $UserIdsInput = $Prompt.popup("Do you want to open output file?",0,"Open Output File",4)
    # If ($UserIdsInput -eq 6) {
    # 	Invoke-Item "$OutputCSV"
    # }
}
Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

exit
