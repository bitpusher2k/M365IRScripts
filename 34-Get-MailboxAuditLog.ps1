#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-MailboxAuditLog.ps1 - By Bitpusher/The Digital Fox
# v2.8 last updated 2024-05-03
# Script to get the mailbox audit log of specified users, or all users.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-MailboxAuditLog.ps1 -OutputPath "Default" -UserIds "compromisedaccount@contoso.com" -DaysAgo "10"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
#
#comp #m365 #security #bec #script #irscript #powershell #mailbox #audit #log

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$Encoding = "utf8bom" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
)

if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }

try {
    $areYouConnected = Search-MailboxAuditlog -ErrorAction stop
} catch {
    Write-Output "[WARNING] You must call Connect-M365 before running this script"
    break
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

## If UserIds variable is not defined, prompt for it
if (!$UserIds) {
    Write-Output ""
    $UserIds = Read-Host 'Enter the user ID (email address) to retreive mailbox audit log of (leave blank to retirieve for all users - could take a long time)'
}

## If DaysAgo variable is not defined, prompt for it
if (!$DaysAgo) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to retrieve ALL available Mailbox Audit Log entries (default: 30, maximum: 180)'
    if ($DaysAgo -eq '') { $DaysAgo = "30" }
    Write-Output "Will attempt to retrieve all UAC entries going back $DaysAgo days from today."
}
if ($DaysAgo -gt 180) { $DaysAgo = "180" }

$StartDate = (Get-Date).AddDays(- $DaysAgo)
$EndDate = (Get-Date).AddDays(1)
$resultSize = 5000 #Maximum number of records that can be retrieved per query
$date = Get-Date -Format "yyyyMMddHHmmss"

Write-Output "Search-MailboxAuditLog is being deprecated by Microsoft in April 2024 (https://aka.ms/AuditCmdletBlog)"
Write-Output "Microsoft has said to use the `"Search-UnifiedAuditLog -RecordType ExchangeItem`" instead."
Write-Output "This script currently uses both queries."
Write-Output "Running Search-MailboxAuditLog and Search-UnifiedAuditLog commands..."


if (($null -eq $UserIds) -or ($UserIds -eq "")) {
    Write-Output "No users specified. Getting the Mailbox Audit Log for all users..."
    Get-mailbox -resultsize unlimited |
        ForEach-Object {
            $date = Get-Date -Format "yyyyMMddHHmmss"
            $outputFile = "$OutputPath\$DomainName\mailboxAuditLog_$($_.UserPrincipalName)_going_back_$($DaysAgo)_days_from_$($date).csv"
            $outputFileUAL = "$OutputPath\$DomainName\mailboxAuditLogUAL_$($_.UserPrincipalName)_going_back_$($DaysAgo)_days_from_$($date).csv"

            Write-Output "Collecting the MailboxAuditLog for $($_.UserPrincipalName)"

            Write-Output "Search-MailboxAuditlog -Identity $_.UserPrincipalName -LogonTypes Delegate,Admin,Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -ResultSize 250000"
            $result = Search-MailboxAuditlog -Identity $_.UserPrincipalName -LogonTypes Delegate, Admin, Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -resultsize 250000
            $result | Export-Csv -NoTypeInformation -Path $outputFile -Encoding $Encoding -Append

            $sesid = Get-Random # Get random session number
            Write-Output "Search-UnifiedAuditLog -RecordType ExchangeItem -UserIds $_.UserPrincipalName -StartDate $StartDate -EndDate $EndDate -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize"
            $count = 1
            do {
                Write-Output "Getting unified audit logs page $count - Please wait"
                try {
                    $currentOutput = Search-UnifiedAuditLog -RecordType ExchangeItem -UserIds $_.UserPrincipalName -StartDate $StartDate -EndDate $EndDate -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
                } catch {
                    Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n"
                    Write-Output "Exception message:", $_.Exception.Message, "`n"
                    exit 2 # Terminate script
                }
                $result += $currentoutput # Build total results array
                ++ $count # Increment page count
            } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
            
            $result | Export-Csv -NoTypeInformation -Path $outputFileUAL -Encoding $Encoding -Append

            Write-Output "Results have been written to $outputFile & $outputFileUAL"
        }
} elseif ($UserIds -match ",") {
    $UserIds.Split(",") | ForEach-Object {
        $date = Get-Date -Format "yyyyMMddHHmmss"
        $user = $_
        $outputFile = "$OutputPath\$DomainName\mailboxAuditLog_$($user)_going_back_$($DaysAgo)_days_from_$($date).csv"
        $outputFileUAL = "$OutputPath\$DomainName\mailboxAuditLogUAL_$($user)_going_back_$($DaysAgo)_days_from_$($date).csv"

        Write-Output "Collecting the MailboxAuditLog for $user"

        Write-Output "Search-MailboxAuditlog -Identity $user -LogonTypes Delegate,Admin,Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -ResultSize 250000"
        $result = Search-MailboxAuditlog -Identity $user -LogonTypes Delegate, Admin, Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -resultsize 250000
        $result | Export-Csv -NoTypeInformation -Path $outputFile -Encoding $Encoding -Append

        $sesid = Get-Random # Get random session number
        Write-Output "Search-UnifiedAuditLog -RecordType ExchangeItem -UserIds $user -StartDate $StartDate -EndDate $EndDate -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize"
        $count = 1
        do {
            Write-Output "Getting unified audit logs page $count - Please wait"
            try {
                $currentOutput = Search-UnifiedAuditLog -RecordType ExchangeItem -UserIds $user -StartDate $StartDate -EndDate $EndDate -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
            } catch {
                Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n"
                Write-Output "Exception message:", $_.Exception.Message, "`n"
                exit 2 # Terminate script
            }
            $result += $currentoutput # Build total results array
            ++ $count # Increment page count
        } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get

        $result | Export-Csv -NoTypeInformation -Path $outputFileUAL -Encoding $Encoding -Append

        Write-Output "Results have been written to $outputFile & $outputFileUAL"
    }
} else {
    $outputFile = "$OutputPath\$DomainName\mailboxAuditLog_$($UserIds)_going_back_$($DaysAgo)_days_from_$($date).csv"
    $outputFileUAL = "$OutputPath\$DomainName\mailboxAuditLogUAL_$($UserIds)_going_back_$($DaysAgo)_days_from_$($date).csv"

    Write-Output "Collecting the MailboxAuditLog for $UserIds"

    Write-Output "Search-MailboxAuditlog -Identity $UserIds -LogonTypes Delegate,Admin,Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -ResultSize 250000"
    $result = Search-MailboxAuditlog -Identity $UserIds -LogonTypes Delegate, Admin, Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -resultsize 250000
    $result | Export-Csv -NoTypeInformation -Path $outputFile -Encoding $Encoding -Append

    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -RecordType ExchangeItem -UserIds $UserIds -StartDate $StartDate -EndDate $EndDate -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize"
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait"
        try {
            $currentOutput = Search-UnifiedAuditLog -RecordType ExchangeItem -UserIds $UserIds -StartDate $StartDate -EndDate $EndDate -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n"
            Write-Output "Exception message:", $_.Exception.Message, "`n"
            exit 2 # Terminate script
        }
        $result += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    
    $result | Export-Csv -NoTypeInformation -Path $outputFileUAL -Encoding $Encoding -Append

    Write-Output "Results have been written to $outputFile & $outputFileUAL"
}

# * Check mailbox audit settings:
# Get-OrganizationConfig | Format-List AuditDisabled
# Get-MailboxAuditBypassAssociation | Select-Object Name, AuditByPassEnabled | Where-Object -Property AuditBypassEnabled -eq $True | FT
# Get-Mailbox -ResultSize Unlimited | Where-Object { $_.AuditEnabled -eq "$true" } | Select-Object DisplayName, Alias, AuditEnabled, DefaultAuditSet, AuditLogAgeLimit, AuditOwner, AuditDelegate, AuditAdmin | Export-CSV MailboxAuditSettings.csv -NoTypeInformation -Encoding $encoding
# Get-Mailbox -Identity "MailboxIdentity" | Select-Object DisplayName, Alias, AuditEnabled, DefaultAuditSet, AuditLogAgeLimit, AuditOwner, AuditDelegate, AuditAdmin
# Get-Mailbox -Identity "MailboxIdentity" | Select-Object -ExpandProperty AuditOwner
# Get-Mailbox -Identity "MailboxIdentity" | Select-Object -ExpandProperty AuditDelegate
# Get-Mailbox -Identity "MailboxIdentity" | Select-Object -ExpandProperty AuditAdmin
# Get-Mailbox -Identity "MailboxIdentity" | Format-List
# Get-MailboxFolderStatistics -Identity "MailboxIdentity" | Where-Object {$_.FolderType -eq 'Audits'} | Format-Table Identity, ItemsInFolder, FolderSize –auto
# * Restore default settings:
# Set-OrganizationConfig -AuditDisabled $false
# Set-Mailbox -Identity "MailboxIdentity" -DefaultAuditSet Admin,Delegate,Owner
# * Enable auditing of all possible actions:
# Set-Mailbox "MailboxIdentity" -AuditOwner "Create, SoftDelete, HardDelete, Update, Move, MoveToDeletedItems, MailboxLogin, UpdateFolderPermissions"
# Set-Mailbox "MailboxIdentity" -AuditDelegate "Create, FolderBind, SendAs, SendOnBehalf, SoftDelete, HardDelete, Update, Move, MoveToDeletedItems, UpdateFolderPermissions"
# Set-Mailbox "MailboxIdentity" -AuditAdmin "Create, FolderBind, MessageBind, SendAs, SendOnBehalf, SoftDelete, HardDelete, Update, Move, Copy, MoveToDeletedItems, UpdateFolderPermissions"

Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

exit
