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
# v3.1 last updated 2025-07-26
# Script to get the mailbox audit log of specified users, or all users.
#
# Obsolete "Search-MailboxAuditLog" commands have been commented out
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-MailboxAuditLog.ps1 -OutputPath "Default" -UserIds "compromisedaccount@contoso.com" -DaysAgo "10"
#
# powershell -executionpolicy bypass -f .\Get-MailboxAuditLog.ps1 -OutputPath "Default" -UserIds "compromisedaccount@contoso.com" -StartDate "2025-07-12" -EndDate "2025-07-20"
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
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Get-MailboxAuditLog",
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
    [string]$Encoding = "utf8NoBOM" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
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

try {
    $areYouConnected = Search-MailboxAuditlog -ErrorAction stop
} catch {
    Write-Output "[WARNING] You must call Connect-M365 before running this script"
    break
}

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
$PrimaryDomain = Get-AcceptedDomain | Where-Object Default -EQ $true
$DomainName = $PrimaryDomain.DomainName

$CheckSubDir = Get-Item $OutputPath\$DomainName -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
    Write-Output ""
    Write-Output "Domain sub-directory does not exist. Sub-directory `"$DomainName`" will be created." | Tee-Object -FilePath $logFilePath -Append
    mkdir $OutputPath\$DomainName
}
Write-Output "Domain sub-directory will be `"$DomainName`"" | Tee-Object -FilePath $logFilePath -Append

## If UserIds variable is not defined, prompt for it
if (!$UserIds) {
    Write-Output ""
    $UserIds = Read-Host 'Enter the user ID (email address) to retreive mailbox audit log of (leave blank to retirieve for all users - could take a long time)'
}

## Get valid starting end ending dates
if (!$DaysAgo -and (!$StartDate -or !$EndDate)) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to retrieve relevant UAL entries (default: 10, maximum: 180)'
    if ($DaysAgo -eq '') { $DaysAgo = "10" } elseif ($DaysAgo -gt 180) { $DaysAgo = "180" }
}

if ($DaysAgo) {
    if ($DaysAgo -gt 180) { $DaysAgo = "180" }
    Write-Output "`nScript will search UAC $DaysAgo days back from today for relevant events." | Tee-Object -FilePath $logFilePath -Append
    $StartDate = (Get-Date).touniversaltime().AddDays(-$DaysAgo)
    $EndDate = (Get-Date).touniversaltime()
    Write-Output "StartDate: $StartDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "EndDate: $EndDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
} elseif ($StartDate -and $EndDate) {
    $StartDate = ($StartDate).touniversaltime()
    $EndDate = ($EndDate).touniversaltime()
    if ($StartDate -lt (Get-Date).touniversaltime().AddDays(-180)) { $StartDate = (Get-Date).touniversaltime().AddDays(-180) }
    if ($StartDate -ge $EndDate) { $EndDate = ($StartDate).AddDays(1) }
    Write-Output "`nScript will search UAC between StartDate and EndDate for relevant events." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "StartDate: $StartDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "EndDate: $EndDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "Neither DaysAgo nor StartDate/EndDate specified. Ending." | Tee-Object -FilePath $logFilePath -Append
    exit
}


$resultSize = 5000 #Maximum number of records that can be retrieved per query
$date = Get-Date -Format "yyyyMMddHHmmss"

Write-Output "Search-MailboxAuditLog is being deprecated by Microsoft in April 2024 (https://aka.ms/AuditCmdletBlog)"
Write-Output "Microsoft has said to use the `"Search-UnifiedAuditLog -RecordType ExchangeItem`" instead."
Write-Output "This script now only attempts to search UAL."
Write-Output "Running Search-UnifiedAuditLog commands..." | Tee-Object -FilePath $logFilePath -Append


if (($null -eq $UserIds) -or ($UserIds -eq "")) {
    Write-Output "No users specified. Getting the Mailbox Audit Log for all users..." | Tee-Object -FilePath $logFilePath -Append
    Get-mailbox -resultsize unlimited |
        ForEach-Object {
            $date = Get-Date -Format "yyyyMMddHHmmss"
            $outputFile = "$OutputPath\$DomainName\mailboxAuditLog_$($_.UserPrincipalName)_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC.csv"
            $outputFileUAL = "$OutputPath\$DomainName\mailboxAuditLogUAL_$($_.UserPrincipalName)_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC.csv"

            Write-Output "Collecting the MailboxAuditLog for $($_.UserPrincipalName)"

            # Obsolete "Search-MailboxAuditLog commands:
            # Write-Output "Search-MailboxAuditlog -Identity $_.UserPrincipalName -LogonTypes Delegate,Admin,Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -ResultSize 250000"
            # $result = Search-MailboxAuditlog -Identity $_.UserPrincipalName -LogonTypes Delegate, Admin, Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -resultsize 250000
            # $result | Export-Csv -NoTypeInformation -Path $outputFile -Encoding $Encoding -Append

            $sesid = Get-Random # Get random session number
            Write-Output "Search-UnifiedAuditLog -RecordType ExchangeItem -UserIds $_.UserPrincipalName -StartDate $StartDate -EndDate $EndDate -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
            $count = 1
            do {
                Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
                try {
                    Write-Output "Test query:" ; Search-UnifiedAuditLog -StartDate $EndDate -EndDate $EndDate -resultsize 1 # Test query to show warning if present
                    $currentOutput = Search-UnifiedAuditLog -RecordType ExchangeItem -UserIds $_.UserPrincipalName -StartDate $StartDate -EndDate $EndDate -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
                } catch {
                    Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
                    Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
                    exit 2 # Terminate script
                }
                $result += $currentoutput # Build total results array
                ++ $count # Increment page count
            } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
            
            $result | Export-Csv -NoTypeInformation -Path $outputFileUAL -Encoding $Encoding -Append

            Write-Output "Results have been written to $outputFile & $outputFileUAL" | Tee-Object -FilePath $logFilePath -Append
        }
} elseif ($UserIds -match ",") {
    $UserIds.Split(",") | ForEach-Object {
        $date = Get-Date -Format "yyyyMMddHHmmss"
        $user = $_
        $outputFile = "$OutputPath\$DomainName\mailboxAuditLog_$($user)_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC.csv"
        $outputFileUAL = "$OutputPath\$DomainName\mailboxAuditLogUAL_$($user)_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC.csv"

        Write-Output "Collecting the MailboxAuditLog for $user" | Tee-Object -FilePath $logFilePath -Append

        # Obsolete "Search-MailboxAuditLog commands:
        # Write-Output "Search-MailboxAuditlog -Identity $user -LogonTypes Delegate,Admin,Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -ResultSize 250000"
        # $result = Search-MailboxAuditlog -Identity $user -LogonTypes Delegate, Admin, Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -resultsize 250000
        # $result | Export-Csv -NoTypeInformation -Path $outputFile -Encoding $Encoding -Append

        $sesid = Get-Random # Get random session number
        Write-Output "Search-UnifiedAuditLog -RecordType ExchangeItem -UserIds $user -StartDate $StartDate -EndDate $EndDate -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
        $count = 1
        do {
            Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
            try {
                Write-Output "Test query:" ; Search-UnifiedAuditLog -StartDate $EndDate -EndDate $EndDate -resultsize 1 # Test query to show warning if present
                $currentOutput = Search-UnifiedAuditLog -RecordType ExchangeItem -UserIds $user -StartDate $StartDate -EndDate $EndDate -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
            } catch {
                Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
                Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
                exit 2 # Terminate script
            }
            $result += $currentoutput # Build total results array
            ++ $count # Increment page count
        } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get

        $result | Export-Csv -NoTypeInformation -Path $outputFileUAL -Encoding $Encoding -Append

        Write-Output "Results have been written to $outputFile & $outputFileUAL" | Tee-Object -FilePath $logFilePath -Append
    }
} else {
    $outputFile = "$OutputPath\$DomainName\mailboxAuditLog_$($UserIds)_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC.csv"
    $outputFileUAL = "$OutputPath\$DomainName\mailboxAuditLogUAL_$($UserIds)_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC.csv"

    Write-Output "Collecting the MailboxAuditLog for $UserIds" | Tee-Object -FilePath $logFilePath -Append

    # Obsolete "Search-MailboxAuditLog commands:
    # Write-Output "Search-MailboxAuditlog -Identity $UserIds -LogonTypes Delegate,Admin,Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -ResultSize 250000"
    # $result = Search-MailboxAuditlog -Identity $UserIds -LogonTypes Delegate, Admin, Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -resultsize 250000
    # $result | Export-Csv -NoTypeInformation -Path $outputFile -Encoding $Encoding -Append

    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -RecordType ExchangeItem -UserIds $UserIds -StartDate $StartDate -EndDate $EndDate -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
        try {
            $currentOutput = Search-UnifiedAuditLog -RecordType ExchangeItem -UserIds $UserIds -StartDate $StartDate -EndDate $EndDate -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
            exit 2 # Terminate script
        }
        $result += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    
    $result | Export-Csv -NoTypeInformation -Path $outputFileUAL -Encoding $Encoding -Append

    Write-Output "Results have been written to $outputFile & $outputFileUAL" | Tee-Object -FilePath $logFilePath -Append
}

# * To Check mailbox audit settings:
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

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"

exit
