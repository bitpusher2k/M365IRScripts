#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-ExchangeMessageContentSearch.ps1 - By Bitpusher/The Digital Fox
# v3.1.2 last updated 2025-11-07
# Script to walk through usual content search steps for dealing with spam/phishing messages:
# * Search for messages by sender, subject, and date ranges based on days ago
# * Export preview report
# * Open browser window to export message contents (must now be done through web interface)
# * Purge messages (soft delete) and provide report of purge
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-ExchangeMessageContentSearch.ps1 -OutputPath "Default" -UserIds "compromisedaccount@contoso.com" -DaysAgo "5" -Subject "Phishing Message"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangeOnlineManagement (IPPS) commands. Requires minimum module version of 3.9.0.
#
#comp #m365 #security #bec #script #irscript #powershell #contentsearch #export #message #purge #content #search

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [string]$Subject,
    [string]$Identifier,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Get-ExchangeMessageContentSearch",
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

Write-Output "You are signed in as:"
$CurrentUser = (Get-ConnectionInformation).UserPrincipalName[1]
$CurrentUser

# https://www.nextpoint.com/ediscovery-blog/ediscovery-keyword-search-examples/
# ((From:Dave recipients:Sue) OR (From:Sue recipients:Dave) OR (From:Dave recipients:Mike) OR (From:Mike recipients:Dave)) received:"This month"
# (c:c)(subjecttitle=“The Care Employment Opportunity”)(sent=2023-10-30..2023-10-31)

# Connect-IPPSSession
# Enable-OrganizationCustomization
Write-Output ""
Write-Output "Current users with Mailbox Search permissions are:" | Tee-Object -FilePath $logFilePath -Append
Get-ManagementRoleAssignment -Role "Mailbox Search" -GetEffectiveUsers -Delegating $false | Select-Object EffectiveUserName, RoleAssigneeName, AssignmentMethod, DistinguishedName | Format-Table | Tee-Object -FilePath $logFilePath -Append
Get-ManagementRoleAssignment -Role "Mailbox Search" -GetEffectiveUsers -Delegating $true | Select-Object EffectiveUserName, RoleAssigneeName, AssignmentMethod, DistinguishedName | Format-Table | Tee-Object -FilePath $logFilePath -Append
Write-Output "" | Tee-Object -FilePath $logFilePath -Append
Write-Output "Current users with eDiscovery Case Admin (eDiscovery Administrator) permissions are:" | Tee-Object -FilePath $logFilePath -Append
Get-eDiscoveryCaseAdmin | Select-Object WindowsLiveID, Alias, DisplayName, PrimarySmtpAddress, DistinguishedName | Format-Table | Tee-Object -FilePath $logFilePath -Append
Write-Output "" | Tee-Object -FilePath $logFilePath -Append
Write-Output "Additional objects often configured with with eDiscovery permissions:" | Tee-Object -FilePath $logFilePath -Append
# Get-RoleGroupMember -Identity "eDiscovery Manager"
try { Get-RoleGroupMember -Identity "eDiscovery Manager" -ErrorAction stop | Select-Object EffectiveUserName, DisplayName, Name, DistinguishedName, guid | Tee-Object -FilePath $logFilePath -Append } catch { Write-Output "object eDiscovery Manager not found" | Tee-Object -FilePath $logFilePath -Append }
try { Get-RoleGroupMember -Identity eDiscoveryManager -ErrorAction stop | Select-Object EffectiveUserName, DisplayName, Name, DistinguishedName, guid | Tee-Object -FilePath $logFilePath -Append } catch { Write-Output "object eDiscoveryManager not found" | Tee-Object -FilePath $logFilePath -Append }
try { Get-RoleGroupMember -Identity Reviewer -ErrorAction stop | Select-Object EffectiveUserName, DisplayName, Name, DistinguishedName, guid | Tee-Object -FilePath $logFilePath -Append } catch { Write-Output "object Reviewer not found" | Tee-Object -FilePath $logFilePath -Append }
try { Get-RoleGroupMember -Identity ComplianceAdministrator -ErrorAction stop | Select-Object EffectiveUserName, DisplayName, Name, DistinguishedName, guid | Tee-Object -FilePath $logFilePath -Append } catch { Write-Output "object ComplianceAdministrator not found" | Tee-Object -FilePath $logFilePath -Append }


Write-Output "" | Tee-Object -FilePath $logFilePath -Append
Write-Output "If your username is included in the above manager/admin permissions you can continue. Otherwise: Ctrl+c, update permissions (https://purview.microsoft.com/settings/purviewpermissions  Old link: https://compliance.microsoft.com/compliancecenterpermissions), sign-out, sign-in, and try again..." | Tee-Object -FilePath $logFilePath -Append
Write-Output "`nOr use these commands from PoswerShell:" | Tee-Object -FilePath $logFilePath -Append
Write-Output "Add-RoleGroupMember `"eDiscovery Manager`" -Member $CurrentUser; Get-RoleGroupMember -Identity `"eDiscovery Manager`"" | Tee-Object -FilePath $logFilePath -Append
Write-Output "Add-eDiscoveryCaseAdmin $CurrentUser; Get-eDiscoveryCaseAdmin" | Tee-Object -FilePath $logFilePath -Append
Write-Output "." | Tee-Object -FilePath $logFilePath -Append
Write-Output "." | Tee-Object -FilePath $logFilePath -Append

## Search attribute information - https://learn.microsoft.com/en-us/purview/edisc-condition-builder#conditions-for-common-properties

## If UserIds variable is not defined, prompt for it
if (!$UserIds) {
    Write-Output "" | Tee-Object -FilePath $logFilePath -Append
    $UserIds = Read-Host 'Enter the email address of the spam message source to be searched for/purged (leave blank to search all senders, seaparate multiple senders with commas)' | Tee-Object -FilePath $logFilePath -Append
    if (!$UserIds) {
        $UserIds = "Any Sender"
        Write-Output "Will search messages from ANY sender - Use with caution." | Tee-Object -FilePath $logFilePath -Append
    }
}

if (!$Subject) {
    Write-Output "" | Tee-Object -FilePath $logFilePath -Append
    Write-Output 'Enter partial or complete subject of the malicious message to search for (escape apostrophies and quote marks with backslash, leave blank or use * to search any subject line)' | Tee-Object -FilePath $logFilePath -Append
    $Subject = Read-Host '(Note that subject search here using PS can include COMMAS, which is not possible through the web GUI - GUI always splits search terms at a comma)' | Tee-Object -FilePath $logFilePath -Append
    if (!$Subject) {
        $Identifier = Read-Host 'Enter MessageID/Identifier to search for (e.g. <XXXXXX@XXXX.prod.outlook.com>):' | Tee-Object -FilePath $logFilePath -Append
        if (!$Identifier) {
            Write-Output "No Subject line or MessageID specified - will search for all messages from specified sender(s) in date range." | Tee-Object -FilePath $logFilePath -Append
            exit
        }
    }
}

if (!$DaysAgo -and !$Identifier) {
    Write-Output "" | Tee-Object -FilePath $logFilePath -Append
    $DaysAgo = Read-Host 'Enter how many days back to search for message to be "sent" from (default 30)' | Tee-Object -FilePath $logFilePath -Append
    if ($DaysAgo -eq '') { $DaysAgo = "30" }
}

$StartDate = (Get-Date).AddDays(-$DaysAgo)
$EndDate = (Get-Date).AddDays(1)


# (Get-ConnectionInformation).UserPrincipalName
# Add-RoleGroupMember "eDiscovery Manager" -Member "user@domain.com"
# (Remove-RoleGroupMember "eDiscovery Manager" -Member "user@domain.com")
# Get-eDiscoveryCaseAdmin
# Add-eDiscoveryCaseAdmin me@example.com
# Add-RoleGroupMember -Identity "eDiscovery Manager" -Member me@example.com

Write-Output "." | Tee-Object -FilePath $logFilePath -Append
Write-Output "." | Tee-Object -FilePath $logFilePath -Append
$SearchName = "Suspicious email search $date"
if ($Identifier) {
    $Query = "(Identifier:" + $Identifier + ")"
} elseif ($UserIds -eq "Any Sender") {
    $Query = "sent>=" + $(($StartDate).ToString('yyyy-MM-dd')) + " AND (subject:" + $Subject + ")"
} elseif ($UserIds) {
    if (!$Subject) {
        if ($UserIds -like "*,*") {
            $FromField = "(From:`"$($UserIds.replace(',','" OR From:"'))`")"
            $Query = $FromField + " AND sent>=" + $(($StartDate).ToString('yyyy-MM-dd'))
        } else {
            $Query = "From:" + $UserIds + " AND sent>=" + $(($StartDate).ToString('yyyy-MM-dd'))
        }
    } else {
        if ($UserIds -like "*,*") {
            $FromField = "(From:`"$($UserIds.replace(',','" OR From:"'))`")"
            $Query = $FromField + " AND sent>=" + $(($StartDate).ToString('yyyy-MM-dd')) + " AND (subject:`"" + $Subject + "`")"
        } else {
            $Query = "From:" + $UserIds + " AND sent>=" + $(($StartDate).ToString('yyyy-MM-dd')) + " AND (subject:`"" + $Subject + "`")"
        }
    }
}
Write-Output "Starting content search - `"$SearchName`"" | Tee-Object -FilePath $logFilePath -Append
Write-Output "New-ComplianceSearch -name `"$SearchName`" -ExchangeLocation all -ContentMatchQuery $Query`n" | Tee-Object -FilePath $logFilePath -Append
New-ComplianceSearch -Name "$SearchName" -ExchangeLocation all -ContentMatchQuery $Query

# $Search=New-ComplianceSearch -Name "Remove Phishing Message" -ExchangeLocation All -ContentMatchQuery '(Received:4/13/2016..4/14/2016) AND (Subject:"Action required")'
# $Search=New-ComplianceSearch -Name "Remove Phishing Message" -ExchangeLocation All -ContentMatchQuery '(c:c)(from=greg@aefresno.com)(sent=2023-10-29..2023-11-29)'

Start-ComplianceSearch -Identity $SearchName
# $SearchStatus = Get-ComplianceSearch -Identity $SearchName
# Get-ComplianceSearch -Identity $SearchName | FL

$Continue = ""
while ($Continue -ne "Y") {
    $OperationStatus = Get-ComplianceSearch -Identity "$SearchName"
    # $OperationStatus
    $OperationStatus.Name | Tee-Object -FilePath $logFilePath -Append
    $OperationStatus.ContentMatchQuery | Tee-Object -FilePath $logFilePath -Append
    # $OperationStatus.CreatedTime
    # $OperationStatus.JobStartTime
    # $OperationStatus.JobEndTime
    $OperationStatus.Status | Tee-Object -FilePath $logFilePath -Append
    $Continue = Read-Host "`nIf the search status above is 'Completed' enter 'Y' to continue and export a preview. Press enter to refresh status" | Tee-Object -FilePath $logFilePath -Append
}

Write-Output "." | Tee-Object -FilePath $logFilePath -Append
Write-Output "." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Starting preview export - `"$SearchName`"" | Tee-Object -FilePath $logFilePath -Append
Write-Output "New-ComplianceSearchAction -SearchName `"$SearchName`" -Preview`n" | Tee-Object -FilePath $logFilePath -Append
New-ComplianceSearchAction -SearchName "$SearchName" -Preview
Write-Output "If there is an error above about `"A parameter cannot be found that matches parameter name 'Preview'`" you need to add the eDiscovery manager or admin role to your account and sign out/sign in again." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Go to https://purview.microsoft.com/settings/purviewpermissions / https://purview.microsoft.com/ediscovery/casespage/ / https://purview.microsoft.com/ediscovery/contentsearchv2 (old link: https://compliance.microsoft.com/contentsearchv2) in Edge to manage through admin center." | Tee-Object -FilePath $logFilePath -Append
$Continue = ""
while ($Continue -ne "Y") {
    $OperationStatus = Get-ComplianceSearchAction -Identity "$($SearchName)_Preview"
    # $OperationStatus
    $OperationStatus.Name | Tee-Object -FilePath $logFilePath -Append
    # $OperationStatus.CreatedTime
    # $OperationStatus.JobStartTime
    # $OperationStatus.JobEndTime
    $OperationStatus.Status | Tee-Object -FilePath $logFilePath -Append
    $Continue = Read-Host "`nIf the preview status above is 'Completed' enter 'Y' to continue and save the report. Press enter to refresh status" | Tee-Object -FilePath $logFilePath -Append
}

Write-Output "Exporting content search preview results..." | Tee-Object -FilePath $logFilePath -Append
$Results = (Get-ComplianceSearchAction "$($SearchName)_Preview" -Details).Results -replace '{', "`"Location`",`"Sender`",`"Subject`",`"Type`",`"Size`",`"ReceivedTime`",`"DataLink`"`r`n" -replace '}' -replace 'Location: ', '"' -replace '; Sender: ', '","' -replace '; Subject: ', '","' -replace '; Type: ', '","' -replace '; Size: ', '","' -replace '; Received Time: ', '","' -replace '; Data Link: ', '","' -replace ",`r`n", "`"`r`n" | Out-File "$OutputPath\$DomainName\ContentSearchResults_$($date).csv"

Invoke-Item "$OutputPath\$DomainName"

Write-Output "." | Tee-Object -FilePath $logFilePath -Append
Write-Output "." | Tee-Object -FilePath $logFilePath -Append

Write-Output "Opening Purview Cases page in Edge browser to start/retrieve Content Search export (must be done through web console)..." | Tee-Object -FilePath $logFilePath -Append
Write-Output "https://purview.microsoft.com/ediscovery/casespage" | Tee-Object -FilePath $logFilePath -Append
Start-Process msedge.exe -ArgumentList "https://purview.microsoft.com/ediscovery/casespage"
# Start-Process msedge.exe -ArgumentList "https://compliance.microsoft.com/contentsearchv2?viewid=export -inprivate" # Use this string to open private window if Edge is not the browser being used for M365 management
Write-Output "Sign-in with the account that started this content search, navigate to Content Search > `"$SearchName`" > `"Export`"." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Choose name/options (individual MSG files recommended for smaller exports) and click `"Export`"." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Navigate to `"Process manager`" to monitor progress. When the export is `"Completed`" select it & click `"Download`"." | Tee-Object -FilePath $logFilePath -Append

# eDiscovery (Standard): compliance.microsoft.com/classicediscovery
Write-Output "." | Tee-Object -FilePath $logFilePath -Append
Write-Output "." | Tee-Object -FilePath $logFilePath -Append

$Continue = ""
while ($Continue -ne "Y") {
    $Continue = Read-Host "Enter 'Y' to continue with *PURGE* (SoftDelete) of all messages found though this content search from all mailboxes. Press Ctrl+c to exit script now" | Tee-Object -FilePath $logFilePath -Append
}

$Continue = ""
while ($Continue -ne "YES") {
    $Continue = Read-Host "*** Are you sure you are ready to PURGE all messages found through content search `"$SearchName`" from all mailboxes? Enter 'YES' to continue. Press Ctrl+c to exit script now" | Tee-Object -FilePath $logFilePath -Append
}

if ($Continue -eq "YES") {
    Write-Output "PURGING messages found through `"$SearchName`"" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "New-ComplianceSearchAction -SearchName `"$SearchName`" -Purge -PurgeType SoftDelete" | Tee-Object -FilePath $logFilePath -Append # can also be HardDelete
    New-ComplianceSearchAction -SearchName "$SearchName" -Purge -PurgeType SoftDelete
    # New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType HardDelete
    Get-ComplianceSearchAction -Identity "$($SearchName)_Purge"
    $Continue = ""
    while ($Continue -ne "Y") {
        $OperationStatus = Get-ComplianceSearchAction -Identity "$($SearchName)_Purge"
        # $OperationStatus
        $OperationStatus.Status | Tee-Object -FilePath $logFilePath -Append
        $Continue = Read-Host "`nIf the purge status above is 'Completed' enter 'Y' to continue. Press enter to refresh status" | Tee-Object -FilePath $logFilePath -Append
    }
    "Search name: $($OperationStatus.SearchName)" | Out-File "$OutputPath\$DomainName\ContentSearchPurgeResults_$($date).txt"
    "Action: $($OperationStatus.Action)" | Out-File "$OutputPath\$DomainName\ContentSearchPurgeResults_$($date).txt" -Append
    "Operation name: $($OperationStatus.Name)" | Out-File "$OutputPath\$DomainName\ContentSearchPurgeResults_$($date).txt" -Append
    "Start time: $($OperationStatus.JobStartTime)" | Out-File "$OutputPath\$DomainName\ContentSearchPurgeResults_$($date).txt" -Append
    "End time: $($OperationStatus.JobEndTime)" | Out-File "$OutputPath\$DomainName\ContentSearchPurgeResults_$($date).txt" -Append
    "`nResults:`n$($OperationStatus.results)" | Out-File "$OutputPath\$DomainName\ContentSearchPurgeResults_$($date).txt" -Append
    "`nErrors:`n$($OperationStatus.Errors)" | Out-File "$OutputPath\$DomainName\ContentSearchPurgeResults_$($date).txt" -Append
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"

exit
