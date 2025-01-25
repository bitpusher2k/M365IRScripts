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
# v2.9 last updated 2025-01-24
# Script to walk through usual content search steps for dealing with spam/phishing messages:
# * Search for messages by sender & subject
# * Export preview report
# * Export message contents
# * Purge messages
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-ExchangeMessageContentSearch.ps1 -OutputPath "Default" -UserIds "compromisedaccount@contoso.com" -DaysAgo "5" -Subject "Phishing Message"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell (IPPS) commands.
#
#comp #m365 #security #bec #script #irscript #powershell #contentsearch #export #message #purge #content #search

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$UserIds,
    [int]$DaysAgo,
    [string]$Subject,
    [string]$Identifier,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$Encoding = "utf8bom" # "ascii","ansi","bigendianunicode","unicode","utf8","utf8","utf8NoBOM","utf32"
)

if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }

$date = Get-Date -Format "yyyyMMddHHmmss"

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

Write-Output "You are signed in as:"
$CurrentUser = (Get-ConnectionInformation).UserPrincipalName[1]
$CurrentUser

# https://www.nextpoint.com/ediscovery-blog/ediscovery-keyword-search-examples/
# ((From:Dave recipients:Sue) OR (From:Sue recipients:Dave) OR (From:Dave recipients:Mike) OR (From:Mike recipients:Dave)) received:"This month"
# (c:c)(subjecttitle=“The Care Employment Opportunity”)(sent=2023-10-30..2023-10-31)

# Connect-IPPSSession
# Enable-OrganizationCustomization
Write-Output ""
Write-Output "Current users with Mailbox Search permissions are:"
Get-ManagementRoleAssignment -Role "Mailbox Search" -GetEffectiveUsers -Delegating $false | Select-Object EffectiveUserName, RoleAssigneeName, AssignmentMethod, DistinguishedName | Format-Table
Get-ManagementRoleAssignment -Role "Mailbox Search" -GetEffectiveUsers -Delegating $true | Select-Object EffectiveUserName, RoleAssigneeName, AssignmentMethod, DistinguishedName | Format-Table
Write-Output ""
Write-Output "Current users with eDiscovery Case Admin (eDiscovery Administrator) permissions are:"
Get-eDiscoveryCaseAdmin | Select-Object WindowsLiveID, Alias, DisplayName, PrimarySmtpAddress, DistinguishedName | Format-Table
Write-Output ""
Write-Output "Additional objects often configured with with eDiscovery permissions:"
# Get-RoleGroupMember -Identity "eDiscovery Manager"
try { Get-RoleGroupMember -Identity "eDiscovery Manager" -ErrorAction stop | Select-Object EffectiveUserName, DisplayName, Name, DistinguishedName, guid } catch { Write-Output "object eDiscovery Manager not found" }
try { Get-RoleGroupMember -Identity eDiscoveryManager -ErrorAction stop | Select-Object EffectiveUserName, DisplayName, Name, DistinguishedName, guid } catch { Write-Output "object eDiscoveryManager not found" }
try { Get-RoleGroupMember -Identity Reviewer -ErrorAction stop | Select-Object EffectiveUserName, DisplayName, Name, DistinguishedName, guid } catch { Write-Output "object Reviewer not found" }
try { Get-RoleGroupMember -Identity ComplianceAdministrator -ErrorAction stop | Select-Object EffectiveUserName, DisplayName, Name, DistinguishedName, guid } catch { Write-Output "object ComplianceAdministrator not found" }


Write-Output ""
Write-Output "If your username is included in the above manager/admin permissions you can continue. Otherwise: Ctrl+c, update permissions (https://compliance.microsoft.com/compliancecenterpermissions), sign-out, sign-in, and try again..."
Write-Output "`nOr use these commands from PoswerShell:"
Write-Output "Add-RoleGroupMember `"eDiscovery Manager`" -Member $CurrentUser; Get-RoleGroupMember -Identity `"eDiscovery Manager`""
Write-Output "Add-eDiscoveryCaseAdmin $CurrentUser; Get-eDiscoveryCaseAdmin"
Write-Output "."
Write-Output "."

## Search attribute information - https://learn.microsoft.com/en-us/purview/edisc-condition-builder#conditions-for-common-properties

## If UserIds variable is not defined, prompt for it
if (!$UserIds) {
    Write-Output ""
    $UserIds = Read-Host 'Enter the email address of the spam message source to be searched for/purged (leave blank to search all senders)'
    if (!$UserIds) {
        $UserIds = "Any Sender"
        Write-Output "Will search messages from ANY sender - Use with caution."
    }
}

if (!$Subject) {
    Write-Output ""
    Write-Output 'Enter partial or complete subject of the malicious message to search for (escape apostrophies and quote marks with backslash)'
    $Subject = Read-Host '(Note that subject search here using PS can include COMMAS, which is not possible through the web GUI - GUI always splits search terms at a comma)'
    if (!$Subject) {
        $Identifier = Read-Host 'Enter MessageID/Identifier to search for (e.g. <XXXXXX@XXXX.prod.outlook.com>):'
        if (!$Identifier) {
            Write-Output "Specifying a Subject line or MessageID is required for this script to search. Exiting"
            exit
        }
    }
}

if (!$DaysAgo -and !$Identifier) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to search for message to be "sent" from (default 30)'
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

Write-Output "."
Write-Output "."
$SearchName = "Suspicious email search $date"
if ($Identifier) {
    $Query = "(Identifier:" + $Identifier + ")"
} elseif ($UserIds -eq "Any Sender") {
    $Query = "sent>=" + $StartDate + " AND (subject:" + $Subject + ")"
} else {
    $Query = "From:" + $UserIds + " AND sent>=" + $StartDate + " AND (subject:" + $Subject + ")"
}
Write-Output "Starting content search - `"$SearchName`""
Write-Output "New-ComplianceSearch -name `"$SearchName`" -ExchangeLocation all -ContentMatchQuery $Query`n"
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
    $OperationStatus.Name
    $OperationStatus.ContentMatchQuery
    # $OperationStatus.CreatedTime
    # $OperationStatus.JobStartTime
    # $OperationStatus.JobEndTime
    $OperationStatus.Status
    $Continue = Read-Host "`nIf the search status above is 'Completed' enter 'Y' to continue and export a preview. Press enter to refresh status"
}

Write-Output "."
Write-Output "."
Write-Output "Starting preview export - `"$SearchName`""
Write-Output "New-ComplianceSearchAction -SearchName `"$SearchName`" -Preview`n"
New-ComplianceSearchAction -SearchName "$SearchName" -Preview
Write-Output "If there is an error above about `"A parameter cannot be found that matches parameter name 'Preview'`" you need to add the eDiscovery manager or admin role to your account and sign out/sign in again."
Write-Output "Go to https://compliance.microsoft.com/contentsearchv2 in Edge to manage through admin center."
$Continue = ""
while ($Continue -ne "Y") {
    $OperationStatus = Get-ComplianceSearchAction -Identity "$($SearchName)_Preview"
    # $OperationStatus
    $OperationStatus.Name
    # $OperationStatus.CreatedTime
    # $OperationStatus.JobStartTime
    # $OperationStatus.JobEndTime
    $OperationStatus.Status
    $Continue = Read-Host "`nIf the preview status above is 'Completed' enter 'Y' to continue and save the report. Press enter to refresh status"
}

Write-Output "Exporting content search preview results..."
$Results = (Get-ComplianceSearchAction "$($SearchName)_Preview" -Details).Results -replace '{', "`"Location`",`"Sender`",`"Subject`",`"Type`",`"Size`",`"ReceivedTime`",`"DataLink`"`r`n" -replace '}' -replace 'Location: ', '"' -replace '; Sender: ', '","' -replace '; Subject: ', '","' -replace '; Type: ', '","' -replace '; Size: ', '","' -replace '; Received Time: ', '","' -replace '; Data Link: ', '","' -replace ",`r`n", "`"`r`n" | Out-File "$OutputPath\$DomainName\ContentSearchResults_$($date).csv"

Invoke-Item "$OutputPath\$DomainName"

Write-Output "."
Write-Output "."
$Continue = ""
while ($Continue -ne "Y") {
    $Continue = Read-Host "Enter 'Y' to continue with content search export. Press Ctrl+c to exit script now"
}
Write-Output "New-ComplianceSearchAction -SearchName `"$SearchName`" -Export"
New-ComplianceSearchAction -SearchName "$SearchName" -Export
$OperationStatus = Get-ComplianceSearchAction -Identity "$($SearchName)_Export"
$OperationStatus.Name
$OperationStatus.Status

Write-Output "Opening Edge browser window so content search export can be retrieved and reviewed..."
Write-Output "https://compliance.microsoft.com/contentsearchv2?viewid=export"
Start-Process msedge.exe -ArgumentList "https://compliance.microsoft.com/contentsearchv2?viewid=export"
# Start-Process msedge.exe -ArgumentList "https://compliance.microsoft.com/contentsearchv2?viewid=export -inprivate" # Use this string to open private window if Edge is not the browser being used for M365 management
Write-Output "Sign-in with the account that started this content search, click `"Export`". When the export is 'Completed' retrieve the messages using `"Download results`" and the Export Key."

# eDiscovery (Standard): compliance.microsoft.com/classicediscovery
# eDiscovery (Premium): compliance.microsoft.com/advancedediscovery

Write-Output "."
Write-Output "."

$Continue = ""
while ($Continue -ne "Y") {
    $Continue = Read-Host "Enter 'Y' to continue with *PURGE* (SoftDelete) of all messages found though this content search from all mailboxes. Press Ctrl+c to exit script now"
}

$Continue = ""
while ($Continue -ne "YES") {
    $Continue = Read-Host "*** Are you sure you are ready to PURGE all messages found through content search `"$SearchName`" from all mailboxes? Enter 'YES' to continue. Press Ctrl+c to exit script now"
}

if ($Continue -eq "YES") {
    Write-Output "PURGING messages found through `"$SearchName`""
    Write-Output "New-ComplianceSearchAction -SearchName `"$SearchName`" -Purge -PurgeType SoftDelete"
    New-ComplianceSearchAction -SearchName "$SearchName" -Purge -PurgeType SoftDelete
    # New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType HardDelete
    Get-ComplianceSearchAction -Identity "$($SearchName)_Purge"
    $Continue = ""
    while ($Continue -ne "Y") {
        $OperationStatus = Get-ComplianceSearchAction -Identity "$($SearchName)_Purge"
        # $OperationStatus
        $OperationStatus.Status
        $Continue = Read-Host "`nIf the purge status above is 'Completed' enter 'Y' to continue. Press enter to refresh status"
    }
}

Write-Output "`nDone! Check output path for results."

exit
