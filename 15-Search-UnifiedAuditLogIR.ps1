#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Search-UnifiedAuditLogIR.ps1 - By Bitpusher/The Digital Fox
# v2.7 last updated 2024-02-26
# Script to search the UAC for events particularly
# relevant to incident response.
#
# Usage:
# powershell -executionpolicy bypass -f .\Search-UnifiedAuditLogIR.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
#
#comp #m365 #security #bec #script #unified #audit #log #ir

#Requires -Version 5.1

param(
    [string]$OutputPath,
    [string]$DaysAgo,
    [string]$Encoding = "utf8bom" # "ascii","ansi","bigendianunicode","unicode","utf8","utf8","utf8NoBOM","utf32"
)

if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }

# Initial variables
$OutputPath = ""
$DaysAgo = ""
$date = Get-Date -Format "yyyyMMddHHmmss"

$CheckLog = (Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled
if (!$CheckLog) {
    Write-Output "The Unified Audit Log does not appear to be enabled on this tenant. Export of UAL activities may fail. Try running 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true' if export fails."
}

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

Write-Output ""
Write-Output "Script will search the UAC for entries often relevant to incident investigation & response."
Write-Output "Reports of events in each of these categories will be created if associated events are found:"
Write-Output " * Entra ID Role Changes"
Write-Output " * Entra ID Application Changes"
Write-Output " * Conditional Access Policy Changes"
Write-Output " * Entra ID Domain Changes (Add/Remove, Federation, etc.)"
Write-Output " * Partner Management Changes"
Write-Output " * Users Added or Deleted"
Write-Output " * Password Resets and Changes"
Write-Output " * Update User Events (MFA reg & Security Info changes)"
Write-Output " * Devices Added Or Deleted"
Write-Output " * Exchange Admin Events (Inbox Rules, Mailbox Forwarding, Mailbox Permissions)"
Write-Output " * File Created or Modified"
Write-Output " * File Deleted"
Write-Output " * Mailbox Permission Events"
Write-Output " * External User Events"
Write-Output " * Anonymous Link Events"
Write-Output " * Email Deletion Events"
Write-Output ""
if (!$DaysAgo) {
    $DaysAgo = Read-Host "Enter number of days back to search in the Unified Audit Log (default: 30, max: 90)"
}
if ($DaysAgo -eq '') { $DaysAgo = "30" } elseif ($DaysAgo -gt "90") { $DaysAgo = "90" }
Write-Output "Will search UAC $DaysAgo days back from today for relevant events."
Write-Output "This script does not currently loop through UAC results - Maximum records retrieved for each event category is limited to 5000."

## Set Start and End Dates
$StartDate = (Get-Date).AddDays(- $DaysAgo)
$EndDate = Get-Date

## Get changes to membership in Entra ID roles (new adds could indicate escalation of privilege)
$SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add member to role.", "Remove member from role.") -SessionCommand ReturnLargeSet -ResultSize 5000

## Check to see if the variable is null
if (!$SearchResults) {
    Write-Output ""
    Write-Output "There are no events matching Entra ID role changes for the time period specified"
    Write-Output ""
} else {
    ## Output the events to CSV
    $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_EntraIDRoleChanges_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Write-Output ""
    Write-Output "See Entra ID Roles Changes events in the output path"
    Write-Output ""
}

## Get changes to applications, client app credentials, permissions, and new consents (could indicate app abuse)
$SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add application.", "Add service principal.", "Add service principal credentials.", "Update application – Certificates and secrets", "Add app role assignment to service principal.", "Add app role assignment grant to user.", "Add delegated permission grant.", "Consent to application.") -SessionCommand ReturnLargeSet -ResultSize 5000

## Check to see if the variable is null
if (!$SearchResults) {
    Write-Output "There are no events matching Entra ID app changes for the time period specified"
    Write-Output ""
} else {
    ## Output the events to CSV
    $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_EntraIDAppChanges_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Write-Output "See Entra ID application events in the output path"
    Write-Output ""
}

## Get Conditional Access policy changes
$SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add policy.", "Update policy.", "Delete policy.") -SessionCommand ReturnLargeSet -ResultSize 5000

## Check to see if the variable is null
if (!$SearchResults) {
    Write-Output "There are no Conditional Access events for the time period specified"
    Write-Output ""
} else {
    ## Output the events to CSV
    $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_ConditionalAccessPolicyChanges_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Write-Output "See Conditional Access Policy events in the output path"
    Write-Output ""
}

## Get Domain changes
$SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add domain to company.", "Remove domain from company.", "Set domain authentication.", "Set federation settings on domain.", "Set DirSyncEnabled flag.", "Update domain.", "Verify domain.", "Verify email verified domain.") -SessionCommand ReturnLargeSet -ResultSize 5000

## Check to see if the variable is null
if (!$SearchResults) {
    Write-Output "There are no Domain Management events for the time period specified"
    Write-Output ""
} else {
    ## Output the events to CSV
    $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_EntraIDDomainChanges_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Write-Output "See Domain Management events in the output path"
    Write-Output ""
}

## Get Partner changes
$SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add partner to company.", "Remove partner from company.") -SessionCommand ReturnLargeSet -ResultSize 5000

## Check to see if the variable is null
if (!$SearchResults) {
    Write-Output "There are no Partner management events for the time period specified"
    Write-Output ""
} else {
    ## Output the events to CSV
    $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_PartnerManagementChanges_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Write-Output "See Partner Management events in the output path"
    Write-Output ""
}

## Get user add and delete events
$SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add user.", "Delete user.") -SessionCommand ReturnLargeSet -ResultSize 5000

## Check to see if the variable is null
if (!$SearchResults) {
    Write-Output "There are no Users Added events for the time period specified"
    Write-Output ""
} else {
    ## Output the events to CSV
    $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_UsersAddedOrDeleted_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Write-Output "See events matching 'Add user' and 'Delete user' in the output path"
    Write-Output ""
}

## Get password changes
$SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Change user password.", "Reset user password.", "Set force change user password.") -SessionCommand ReturnLargeSet -ResultSize 5000

## Check to see if the variable is null
if (!$SearchResults) {
    Write-Output "There are no Password events for the time period specified"
    Write-Output ""
} else {
    ## Output the events to CSV
    $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_PasswordResetsAndChanges_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Write-Output "See password events in the output path"
    Write-Output ""
}

## Get user update events (this includes MFA registration / security info changes)
$SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Update user.") -SessionCommand ReturnLargeSet -ResultSize 5000

## Check to see if the variable is null
if (!$SearchResults) {
    Write-Output "There are no events matching 'Update user' for the time period specified"
    Write-Output ""
} else {
    ## Output the events to CSV
    $SearchResults | Export-Csv "$OutputPath\$DomainName\AuditLog_UpdateUser_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Write-Output "See events matching 'Update user' in the output path (this includes MFA method updates)"
    Write-Output ""
}

## Get Entra ID Device add and delete events
$SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add device.", "Delete device.") -SessionCommand ReturnLargeSet -ResultSize 5000

## Check to see if the variable is null
if (!$SearchResults) {
    Write-Output "There are no events matching 'Add device' or 'Delete device' for the time period specified"
    Write-Output ""
} else {
    ## Output the events to CSV
    $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_DevicesAddedOrDeleted_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Write-Output "See events matching 'Add device' or 'Delete device' in the output path"
    Write-Output ""
}

## Get Exchange admin log events (includes new inbox rules, mailbox forwarding, mailbox permissions, mailbox delegations, etc.)
$SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType ExchangeAdmin -SessionCommand ReturnLargeSet -ResultSize 5000

## Check to see if the variable is null
if (!$SearchResults) {
    Write-Output "There are no Exchange admin events for the time period specified"
    Write-Output ""
} else {
    ## Output the events to CSV
    $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_ExchangeAdminEvents_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Write-Output "See Exchange Admin events in the output path"
    Write-Output ""
}

## Get file creation & modification events
$SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "Created,FileModified" -SessionCommand ReturnLargeSet -ResultSize 5000

## Check to see if the variable is null
if (!$SearchResults) {
    Write-Output "There are no File Creation/Modification events for the time period specified"
    Write-Output ""
} else {
    ## Output the events to CSV
    $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_FileCreatedModifiedEvents_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Write-Output "See file creation events in the output path"
    Write-Output ""
}

## Get file deletion events
$SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "FileDeleted,FileDeletedFirstStageRecycleBin,FileDeletedSecondStageRecycleBin" -SessionCommand ReturnLargeSet -ResultSize 5000

## Check to see if the variable is null
if (!$SearchResults) {
    Write-Output "There are no file deletion events for the time period specified"
    Write-Output ""
} else {
    ## Output the events to CSV
    $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_FileDeletedEvents_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Write-Output "See file deletion events in the output path"
    Write-Output ""
}

## Get Mailbox permission change events
$SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "Add-RecipientPermission,Remove-RecipientPermission,Set-mailbox,Add-MailboxPermission,Remove-MailboxPermission" -SessionCommand ReturnLargeSet -ResultSize 5000

## Check to see if the variable is null
if (!$SearchResults) {
    Write-Output "There are no mailbox permission events for the time period specified"
    Write-Output ""
} else {
    ## Output the events to CSV
    $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_MailboxPermissionEvents_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Write-Output "See mailbox permission events in the output path"
    Write-Output ""
}

## Get external user activity events
$SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds "*#EXT*" -SessionCommand ReturnLargeSet -ResultSize 5000
# Just file access events: $SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations FileAccessed -UserIds "*#EXT*" -SessionCommand ReturnLargeSet -ResultSize 5000

## Check to see if the variable is null
if (!$SearchResults) {
    Write-Output "There are no external user events for the time period specified"
    Write-Output ""
} else {
    ## Output the events to CSV
    $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_ExternalUserEvents_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Write-Output "See external user events in the output path"
    Write-Output ""
}

## Get anonymous link events
$SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "AnonymousLinkRemoved,AnonymousLinkcreated,AnonymousLinkUpdated,AnonymousLinkUsed" -SessionCommand ReturnLargeSet -ResultSize 5000

## Check to see if the variable is null
if (!$SearchResults) {
    Write-Output "There are no anonymous link events for the time period specified"
    Write-Output ""
} else {
    ## Output the events to CSV
    $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_AnonymousLinkEvents_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Write-Output "See anonymous link events in the output path"
    Write-Output ""
}

## Get email deletion events
$SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "SoftDelete,HardDelete,MoveToDeletedItems" -SessionCommand ReturnLargeSet -ResultSize 5000

## Check to see if the variable is null
if (!$SearchResults) {
    Write-Output "There are no email deletion events for the time period specified"
    Write-Output ""
} else {
    ## Output the events to CSV
    $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_EmailDeletionEvents_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    Write-Output "See email deletion events in the output path"
    Write-Output ""
}

# ## Get ..... events
# $SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType ... -Operations -SessionCommand ReturnLargeSet -ResultSize 5000
#
# ## Check to see if the variable is null
# if (!$SearchResults) {
#     Write-Output "There are no ... events for the time period specified"
#     Write-Output ""
# } else {
#     ## Output the events to CSV
#     $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_...Events_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
#     Write-Output "See ... events in the output path"
#     Write-Output ""
# }

Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

exit
