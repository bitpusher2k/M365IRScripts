#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-BasicTenantInformation.ps1 - By Bitpusher/The Digital Fox
# v2.9 last updated 2024-11-19
# Script to collect basic Tenant information before further investigation.
#
# Allows quickly verifying the tenant name, subscriptions, and auditing status.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-BasicTenantInformation.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell, MSOnline, AzureAD, Microsoft Graph commands.
#
#comp #m365 #security #bec #script #info #tenant

#Requires -Version 5.1

param(
    [string]$OutputPath,
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
$PrimaryDomain = Get-AcceptedDomain | Where-Object Default -EQ $true
$DomainName = $PrimaryDomain.DomainName

$CheckSubDir = Get-Item $OutputPath\$DomainName -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
    Write-Output ""
    Write-Output "Domain sub-directory does not exist. Sub-directory `"$DomainName`" will be created."
    mkdir $OutputPath\$DomainName
}

$admins = Get-MgDirectoryRole | Select-Object DisplayName, Id | ForEach-Object {$role = $_.DisplayName; Get-MgDirectoryRoleMember -DirectoryRoleId $_.id | where-object {$_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.user"} | ForEach-Object {Get-MgUser -userid $_.id } } | Select @{Name="Role"; Expression = {$role}}, DisplayName, UserPrincipalName, Mail, Id | Sort-Object -Property Mail -Unique
$info = Get-MsolCompanyInformation
$orgconfig = Get-OrganizationConfig
$orgconfigGraph = Get-MgOrganization
$logconfig = Get-AdminAuditLogConfig
$connectors = Get-InboundConnector
$rules = Get-TransportRule
$admins | Out-File -FilePath "$OutputPath\$DomainName\TenantAdmins_$($date).txt" -Encoding $Encoding
$info | Out-File -FilePath "$OutputPath\$DomainName\TenantCompanyInfo_$($date).txt" -Encoding $Encoding
$orgconfig | Out-File -FilePath "$OutputPath\$DomainName\TenantOrgConfig_$($date).txt" -Encoding $Encoding
$orgconfigGraph | Out-File -FilePath "$OutputPath\$DomainName\TenantOrgConfig_Graph_$($date).txt" -Encoding $Encoding
$logconfig | Out-File -FilePath "$OutputPath\$DomainName\TenantAuditLogConfig_$($date).txt" -Encoding $Encoding
$connectors | Out-File -FilePath "$OutputPath\$DomainName\ConnectorConfig_$($date).txt" -Encoding $Encoding
$rules | Out-File -FilePath "$OutputPath\$DomainName\TransportRuleConfig_$($date).txt" -Encoding $Encoding


Write-Output "`nTenant details:"
Get-AzureADTenantDetail

Write-Output "`nEntra ID subscriptions (look for AAD premium):"
(Get-MgSubscribedSku).ServicePlans | Where-Object serviceplanname -Like "*aad*"

Write-Output "`nLast directory sync time:"
Get-MsolCompanyInformation | Select-Object lastdirsynctime

Write-Output "`nMailbox auditing should be enabled by default."
Write-Output "Checking the value of 'AuditDisabled' (this should be `"False`"):"
$OrgConfig.AuditDisabled | Format-List

Write-Output "`nInbound connectors:"
$connectors | Format-List

Write-Output "`nTransport rules:"
$rules | Format-List

# If mailbox auditing is disabled it can be enabled with these commands:
# Get-Mailbox -Identity "UserName" | Format-List
# Set-Mailbox -Identity "UserName" -AuditEnabled $true
# $UserMailboxes= Get-mailbox-Filter {(RecipientTypeDetails-eq 'UserMailbox')} ; $UserMailboxes | ForEach {Set-Mailbox $_.Identity -AuditEnabled$true}

Write-Output "`nChecking if Unified Audit Log is enabled - value of 'UnifiedAuditLogIngestionEnabled' (this should be `"True`"):"
$AuditLogEnabled = Get-AdminAuditLogConfig
$AuditLogEnabled.UnifiedAuditLogIngestionEnabled | Format-List
if (!$AuditLogEnabled.UnifiedAuditLogIngestionEnabled) {
    Write-Output "Unified Audit Log does NOT appear to be enabled on tenant. This value will always be 'False' if run from the IPPS (Security & Compliance) PowerShell"
    Write-Output "session instead of Exchange Online Powershell (https://learn.microsoft.com/en-us/purview/audit-log-enable-disable)."
    Write-Output "Check https://compliance.microsoft.com/auditlogsearch and see if searching the audit log from there is possible before"
    Write-Output "attempting to enable the UAC from here."
    $Answer = Read-Host "Enter 'Y' to attempt to enable the UAC now, or simply press enter to continue"
    if ($Answer -eq "Y") {
        Enable-OrganizationCustomization
        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
        Write-Output "Commands to enable the Unified Audit Log have been run, but if it really was not yet enabled data from the UAC will not be available for this investigation."
    }
}

Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

exit
