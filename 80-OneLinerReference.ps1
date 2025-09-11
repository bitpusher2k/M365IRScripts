#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# OneLinerReference.ps1 - By Bitpusher/The Digital Fox
# v3.1 last updated 2025-07-26
# Script to print list of simple PowerShell commands that are useful during M365 BEC investigation & response. 
#
# For use as reference to remember syntax & other details of short commands & sets of commands that don't have a full script in this set.
#
# Usage:
# powershell -executionpolicy bypass -f .\OneLinerReference.ps1
#
#comp #m365 #security #bec #script #irscript #powershell #oneliner #reference

#Requires -Version 5.1

Param (
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$Encoding = "utf8bom" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
)

if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }

$date = Get-Date -Format "yyyyMMddHHmmss"

Write-Output `n '-----------------------------------------------'
Write-Output 'Download and Run CrowdStrike Reporting Tool for Azure (CRT)'
Write-Output '-----------------------------------------------'
Write-Output `n 'Usefule script for collecting Federation Configuration, Federation Trust,'
Write-Output 'Client Access Settings Configured on Mailboxes, Mail Forwarding Rules for Remote Domains,'
Write-Output 'Mailbox SMTP Forwarding Rules, Mail Transport Rules,'
Write-Output 'Delegates with "Full Access" and with Any Permissions Granted,'
Write-Output 'Delegates with "Send As" or "SendOnBehalf" Permissions,'
Write-Output 'Exchange Online PowerShell Enabled Users, Users with "Audit Bypass" Enabled,'
Write-Output 'Mailboxes Hidden from the Global Address List (GAL),'
Write-Output 'and administrator audit logging configuration settings for review.'
Write-Output '   Invoke-WebRequest "https://github.com/CrowdStrike/CRT/raw/refs/heads/main/Get-CRTReport.ps1" -OutFile .\Get-CRTReport.ps1'
Write-Output '   .\Get-CRTReport.ps1 -WorkingDirectory "$($env:userprofile)\Desktop\Investigation\CRTReport" -Interactive'
Write-Output `n '-----------------------------------------------'
Write-Output 'Inbox rule review & removal'
Write-Output '-----------------------------------------------'
Write-Output `n '   Connect-ExchangeOnline'
Write-Output '   Get-InboxRule -IncludeHidden –Mailbox "EMAILADDRESS"'
Write-Output '   Get-InboxRule -IncludeHidden –Mailbox "EMAILADDRESS" | FL'
Write-Output '   Get-InboxRule -IncludeHidden –Mailbox "EMAILADDRESS" | Select Name,Priority,Enabled,Description,Identity,From,SubjectContainsWords,SubjectOrBodyContainsWords,ForwardTo,MoveToFolder,SoftDeleteMessage,DeleteMessage | FL'
Write-Output '   Remove-InboxRule –Mailbox "EMAILADDRESS" -identity "RULENAMEorID"'
Write-Output '   Disconnect-ExchangeOnline -Confirm:$false'
Write-Output `n '-----------------------------------------------'
Write-Output 'Use Powershell to set the Connection Filter Policy (block an IP from sending messages on any license level):'
Write-Output '-----------------------------------------------'
Write-Output `n '   Set-HostedConnectionFilterPolicy -Identity Default [-AdminDisplayName <"Optional Comment">] [-EnableSafeList <$true | $false>] [-IPAllowList <IPAddressOrRange1,IPAddressOrRange2...>] [-IPBlockList <IPAddressOrRange1,IPAddressOrRange2...>]'
Write-Output 'Valid IP addr or address range values are:'
Write-Output 'Single IP: For example, 192.168.1.1.'
Write-Output 'IP range: For example, 192.168.0.1-192.168.0.254.'
Write-Output 'CIDR IP: For example, 192.168.0.1/25. Valid network mask values are /24 through /32.'
Write-Output 'To overwrite any existing entries with the values you specify, use the following syntax: IPAddressOrRange1,IPAddressOrRange2,...,IPAddressOrRangeN.'
Write-Output 'To add or remove IP addresses or address ranges without affecting other existing entries, use the following syntax: @{Add="IPAddressOrRange1","IPAddressOrRange2",...,"IPAddressOrRangeN";Remove="IPAddressOrRange3","IPAddressOrRange4",...,"IPAddressOrRangeN"}.'
Write-Output 'To empty the IP Allow List or IP Block List, use the value $null'
Write-Output `n '   Set-HostedConnectionFilterPolicy "Default" -IPAllowList 192.168.1.10,192.168.1.23 -IPBlockList 10.10.10.0/25,172.17.17.0/24'
Write-Output '   Set-HostedConnectionFilterPolicy -Identity Default -IPAllowList @{Add="192.168.2.10","192.169.3.0/24","192.168.4.1-192.168.4.5";Remove="192.168.1.10"}'
Write-Output 'https://learn.microsoft.com/en-us/defender-office-365/connection-filter-policies-configure'
Write-Output `n '-----------------------------------------------'
Write-Output 'Use Powershell to set the Tenant Allow/Block List (block an IP from sending messages on any license level):'
Write-Output '-----------------------------------------------'
Write-Output `n 'For IPV4'
Write-Output '   New-TenantAllowBlockListItems -ListType Url -Allow -Entries "Value1","Value2",..."ValueN" [-RemoveAfter 45]  [-Notes <String>]'
Write-Output 'Wildcards are not allowed.'
Write-Output 'For IPV6'
Write-Output '   New-TenantAllowBlockListItems -ListType IP -Action Block -Entries "2001:0db8:85a3:0000:0000:8a2e:0370:7334" -ExpirationDate (Get-Date).AddDays(30) -Reason "Suspicious activity"'
Write-Output 'If you manually create a block entry, all incoming email messages from that IP address are dropped at the edge of the service.'
Write-Output 'IP addresses for IPV6 accepts these formats:'
Write-Output 'Colon-hexadecimal notation single IPv6 address (for example, 2001:0db8:85a3:0000:0000:8a2e:0370:7334)'
Write-Output 'Zero compression single IPv6 address (for example, 2001:db8::1)'
Write-Output 'Classless inter-domain routing (CIDR) IPv6 (for example, 2001:0db8::/32). The range supported is 1-128.'
Write-Output 'The IP block entry will drop any email sent from that IP at the edge, whereas the IP allow will just override the IP filtering,'
Write-Output 'allowing the rest of the Defender for Office 365 stack to evaluate threats. IP block has a higher priority over IP allow entries.'
Write-Output 'Limits:'
Write-Output 'Exchange Online Protection: The maximum number of allow entries is 500, and the maximum number of block entries is 500 (1000 entries in total).'
Write-Output 'Defender for Office 365 Plan 1: The maximum number of allow entries is 1000, and the maximum number of block entries is 1000 (2000 entries in total).'
Write-Output 'Defender for Office 365 Plan 2: The maximum number of allow entries is 5000, and the maximum number of block entries is 10000 (15000 entries in total).'
Write-Output 'https://security.microsoft.com/tenantAllowBlockList'
Write-Output 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-tenantallowblocklistitems'
Write-Output `n '-----------------------------------------------'
Write-Output 'Useful Mail Flow Rule Creation'
Write-Output '-----------------------------------------------'
Write-Output `n 'Block bulk email using common phrases:'
Write-Output '   New-TransportRule -Name "Bulk email filtering - Common phrases" -SubjectOrBodyContainsWords "to change your preferences or unsubscribe","Modify email preferences or unsubscribe","This is a promotional email","You are receiving this email because you requested a subscription","click here to unsubscribe","You have received this email because you are subscribed","If you no longer wish to receive our email newsletter","to unsubscribe from this newsletter","If you have trouble viewing this email","This is an advertisement","you would like to unsubscribe or change your","view this email as a webpage","You are receiving this email because you are subscribed" -SetSCL 9'
Write-Output 'https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/use-rules-to-filter-bulk-mail'
Write-Output `n 'Block messages that contain executable attachments:'
Write-Output '   New-TransportRule -Name "<UniqueName>" -AttachmentHasExecutableContent $true [-RejectMessageEnhancedStatusCode <5.7.1 | 5.7.900 to 5.7.999>] [-RejectMessageReasonText "<Text>"] [-DeleteMessage $true]'
Write-Output '   New-TransportRule -Name "Block Executable Attachments" -AttachmentHasExecutableContent $true -DeleteMessage $true'
Write-Output `n 'Create rule that adds a disclaimer with an image at the end of all email messages that are sent outside the organization:'
Write-Output '   New-TransportRule -Name "External Disclaimer" -SentToScope NotInOrganization -ApplyHtmlDisclaimerText "<h3>Disclaimer Title</h3><p>This is the disclaimer text.</p><img alt="Contoso logo" src="http://www.contoso.com/images/logo.gif">"'
Write-Output `n 'Add warning to external messages:'
Write-Output "   $WarningBanner = '<table border=0 cellspacing=0 cellpadding=0 align=`"left`" width=`"100%`"><tr><td style=`"background:#ffb900;padding:5pt 2pt 5pt 2pt`"></td><td width=`"100%`" cellpadding=`"7px 6px 7px 15px`" style=`"background:#fff8e5;padding:5pt 4pt 5pt 12pt;word-wrap:break-word`"><div style=`"color:#222222;`"><span style=`"color:#222; font-weight:bold;`">Warning: </span>This message originated outside of your email system. Maintain caution when opening external links and attachments</div></td></tr></table><br/>'"
Write-Output '   New-TransportRule -Name "External message warning banner" -FromScope NotInOrganization -SentToScope InOrganization -ApplyHtmlDisclaimerLocation Prepend -ApplyHtmlDisclaimerText $HTMLDisclaimer -ApplyHtmlDisclaimerFallbackAction Wrap'
Write-Output 'https://lazyadmin.nl/it/add-external-email-warning-to-office-365-and-outlook/'
Write-Output `n 'Block attempted impersonation (display name matches an internal user and message is from external source):'
Write-Output '   $displayNames = (Get-EXOMailbox -ResultSize unlimited  -RecipientTypeDetails usermailbox).displayname'
Write-Output '   New-TransportRule -Name "Block impersonation attempt" -FromScope NotInOrganization -SentToScope InOrganization -HeaderMatchesMessageHeader From -HeaderMatchesPatterns $displayNames -Quarantine $true'
Write-Output 'https://lazyadmin.nl/office-365/warn-users-for-email-impersonation-phishing-mail/'
Write-Output `n '-----------------------------------------------'
Write-Output 'Review & edit Outlook web application policies'
Write-Output '-----------------------------------------------'
Write-Output `n 'Exchange Admin Center > Roles > Outlook web APP policies'
Write-Output `n '   Get-OwaMailboxPolicy'
Write-Output `n 'Set all accounts to use default policy'
Write-Output '   Get-Mailbox -ResultSize unlimited | Set-CASMailbox -OWAMailboxPolicy "Default"'
Write-Output '   Set-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default -RulesEnabled $false'
Write-Output 'The RulesEnabled parameter specifies whether a user can view, create, or modify server-side rules in Outlook on the web. Valid values are:'
Write-Output '$true: Users can view, create, or modify server-side rules in Outlook on the web. This is the default value.'
Write-Output '$false: Users can not view, create, or modify server-side rules in Outlook on the web.'
Write-Output `n '-----------------------------------------------'
Write-Output 'Send mass email notification as follow up to phiching blast sent from compromised account by threat actor'
Write-Output '-----------------------------------------------'
Write-Output `n 'Create list of contacts from message trace with EMAIL address and a NAME'
Write-Output 'Save list of addresses to a txt file.'
Write-Output '   Connect-ExchangeOnline'
Write-Output 'Add all addresses in the txt file to a new distribution list'
Write-Output '   $AddressList = "Path\to\address\list.txt"'
Write-Output '   $GroupID = "PhishingWarning@Contovo.com"'
Write-Output '   New-DistributionGroup -Name $GroupID -PrimarySmtpAddress "return@emailaddress.com"'
Write-Output '   $ListMembers =  Get-DistributionGroupMember -Identity $GroupID -ResultSize Unlimited | Select -Expand PrimarySmtpAddress'
Write-Output '   Import-CSV $AddressList -Header "UPN" | ForEach { If ($ListMembers -contains $_.UPN) { Write-Output "$($_.UPN) already member of the Distribution List" } Else { Add-DistributionGroupMember –Identity $GroupID -Member $_.UPN; Write-Output "$($_.UPN) added to Distribution List" } }'
Write-Output 'Send the notification from a suitable account to the distribution list. Example messages:'
Write-Output 'https://blog.hubspot.com/marketing/sample-letter-for-hacked-email'
Write-Output 'Then removed the Distribution group'
Write-Output '   Remove-DistributionGroup -Identity $GroupID'
Write-Output `n '-----------------------------------------------'
Write-Output 'List & unblock restricted users'
Write-Output '-----------------------------------------------'
Write-Output `n 'List restricted users:'
Write-Output '   $restrictedUsers = Get-BlockedSenderAddress'
Write-Output '   $restrictedUsers | Format-Table DisplayName, EmailAddress, Reason, BlockedDate'
Write-Output 'Remove user from restricted list:'
Write-Output '   Remove-BlockedSenderAddress -SenderAddress <emailaddress>'
Write-Output 'Note that it can take 24 hours for the change to propagate & user to be able to send email again.'
Write-Output `n '-----------------------------------------------'
Write-Output 'Verify mailbox auditing is turned on, and turn it on if it is not'
Write-Output '-----------------------------------------------'
Write-Output `n 'Not currently scripted as this log entry type is not yet generally available to M365 tenants'
Write-Output '   Get-OrganizationConfig | Format-List AuditDisabled'
Write-Output '   Get-Mailbox -Identity <MailboxIdentity> | Format-List DefaultAuditSet'
Write-Output '   Get-Mailbox -Identity <MailboxIdentity> | Select-Object -ExpandProperty AuditOwner'
Write-Output '   Get-Mailbox -Identity <MailboxIdentity> | Select-Object -ExpandProperty AuditDelegate'
Write-Output '   Get-Mailbox -Identity <MailboxIdentity> | Select-Object -ExpandProperty AuditAdmin'
Write-Output '   Set-OrganizationConfig -AuditDisabled $false'
Write-Output '   Set-Mailbox -Identity <MailboxIdentity> -DefaultAuditSet <Admin | Delegate | Owner>'
Write-Output '   Set-Mailbox -Identity <MailboxIdentity> -AuditAdmin @{Add="Create","FolderBind","HardDelete","MailItemsAccessed","MessageBind","Move","Send","SendAs","SendOnBehalf","SoftDelete","Update","UpdateInboxRules"}'
Write-Output '   Set-Mailbox -Identity <MailboxIdentity> -AuditDelegate @{Add="Create","FolderBind","HardDelete","MailItemsAccessed","Move","SendAs","SendOnBehalf","SoftDelete","Update","UpdateInboxRules"}'
Write-Output '   Set-Mailbox -Identity <MailboxIdentity> -AuditOwner @{Add="Create","HardDelete","MailboxLogin","MailItemsAccessed","Move","SearchQueryInitiated","Send","SoftDelete","Update","UpdateInboxRules"}'
Write-Output 'Loop over all mailboxes with: $Mailboxes = Get-Mailbox -ResultSize Unlimited -filter {RecipientTypeDetails -eq "UserMailbox"} ; foreach ($Mailbox in $Mailboxes) { <INSERT SET-MAILBOX LINE ABOVE WITH $Mailbox AS MAILBOXIDENTITY> }'
Write-Output 'https://learn.microsoft.com/en-us/purview/audit-mailboxes'
Write-Output `n '-----------------------------------------------'
Write-Output 'Check & update spam filter policies'
Write-Output '-----------------------------------------------'
Write-Output `n '   Get-HostedOutboundSpamFilterPolicy | Format-Table Name,Enabled,IsDefault,Action*'
Write-Output '   Get-HostedOutboundSpamFilterPolicy -identity "name"'
Write-Output '   New-HostedOutboundSpamFilterPolicy -Name "<FilterPolicyName>" -RecipientLimitInternalPerHour <Value> -RecipientLimitExternalPerHour <Value> -RecipientLimitPerDay <Value> -ActionWhenThresholdReached <ActionToBeTaken> -NotifyOutboundSpamRecipients $true  '
Write-Output 'https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-configure'
Write-Output 'Message limits sections: The settings in this section configure the limits for outbound email messages from Exchange Online mailboxes:'
Write-Output 'Set an external message limit: The maximum number of external recipients per hour.'
Write-Output 'Set an internal message limit: The maximum number of internal recipients per hour.'
Write-Output 'Set a daily message limit: The maximum total number of recipients per day.'
Write-Output 'if a setting is 0 default is used: https://learn.microsoft.com/en-us/office365/servicedescriptions/exchange-online-service-description/exchange-online-limits#sending-limits-1'
Write-Output 'https://www.jorgebernhardt.com/manage-outbound-spam-policy/'
Write-Output `n
Write-Output 'Get-HostedOutboundSpamFilterRule'
Write-Output `n
Write-Output '$orgConfig = Get-OrganizationConfig'
Write-Output '$orgConfig.isdehydrated'
Write-Output 'Check for "IsDehydrated : False"'
Write-Output 'If it is true:'
Write-Output 'Enable-OrganizationCustomization'
Write-Output `n
Write-Output 'Get-HostedConnectionFilterPolicy -Identity Default | Format-Table Name, IP*, EnableSafeList'
Write-Output `n
Write-Output 'Set-HostedConnectionFilterPolicy -Identity Default -IPAllowList @{Add="192.168.1.11", "192.168.1.12", "172.16.1.0/24"; Remove="192.168.2.0/24"}'
Write-Output 'https://learn.microsoft.com/en-us/powershell/module/exchange/set-hostedoutboundspamfilterpolicy?view=exchange-ps'
Write-Output `n
Write-Output 'Get-HostedContentFilterPolicy'
Write-Output 'Set-HostedContentFilterPolicy -Identity Default -HighConfidenceSpamAction Quarantine'
Write-Output 'https://learn.microsoft.com/en-us/powershell/module/exchange/set-hostedcontentfilterpolicy?view=exchange-ps'
Write-Output `n
Write-Output 'https://4sysops.com/archives/configure-spam-filter-in-exchange-online-protection-eop-using-powershell/'
Write-Output `n
Write-Output 'https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-configure'
Write-Output `n '-----------------------------------------------'
Write-Output 'Check password policy settings'
Write-Output '-----------------------------------------------'
Write-Output `n 'https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/update-mgpolicyidentitysecuritydefaultenforcementpolicy?view=graph-powershell-1.0'
Write-Output 'Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy | Fl'
Write-Output `n '-----------------------------------------------'
Write-Output 'Misc'
Write-Output '-----------------------------------------------'
Write-Output `n 'Additional places to review/update:'
Write-Output 'Tenant Allow/Block List: https://security.microsoft.com/tenantAllowBlockList'
Write-Output 'Threat Policies: https://security.microsoft.com/threatpolicy'
Write-Output 'Anti-spam outbound policy (Default), Connection filter policy (Default): https://security.microsoft.com/antispam'
Write-Output 'Entra ID User Settings: https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/UserSettings'
Write-Output 'SharePoint Sharing: https://go.microsoft.com/fwlink/?linkid=2185222'
Write-Output 'Check authentication policies, including legacy: Get-AuthenticationPolicy'
# Write-Output `n '-----------------------------------------------'
# Write-Output 'Blank section'
# Write-Output '-----------------------------------------------'
# Write-Output `n 'Stuff'
# Write-Output 'Stuff'
# rite-Output 'Stuff'
Write-Output `n '-----------------------------------------------'
Write-Output `n`n "Done!"

Exit
