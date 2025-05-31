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
# v3.0 last updated 2025-05-31
# Script to print list of PowerShell one-liners that are useful for M365 BEC investigation & response. 
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
Write-Output 'Useful Mail Flow Rules'
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
Write-Output 'Using MailItemsAccessed audit records for forensic investigations'
Write-Output '-----------------------------------------------'
Write-Output `n 'Not currently scripted as this log entry type is not yet generally available to M365 tenants'
Write-Output '   Search-UnifiedAuditLog -StartDate 01/06/2020 -EndDate 01/20/2020 -UserIds <user1,user2> -Operations MailItemsAccessed -ResultSize 1000'
Write-Output '   Search-MailboxAuditLog -Identity <user> -StartDate 01/06/2020 -EndDate 01/20/2020 -Operations MailItemsAccessed -ResultSize 1000 -ShowDetails'
Write-Output 'https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts'
Write-Output 'https://petri.com/interpreting-the-office-365-mailitemsaccessed-audit-event/'
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
Write-Output `n 'Stuff'
Write-Output 'https://security.microsoft.com/tenantAllowBlockList'
Write-Output 'https://security.microsoft.com/threatpolicy'
Write-Output 'https://security.microsoft.com/antispam'
Write-Output 'Anti-spam outbound policy (Default)'
Write-Output 'Get-AuthenticationPolicy'
# Write-Output `n '-----------------------------------------------'
# Write-Output 'Blank section'
# Write-Output '-----------------------------------------------'
# Write-Output `n 'Stuff'
# Write-Output 'Stuff'
# rite-Output 'Stuff'
Write-Output `n '-----------------------------------------------'
Write-Output `n`n "Done!"

Exit
