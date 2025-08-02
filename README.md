           Bitpusher
            \`._,'/
            (_- -_)
              \o/
          The Digital
              Fox
          @VinceVulpes
    https://theTechRelay.com
 https://github.com/bitpusher2k

# M365IRScripts

## Collection of modular M365 incident response & investigation scripts

## By Bitpusher/The Digital Fox

## v3.1 last updated 2025-07-26 - Reviewed all scripts, updated functions, homogenized structure and started removing MSOL versions of commands

#comp #m365 #security #bec #script #irscript #powershell #collection #playbook #readme #lotlir #lolir #incident #response #investigation

### Scripts provided as-is. Use at your own risk. No guarantees or warranty provided.


# Purpose:

When utilizing native M365 tools for business email compromise response/investigation tasks some things are easier to do through M365 admin consoles, while some things are easier through PowerShell. Monolithic response scripts are useful, especially when used frequently, but more prone to breaking and harder to troubleshoot when there is any issue. After using various PS commands and scripts piecemeal (often forgetting details between use) a systematic set of scripts has been prepared. This collection recognizes the utility in consolidating & refining each task - keeping each script modular for ease of understanding, ease of maintenance, and organizing into a loose investigative flow.

If you have SIEM/SOAR or other third-party monitoring and response tools in place, use them! However, such tools are often not immediately available at need due to cost, timeline, access permissions, outage, or other issues. In particular, responses to BEC in the SME/SMB sector may need to be performed without the support of third-party tools or more sophisticated native systems available at higher licensing levels. In these cases having a framework and set of scripts that are easy to follow, easy to learn from, which provide multiple methods for the retrieval of critical information, and which have no dependencies outside of native M365 modules can be very valuable. Welcome to LOtL IR - Living off the Land Incident Response.

All scripts in this collection are pretty simple and do not require things like setting up application tokens before use (they are all meant to be run manually). The utility of such simple scripts should show how much more could be done with more sophisticated automation & processing, as well as how such detection & response could be tuned to make more capable SIEM/SOAR platforms even more effective. Think of these scripts as well-annotated command notes which should allow faster execution of the various processes, all documented just enough to clarify execution once experimented with a bit. And if much more than that is needed then there are real developers out there who have created real products that can do a lot more - but charge for them.


# Script Organization:

* 00-09: Scripts for module updating & connecting, as well as log processing.
* 10-29: Broader tenant-wide information gathering scripts.
* 30-39: Narrower user or IP-specific information gathering and setting altering scripts.
* 80-89: Misc.
* 90-99: Scripts for reviewing & updating tenant settings and disconnecting from modules when finished.


# Script Descriptions:

Functions and scripts modified from other sources are attributed in each script - If any attribution is missed please let me know.

* 00-Update-M365Modules.ps1 - Installs/updates all needed M365 PowerShell modules. Original script by https://github.com/directorcia
* 01-Connect-M365Modules.ps1 - Connect PowerShell through MS Graph, MSOL, IPPS, Exchange Online, and Azure AD modules. Prerequisite for most of the following scripts.
* 02-ProcessEntraSignInLog.bat - Shim to enable drag-and-drop of downloaded log (from Entra ID admin center) to PS script of the same name.
* 02-ProcessEntraSignInLog.ps1 - Process CSV of Entra ID sign-in log exported from Admin Center. Re-orders some columns and re-formats datestamp/location data to make more usable during a manual review.
* 03-ProcessEntraAuditLog.bat - Shim to enable drag-and-drop of downloaded log (from Entra ID admin center) to PS script of the same name.
* 03-ProcessEntraAuditLog.ps1 - Process CSV of Entra ID audit log exported from Admin Center to make more usable during manual review.
* 04-ProcessMailboxAuditLog.bat - Shim to enable drag-and-drop of mailbox audit log exported through  log to PS script of the same name.
* 04-ProcessMailboxAuditLog.ps1 - Process CSV of Exchange Online mailbox audit log exported with script 34 below (Search-MailboxAuditLog command) to make more usable during manual review.
* 05-ProcessUnifiedAuditLogFlatten.bat - Shim to enable drag-and-drop of downloaded log to PS script of the same name.
* 05-ProcessUnifiedAuditLogFlatten.ps1 - Process CSV of any event logs from the Unified Audit Log exported with these scripts. Flattens objects and makes more usable during manual review.
* 06-Lookup-IPInfoCSV.bat - Shim to enable drag-and-drop of downloaded log to PS script of the same name.
* 06-Lookup-IPInfoCSV.ps1 - Process CSV of exported logs from the Unified Audit Log or other source which includes a column of IP addresses - Enrich the CSV with information on each IP address.
* 07-ProcessObjectFlatten.bat - Shim to enable drag-and-drop of downloaded log to PS script of the same name.
* 07-ProcessObjectFlatten.ps1 - Process JSON file into flattened CSV more usable during manual review.
* 08-SelectUniquePairsCSV.bat - Shim to enable drag-and-drop of downloaded log to PS script of the same name.
* 08-SelectUniquePairsCSV.ps1 - Process CSV file taking two columns and returning a new CSV containing those two columns with only unique rows.
* 09-Hydra-Collect.ps1 - Use to run often used set of collection scripts sequentially with default settings at outset of an investigation. "Hydra" because each sub-script "head" is independent, and because it's memorable.
* 10-Get-BasicTenantInformation.ps1 - Retrieve basic tenant information & settings relevant to further log collection. Verify tenant name, licensing level, UAL enabled, etc..
* 11-Get-EntraIDAuditAndSignInLogs30-P1.ps1 - Retrieve Entra ID sign-in and audit logs using AzureAD and Graph modules. Requires at least Entra ID P1 - otherwise logs must be retrieved through admin console.
* 12-Search-UnifiedAuditLogSignIn.ps1 - Retrieve sign-in log entries from the Unified Audit Log (less detailed but longer retention than Entra ID sign-in logs).
* 13-Get-AllM365EmailAddresses.ps1 - List all email accounts on an M365 tenant, mailbox type, aliases.
* 14-Get-AllUserPasswordReport.ps1 - Generate report of all accounts on a tenant and password information (creation date, licensed, last sync time, blocked, last password change, etc.).
* 15-Search-UnifiedAuditLogIR.ps1 - Search and collect events from the UAL that are often valuable during an investigation - role changes, domain changes, users added, password resets, files created, etc..
* 16-Get-UnifiedAuditLogEntries.ps1 - Export all UAL entries in given date range.
* 17-Search-MailboxSuspiciousRules.ps1 - List all rules on tenant mailboxes that are suspicious based on several heuristics: forwarding, rule names, message moving, keywords, message deletion.
* 18-Search-InboxRuleChanges.ps1 - Search the UAL for all recent inbox rule changes.
* 19-Get-AllInboxRules.ps1 - List all inbox rules from all accounts on tenant.
* 20-Get-ForwardingSettings.ps1 - List all mailboxes which have a forwarding address set.
* 21-Get-MailboxPermissions.ps1 - List all mailboxes which have non-standard permissions set.
* 22-Get-EnterpriseApplications.ps1 - List all Enterprise Applications on a tenant, from most newest to oldest.
* 23-Get-DefenderInformation.ps1 - Get information on Microsoft Defender alert configuration, threat detections, blocked senders, quarantine policy, and quarantined messages.
* 24-Get-EntraIDRisk.ps1 - Generate report of recent risk detections by Entra ID.
* 25-Lockdown-Account.ps1 - Lock down a given M365 that is suspected of being compromised (revoke sessions, set random password, block sign-in - Not effective on AD-synced accounts unless password writeback is enabled).
* 30-Get-BasicUserInformation.ps1 -  List the rolls and permissions (send as, send on behalf, full access) of specified user.
* 31-Get-UserMFAMethodsAndDevices.ps1 - List the registered authentication methods and devices of a specified user.
* 32-Get-UserJunkMailSettings.ps1 - List the junk mail settings of a specified user.
* 33-Get-UserMessageTrace.ps1 - Generate report of recent incoming & outgoing email for a specified user.
* 34-Get-MailboxAuditLog.ps1 - Generate reports of mailbox audit log activity of specified user or all users. Uses both Search-MailboxAuditLog and Search-UnifiedAuditLog.
* 36-Search-UALActivityByIPAddress.ps1 - Export all UAL entries associated with a given set of IP addresses.
* 37-Search-UALActivityByUser.ps1 - Export all UAL entries associated with a given set of user accounts.
* 38-Search-UALFileAccessedByUser.ps1 - Export all "FileAccessed" & related records from the Unified Audit Log for specified users.
* 39-Search-UALMailItemsAccessedByUser.ps1 - Export all "MailItemsAccessed" & related records from the Unified Audit Log for specified users - Such records should be more widely available now.
* 44-Get-ExchangeMessageContentSearch.ps1 - Walk through frequently used content search steps for dealing with spam/phishing messages - Create Exchange search based on sender/date/message subject, export preview, export content, purge.
* 45-Search-MailboxMessage.ps1 - Search Exchange Online mailbox using Graph API by Message IDs and save messages to folder along with a metadata index CSV.
* 80-OneLinerReference.ps1 - Reference for various PowerShell one-line commands that are useful during BEC response & investigation.
* 90-Get-MFAReport.ps1 - Export report of M365 MFA settings of each account through Microsoft Graph.
* 91-Get-CAPReport-P1.ps1 - Generate report of current Conditional Access Policies and Named Locations. Requires at least Entra ID P1.
* 92-Create-ConditionalAccessPolicies-P1.ps1 - Backup current Named Locations/Conditional Access Policies and set up a recommended basic set of Named Locations and Conditional Access Policies in report-only mode. Requires at least Entra ID P1, and requires P2 for some policies.
* 93-Get-SecureScoreInformation.ps1 Retrieve and list M365 Secure Score information.
* 99-Disconnect-M365Modules.ps1 - Disconnect from all M365 modules. Run when finished with above scripts.
* IRScript-Template.ps1 - Template for additional scripts in this series.


# Script Use:

## Basic playbook for M365 Business Email Compromise (BEC) utilizing scripts:

Scripts in this collection are organized roughly in the order in which they are used during the course of a BEC investigation and response.

All scripts that output reports do so to a folder named "Investigation" on the current user's desktop (this can be overridden by setting -OutputFolder parameter to desired path when running a script.), in a subfolder created with the name of the primary domain of tenant under investigation. 

General playbook steps for investigating & remediating a BEC incident in M365. IR scripts can be iterated through to support the investigation as it progresses.

1. Contain incident - block sign-in to known or suspected compromised accounts and initiate password resets. Check user roles and mailbox permissions, and expand scope of incident accordingly.
2. Retrieve and review account logs - start with sign-in logs, audit logs, inbox rules, mailbox audit logs. See below "Investigation Tips" for specifics on retrieving and reviewing M365 settings/logs using these IR scripts.
3. Check built-in protections - Entra ID risk detections and Microsoft Defender alerts/incidents/quarantine ()
4. Review tenant Enterprise Applications, impacted account MFA methods and registered devices (https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Users), changes to OneDrive files and junk mail configurations.
5. Pivot through logs following identified malicious/suspicious events to find related events - Chronology is the first element of induction; topology is the second. Correlate events by proximity in time and proximity in source.
6. If impacted account scope is expanded by findings from logs & settings start back at step one and repeat.
7. Once investigation is concluded and account(s) are secured clear messages from Microsoft Defender quarantine, unblock sending of any blocked account(s), use eDiscovory to find and remove identified spam/phishing messages from mailboxes. 

## Investigation tips utilizing these scripts:

* Download/clone this repository.
* Open PowerShell window & navigate to location of scripts.
* Install/update needed PowerShell modules by running .\00-Update-M365Modules.ps1.
* Connect to M365 tenant by running .\01-Connect-M365Modules.ps1.
* Run .\09-Hydra-Collect.ps1 script to automatically run in sequence:
    * 10-Get-BasicTenantInformation.ps1
    * 18-Search-InboxRuleChanges.ps1 (first pass)
    * 11-Get-EntraIDAuditAndSignInLogs30-P1.ps1
    * 12-Search-UnifiedAuditLogSignIn.ps1
    * 13-Get-AllM365EmailAddresses.ps1
    * 14-Get-AllUserPasswordReport.ps1
    * 17-Search-MailboxSuspiciousRules.ps1
    * 19-Get-AllInboxRules.ps1
    * 22-Get-EnterpriseApplications.ps1
    * 20-Get-ForwardingSettings.ps1
    * 21-Get-MailboxPermissions.ps1
    * 23-Get-DefenderInformation.ps1
    * 24-Get-EntraIDRisk.ps1
    * 90-Get-MFAReport.ps1
    * 91-Get-CAPReport-P1.ps1
    * 93-Get-SecureScoreInformation.ps1
    * OPTIONALLY: 15-Search-UnifiedAuditLogIR.ps1
    * OPTIONALLY: Get-UnifiedAuditLogEntries.ps1
    * 18-Search-InboxRuleChanges.ps1 (second pass)
    * OPTIONALLY: a set of Invictus IR cmdlets (details below)
    * OPTIONALLY: CrowdStrike Reporting Tool for Azure (details below)

* To review sign-in logs
    * Export CSV versions of Interactive and Non-Interactive sign-ins going back one week (further if available and if incident scope warrants it) from https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/SignIns
    * If sign-in log retention is not sufficient use .\12-Search-UnifiedAuditLogSignIn.ps1 to export sign-in information from the UAL (goes back up to 180 days).
    * Parse exported sign-in log CSV using 02-ProcessEntraSignInLog.bat/02-ProcessEntraSignInLog.ps1 scripts.
    * Add IP geolocation/ISP/company data to CSV using 06-Lookup-IPInfoCSV.bat/06-Lookup-IPInfoCSV.ps1 scripts.
    * Use Excel filtering to review sign-ins of account(s) under investigation, observing baseline pattern and deviations from pattern (recommend using Excel macros - https://github.com/bitpusher2k/ExcelMacros)
    * Evaluate suspicious sign-in activity by correlating as many suspect traits found as possible, including:
        * Past sign-in history of account(s) (deviations from history are more suspect)
        * Geolocation of sign-in IP (sign-in from countries with bad reputation or sign-ins from distant locations in a short space of time are more suspect)
        * Reputation of sign-in IP/ISP/Company (sign-ins from an IP with a poor reputation, or from an IP associated with VPN/DCH are more suspect)
        * Device used to sign-in (sign-ins from endpoints that are not registered/joined through Entra ID are more suspect)
        * OS used to sign-in (sign-ins from less common operating systems such as "Mac OS" and "Linux" are more suspect)
        * User Agent used to sign-in (sign-ins from less common and automated user agents such as "python-httpx" or "axios" are more suspect)
        * Authentication factors used to sign-in (sign-ins that did not pass MFA, whether through single-factor only being needed or through MFA requirement being "satisfied by claim in token" are more suspect)
    * Use any identified suspect traits (listed above) as basis for re-filtering table to give context to events and potentially identify additional compromise

* To review audit logs
    * Export CSV version going back one week (further if available and if incident scope warrants it) from https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Audit
    * Parse exported audit log CSV using 03-ProcessEntraAuditLog.bat/03-ProcessEntraAuditLog.ps1 scripts.
    * Look for recent activity in the audit log related to the account being investigated - permissions changes, password changes, addition of authentication methods.

* To review inbox rules
    * Export inbox rule reports using .\17-Search-MailboxSuspiciousRules.ps1, .\18-Search-InboxRuleChanges.ps1, .\19-Get-AllInboxRules.ps1 scripts.
    * Review reports paying special attention to inbox rules related to the account(s) under investigation and rules listed report from 17-Search-MailboxSuspiciousRules.ps1 script.
    * Refer to contents of 80-OneLinerReference.ps1 for commands related to remediation of any discovered malicious inbox rules.

* To review mailbox audit logs
    * Run message trace on account(s) under investigation using .\33-Get-UserMessageTrace.ps1 script.
    * Run mailbox audit log export using .\34-Get-MailboxAuditLog.ps1 script.
    * Parse exported logs using 05-ProcessUnifiedAuditLogFlatten.bat/05-ProcessUnifiedAuditLogFlatten.ps1 scripts.
    * Review output of scripts focusing on activity from any identified suspect IP addresses and related to any know suspect message subject lines.

* To review Enterprise Applications
    * View in console at https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/EnterpriseApps and/or use .\22-Get-EnterpriseApplications.ps1 to export report.
    * Look for any applications added within the scope of the incident, and any applications often used for malicious purposes (PerfectData, eM Client - https://cybercorner.tech/malicious-azure-application-perfectdata-software-and-office365-business-email-compromise/, https://cybercorner.tech/malicious-usage-of-em-client-in-business-email-compromise/)

* To review Microsoft Defender alerts and Entra ID risk
    * View Defender alerts in console at https://security.microsoft.com > Alerts and/or use .\23-Get-DefenderInformation.ps1 to export report.
    * View Entra ID risk in console at https://portal.azure.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskyUsers and https://portal.azure.com/#view/Microsoft_AAD_IAM/SecurityMenuBlade/~/RiskySignIns and/or use .\24-Get-EntraIDRisk.ps1.
    * Review for recent relevant alerts.

* To generate and review additional reports related to:
    * Security Defaults, Transport Rules, Security Alerts, Administrative roles and users with those roles, Mailbox Audit settings of each mailbox, OAuth application permissions, and user MFA settings...
    * Use Invictus IR Microsoft Extractor Suite module cmdlets:
    * Get-EntraSecurityDefaults
    * Get-TransportRules
    * Get-SecurityAlerts
    * Get-AdminUsers
    * Get-MailboxAuditStatus
    * Get-OAuthPermissionsGraph
    * Get-MFA
    * See full documentation at: https://microsoft-365-extractor-suite.readthedocs.io/en/latest/
    * Included in a run of Hydra-Collect script

* To generate and review additional reports related to:
    * Federation Configuration, Federation Trust, Client Access Settings Configured on Mailboxes, Mail Forwarding Rules for Remote Domains, Mailbox SMTP Forwarding Rules, Mail Transport Rules, Delegates with "Full Access" and those with Any Permissions Granted, Delegates with "Send As" or "SendOnBehalf" Permissions, Exchange Online PowerShell Enabled Users, Users with "Audit Bypass" Enabled, Mailboxes Hidden from the Global Address List (GAL), and administrator audit logging configuration settings...
    * Use the CrowdStrike Reporting Tool for Azure (CRT)
    * Invoke-WebRequest "https://github.com/CrowdStrike/CRT/raw/refs/heads/main/Get-CRTReport.ps1" -OutFile .\Get-CRTReport.ps1 ; .\Get-CRTReport.ps1 -WorkingDirectory "$($env:userprofile)\Desktop\Investigation\CRTReport" -Interactive
    * Included in a run of Hydra-Collect script

* To contain compromise
    * Block sign-in and change password of compromised account in console at https://admin.exchange.microsoft.com/ > Users > Active users and/or use .\25-Lockdown-Account.ps1 script. 
    * If account is synced from AD and tenant does not have password writeback enabled note that you will need to change password in AD and sync it up to Entra ID - if you do not the account with automatically have sign-in re-enabled and password reverted.

* To review user account settings
    * Review account MFA methods in console at https://portal.azure.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers > SEARCH FOR USER > Authentication methods and/or use .\31-Get-UserMFAMethodsAndDevices.ps1 to export report.
    * Review account devices in console at https://portal.azure.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers > SEARCH FOR USER > Devices and/or use .\32-Get-UserJunkMailSettings.ps1 to export report.
    * Look for unrecognized authentication methods and devices.

* To further investigate the logged activity of known compromised accounts and from identified malicious IP addresses.
    * Run .\36-Search-UALActivityByIPAddress.ps1 to export all UAL entries associated with a given set of IP addresses.
    * Run .\37-Search-UALActivityByUser.ps1 to export all UAL entries associated with specific user account(s).
    * Parse exported logs using 05-ProcessUnifiedAuditLogFlatten.bat/05-ProcessUnifiedAuditLogFlatten.ps1 scripts.
    * Review reports looking for any activity not yet identified previously in logs.
    * Use 08-SelectUniquePairsCSV.bat/08-SelectUniquePairsCSV.ps1 to filter a user's sign-in history to IP and SessionID combinations in order to identify all malicious sessions and discover/confirm malicious IP addresses.
    * Run .\39-Search-UALMailItemsAccessedByUser.ps1 to export all MailItemsAccessed events on a users account, then filter on known malicious IP addresses and SessionIDs to identify known messages which were interacted with by the threat actor.
    * Run .\45-Search-MailboxMessage.ps1 (STILL IN DEVELOPMENT - NOT YET FUNCTIONAL) to retrieve message information based on list of previously identified InternetMessageIDs.

* To search for suspect phishing messages by sender/subject line and export for review and/or purge from tenant
    * Run .\44-Get-ExchangeMessageContentSearch.ps1 and follow prompts.

* Refer to the contents/output of .\80-OneLinerReference.ps1 for often used and useful commands related to M365 BEC investigation/remediation.

* When investigation/remediation is complete run .\99-Disconnect-M365Modules.ps1 to disconnect all modules from M365 tenant.


# Key Takeaways:

* Prepare for BEC incident response before one is needed. Know what logs are available and enabled, have access to an account with permissions to collect these logs.
* Basic hardening of the M365 tenant accounts can go a long way towards preventing BEC incidents.
* Define the scope of an investigation by using questions and a checklist, iterating over the list as the picture of known anomalous/suspicious/malicious activity grows and clarifies.
* Inbox rules are one of the most common tactics utilized by threat actors in BEC incidents.
* Identifying suspicious sign-in activity is a useful tool for assessing initial access scope of incident. Unusual source IP addresses based on history & geolocation are a good starting point.
* Determining which email messages and other data has been accessed and/or exfiltrated is critical for determining the impact on an organization. This is often hampered by the limited logging available at most M365 licensing levels.


# Basic Tenant Hardening:

* Reduce the number of accounts with Global Admin permissions, and separate all such accounts from regular user accounts.
* Enable MFA for all accounts - Preferably a form of phish-resistant MFA.
* Check that mailbox auditing is enabled on all accounts, and that UAL is enabled on tenant.
* Review the tenant password policy - Enforce strong passwords and block the use of easy to guess passwords related to the organization.
* Block external forwarding of email messages, block user consent to applications, block anonymous sharing.
* Utilize Conditional Access Policies to improve security of tenant - See 92-Create-ConditionalAccessPolicies-P1.ps1 
* Monitor creation of inbox rules, addition of security principles, creation of enterprise applications.
* Implement Security Awareness Training.


# Tips:

M365 requires that some operations, such as downloading data found through compliance searches, be performed using the Edge browser. So: set Edge as the default browser in Windows on the account from which incident response is performed. This will allow authentication prompts from PowerShell to automatically be opened in Edge, facilitating authentication for the PowerShell session IR scripts and the M365 Admin Console. If you work with multiple M365 tenants set the Edge browser to clear all data every time the browser is closed to keep things tidy.


# Recommended Resources:

* Micorsoft's steps for responding to BEC - https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account
* FBI site for BEC information - https://www.fbi.gov/how-we-can-help-you/scams-and-safety/common-scams-and-crimes/business-email-compromise
* Awesome-BEC - https://randomaccess3.github.io/Awesome-BEC/
* Sparrow - https://github.com/cisagov/Sparrow
* Hawk - https://github.com/T0pCyber/hawk
* AzureHunter - https://github.com/darkquasar/AzureHunter
* M365 extractor - https://github.com/PwC-IR/Office-365-Extractor
* O365 scripts - https://o365reports.com
* LazyAdmin - https://lazyadmin.nl/
* Evotec - https://github.com/EvotecIT
* PwC-IR - https://github.com/PwC-IR/MIA-MailItemsAccessed-
* Invictus - https://www.invictus-ir.com/news/major-update-v-1-2-for-the-microsoft-extractor-suite
* IP address bulk lookup tool - https://www.infobyip.com/ipbulklookup.php
