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

## v2.8 last updated 2024-07-14

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
* 35-Get-MailItemsAccessed-E5.ps1 - Generate report of the mail items accessed in an Exchange Online Mailbox. Requires E5 licensing (for now). Original script by PricewaterhouseCoopers Advisory N.V.
* 36-Search-UALActivityByIPAddress.ps1 - Export all UAL entries associated with a given set of IP addresses.
* 37-Search-UALActivityByUser.ps1 - Export all UAL entries associated with a given set of user accounts.
* 38-Get-ExchangeMessageContentSearch.ps1 - Walk through frequently used content search steps for dealing with spam/phishing messages - Create Exchange search based on sender/date/message subject, export preview, export content, purge.
* 80-OneLinerReference.ps1 - Reference for various PowerShell one-line commands that are useful during BEC response & investigation.
* 90-Get-MFAReport.ps1 - Export report of M365 MFA settings of each account through Microsoft Graph.
* 91-Get-CAPReport-P1.ps1 - Generate report of current Conditional Access Policies and Named Locations. Requires at least Entra ID P1.
* 92-Create-ConditionalAccessPolicies-P1.ps1 - Backup current Named Locations/Conditional Access Policies and set up a recommended basic set of Named Locations and Conditional Access Policies in report-only mode. Requires at least Entra ID P1, and requires P2 for some policies.
* 99-Disconnect-M365Modules.ps1 - Disconnect from all M365 modules. Run when finished with above scripts.
* IRScript-Template.ps1 - Template for additional scripts in this series.


# Script Use:

## Basic playbook for M365 Business Email Compromise (BEC) utilizing scripts:

Scripts in this collection are organized roughly in the order in which they are used during the course of a BEC investigation and response.

All scripts that output reports by default do so to a new folder named "Investigation" on the current user's desktop, in a subfolder with the name of the primary domain of tenant under investigation. The prompt for this can be skipped by setting -OutputFolder parameter to "Default" when running a script.

General playbook steps for investigating a BEC incident in M365.

1. 
2. 
3. 
4. 
5. 


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
