#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-MailItemsAccessed-E5.ps1
# Created by PricewaterhouseCoopers Advisory N.V.
# modified by Bitpusher/The Digital Fox
# v3.0 last updated 2025-05-31
# Script to get information on the mail items accessed in an Exchange Online mailbox.
#
# MUST HAVE Office 365 or Microsoft 365 E5 license or a Microsoft 365 E5 Compliance add-on subscription!!!
# https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-log-investigate-accounts?view=o365-worldwide
# https://www.linkedin.com/pulse/everything-you-need-know-mailitemsaccessed-more-korstiaan-stam
# Edited to work with the M365 investigation script set flow - assumes already existing Exchange Online PS session and leaves session open after.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-MailItemsAccessed-E5.ps1
#
# Default range is last 14 days.
#
# Most useful options found thus far...
#
# First filter on suspect account/IP address:
# .\Get-MailItemsAccessed-E5.ps1 -Action Sessions -User example@XXXXXXXXXXXXXX.com -IP 95.96.75.118
# .\Get-MailItemsAccessed-E5.ps1 -Action Sessions -IP 95.96.75.118
#
# Then search for messages information:
# .\Get-MailItemsAccessed-E5.ps1 -Action Messages -IP 95.96.75.118
# .\Get-MailItemsAccessed-E5.ps1 -Action Messages -Sessions 19ebe2eb-a557-4c49-a21e-f2936ccdbc46,ad2dd8dc-507b-49dc-8dd5-7a4f4c113eb4 -IP 95.96.75.118
# .\Get-MailItemsAccessed-E5.ps1 -Action Messages -Sessions 19ebe2eb-a557-4c49-a21e-f2936ccdbc46,ad2dd8dc-507b-49dc-8dd5-7a4f4c113eb4
#
# Then list the emails from the message IDs:
# .\Get-MailItemsAccessed-E5.ps1 -Action Email -Output File -Input "C:\Users\user\Desktop\messageids.txt"
#
# More information listed below.
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
#
#comp #m365 #security #bec #script #irscript #powershell #exchange #online #items #accessed #e5

#Requires -Version 5.1

<#
Copyright 2020 PricewaterhouseCoopers Advisory N.V.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that
the following conditions are met:
	1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
	2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
	   following disclaimer in the documentation and/or other materials provided with the distribution.
	3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or
	   promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS &quot;AS IS&quot; AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
OF SUCH DAMAGE.
HENCE, USE OF THE SCRIPT IS FOR YOUR OWN ACCOUNT, RESPONSIBILITY AND RISK. YOU SHOULD
NOT USE THE (RESULTS OF) THE SCRIPT WITHOUT OBTAINING PROFESSIONAL ADVICE. PWC DOES
NOT PROVIDE ANY WARRANTY, NOR EXPLICIT OR IMPLICIT, WITH REGARD TO THE CORRECTNESS
OR COMPLETENESS OF (THE RESULTS) OF THE SCRIPT. PWC, ITS REPRESENTATIVES, PARTNERS
AND EMPLOYEES DO NOT ACCEPT OR ASSUME ANY LIABILITY OR DUTY OF CARE FOR ANY
(POSSIBLE) CONSEQUENCES OF ANY ACTION OR OMISSION BY ANYONE AS A CONSEQUENCE OF THE
USE OF (THE RESULTS OF) SCRIPT OR ANY DECISION BASED ON THE USE OF THE INFORMATION
CONTAINED IN (THE RESULTS OF) THE SCRIPT.
‘PwC’ refers to the PwC network and/or one or more of its member firms. Each member firm in the PwC
network is a separate legal entity. For further details, please see www.pwc.com/structure.


Contents of README:

<h3>MIA</h3>
MIA makes it possible to extract Sessions, MessageID(s) and find emails belonging to the MessageID(s). This script utilizes the MailItemsAccessed features from the Office 365 Audit Log.
The goal of this script is to help investigators answer the question: <b>What email data was accessed by the threat actor?</b><br><br>

The script supports three actions, you can configure the action with the -Action flag.
  1. Sessions
  2. MessageID
  3. Email

<h3>Sessions</h3>
Find SessionID(s) in the Audit Log. You can filter based on IP address or Username.
The first step is to identify what sessions belong to the threat actor. With this information you can go to the next step and find the MessageID(s) belonging to those sessions.<br><br>
<b>Example usage:</b><br>
Filter on Username and IP address<br>
.\MIA.ps1 -Action Sessions -User bobby@kwizzy.onmicrosoft.com -IP 95.96.75.118<br><br>
Filter on IP address<br>
.\MIA.ps1 -Action Sessions -IP 95.96.75.118<br><br>
Show all Sessions available in the Audit Log<br>
.\MIA.ps1 -Action Sessions<br><br>

<h3>Messages</h3>
Find the InternetMessageID(s). You can filter on SessionID(s) or IP addresses.
After you identified the session(s) of the threat actor, you can use this information to find all MessageID(s) belonging to the sessions.
With the MessageID(s) you can identify what emails were exposed to the threat actor.<br><br>
<b>Example usage:</b><br>
Filter on SessionID(s) and IP address<br>
.\MIA.ps1 -Action Messages -Sessions 19ebe2eb-a557-4c49-a21e-f2936ccdbc46,ad2dd8dc-507b-49dc-8dd5-7a4f4c113eb4 -IP 95.96.75.118<br><br>
Filter on SessionID(s)<br>
.\MIA.ps1 -Action Messages -Sessions 19ebe2eb-a557-4c49-a21e-f2936ccdbc46,ad2dd8dc-507b-49dc-8dd5-7a4f4c113eb4<br><br>
Show all MessageIDs available in the Audit Log<br>
.\MIA.ps1 -Action Messages<br><br>
Show all MessageIDs available in the Audit Log and find mails belonging to MessageID(s) and them to .txt files <br>
.\MIA.ps1 -Action Messages -Save yes<br><br>

<h3>Email</h3>
Find emails belonging to the MessageID(s) and save them to a file or print them to the Terminal.<br>
With the MessageID(s), we can use this option to find the metadata of the emails belonging to the ID(s).<br><br>
<b>Example usage</b><br>
Find all emails belonging to the MessageID(s) stored in the input file and print them to the terminal<br>
.\MIA.ps1 -Action Email -Output Terminal -Input "C:\Users\jrentenaar001\Desktop\messageids.txt"<br><br>
Find all emails belonging to the MessageID(s) stored in the input file and save them to a file<br>
.\MIA.ps1 -Action Email -Output File -Input "C:\Users\jrentenaar001\Desktop\messageids.txt"<br><br>
Find all emails belonging to the MessageID(s) provided in the Terminal and print the emails to the Terminal<br>
.\MIA.ps1 -Action Email -Output Terminal -IDs VI1PR01MB657547855449E4F22E7C2804B6E50@VI1PR01MB6575.eurprd01.prod.exchangelabs.com,VI1PR01MB65759C03FB572C407819A2F5B6E20@VI1PR01MB6575.eurprd01.prod.exchangelabs.com

<h3>Prerequisites</h3>
	-PowerShell<br>
	-Office365 account with privileges to access/extract audit logging<br>
	-One of the following windows versions:<br>
Windows 10, Windows 8.1, Windows 8, or Windows 7 Service Pack 1 (SP1)<br>
Windows Server 2019, Windows Server 2016, Windows Server 2012 R2, Windows Server 2012, or Windows Server 2008 R2 SP1<br>
<br>

You have to be assigned the View-Only Audit Logs or Audit Logs role in Exchange Online to search the Office 365 audit log.
By default, these roles are assigned to the Compliance Management and Organization Management role groups on the Permissions page in the Exchange admin center. To give a user the ability to search the Office 365 audit log with the minimum level of privileges, you can create a custom role group in Exchange Online, add the View-Only Audit Logs or Audit Logs role, and then add the user as a member of the new role group. For more information, see Manage role groups in Exchange Online.
https://docs.microsoft.com/en-us/office365/securitycompliance/search-the-audit-log-in-security-and-compliance)<br>

<h3>How to use the script</h3>
1.	Download MIA.ps1<br>
2.	Run the script with Powershell
3. ./MIA -Actions [Sessions|MessageID|Emails]

<h3>Frequently Asked Questions</h3>
<b>I logged into a mailbox with auditing turned on but I don't see my events?</b><br>
It can take up to 24 hours before an event is stored in the UAL.
<br>
<br>
<b>What about timestamps?</b><br>
The audit logs are in UTC, and they will be exported as such<br>
<br>

<b>What is the retention period?</b><br>
Office 365 E3 - Audit records are retained for 180 days. That means you can search the audit log for activities that were performed within the last 180 days.

Office 365 E5 - Audit records are retained for 365 days (one year). That means you can search the audit log for activities that were performed within the last year. Retaining audit records for one year is also available for users that are assigned an E3/Exchange Online Plan 1 license and have an Office 365 Advanced Compliance add-on license.
<br>

<h3>Known errors</h3>
<b>Import-PSSession : No command proxies have been created, because all of the requested remote....</b><br>
This error is caused when the script did not close correctly and an active session will be running in the background.
The script tries to import/load all modules again, but this is not necessary since it is already loaded. This error message has no impact on the script and will be gone when the open session gets closed. This can be done by restarting the PowerShell Windows or entering the following command: Get-PSSession | Remove-PSSession <br>

<b>Audit logging is enabled in the Office 365 environment but no logs are getting displayed?</b><br>
The user must be assigned an Office 365 E5 license. Alternatively, users with an Office 365 E1 or E3 license can be assigned an Advanced eDiscovery standalone license. Administrators and compliance officers who are assigned to cases and use Advanced eDiscovery to analyze data don't need an E5 license.<br>

<b>Audit log search argument start date should be after</b><br>
The start date should be earlier then the end date.

<b>New-PSSession: [outlook.office365.com] Connecting to remove server outlook.office365.com failed with the following error message: Access is denied.</b><br>
The password/username combination are incorrect or the user has not enough privileges to extract the audit logging.<br>
<br>
<br>
Custom script was developed by Joey Rentenaar and Korstiaan Stam from PwC Netherlands Incident Response team. <br>
#>

param(
    [string]$Action,
    [string]$User,
    [string]$IP,
    [string]$Sessions,
    [string]$Output,
    [string]$IDs,
    [string]$Inputfile,
    [datetime]$StartDate = (Get-Date).AddDays(-14),
    [datetime]$EndDate = (Get-Date),
    [ValidateRange(1, 5000)] [int]$ResultSize = 5000,
    [string]$Save,
    [string]$OutputPath = "Default",
    [string]$Encoding = "utf8bom" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
)

if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }


function Sessions {
    #$UserCredential = Get-Credential
    #$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
    #Import-PSSession $Session

    if ($User -and !$IP) {
        $Results = @()
        $MailItemRecords = (Search-UnifiedAuditLog -UserIds $User -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Where-Object { $_.Operations -eq "MailItemsAccessed" })

        foreach ($Rec in $MailItemRecords) {
            $AuditData = ConvertFrom-Json $Rec.Auditdata
            $Line = [pscustomobject]@{
                TimeStamp      = $AuditData.CreationTime
                User           = $AuditData.UserId
                Action         = $AuditData.Operation
                SessionId      = $AuditData.SessionId
                ClientIP       = $AuditData.ClientIPAddress
                OperationCount = $AuditData.OperationCount 
            }

            $Results += $Line 
        }
        $Results | sort SessionId, TimeStamp | Format-Table Timestamp, User, Action, SessionId, ClientIP, OperationCount -AutoSize 
    }

    elseif ($IP -and !$User) {
        $Results = @()
        $MailItemRecords = (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Where-Object { $_.Operations -eq "MailItemsAccessed" })

        Write-Output $IP
        foreach ($Rec in $MailItemRecords) {
            $AuditData = ConvertFrom-Json $Rec.Auditdata
            $Line = [pscustomobject]@{
                TimeStamp      = $AuditData.CreationTime
                User           = $AuditData.UserId
                Action         = $AuditData.Operation
                SessionId      = $AuditData.SessionId
                ClientIP       = $AuditData.ClientIPAddress
                OperationCount = $AuditData.OperationCount 
            }

            if ($AuditData.ClientIPAddress -eq $IP) {
                $Results += $Line 
            } 
        }

        $Results | Sort-Object SessionId, TimeStamp | Format-Table Timestamp, User, Action, SessionId, ClientIP, OperationCount -AutoSize 
    }

    elseif ($IP -and $User) {
        $Results = @()
        $MailItemRecords = (Search-UnifiedAuditLog -UserIds $User -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Where-Object { $_.Operations -eq "MailItemsAccessed" })

        foreach ($Rec in $MailItemRecords) {
            $AuditData = ConvertFrom-Json $Rec.Auditdata
            $Line = [pscustomobject]@{
                TimeStamp      = $AuditData.CreationTime
                User           = $AuditData.UserId
                Action         = $AuditData.Operation
                SessionId      = $AuditData.SessionId
                ClientIP       = $AuditData.ClientIPAddress
                OperationCount = $AuditData.OperationCount 
            }

            if ($AuditData.ClientIPAddress -eq $IP) {
                $Results += $Line 
            } 
        }

        $Results | Sort-Object SessionId, TimeStamp | Format-Table Timestamp, User, Action, SessionId, ClientIP, OperationCount -AutoSize 
    }

    else {
        $Results = @()
        $MailItemRecords = (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Where-Object { $_.Operations -eq "MailItemsAccessed" })
        foreach ($Rec in $MailItemRecords) {
            $AuditData = ConvertFrom-Json $Rec.Auditdata
            $Line = [pscustomobject]@{
                TimeStamp      = $AuditData.CreationTime
                User           = $AuditData.UserId
                Action         = $AuditData.Operation
                SessionId      = $AuditData.SessionId
                ClientIP       = $AuditData.ClientIPAddress
                OperationCount = $AuditData.OperationCount 
            }

            $Results += $Line 
        }
        $Results | Sort-Object SessionId, TimeStamp | Format-Table Timestamp, User, Action, SessionId, ClientIP, OperationCount -AutoSize 
    }
}
#Remove-PSSession -ID $Session.ID}


function MessageIDs {
    #$UserCredential = Get-Credential
    #$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
    #Import-PSSession $Session

    $Today = Get-Date -Format "MM/dd/yyyy"
    $30daysago = $(Get-Date).AddDays(-30).ToString("MM/dd/yyyy")
    $EmailFolder = "\Email_Files\"
    $SavedEmails = Join-Path $PSScriptRoot $EmailFolder

    if (!$Sessions -and !$IP) {
        $MailItemRecords = (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Where-Object { $_.Operations -eq "MailItemsAccessed" })

        foreach ($Rec in $MailItemRecords) {
            $AuditData = ConvertFrom-Json $Rec.Auditdata
            $InternetMessageId = $AuditData.Folders.FolderItems
            $TimeStamp = $AuditData.CreationTime
            $SessionId = $AuditData.SessionId
            $ClientIP = $AuditData.ClientIPAddress

            if ($SessionId) {
                Write-Output "SessionID: $SessionId"
                Write-Output "Timestamp $Timestamp"
                Write-Output "IP address: $ClientIP"
                if ($AuditData.OperationCount -gt 1) {
                    foreach ($i in $InternetMessageId) {
                        $ii = [string]$i
                        $iii = $ii.trim("@{InternetMessageId=<").trim(">}")
                        Write-Output "- $iii"

                        if ($Save) {
                            $Txtfile = "$iii" + ".txt"
                            $finalPath = $SavedEmails + $Txtfile
                            Write-Output "Saving output to: $finalPath"
                            Get-MessageTrace -StartDate $30daysago -EndDate $Today -MessageID $iii | Format-List * | Out-File -FilePath $finalPath -Encoding $Encoding 
                        } 
                    } 
                }

                else {
                    $strInternetMessageId = [string]$InternetMessageId
                    $trimInternetMessageId = $strInternetMessageId.trim("@{InternetMessageId=<").trim(">}")
                    Write-Output "- $trimInternetMessageId"
                    if ($Save) {
                        $Txtfile = "$trimInternetMessageId" + ".txt"
                        $finalPath = $SavedEmails + $Txtfile
                        Write-Output "Saving output to: $finalPath"
                        Get-MessageTrace -StartDate $30daysago -EndDate $Today -MessageID $trimInternetMessageId | Format-List * | Out-File -FilePath $finalPath -Encoding $Encoding 
                    } 
                }

                Write-Output "" 
            } 
        } 
    }

    elseif ($IP -and $Sessions) {
        $MailItemRecords = (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Where-Object { $_.Operations -eq "MailItemsAccessed" })

        foreach ($Rec in $MailItemRecords) {
            $AuditData = ConvertFrom-Json $Rec.Auditdata
            $InternetMessageId = $AuditData.Folders.FolderItems
            $TimeStamp = $AuditData.CreationTime
            $SessionId = $AuditData.SessionId

            if ($SessionId) {
                if ($Sessions.Contains($SessionId)) {
                    if ($AuditData.ClientIPAddress -eq $IP) {
                        $ClientIP = $AuditData.ClientIPAddress
                        Write-Output "SessionID: $SessionId"
                        Write-Output "Timestamp: $Timestamp"
                        Write-Output "IP address: $ClientIP"
                        if ($AuditData.OperationCount -gt 1) {
                            foreach ($i in $InternetMessageId) {
                                $ii = [string]$i
                                $iii = $ii.trim("@{InternetMessageId=<").trim(">}")
                                Write-Output "- $iii"

                                if ($Save) {
                                    $Txtfile = "$iii" + ".txt"
                                    $finalPath = $SavedEmails + $Txtfile
                                    Write-Output "Saving output to: $finalPath"
                                    Get-MessageTrace -StartDate $30daysago -EndDate $Today -MessageID $iii | Format-List * | Out-File -FilePath $finalPath -Encoding $Encoding 
                                } 
                            } 
                        }

                        else {
                            $strInternetMessageId = [string]$InternetMessageId
                            $trimInternetMessageId = $strInternetMessageId.trim("@{InternetMessageId=<").trim(">}")
                            Write-Output "- $trimInternetMessageId"
                            if ($Save) {
                                $Txtfile = "$trimInternetMessageId" + ".txt"
                                $finalPath = $SavedEmails + $Txtfile
                                Write-Output "Saving output to: $finalPath"
                                Get-MessageTrace -StartDate $30daysago -EndDate $Today -MessageID $trimInternetMessageId | Format-List * | Out-File -FilePath $finalPath -Encoding $Encoding 
                            } 
                        }
                    } Write-Output "" 
                } 
            } 
        } 
    }

    elseif ($Sessions -and !$IP) {
        $MailItemRecords = (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Where-Object { $_.Operations -eq "MailItemsAccessed" })

        foreach ($Rec in $MailItemRecords) {
            $AuditData = ConvertFrom-Json $Rec.Auditdata
            $InternetMessageId = $AuditData.Folders.FolderItems
            $TimeStamp = $AuditData.CreationTime
            $SessionId = $AuditData.SessionId

            if ($SessionId) {
                if ($Sessions.Contains($SessionId)) {
                    Write-Output "SessionID: $SessionId"
                    Write-Output "Timestamp $Timestamp"
                    if ($AuditData.OperationCount -gt 1) {
                        foreach ($i in $InternetMessageId) {
                            $ii = [string]$i
                            $iii = $ii.trim("@{InternetMessageId=<").trim(">}")
                            Write-Output "- $iii"

                            if ($Save) {
                                $Txtfile = "$iii" + ".txt"
                                $finalPath = $SavedEmails + $Txtfile
                                Write-Output "Saving output to: $finalPath"
                                Get-MessageTrace -StartDate $30daysago -EndDate $Today -MessageID $iii | Format-List * | Out-File -FilePath $finalPath -Encoding $Encoding 
                            } 
                        } 
                    }

                    else {
                        $strInternetMessageId = [string]$InternetMessageId
                        $trimInternetMessageId = $strInternetMessageId.trim("@{InternetMessageId=<").trim(">}")
                        Write-Output "- $trimInternetMessageId"

                        if ($Save) {
                            $Txtfile = "$trimInternetMessageId" + ".txt"
                            $finalPath = $SavedEmails + $Txtfile
                            Write-Output "Saving output to: $finalPath"
                            Get-MessageTrace -StartDate $30daysago -EndDate $Today -MessageID $trimInternetMessageId | Format-List * | Out-File -FilePath $finalPath -Encoding $Encoding 
                        } 
                    }
                    Write-Output "" 
                }
            } 
        } 
    }

    elseif ($IP) {
        $MailItemRecords = (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 | Where-Object { $_.Operations -eq "MailItemsAccessed" })

        foreach ($Rec in $MailItemRecords) {
            $AuditData = ConvertFrom-Json $Rec.Auditdata
            $InternetMessageId = $AuditData.Folders.FolderItems
            $TimeStamp = $AuditData.CreationTime
            $SessionId = $AuditData.SessionId
            $ClientIP = $AuditData.ClientIPAddress

            if ($SessionId) {
                if ($AuditData.ClientIPAddress -eq $IP) {
                    Write-Output "SessionID: $SessionId"
                    Write-Output "Timestamp: $Timestamp"
                    Write-Output "IP address: $ClientIP"
                    if ($AuditData.OperationCount -gt 1) {
                        foreach ($i in $InternetMessageId) {
                            $ii = [string]$i
                            $iii = $ii.trim("@{InternetMessageId=<").trim(">}")
                            Write-Output "- $iii"

                            if ($Save) {
                                $Txtfile = "$iii" + ".txt"
                                $finalPath = $SavedEmails + $Txtfile
                                Write-Output "Saving output to: $finalPath"
                                Get-MessageTrace -StartDate $30daysago -EndDate $Today -MessageID $iii | Format-List * | Out-File -FilePath $finalPath -Encoding $Encoding 
                            } 
                        } 
                    }

                    else {
                        $strInternetMessageId = [string]$InternetMessageId
                        $trimInternetMessageId = $strInternetMessageId.trim("@{InternetMessageId=<").trim(">}")
                        Write-Output "- $trimInternetMessageId"

                        if ($Save) {
                            $Txtfile = "$trimInternetMessageId" + ".txt"
                            $finalPath = $SavedEmails + $Txtfile
                            Write-Output "Saving output to: $finalPath"
                            Get-MessageTrace -StartDate $30daysago -EndDate $Today -MessageID $trimInternetMessageId | Format-List * | Out-File -FilePath $finalPath -Encoding $Encoding 
                        } 
                    }
                } Write-Output "" 
            } 
        } 
    }

    else {
        Write-Output "Unknown action" 
    }
}
#Remove-PSSession -ID $Session.ID}


function Email {
    #$UserCredential = Get-Credential
    #$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
    #Import-PSSession $Session

    $Today = Get-Date -Format "MM/dd/yyyy"
    $7days = $(Get-Date).AddDays(-7).ToString("MM/dd/yyyy")
    $EmailFolder = "\Email_Files\"
    $SavedEmails = Join-Path $PSScriptRoot $EmailFolder

    if (!(Test-Path $SavedEmails)) {
        New-Item -ItemType Directory -Force -Path $SavedEmails | Out-Null 
    }

    if ($Output -eq "Terminal" -and !$Inputfile) {
        $IDs.Split(" ") | ForEach-Object {
            $ID = $_
            Get-MessageTrace -StartDate $7days -EndDate $Today -MessageID $ID | Format-List * } 
    }

    elseif ($Output -eq "File" -and !$Inputfile) {
        $IDs.Split(" ") | ForEach-Object {
            $ID = $_
            $Txtfile = "$ID" + ".txt"
            $finalPath = $SavedEmails + $Txtfile
            Write-Output "Saving output to: $finalPath"
            Get-MessageTrace -StartDate $7days -EndDate $Today -MessageID $ID | Format-List * | Out-File -FilePath $finalPath -Encoding $Encoding } 
    }

    elseif ($Output -eq "Terminal" -and $Inputfile) {
        foreach ($line in Get-Content $Inputfile) {
            Get-MessageTrace -StartDate $7days -EndDate $Today -MessageID $line | Format-List * 
        } 
    }

    elseif ($Output -eq "File" -and $Inputfile) {
        foreach ($line in Get-Content $Inputfile) {
            $Txtfile = "$line" + ".txt"
            $finalPath = $SavedEmails + $Txtfile
            Write-Output "Saving output to: $finalPath"
            Get-MessageTrace -StartDate $7days -EndDate $Today -MessageID $line | Format-List * | Out-File -FilePath $finalPath -Encoding $Encoding 
        } 
    }
}
#Remove-PSSession -ID $Session.ID}


function Main {
    if (!$StartDate) {
        $StartDate = [datetime]::Now.ToUniversalTime().AddDays(-180) 
    }
    if (!$EndDate) {
        $EndDate = [datetime]::Now.ToUniversalTime() 
    }

    if ($Action) {
        if ($Action -eq "Sessions") {
            Sessions 
        } elseif ($Action -eq "Messages") {
            MessageIDs 
        } elseif ($Action -eq "Email") {
            Email 
        } else {
            Write-Output "Possible actions are:"
            Write-Output "Sessions  | Find SessionID(s)"
            Write-Output "Messages | Find InternetMessageID(s)"
            Write-Output "Email     | Find email metadata for the InternetMessageID(s)" 
        } 
    } else {
        $help = @"
   ___  ___      __          ___
  |   \/   |    |  |        /   \
  |  \  /  |    |  |       /  ^  \
  |  |\/|  |    |  |      /  /_\  \
  |  |  |  |  __|  |  __ /  _____  \   __
  |__|  |__| (__)__| (__)__/     \__\ (__)


The script supports three actions, you can configure the action with the -Action flag.
  1. Sessions
  2. Messages
  3. Email

.Sessions
  Identify SessionID(s) in the Unified Audit Log. You can filter based on IP address or Username.

  Example usage:
    Filter on Username and IP address
    .\MIA.ps1 -Action Sessions -User johndoe@acme.onmicrosoft.com -IP 1.1.1.1
    Filter on IP address
    .\MIA.ps1 -Action Sessions -IP 1.1.1.1

    Show all Sessions available in the Audit Log
    .\MIA.ps1 -Action Sessions

.Messages
  Identify InternetMessageID(s) in the Unified Audit Log. You can filter on SessionID(s) or IP addresses.

  Example usage:
    Filter on SessionID(s)
    .\MIA.ps1 -Action Messages -Sessions 19ebe2eb-a557-4c49-a21e-f2936ccdbc46,ad2dd8dc-507b-49dc-8dd5-7a4f4c113eb4

    Filter on SessionID(s) and IP address
    .\MIA.ps1 -Action Messages -Sessions 19ebe2eb-a557-4c49-a21e-f2936ccdbc46,ad2dd8dc-507b-49dc-8dd5-7a4f4c113eb4 -IP 1.1.1.1

    Show all IntenetMessageID(s) available in the Unified Audit Log
    .\MIA.ps1 -Action Messages

    Show all InternetMessageID(s) available in the Unified Audit Log and save the InternetMessageID(s) to .txt files
    .\MIA.ps1 -Action Messages -Save yes

.Email
  Identify email metadata belonging to the InternetMessageID(s) and save them to a file or print them to the terminal.

  Example usage:
    Identify all emails belonging to the InternetMessageID(s) based on the input file and print them to the terminal
    .\MIA.ps1 -Action Email -Output Terminal -Input "C:\Users\test\Desktop\messageids.txt"

    Identify all emails belonging to the MessageID(s) based on the input file and save the output as a file
    .\MIA.ps1 -Action Email -Output File -Input "C:\Users\test\Desktop\messageids.txt"

    Identify all emails belonging to the MessageID(s) provided in the terminal and print email metadata to the terminal, multiple IDs can be provided as comma separated values
    .\MIA.ps1 -Action Email -Output Terminal -IDs VI1PR01MB657547855449E4F22E7C2804B6E50@VI1PR01MB6575.eurprd01.prod.exchangelabs.com

Custom script was developed by Joey Rentenaar and Korstiaan Stam from PwC Netherlands Incident Response team.

"@
        $help 
    } 
}

Main

exit
