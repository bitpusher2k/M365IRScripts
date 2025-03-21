#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Search-UnifiedAuditLogSignIn.ps1
# Original script created by https://github.com/directorcia @directorcia
# Modified and updated by Bitpusher/The Digital Fox
# v2.8 last updated 2024-05-03
# Script to search the Unified Audit Logs (UAC) for
# sign-ins made by a specified user or all users.
#
# Note that UAC entries may take hours to appear.
#
# The advantage to searching UAC for sign-in information
# is that while Entra ID sign-in logs are retained
# for a maximum of 30 days, UAC goes back 180 days.
# (https://learn.microsoft.com/en-us/purview/audit-log-retention-policies)
# Disadvantage is less verbose information and no record
# of non-interactive sign-ins.
#
# Usage:
# powershell -executionpolicy bypass -f .\Search-UnifiedAuditLogSignIn.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
#
# Office 365 Management Activity API schema - UserAuthenticationMethod
# 
#comp #m365 #security #bec #script #unified #audit #log #sign-in

# CIAOPS
# Script provided as is. Use at own risk. No guarantees or warranty provided.
# Description - Report on user logins from Office 365 Unified Audit logs
# Notes:
# 1. That the Office 365 Unified audit log are NOT immediate. Information may take a while to actually end up in there.
# 2. That the unified logs generally only record 'interactive' logins not app token refresh. This may explain why you see more login entries in Azure AD Signs reports
# Original source - https://github.com/directorcia/Office365/blob/master/o365-login-audit.ps1
# More scripts available by joining http://www.ciaopspatron.com

#Requires -Version 5.1

param(
    [string]$OutputPath,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [int]$DaysAgo,
    [switch]$fail = $false, # if -fail parameter only show failed logins
    [string]$Encoding = "utf8bom" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
)

if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }

$date = Get-Date -Format "yyyyMMddHHmmss"
$version = "2.8"
$resultSize = 5000 #Maximum number of records that can be retrieved per query
$sesid = Get-Random # Get random session number
$Results = @() # initialise array
$displays = @() # initailise array
$AuditOutput = @() # initialise array
$currentoutput = @() # initialise array
$strCurrentTimeZone = (Get-CimInstance win32_timezone).StandardName # determine current local timezone
$TZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($strCurrentTimeZone) # for Timezone calculations
# Valid record types =
# AzureActiveDirectory, AzureActiveDirectoryAccountLogon,AzureActiveDirectoryStsLogon, ComplianceDLPExchange
# ComplianceDLPSharePoint, CRM, DataCenterSecurityCmdlet, Discovery, ExchangeAdmin, ExchangeAggregatedOperation
# ExchangeItem, ExchangeItemGroup, MicrosoftTeams, MicrosoftTeamsAddOns, MicrosoftTeamsSettingsOperation, OneDrive
# PowerBIAudit, SecurityComplianceCenterEOPCmdlet, SharePoint, SharePointFileOperation, SharePointSharingOperation
# SkypeForBusinessCmdlets, SkypeForBusinessPSTNUsage, SkypeForBusinessUsersBlocked, Sway, ThreatIntelligence, Yammer
$recordtype = "azureactivedirectorystslogon"

# Office 365 Management Activity API schema
# Valid record types = https://docs.microsoft.com/en-us/office365/securitycompliance/search-the-audit-log-in-security-and-compliance?redirectSourcePath=%252farticle%252f0d4d0f35-390b-4518-800e-0c7ec95e946c#audited-activities
# Operation types = "<value1>","<value2>","<value3>"
$operation = "userloginfailed", "userloggedin" # use this line to report failed and successful logins
# $operation = "userloginfailed" # use this line to report just failed logins
# $operation = "userloggedin" # use this line to report just successful logins

# If OutputPath variable is not defined, prompt for it
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

# If OutputPath does not exist, create it
$CheckOutputPath = Get-Item $OutputPath -ErrorAction SilentlyContinue
if (!$CheckOutputPath) {
    Write-Output ""
    Write-Output "Output path does not exist. Directory will be created."
    mkdir $OutputPath
}

# Get Primary Domain Name for output subfolder
$PrimaryDomain = Get-AcceptedDomain | Where-Object Default -EQ $true
$DomainName = $PrimaryDomain.DomainName

$CheckSubDir = Get-Item $OutputPath\$DomainName -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
    Write-Output ""
    Write-Output "Domain sub-directory does not exist. Sub-directory `"$DomainName`" will be created."
    mkdir $OutputPath\$DomainName
}

Write-Output "Script started. Version = $version`n"
Write-Output "Script to display interactive user logins from Unified Audit log `n"

if (!$DaysAgo -and (!$StartDate -and !$EndDate)) {
    do {
        $NumberDays = Read-Host -Prompt "`nEnter total number of days back from today to search log (maximum: 180)" # Prompt for number of days to check
    } until ((-not [string]::IsNullOrEmpty($NumberDays)) -and ($NumberDays -match "^\d+$")) # Keep prompting until not blank and numeric
    Write-Output ""
    $NumberDaysInt = [int]$NumberDays
    $DaysAgo = $NumberDaysInt
    if ($DaysAgo -gt 180) {
        $DaysAgo = 180
    }
    $StartDateLocal = (Get-Date).adddays(-$DaysAgo)
    $StartDate = $StartDateLocal.touniversaltime() # Convert local start time to UTC
    $EndDate = (Get-Date).touniversaltime() # Ending date for audit log search UTC. Default = current time
} elseif ($StartDate -and $EndDate) {
    Write-Output "Starting and ending date specified - will search for sign-ins between $StartDate and $EndDate"
    [datetime]$Start = [datetime]$StartDate
    [datetime]$End = [datetime]$EndDate
    $StartDate = $Start.touniversaltime() # Convert local start time to UTC
    $EndDate = $End.touniversaltime() # Convert local end time to UTC
    if ($StartDate -lt (Get-Date).adddays(-180)) {
        Write-Output "Starting date is more than 180 days ago, and outside the range of UAL records. Please try again with a start date within 180 days ago. Ending."
        exit
    }
    Write-Output "This is between $StartDate and $EndDate UTC..."
} elseif ($DaysAgo) {
    if ($DaysAgo -gt "180") { $DaysAgo = "180" }
    $NumberDaysInt = [int]::Parse($DaysAgo) # Convert string to integer
    $StartDateLocal = (Get-Date).adddays(- $NumberDaysInt)
    $StartDate = $StartDateLocal.touniversaltime() # Convert local start time to UTC
    $EndDate = (Get-Date).touniversaltime() # Ending date for audit log search UTC. Default = current time
}

$date = Get-Date -Format "yyyyMMddHHmmss"
$diff = New-TimeSpan -Start $StartDate -End $EndDate # Determine the difference between start and finish dates
$totalDays = ([int]$diff.TotalDays)

if ((Get-Module -ListAvailable -Name ExchangeOnlineManagement) -or (Get-Module -ListAvailable -Name msonline)) {
    # Has the Exchange Online PowerShell module been loaded?
    Write-Output "`nExchange Online PowerShell found"
} else {
    # If Exchange Online PowerShell module not found
    Write-Output "`n[001] - Exchange Online PowerShell module not installed. Please install and re-run script`n"
    Write-Output "Exception message:", $_.Exception.Message, "`n"
    exit 1 # Terminate script
}

# Search the defined date(s), SessionId + SessionCommand in combination with the loop will return and append 5000 object per iteration until all objects are returned (minimum limit is 50k objects)
$User = Read-Host "`nEnter the user's primary email address (UPN) - leave blank to retrieve authentication entries for all users, comma-separate multiple users"

if ($User) {
    $OutputUser = $User
} else {
    $OutputUser = "ALL"
}
$OutputCSV = "$OutputPath\$DomainName\UnifiedAuditLogSignIns_$($OutputUser)_between_$($StartDate.ToString(`"yyyyMMddHHmm`"))_and_$($EndDate.ToString(`"yyyyMMddHHmm`"))_$($totalDays)_days_Processed.csv"

Write-Output "`nTotal range of days to check for sign-ins: $totalDays"
Write-Output "Start date: $StartDate"
Write-Output "End date: $EndDate"
Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $User -recordtype $recordtype -operations $operation -SessionId $sesid -SessionCommand ReturnLargeSet -resultsize $resultSize"

$count = 1
do {
    Write-Output "Getting unified audit logs page $count - Please wait"
    try {
        if ($User) {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $User -recordtype $recordtype -operations $operation -SessionId $sesid -SessionCommand ReturnLargeSet -resultsize $resultSize
        } else {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -recordtype $recordtype -operations $operation -SessionId $sesid -SessionCommand ReturnLargeSet -resultsize $resultSize
        }
    } catch {
        Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n"
        Write-Output "Exception message:", $_.Exception.Message, "`n"
        exit 2 # Terminate script
    }
    $AuditOutput += $currentoutput # Build total results array
    ++ $count # Increment page count
} until ($currentoutput.count -eq 0) # Until there are no more logs in range to get

# Select and expand the nested object (AuditData) as it holds relevant reporting data. Convert output format from default JSON to enable export to CSV
$ConvertedOutput = $AuditOutput | Select-Object -ExpandProperty AuditData | Sort-Object creationtime | ConvertFrom-Json

foreach ($Entry in $convertedoutput) { # Loop through all result entries
    $return = "" | Select-Object Creationtime, Localtime, ClientIP, Operation, UserId, ResultStatusDetail, KeepMeSignedIn, UserAgent, UserAuthenticationMethod, RequestType, DisplayName, OS, BrowserType, TrustType, IsCompliant, IsCompliantAndManaged, SessionId
    $return.CreationTime = $Entry.CreationTime
    $return.localtime = [System.TimeZoneInfo]::ConvertTimeFromUtc($Entry.CreationTime, $TZ) # Convert entry to local time
    $return.clientip = $Entry.clientip
    $return.Operation = $Entry.Operation
    $return.UserId = $Entry.UserId
    $return.ResultStatusDetail = ($Entry.ExtendedProperties.GetEnumerator() | Where-Object {$_.Name -eq "ResultStatusDetail"}).value
    $return.KeepMeSignedIn = ($Entry.ExtendedProperties.GetEnumerator() | Where-Object {$_.Name -eq "KeepMeSignedIn"}).value
    $return.UserAgent = ($Entry.ExtendedProperties.GetEnumerator() | Where-Object {$_.Name -eq "UserAgent"}).value
    $return.UserAuthenticationMethod = ($Entry.ExtendedProperties.GetEnumerator() | Where-Object {$_.Name -eq "UserAuthenticationMethod"}).value
    $return.RequestType = ($Entry.ExtendedProperties.GetEnumerator() | Where-Object {$_.Name -eq "RequestType"}).value
    $return.DisplayName = ($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "DisplayName"}).value
    $return.OS = ($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "OS"}).value
    $return.BrowserType = ($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "BrowserType"}).value
    $return.TrustType = ($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "TrustType"}).value
    $return.IsCompliant = ($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "IsCompliant"}).value
    $return.IsCompliantAndManaged = ($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "IsCompliantAndManaged"}).value
    $return.SessionId = ($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "SessionId"}).value
    $Results += $return # Build results array
}

$displays = $results | Sort-Object -Descending localtime # Sort result array in reverse chronological order
Write-Output "$($displays.count) relevant sign-in records fount. Writing all output to file..."
$displays | Select-Object CreationTime, LocalTime, ClientIP, Operation, UserId, ResultStatusDetail, KeepMeSignedIn, UserAgent, UserAuthenticationMethod, RequestType, DisplayName, OS, BrowserType, TrustType, IsCompliant, IsCompliantAndManaged, SessionId | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding $Encoding
Write-Output ""
Write-Output "Local Time`t`t Client IP`t`t Operation`t`t Login" # Merely an indication of the headings
Write-Output "----------`t`t ---------`t`t ---------`t`t -----" # Not possible to align for every run option
foreach ($display in $displays) {
    if (($display.clientip).length -lt 14) {
        # Determine total length of first field
        $gap = "`t`t" # If a shorter field add two tabs in output
    } else {
        $gap = "`t"
    }
    if ($display.Operation -eq "userloginfailed") {
        # Report failed logins
        Write-Output "$($display.localtime) `t $($display.clientip) $gap $($display.Operation) `t $($display.UserId)"
    } elseif (-not $fail) {
        # Report successful logins in
        Write-Output "$($display.localtime) `t $($display.clientip) $gap $($display.Operation) `t`t $($display.UserId)"
    }
}

Write-Output "`nScript Completed`n"

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:"
    Write-Output $OutputCSV
    $Prompt = New-Object -ComObject wscript.shell
    $UserInput = $Prompt.popup("Do you want to open output file?", 0, "Open Output File", 4)
    if ($UserInput -eq 6) {
        Invoke-Item "$OutputCSV"
    }
}

Write-Output "`nDone! Check output path for results. If results are empty check that Unified Audit Logging is enabled on the tenant."
Invoke-Item "$OutputPath\$DomainName"
