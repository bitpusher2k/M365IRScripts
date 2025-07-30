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
# v3.1 last updated 2025-07-26
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
# powershell -executionpolicy bypass -f .\Search-UnifiedAuditLogSignIn.ps1 -OutputPath "Default" -UserIds "All" -DaysAgo "10"
#
# powershell -executionpolicy bypass -f .\Search-UnifiedAuditLogSignIn.ps1 -OutputPath "Default" -UserIds "All" -StartDate "2025-07-12" -EndDate "2025-07-20"
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
    [string]$OutputPath = "Default",
    [datetime]$StartDate,
    [datetime]$EndDate,
    [int]$DaysAgo,
    [string]$UserIds,
    [switch]$fail = $false, # if -fail parameter only show failed logins
    [string]$scriptName = "Search-UnifiedAuditLogSignIn",
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
    [string]$Encoding = "utf8bom" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
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
# $PrimaryDomain = Get-AcceptedDomain | Where-Object Default -eq $true
# $DomainName = $PrimaryDomain.DomainName
$PrimaryDomain = Get-MgDomain | Where-Object { $_.isdefault -eq $True } | Select-Object -Property ID
if ($PrimaryDomain) {
    $DomainName = $PrimaryDomain.ID
} else {
    $DomainName = "DefaultOutput"
}

$CheckSubDir = Get-Item $OutputPath\$DomainName -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
    Write-Output ""
    Write-Output "Domain sub-directory does not exist. Sub-directory `"$DomainName`" will be created." | Tee-Object -FilePath $logFilePath -Append
    mkdir $OutputPath\$DomainName
}

Write-Output "Script started. Version = $version`n"
Write-Output "Script to display interactive user logins from Unified Audit log `n"

## Get valid starting end ending dates
if (!$DaysAgo -and (!$StartDate -or !$EndDate)) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to retrieve sign-in UAL entries (default: 10, maximum: 180)'
    if ($DaysAgo -eq '') { $DaysAgo = "10" } elseif ($DaysAgo -gt 180) { $DaysAgo = "180" }
}

if ($DaysAgo) {
    if ($DaysAgo -gt 180) { $DaysAgo = "180" }
    Write-Output "`nScript will search UAC $DaysAgo days back from today for relevant events."
    $StartDate = (Get-Date).touniversaltime().AddDays(-$DaysAgo)
    $EndDate = (Get-Date).touniversaltime()
    Write-Output "StartDate: $StartDate (UTC)"
    Write-Output "EndDate: $EndDate (UTC)"
} elseif ($StartDate -and $EndDate) {
    $StartDate = ($StartDate).touniversaltime()
    $EndDate = ($EndDate).touniversaltime()
    if ($StartDate -lt (Get-Date).touniversaltime().AddDays(-180)) { $StartDate = (Get-Date).touniversaltime().AddDays(-180) }
    if ($StartDate -ge $EndDate) { $EndDate = ($StartDate).AddDays(1) }
    Write-Output "`nScript will search UAC between StartDate and EndDate for relevant events."
    Write-Output "StartDate: $StartDate (UTC)"
    Write-Output "EndDate: $EndDate (UTC)"
} else {
    Write-Output "Neither DaysAgo nor StartDate/EndDate specified. Ending."
    exit
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

if (!$UserIds) {
    $UserIds = Read-Host "`nEnter the user's primary email address (UPN) - leave blank to retrieve authentication entries for all users, comma-separate multiple users"
}

if ($UserIds) {
    $OutputUser = $UserIds
} else {
    $OutputUser = "ALL"
}
$OutputCSVraw = "$OutputPath\$DomainName\UnifiedAuditLogSignIns_$($OutputUser.Replace(',','-'))_between_$($StartDate.ToString(`"yyyyMMddHHmm`"))_and_$($EndDate.ToString(`"yyyyMMddHHmm`"))_$($totalDays)_days.csv"
$OutputCSV = "$OutputPath\$DomainName\UnifiedAuditLogSignIns_$($OutputUser.Replace(',','-'))_between_$($StartDate.ToString(`"yyyyMMddHHmm`"))_and_$($EndDate.ToString(`"yyyyMMddHHmm`"))_$($totalDays)_days_Processed.csv"
Write-Output "`nWill search for records related to: $UserIds user(s)"

# Search the defined date(s), SessionId + SessionCommand in combination with the loop will return and append 5000 object per iteration until all objects are returned (minimum limit is 50k objects)
Write-Output "`nTotal range of days to check for sign-ins: $totalDays"

$count = 1
do {
    Write-Output "Getting unified audit logs page $count - Please wait"
    try {
        if ($UserIds -eq "ALL") {
            Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -recordtype $recordtype -operations $operation -SessionId $sesid -SessionCommand ReturnLargeSet -resultsize $resultSize"
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -recordtype $recordtype -operations $operation -SessionId $sesid -SessionCommand ReturnLargeSet -resultsize $resultSize
        } elseif ($UserIds) {
            Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $UserIds -recordtype $recordtype -operations $operation -SessionId $sesid -SessionCommand ReturnLargeSet -resultsize $resultSize"
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $UserIds -recordtype $recordtype -operations $operation -SessionId $sesid -SessionCommand ReturnLargeSet -resultsize $resultSize
        } else {
            Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -recordtype $recordtype -operations $operation -SessionId $sesid -SessionCommand ReturnLargeSet -resultsize $resultSize"
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
$AuditOutput | Export-Csv -Path $OutputCSVraw -NoTypeInformation -Encoding $Encoding
$ConvertedOutput = $AuditOutput | Select-Object -ExpandProperty AuditData | Sort-Object creationtime | ConvertFrom-Json

foreach ($Entry in $convertedoutput) { # Loop through all result entries
    $return = "" | Select-Object Creationtime, Localtime, ClientIP, Operation, UserId, ResultStatusDetail, KeepMeSignedIn, UserAgent, UserAuthenticationMethod, RequestType, DisplayName, OS, BrowserType, TrustType, IsCompliant, IsCompliantAndManaged, SessionId
    $return.CreationTime = $Entry.CreationTime
    $return.localtime = [System.TimeZoneInfo]::ConvertTimeFromUtc($Entry.CreationTime, $TZ) # Convert entry to local time
    if ($Entry.clientip -ne $null) { $return.clientip = $Entry.clientip } else { $return.clientip = "Unavailable" }
    if ($Entry.Operation -ne $null) { $return.Operation = $Entry.Operation } else { $return.Operation = "Unavailable" }
    if ($Entry.UserId -ne $null) { $return.UserId = $Entry.UserId } else { $return.UserId = "Unavailable" }
    if ($Entry.ExtendedProperties -and $($Entry.ExtendedProperties.GetEnumerator() | Where-Object {$_.Name -eq "ResultStatusDetail"}).value -ne $null) { $return.ResultStatusDetail = ($Entry.ExtendedProperties.GetEnumerator() | Where-Object {$_.Name -eq "ResultStatusDetail"}).value } else { $return.ResultStatusDetail = "Unavailable" }
    if ($Entry.ExtendedProperties -and $($Entry.ExtendedProperties.GetEnumerator() | Where-Object {$_.Name -eq "KeepMeSignedIn"}).value -ne $null) { $return.KeepMeSignedIn = ($Entry.ExtendedProperties.GetEnumerator() | Where-Object {$_.Name -eq "KeepMeSignedIn"}).value } else { $return.KeepMeSignedIn = "Unavailable" }
    if ($Entry.ExtendedProperties -and $($Entry.ExtendedProperties.GetEnumerator() | Where-Object {$_.Name -eq "UserAgent"}).value -ne $null) { $return.UserAgent = ($Entry.ExtendedProperties.GetEnumerator() | Where-Object {$_.Name -eq "UserAgent"}).value } else { $return.UserAgent = "Unavailable" }
    if ($Entry.ExtendedProperties -and $($Entry.ExtendedProperties.GetEnumerator() | Where-Object {$_.Name -eq "UserAuthenticationMethod"}).value -ne $null) { $return.UserAuthenticationMethod = ($Entry.ExtendedProperties.GetEnumerator() | Where-Object {$_.Name -eq "UserAuthenticationMethod"}).value } else { $return.UserAuthenticationMethod = "Unavailable" }
    if ($Entry.ExtendedProperties -and $($Entry.ExtendedProperties.GetEnumerator() | Where-Object {$_.Name -eq "RequestType"}).value -ne $null) { $return.RequestType = ($Entry.ExtendedProperties.GetEnumerator() | Where-Object {$_.Name -eq "RequestType"}).value } else { $return.RequestType = "Unavailable" }
    if ($Entry.DeviceProperties -and $($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "DisplayName"}).value -ne $null) { $return.DisplayName = ($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "DisplayName"}).value } else { $return.DisplayName = "Unavailable" }
    if ($Entry.DeviceProperties -and $($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "OS"}).value -ne $null) { $return.OS = ($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "OS"}).value } else { $return.OS = "Unavailable" }
    if ($Entry.DeviceProperties -and $($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "BrowserType"}).value -ne $null) { $return.BrowserType = ($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "BrowserType"}).value } else { $return.BrowserType = "Unavailable" }
    if ($Entry.DeviceProperties -and $($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "TrustType"}).value -ne $null) { $return.TrustType = ($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "TrustType"}).value } else { $return.TrustType = "Unavailable" }
    if ($Entry.DeviceProperties -and $($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "IsCompliant"}).value -ne $null) { $return.IsCompliant = ($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "IsCompliant"}).value } else { $return.IsCompliant = "Unavailable" }
    if ($Entry.DeviceProperties -and $($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "IsCompliantAndManaged"}).value -ne $null) { $return.IsCompliantAndManaged = ($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "IsCompliantAndManaged"}).value } else { $return.IsCompliantAndManaged = "Unavailable" }
    if ($Entry.DeviceProperties -and $($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "SessionId"}).value -ne $null) { $return.SessionId = ($Entry.DeviceProperties.GetEnumerator() | Where-Object {$_.Name -eq "SessionId"}).value } else { $return.SessionId = "Unavailable" }
    $Results += $return # Build results array
}

$displays = $results | Sort-Object -Descending localtime # Sort result array in reverse chronological order
$displays | Select-Object CreationTime, LocalTime, ClientIP, Operation, UserId, ResultStatusDetail, KeepMeSignedIn, UserAgent, UserAuthenticationMethod, RequestType, DisplayName, OS, BrowserType, TrustType, IsCompliant, IsCompliantAndManaged, SessionId | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding $Encoding

# Un-comment for console output of results
# Write-Output "Local Time`t`t Client IP`t`t Operation`t`t Login" # Merely an indication of the headings
# Write-Output "----------`t`t ---------`t`t ---------`t`t -----" # Not possible to align for every run option
# foreach ($display in $displays) {
#     if (($display.clientip).length -lt 14) {
#         # Determine total length of first field
#         $gap = "`t`t" # If a shorter field add two tabs in output
#     } else {
#         $gap = "`t"
#     }
#     if ($display.Operation -eq "userloginfailed") {
#         # Report failed logins
#         Write-Output "$($display.localtime) `t $($display.clientip) $gap $($display.Operation) `t $($display.UserId)"
#     } elseif (-not $fail) {
#         # Report successful logins in
#         Write-Output "$($display.localtime) `t $($display.clientip) $gap $($display.Operation) `t`t $($display.UserId)"
#     }
# }

Write-Output "$($displays.count) relevant sign-in records found."
Write-Output "`nScript Completed`n"

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:" | Tee-Object -FilePath $logFilePath -Append
    Write-Output $OutputCSV | Tee-Object -FilePath $logFilePath -Append
    # $Prompt = New-Object -ComObject wscript.shell
    # $UserInput = $Prompt.popup("Do you want to open output file?", 0, "Open Output File", 4)
    # if ($UserInput -eq 6) {
    #     Invoke-Item "$OutputCSV"
    # }
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append
Write-Output "`nDone! Check output path for results. If results are empty check that Unified Audit Logging is enabled on the tenant." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"

Exit
