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
# v3.1 last updated 2025-07-26
# Script to search the UAC for several sets of events particularly
# relevant to incident response across all users.
#
# Usage:
# powershell -executionpolicy bypass -f .\Search-UnifiedAuditLogIR.ps1 -OutputPath "Default" -DaysAgo "10"
#
# powershell -executionpolicy bypass -f .\Search-UnifiedAuditLogIR.ps1 -OutputPath "Default" -StartDate "2025-07-12" -EndDate "2025-07-20"
#
# powershell -executionpolicy bypass -f .\Search-UnifiedAuditLogIR.ps1 -OutputPath "Default" -StartDate "2025-07-12" -EndDate "2025-07-20" -Types "Role","App","CAP"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
#
#comp #m365 #security #bec #script #unified #audit #log #ir

#Requires -Version 5.1

param(
    [string]$OutputPath = "Default",
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string[]]$Types = @("ALL"), # What record types to search for. Can be: Role, App, CAP, Domain, Partner, User, Pass, Update, Device, ExAdmin, Anon, Perm, EmDel, FileMod, FileDel, Ext, or ALL (default)
    [string]$scriptName = "Search-UnifiedAuditLogIR",
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
    [string]$Encoding = "utf8NoBOM" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
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


# Initial variables
$resultSize = 5000 #Maximum number of records that can be retrieved per query
$date = Get-Date -Format "yyyyMMddHHmmss"

$CheckLog = (Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled
if (!$CheckLog) {
    Write-Output "The Unified Audit Log does not appear to be enabled on this tenant. Export of UAL activities may fail. Try running 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true' if export fails."
}

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

Write-Output ""
Write-Output "Script will search the UAC for entries often relevant to incident investigation & response."
Write-Output "Reports of events in each of these categories will be created (in order) if associated events are found:"
Write-Output " * Role    - Entra ID Role Changes"
Write-Output " * App     - Entra ID Application Changes"
Write-Output " * CAP     - Conditional Access Policy Changes"
Write-Output " * Domain  - Entra ID Domain Changes (Add/Remove, Federation, etc.)"
Write-Output " * Partner - Partner Management Changes"
Write-Output " * User    - Users Added or Deleted"
Write-Output " * Pass    - Password Resets and Changes"
Write-Output " * Update  - Update User Events (MFA reg & Security Info changes)"
Write-Output " * Device  - Devices Added Or Deleted"
Write-Output " * ExAdmin - Exchange Admin Events (Inbox Rules, Mailbox Forwarding, Mailbox Permissions)"
Write-Output " * Anon    - Anonymous Link Events"
Write-Output " * Perm    - Mailbox Permission Events"
Write-Output " * EmDel   - Email Deletion Events"
Write-Output " * FileMod - File Created or Modified"
Write-Output " * FileDel - File Deleted"
Write-Output " * Ext     - External User Events"
Write-Output "`n * ALL     - All of the above."
Write-Output "`nWill generate reports this run on: $Types." | Tee-Object -FilePath $logFilePath -Append

## Get valid starting end ending dates
if (!$DaysAgo -and (!$StartDate -or !$EndDate)) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to retrieve relevant UAL entries (default: 10, maximum: 180)'
    if ($DaysAgo -eq '') { $DaysAgo = "10" } elseif ($DaysAgo -gt 180) { $DaysAgo = "180" }
}

if ($DaysAgo) {
    if ($DaysAgo -gt 180) { $DaysAgo = "180" }
    Write-Output "`nScript will search UAC $DaysAgo days back from today for relevant events." | Tee-Object -FilePath $logFilePath -Append
    $StartDate = (Get-Date).touniversaltime().AddDays(-$DaysAgo)
    $EndDate = (Get-Date).touniversaltime()
    Write-Output "StartDate: $StartDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "EndDate: $EndDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
} elseif ($StartDate -and $EndDate) {
    $StartDate = ($StartDate).touniversaltime()
    $EndDate = ($EndDate).touniversaltime()
    if ($StartDate -lt (Get-Date).touniversaltime().AddDays(-180)) { $StartDate = (Get-Date).touniversaltime().AddDays(-180) }
    if ($StartDate -ge $EndDate) { $EndDate = ($StartDate).AddDays(1) }
    Write-Output "`nScript will search UAC between StartDate and EndDate for relevant events." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "StartDate: $StartDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "EndDate: $EndDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "Neither DaysAgo nor StartDate/EndDate specified. Ending." | Tee-Object -FilePath $logFilePath -Append
    exit
}


## Get changes to membership in Entra ID roles (new adds could indicate escalation of privilege)
if ($Types -contains "Role" -or $Types -contains "ALL") {
    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations (`"Add member to role.`",`"Remove member from role.`") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $currentOutput = ""
    $SearchResults = @()
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
        try {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add member to role.","Remove member from role.") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
            exit 2 # Terminate script
        }
        $SearchResults += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    if (!$SearchResults) {
        Write-Output ""
        Write-Output "There are no events matching Entra ID role changes for the time period specified" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    } else {
        ## Output the events to CSV
        $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_EntraIDRoleChanges_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        Write-Output ""
        Write-Output "See Entra ID Roles Changes events in the output path" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    }
}

## Get changes to applications, client app credentials, permissions, and new consents (could indicate app abuse)
if ($Types -contains "App" -or $Types -contains "ALL") {
    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations (`"Add application.`",`"Add service principal.`",`"Add service principal credentials.`",`"Update application – Certificates and secrets.`",`"Add app role assignment to service principal.`",`"Add app role assignment grant to user.`",`"Add delegated permission grant.`",`"Consent to application.`",`"ConsentModificationRequest`") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $currentOutput = ""
    $SearchResults = @()
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
        try {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add application.","Add service principal.","Add service principal credentials.","Update application – Certificates and secrets.","Add app role assignment to service principal.","Add app role assignment grant to user.","Add delegated permission grant.","Consent to application.","ConsentModificationRequest") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
            exit 2 # Terminate script
        }
        $SearchResults += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    if (!$SearchResults) {
        Write-Output "There are no events matching Entra ID app changes for the time period specified" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    } else {
        ## Output the events to CSV
        $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_EntraIDAppChanges_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        Write-Output "See Entra ID application events in the output path" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    }
}

## Get Conditional Access policy changes
if ($Types -contains "CAP" -or $Types -contains "ALL") {
    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations (`"Add policy.`",`"Update policy.`",`"Delete policy.`") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $currentOutput = ""
    $SearchResults = @()
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
        try {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add policy.","Update policy.","Delete policy.") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
            exit 2 # Terminate script
        }
        $SearchResults += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    if (!$SearchResults) {
        Write-Output "There are no Conditional Access events for the time period specified" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    } else {
        ## Output the events to CSV
        $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_ConditionalAccessPolicyChanges_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        Write-Output "See Conditional Access Policy events in the output path" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    }
}

## Get Domain changes
if ($Types -contains "Domain" -or $Types -contains "ALL") {
    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations (`"Add domain to company.`",`"Remove domain from company.`",`"Set domain authentication.`",`"Set federation settings on domain.`",`"Set DirSyncEnabled flag.`",`"Update domain.`",`"Verify domain.`",`"Verify email verified domain.`") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $currentOutput = ""
    $SearchResults = @()
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait"
        try {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add domain to company.","Remove domain from company.","Set domain authentication.","Set federation settings on domain.","Set DirSyncEnabled flag.","Update domain.","Verify domain.","Verify email verified domain.") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
            exit 2 # Terminate script
        }
        $SearchResults += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    if (!$SearchResults) {
        Write-Output "There are no Domain Management events for the time period specified" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    } else {
        ## Output the events to CSV
        $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_EntraIDDomainChanges_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        Write-Output "See Domain Management events in the output path" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    }
}

## Get Partner changes
if ($Types -contains "Partner" -or $Types -contains "ALL") {
    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations (`"Add partner to company.`",`"Remove partner from company.`") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $currentOutput = ""
    $SearchResults = @()
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
        try {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add partner to company.","Remove partner from company.") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
            exit 2 # Terminate script
        }
        $SearchResults += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    if (!$SearchResults) {
        Write-Output "There are no Partner management events for the time period specified" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    } else {
        ## Output the events to CSV
        $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_PartnerManagementChanges_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        Write-Output "See Partner Management events in the output path" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    }
}

## Get user add and delete events
if ($Types -contains "User" -or $Types -contains "ALL") {
    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations (`"Add user.`",`"Delete user.`") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $currentOutput = ""
    $SearchResults = @()
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
        try {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add user.","Delete user.") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
            exit 2 # Terminate script
        }
        $SearchResults += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    if (!$SearchResults) {
        Write-Output "There are no Users Added events for the time period specified" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    } else {
        ## Output the events to CSV
        $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_UsersAddedOrDeleted_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        Write-Output "See events matching 'Add user' and 'Delete user' in the output path" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    }
}

## Get password changes
if ($Types -contains "Pass" -or $Types -contains "ALL") {
    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations (`"Change user password.`",`"Reset user password.`",`"Set force change user password.`") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $currentOutput = ""
    $SearchResults = @()
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
        try {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Change user password.","Reset user password.","Set force change user password.") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
            exit 2 # Terminate script
        }
        $SearchResults += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    if (!$SearchResults) {
        Write-Output "There are no Password events for the time period specified" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    } else {
        ## Output the events to CSV
        $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_PasswordResetsAndChanges_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        Write-Output "See password events in the output path" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    }
}

## Get user update events (this includes MFA registration / security info changes)
if ($Types -contains "Update" -or $Types -contains "ALL") {
    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations (`"Update user.`") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $currentOutput = ""
    $SearchResults = @()
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
        try {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Update user.") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
            exit 2 # Terminate script
        }
        $SearchResults += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    if (!$SearchResults) {
        Write-Output "There are no events matching 'Update user' for the time period specified" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    } else {
        ## Output the events to CSV
        $SearchResults | Export-Csv "$OutputPath\$DomainName\AuditLog_UpdateUser_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        Write-Output "See events matching 'Update user' in the output path (this includes MFA method updates)" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    }
}

## Get Entra ID Device add and delete events
if ($Types -contains "Device" -or $Types -contains "ALL") {
    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations (`"Add device.`",`"Delete device.`") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $currentOutput = ""
    $SearchResults = @()
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
        try {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add device.","Delete device.") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
            exit 2 # Terminate script
        }
        $SearchResults += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    if (!$SearchResults) {
        Write-Output "There are no events matching 'Add device' or 'Delete device' for the time period specified" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    } else {
        ## Output the events to CSV
        $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_DevicesAddedOrDeleted_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        Write-Output "See events matching 'Add device' or 'Delete device' in the output path" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    }
}

## Get Exchange admin log events (includes new inbox rules, mailbox forwarding, mailbox permissions, mailbox delegations, etc.)
if ($Types -contains "ExAdmin" -or $Types -contains "ALL") {
    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType ExchangeAdmin -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $currentOutput = ""
    $SearchResults = @()
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
        try {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType ExchangeAdmin -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
            exit 2 # Terminate script
        }
        $SearchResults += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    if (!$SearchResults) {
        Write-Output "There are no Exchange admin events for the time period specified" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    } else {
        ## Output the events to CSV
        $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_ExchangeAdminEvents_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        Write-Output "See Exchange Admin events in the output path" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    }
}

## Get anonymous link events
if ($Types -contains "Anon" -or $Types -contains "ALL") {
    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations (`"AnonymousLinkRemoved`",`"AnonymousLinkcreated`",`"AnonymousLinkUpdated`",`"AnonymousLinkUsed`") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $currentOutput = ""
    $SearchResults = @()
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
        try {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations ("AnonymousLinkRemoved","AnonymousLinkcreated","AnonymousLinkUpdated","AnonymousLinkUsed") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
            exit 2 # Terminate script
        }
        $SearchResults += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    if (!$SearchResults) {
        Write-Output "There are no anonymous link events for the time period specified" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    } else {
        ## Output the events to CSV
        $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_AnonymousLinkEvents_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        Write-Output "See anonymous link events in the output path" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    }
}

## Get Mailbox permission change events
if ($Types -contains "Perm" -or $Types -contains "ALL") {
    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations (`"Add-RecipientPermission`",`"Remove-RecipientPermission`",`"Set-mailbox`",`"Add-MailboxPermission`",`"Remove-MailboxPermission`") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $currentOutput = ""
    $SearchResults = @()
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
        try {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations ("Add-RecipientPermission","Remove-RecipientPermission","Set-mailbox","Add-MailboxPermission","Remove-MailboxPermission") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
            exit 2 # Terminate script
        }
        $SearchResults += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    if (!$SearchResults) {
        Write-Output "There are no mailbox permission events for the time period specified" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    } else {
        ## Output the events to CSV
        $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_MailboxPermissionEvents_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        Write-Output "See mailbox permission events in the output path" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    }
}

## Get email deletion events
if ($Types -contains "EmDel" -or $Types -contains "ALL") {
    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations (`"SoftDelete`",`"HardDelete`",`"MoveToDeletedItems`") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $currentOutput = ""
    $SearchResults = @()
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
        try {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations ("SoftDelete","HardDelete","MoveToDeletedItems") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
            exit 2 # Terminate script
        }
        $SearchResults += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    if (!$SearchResults) {
        Write-Output "There are no email deletion events for the time period specified" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    } else {
        ## Output the events to CSV
        $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_EmailDeletionEvents_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        Write-Output "See email deletion events in the output path" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    }
}

## Get file creation & modification events
if ($Types -contains "FileMod" -or $Types -contains "ALL") {
    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations (`"Created`",`"FileModified`",`"FileModifiedExtended`") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $currentOutput = ""
    $SearchResults = @()
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
        try {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations ("Created","FileModified","FileModifiedExtended") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
            exit 2 # Terminate script
        }
        $SearchResults += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    if (!$SearchResults) {
        Write-Output "There are no File Creation/Modification events for the time period specified" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    } else {
        ## Output the events to CSV
        $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_FileModifiedEvents_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        Write-Output "See file creation events in the output path" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    }
}

## Get file deletion events
if ($Types -contains "FileDel" -or $Types -contains "ALL") {
    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations (`"FileDeleted`",`"FileDeletedFirstStageRecycleBin`",`"FileDeletedSecondStageRecycleBin`") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $currentOutput = ""
    $SearchResults = @()
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
        try {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations ("FileDeleted","FileDeletedFirstStageRecycleBin","FileDeletedSecondStageRecycleBin") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
            Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
            exit 2 # Terminate script
        }
        $SearchResults += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    if (!$SearchResults) {
        Write-Output "There are no file deletion events for the time period specified" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    } else {
        ## Output the events to CSV
        $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_FileDeletedEvents_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        Write-Output "See file deletion events in the output path" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    }
}

## Get all external user activity events
# For just file access events: $SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations FileAccessed -UserIds "*#EXT*" -SessionCommand ReturnLargeSet -ResultSize $resultSize
if ($Types -contains "Ext" -or $Types -contains "ALL") {
    $sesid = Get-Random # Get random session number
    Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds `"*#EXT#*`" -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
    $currentOutput = ""
    $SearchResults = @()
    $count = 1
    do {
        Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
        try {
            $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds "*#EXT#*" -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
        } catch {
            Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
           Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
           exit 2 # Terminate script
        }
        $SearchResults += $currentoutput # Build total results array
        ++ $count # Increment page count
    } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
    if (!$SearchResults) {
        Write-Output "There are no external user events for the time period specified" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    } else {
        ## Output the events to CSV
        $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_ExternalUserEvents_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
        Write-Output "See external user events in the output path" | Tee-Object -FilePath $logFilePath -Append
        Write-Output ""
    }
}

#  ## Get all mail access events - if the event exists this will be a large collection
#  if ($Types -contains "EmAccess" -or $Types -contains "ALL") {
#      $sesid = Get-Random # Get random session number
#      Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations (`"MailItemsAccessed`",`"MessageBind`") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
#      $currentOutput = ""
#      $SearchResults = @()
#      $count = 1
#      do {
#          Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
#          try {
#              $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations ("MailItemsAccessed","MessageBind","FolderBind") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
#          } catch {
#              Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
#              Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
#              exit 2 # Terminate script
#          }
#          $SearchResults += $currentoutput # Build total results array
#          ++ $count # Increment page count
#      } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
#      if (!$SearchResults) {
#          Write-Output "There are no mail access events for the time period specified" | Tee-Object -FilePath $logFilePath -Append
#          Write-Output ""
#      } else {
#          ## Output the events to CSV
#          $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_...Events_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
#          Write-Output "See mail access events in the output path" | Tee-Object -FilePath $logFilePath -Append
#          Write-Output ""
#      }
#  }
#  
#  ## Get all file access events - could be a large collection
#  if ($Types -contains "FileAccess" -or $Types -contains "ALL") {
#      $sesid = Get-Random # Get random session number
#      Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations (`"FileAccessed`",`"FileAccessedExtended`",`"FileDownloaded`",`"FileSyncDownloadedFull`") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
#      $currentOutput = ""
#      $SearchResults = @()
#      $count = 1
#      do {
#          Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
#          try {
#              $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations ("FileAccessed","FileAccessedExtended","FileDownloaded","FileSyncDownloadedFull") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
#          } catch {
#              Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
#              Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
#              exit 2 # Terminate script
#          }
#          $SearchResults += $currentoutput # Build total results array
#          ++ $count # Increment page count
#      } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
#      if (!$SearchResults) {
#          Write-Output "There are no file access events for the time period specified" | Tee-Object -FilePath $logFilePath -Append
#          Write-Output ""
#      } else {
#          ## Output the events to CSV
#          $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_...Events_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
#          Write-Output "See file access events in the output path" | Tee-Object -FilePath $logFilePath -Append
#          Write-Output ""
#      }
#  }

# ## Get XXXXXX events template
# if ($Types -contains "" -or $Types -contains "ALL") {
#     $sesid = Get-Random # Get random session number
#     Write-Output "Search-UnifiedAuditLog..." | Tee-Object -FilePath $logFilePath -Append
#     $currentOutput = ""
#     $SearchResults = @()
#     $count = 1
#     do {
#         Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
#         try {
#             $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType XXXXXX -Operations XXXXXX -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
#         } catch {
#             Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
#             Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
#             exit 2 # Terminate script
#         }
#         $SearchResults += $currentoutput # Build total results array
#         ++ $count # Increment page count
#     } until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
#     if (!$SearchResults) {
#         Write-Output "There are no ... events for the time period specified" | Tee-Object -FilePath $logFilePath -Append
#         Write-Output ""
#     } else {
#         ## Output the events to CSV
#         $SearchResults | Export-Csv -Path "$OutputPath\$DomainName\AuditLog_...Events_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
#         Write-Output "See ... events in the output path" | Tee-Object -FilePath $logFilePath -Append
#         Write-Output ""
#     }
#  }

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"

exit
