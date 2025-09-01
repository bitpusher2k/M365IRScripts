#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Search-UALMailItemsAccessedByUser.ps1 - By Bitpusher/The Digital Fox
# v3.1 last updated 2025-07-26
# Script to export all "MailItemsAccessed", "MessageBind", "FolderBind"
# records from the Unified Audit Log for specified users.
# Note: This item doesn't support shared mailboxes.
#
# MailItemsAccessed operations are now supposed to be more widely available in the UAL - test if you have any results with:
# Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -Operations "MailItemsAccessed","MessageBind" -ResultSize 5000
#
# Refer to the one-liner reference for information on how to check and set mailbox audit status.
#
# For more information see:
# https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts
# https://office365itpros.com/2019/01/07/using-exchange-session-identifiers-audit-log/
# https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts
# https://petri.com/interpreting-the-office-365-mailitemsaccessed-audit-event/
#
# Usage:
# powershell -executionpolicy bypass -f .\Search-UALMailItemsAccessedByUser.ps1 -OutputPath "Default" -UserIds "compromisedaccount@contoso.com" -DaysAgo "10"
#
# powershell -executionpolicy bypass -f .\Search-UALMailItemsAccessedByUser.ps1 -OutputPath "Default" -UserIds "compromisedaccount@contoso.com" -StartDate "2025-07-12" -EndDate "2025-07-20"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
#
#comp #m365 #security #bec #script #irscript #powershell #unified #audit #log #search #user #mailitemsaccessed

#Requires -Version 5.1

param(
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Search-UALMailItemsAccessedByUser",
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
$PrimaryDomain = Get-AcceptedDomain | Where-Object Default -EQ $true
$DomainName = $PrimaryDomain.DomainName

$CheckSubDir = Get-Item $OutputPath\$DomainName -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
    Write-Output ""
    Write-Output "Domain sub-directory does not exist. Sub-directory `"$DomainName`" will be created." | Tee-Object -FilePath $logFilePath -Append
    mkdir $OutputPath\$DomainName
}
Write-Output "Domain sub-directory will be `"$DomainName`"" | Tee-Object -FilePath $logFilePath -Append

## If UserIds variable is not defined, prompt for it
if (!$UserIds) {
    Write-Output ""
    $UserIds = Read-Host "Enter the user's primary email address (UPN). Comma-separated to search for entries from multiple users"
}

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


$resultSize = 5000 #Maximum number of records that can be retrieved per query

$OutputCSV = "$OutputPath\$DomainName\MailItemsAccessedUALEntries_$($UserIds.Replace(',','-'))_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC.csv"
$OutputTxt = "$OutputPath\$DomainName\MailItemsAccessedUALEntries_$($UserIds.Replace(',','-'))_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC.txt"

$amountResults = (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $UserIds -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount)
$throttledResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $UserIds -Operations MailItemsAccessed -ResultSize 1000 | Where {$_.AuditData -like '*"IsThrottled","Value":"True"*'}
$syncResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $UserIds -Operations MailItemsAccessed -ResultSize 1000 | Where {$_.AuditData -like '*"MailAccessType","Value":"Sync"*'}

Write-Output "`nNumber of MailItemsAccessed events logged for specified user(s) during time range: $amountResults.`n" | Tee-Object -FilePath $logFilePath -Append

if ($throttledResults) {
    Write-Output "`nWARNING: MailItemsAccessed events THROTTLED for specified user(s) during search range - Not all events were logged.`n" | Tee-Object Tee-Object -FilePath $OutputTxt -Append | Tee-Object -FilePath $logFilePath -Append
}

if ($syncResults) {
    Write-Output "`nWARNING: MailItemsAccessed SYNC events for specified user(s) logged during search range - Desktop Outlook client used and only FOLDER level operations are logged - ALL items in synced folder must be assumed accessed.`n" | Tee-Object -FilePath $OutputTxt -Append | Tee-Object -FilePath $logFilePath -Append
}

$sesid = Get-Random # Get random session number
Write-Output "Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $UserIds -Operations (`"MailItemsAccessed`",`"MessageBind`",`"FolderBind`") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize" | Tee-Object -FilePath $logFilePath -Append
$currentoutput = ""
$AuditOutput = @()
$count = 1
do {
    Write-Output "Getting unified audit logs page $count - Please wait" | Tee-Object -FilePath $logFilePath -Append
    try {
        $currentOutput = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $UserIds -Operations ("MailItemsAccessed","MessageBind","FolderBind") -SessionId $sesid -SessionCommand ReturnLargeSet -ResultSize $resultSize
    } catch {
        Write-Output "`n[002] - Search Unified Log error. Typically not connected to Exchange Online. Please connect and re-run script`n" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "Exception message:", $_.Exception.Message, "`n" | Tee-Object -FilePath $logFilePath -Append
        exit 2 # Terminate script
    }
    $AuditOutput += $currentoutput # Build total results array
    ++ $count # Increment page count
} until ($currentoutput.count -eq 0) # Until there are no more logs in range to get
if (!$AuditOutput) {
    Write-Output "`nNo matching activities found in the audit log for the time period specified`n" | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "`nMatching activities found in the audit log - Saving to file...`n" | Tee-Object -FilePath $logFilePath -Append
    $AuditOutput | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding $Encoding

    # Add information columns to object
    $AuditOutput | Add-Member -NotePropertyName "AuditDataCreationTime" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataOperation" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataOrganizationId" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataRecordType" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataResultStatus" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataWorkload" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataUserId" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataAADSessionId" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataClientIPAddress" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataClientInfoString" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataExternalAccess" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataLogonType" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataLogonUserSid" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataMailboxGuid" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataMailboxOwnerSid" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataMailboxOwnerUPN" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataOperationProperties" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataOrganizationName" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataOriginatingServer" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataImmutableId" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataInternetMessageId" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataSizeInBytes" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataId" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataPath" -NotePropertyValue $null
    $AuditOutput | Add-Member -NotePropertyName "AuditDataOperationCount" -NotePropertyValue $null

    Write-Output "Processing AuditData block of each row...`n" | Tee-Object -FilePath $logFilePath -Append

    # Loop through each row in spreadsheet data
    foreach ($Row in $AuditOutput) {

        $AuditData = ConvertFrom-Json $Row.Auditdata

        Write-Output "Parsing row $RowCount" | Tee-Object -FilePath $logFilePath -Append

        if ($AuditData.CreationTime -ne $Null) { $Row.AuditDataCreationTime = $AuditData.CreationTime } else { $Row.AuditDataCreationTime = "Unavailable" }
        if ($AuditData.Operation -ne $Null) { $Row.AuditDataOperation = $AuditData.Operation } else { $Row.AuditDataOperation = "Unavailable" }
        if ($AuditData.OrganizationId -ne $Null) { $Row.AuditDataOrganizationId = $AuditData.OrganizationId } else { $Row.AuditDataOrganizationId = "Unavailable" }
        if ($AuditData.RecordType -ne $Null) { $Row.AuditDataRecordType = $AuditData.RecordType } else { $Row.AuditDataRecordType = "Unavailable" }
        if ($AuditData.ResultStatus -ne $Null) { $Row.AuditDataResultStatus = $AuditData.ResultStatus } else { $Row.AuditDataResultStatus = "Unavailable" }
        if ($AuditData.Workload -ne $Null) { $Row.AuditDataWorkload = $AuditData.Workload } else { $Row.AuditDataWorkload = "Unavailable" }
        if ($AuditData.UserId -ne $Null) { $Row.AuditDataUserId = $AuditData.UserId } else { $Row.AuditDataUserId = "Unavailable" }
        if ($AuditData.AppAccessContext.AADSessionId -ne $Null) { $Row.AuditDataAADSessionId = $AuditData.AppAccessContext.AADSessionId } else { $Row.AuditDataAADSessionId = "Unavailable" }
        if ($AuditData.ClientIPAddress -ne $Null) { $Row.AuditDataClientIPAddress = $AuditData.ClientIPAddress } else { $Row.AuditDataClientIPAddress = "Unavailable" }
        if ($AuditData.ClientInfoString -ne $Null) { $Row.AuditDataClientInfoString = $AuditData.ClientInfoString } else { $Row.AuditDataClientInfoString = "Unavailable" }
        if ($AuditData.ExternalAccess -ne $Null) { $Row.AuditDataExternalAccess = $AuditData.ExternalAccess } else { $Row.AuditDataExternalAccess = "Unavailable" }
        if ($AuditData.LogonType -ne $Null) { $Row.AuditDataLogonType = $AuditData.LogonType } else { $Row.AuditDataLogonType = "Unavailable" }
        if ($AuditData.LogonUserSid -ne $Null) { $Row.AuditDataLogonUserSid = $AuditData.LogonUserSid } else { $Row.AuditDataLogonUserSid = "Unavailable" }
        if ($AuditData.MailboxGuid -ne $Null) { $Row.AuditDataMailboxGuid = $AuditData.MailboxGuid } else { $Row.AuditDataMailboxGuid = "Unavailable" }
        if ($AuditData.MailboxOwnerSid -ne $Null) { $Row.AuditDataMailboxOwnerSid = $AuditData.MailboxOwnerSid } else { $Row.AuditDataMailboxOwnerSid = "Unavailable" }
        if ($AuditData.MailboxOwnerUPN -ne $Null) { $Row.AuditDataMailboxOwnerUPN = $AuditData.MailboxOwnerUPN } else { $Row.AuditDataMailboxOwnerUPN = "Unavailable" }
        if ($AuditData.OperationProperties -ne $Null) { $Row.AuditDataOperationProperties =  $($AuditData.OperationProperties | foreach-object {$_}) -join "|" } else { $Row.AuditDataOperationProperties = "Unavailable" }
        if ($AuditData.OrganizationName -ne $Null) { $Row.AuditDataOrganizationName = $AuditData.OrganizationName } else { $Row.AuditDataOrganizationName = "Unavailable" }
        if ($AuditData.OriginatingServer -ne $Null) { $Row.AuditDataOriginatingServer = $AuditData.OriginatingServer } else { $Row.AuditDataOriginatingServer = "Unavailable" }
        if ($AuditData.Folders.FolderItems -ne $Null) { $Row.AuditDataImmutableId = $($AuditData.Folders.FolderItems | foreach-object {$_.Id}) -join "|" } else { $Row.AuditDataImmutableId = "Unavailable" }
        if ($AuditData.Folders.FolderItems -ne $Null) { $Row.AuditDataInternetMessageId = $($AuditData.Folders.FolderItems | foreach-object {$_.InternetMessageId}) -join "|" } else { $Row.AuditDataInternetMessageId = "Unavailable" }
        if ($AuditData.Folders.FolderItems -ne $Null) { $Row.AuditDataSizeInBytes = $($AuditData.Folders.FolderItems | foreach-object {$_.SizeInBytes}) -join "|" } else { $Row.AuditDataSizeInBytes = "Unavailable" }
        if ($AuditData.Folders.FolderItems -ne $Null) { $Row.AuditDataId = $($AuditData.Folders.FolderItems | foreach-object {$_.Id}) -join "|" } else { $Row.AuditDataId = "Unavailable" }
        if ($AuditData.Folders -ne $Null) { $Row.AuditDataPath = $($AuditData.Folders | foreach-object {$_.Path}) -join "|" } else { $Row.AuditDataPath = "Unavailable" }
        if ($AuditData.OperationCount -ne $Null) { $Row.AuditDataOperationCount = $AuditData.OperationCount } else { $Row.AuditDataOperationCount = "Unavailable" }

        $RowCount++
    }

    # Export updated spreadsheet data to CSV file
    $OutputCSV = "$OutputPath\$DomainName\MailItemsAccessedUALEntries_$($UserIds.Replace(',','-'))_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_Processed.csv"
    $AuditOutput | Export-Csv -Path "$OutputCSV" -NoTypeInformation -Encoding $Encoding

    Write-Output "Processed a total of $RowCount rows." | Tee-Object -FilePath $logFilePath -Append

    Write-Output "`nSee user activities report in the output path.`n" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "Pivot through MailItemsAccessed logs searching by date/time of suspect events, by suspect IP ('ClientIPAddress'), and by associated suspect Session ID ('SessionId')."
}

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:"
    Write-Output $OutputCSV
    # $Prompt = New-Object -ComObject wscript.shell
    # $UserIdsInput = $Prompt.popup("Do you want to open output file?",0,"Open Output File",4)
    # If ($UserIdsInput -eq 6) {
    # 	Invoke-Item "$OutputCSV"
    # }
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"

exit
