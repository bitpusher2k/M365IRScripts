#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-EnterpriseApplications.ps1 - By Bitpusher/The Digital Fox
# v3.0 last updated 2025-05-31
# Script to list all Entra ID enterprise applications (really all Service Principals)
# configured on a tenant, from newest created to oldest.
#
# Usage:
# powershell -executionpolicy bypass -f .\ Get-EnterpriseApplications.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses (ExchangePowerShell), Microsoft Graph commands.
#
#comp #m365 #security #bec #script #irscript #powershell #enterprise #applications #list #entraid #azuread

#Requires -Version 5.1

param(
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Get-EnterpriseApplications",
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
Write-Output "Domain sub-directory will be `"$DomainName`"" | Tee-Object -FilePath $logFilePath -Append


$OutputCSV = "$OutputPath\$DomainName\AllEnterpriseApplications_$($date).csv"

Write-Output "Listing all Enterprise Applications..."

# $apps = Get-AzureADServicePrincipal -All:$true | ? {$_.Tags -eq "WindowsAzureActiveDirectoryIntegratedApp"}
# $apps

# $ServicePrincipalList = Get-MgServicePrincipal -all

# foreach($servicePrincipal in $ServicePrincipalList){
#	Get-AzureADServiceAppRoleAssignment -ObjectId $ServicePrincipal.objectId | Select-Object ResourceDisplayName, ResourceId, PrincipalDisplayName, PrincipalType | Export-Csv -Path $PathCsv -NoTypeInformation -Append
# }

# Get all Enterprise Apps
# $results = Invoke-MGGraphRequest -Method get -Uri 'https://graph.microsoft.com/v1.0/applications/?$select=id,displayName' -OutputType PSObject -Headers @{'ConsistencyLevel' = 'eventual' }
$results = Get-MgServicePrincipal -All

# alternative just application registrations: $results = Invoke-MGGraphRequest -Method get -Uri 'https://graph.microsoft.com/v1.0/applications/?$select=*' -OutputType PSObject -Headers @{'ConsistencyLevel' = 'eventual' }  # use $results.value in place of $results below
# alternative just application registrations: $resultes = Get-MgApplication -All
# $results | Sort-Object createdDateTime -desc | Select-Object createdDateTime,DisplayName | FT
# $results | Sort-Object createdDateTime -desc | Select-Object createdDateTime,DisplayName | FTion -Encoding $Encoding


$results | Select-Object DisplayName, ServicePrincipalType, @{ Name = "CreatedDateTime"; Expression = { $_.additionalproperties['createdDateTime'] } }, AccountEnabled, Id | Sort-Object createdDateTime -desc | Format-Table
$results | Select-Object DisplayName, ServicePrincipalType, @{ Name = "CreatedDateTime"; Expression = { $_.additionalproperties['createdDateTime'] } }, AccountEnabled, Id | Sort-Object createdDateTime -desc | Export-Csv $OutputCSV -Append -notypeinformat -Encoding $Encoding

# Additional info:
#  Get-MgServicePrincipal -ServicePrincipalId XXXX-xxx-xx-xx-XXXX | Select samlSingleSignOnSettings, loginUrl, logoutUrl, notificationEmailAddresses
#  Get-MgServicePrincipalOwner -ServicePrincipalId XXXX-xxx-xx-xx-XXXX
#  Get-MgServicePrincipalAppRoleAssignment -serviceprincipalid XXXX-xxx-xx-xx-XXXX
#  Remove-MgServicePrincipal -ServicePrincipalId XXXX-xxx-xx-xx-XXXX


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

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"

exit
