#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-CAPReport-P1.ps1
# Report functions created by Donovan du Val
# modified by Bitpusher/The Digital Fox
# v3.1 last updated 2025-07-26
# Script to generate report of current Conditional Access Policies and Named Locations.
# Functions modified to work with the IR Scripts collection flow.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-CAPReport-P1.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses (ExchangePowerShell), Microsoft Graph commands.
#
#comp #m365 #security #bec #script #irscript #powershell #cap #conditional #access #policies #report

# If PowerShell logs an error message for MaximumFunctionCount or MaximumVariableCount. This can be increased using the below.
# $MaximumFunctionCount = 8192
# $MaximumVariableCount = 8192

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = "Microsoft.Graph.Authentication"; ModuleVersion = "2.9.0" }
#Requires -Modules @{ ModuleName = "Microsoft.Graph.Identity.SignIns"; ModuleVersion = "2.9.0" }
#Requires -Modules @{ ModuleName = "Microsoft.Graph.Applications"; ModuleVersion = "2.9.0" }
#Requires -Modules @{ ModuleName = "Microsoft.Graph.Users"; ModuleVersion = "2.9.0" }
#Requires -Modules @{ ModuleName = "Microsoft.Graph.Groups"; ModuleVersion = "2.9.0" }


[CmdletBinding()]
param(
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Get-CAPReport-P1",
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

$OutputCSVreport = "$OutputPath\$DomainName\ConditionalAccessPolicyReport_$($date).csv"
$OutputCSVlocations = "$OutputPath\$DomainName\ConditionalAccessNamedLocations_$($date).csv"


function Report-DirectoryApps {
    param(
        [Parameter(Mandatory = $true)]
        [String[]]
        $AppID
    )
    ($servicePrincipals | Where-Object { $_.AppID -eq $AppID }).DisplayName
}

function Report-NamedLocations {
    param(
        [Parameter(Mandatory = $true)]
        [String[]]
        $ID
    )
    switch ($ID) {
        '00000000-0000-0000-0000-000000000000' { 'Unknown Site' }
        'All' { 'All' }
        'AllTrusted' { 'AllTrusted' }
        Default {
            ($namedLocations | Where-Object { $_.ID -eq $ID }).DisplayName
        }
    }
}

function Get-TypeOfNamedLocations {
    param(
        [Parameter(Mandatory = $true)]
        [String[]]
        $TypeString
    )
    switch ($TypeString) {
        '#microsoft.graph.ipNamedLocation' { 'ipNamedLocation' }
        '#microsoft.graph.countryNamedLocation' { 'countryNamedLocation' }
        Default {
            "UnknownType"
        }
    }
}

function Report-Users {
    param(
        [Parameter(Mandatory = $true)]
        [String[]]
        $ID
    )
    switch ($ID) {
        'GuestsOrExternalUsers' { 'GuestsOrExternalUsers' }
        'All' { 'All' }
        Default {
            $user = (Get-MgUser -UserId "$($ID)" -ErrorAction SilentlyContinue).userprincipalname
            if ($user) {
                $user
            } else {
                "LookingUpError-$($ID)"
            }
        }
    }
}

function Report-Groups {
    param(
        [Parameter(Mandatory = $true)]
        [String[]]
        $ID
    )
    switch ($ID) {
        'GuestsOrExternalUsers' { 'GuestsOrExternalUsers' }
        'All' { 'All' }
        Default {
            $group = (Get-MgGroup -GroupId "$($ID)" -ErrorAction silentlycontinue).DisplayName
            if ($group) {
                $group
            } else {
                "LookingUpError-$($ID)"
            }
        }
    }
}

Write-Output ''
Write-Output 'Collecting Named Locations...'
$namedLocations = Get-MgIdentityConditionalAccessNamedLocation | Select-Object displayname, id, `
@{ Name = "Type"; expression = { ($_.AdditionalProperties. '@odata.type' | ForEach-Object { Get-TypeOfNamedLocations -TypeString $_ }) } }, `
@{ Name = "isTrusted"; expression = { $_.AdditionalProperties.isTrusted } }, `
@{ Name = "ipRanges"; expression = { $_.AdditionalProperties.ipRanges.cidrAddress -join "," } }, `
@{ Name = "Country"; express = { $_.AdditionalProperties.countriesAndRegions -join "," } }, `
@{ Name = "includeUnknownCountriesAndRegions"; expression = { $_.AdditionalProperties.includeUnknownCountriesAndRegions } }, `
@{ Name = "countryLookupMethod"; expression = { $_.AdditionalProperties.countryLookupMethod } }

Write-Output 'Collecting Service Principals...'
$servicePrincipals = Get-MgServicePrincipal -All | Select-Object DisplayName, AppId
Write-Output ''
$Report = @()
#Collects the conditional access policies using the mgconditionalaccesspolicy command.
foreach ($pol in (Get-MgIdentityConditionalAccessPolicy -All)) {
    $Report += New-Object PSobject -Property @{
        'Displayname'                             = $pol.DisplayName
        'Description'                             = $pol.Description
        'State'                                   = $pol.state
        'ID'                                      = $pol.ID
        'createdDateTime'                         = if ($pol.createdDateTime) { $pol.createdDateTime } else { 'Null' }
        'ModifiedDateTime'                        = if ($pol.ModifiedDateTime) { $pol.ModifiedDateTime } else { 'Null' }
        'UserIncludeUsers'                        = if ($pol.Conditions.Users.IncludeUsers) { ($pol.Conditions.Users.IncludeUsers | ForEach-Object { (Report-Users -Id $_) }) -join ',' } else { 'Not Configured' }
        'UserExcludeUsers'                        = if ($pol.Conditions.Users.ExcludeUsers) { ($pol.Conditions.Users.ExcludeUsers | ForEach-Object { (Report-Users -Id $_) }) -join ',' } else { 'Not Configured' }
        'UserIncludeGroups'                       = if ($pol.Conditions.Users.IncludeGroups) { ($pol.Conditions.Users.IncludeGroups | ForEach-Object { (Report-Groups -Id $_) }) -join ',' } else { 'Not Configured' }
        'UserExcludeGroups'                       = if ($pol.Conditions.Users.ExcludeGroups) { ($pol.Conditions.Users.ExcludeGroups | ForEach-Object { (Report-Groups -Id $_) }) -join ',' } else { 'Not Configured' }
        'ConditionSignInRiskLevels'               = if ($pol.Conditions.SignInRiskLevels) { $pol.Conditions.SignInRiskLevels -join ',' } else { 'Not Configured' }
        'ConditionClientAppTypes'                 = if ($pol.Conditions.ClientAppTypes) { $pol.Conditions.ClientAppTypes -join ',' } else { 'Not Configured' }
        'PlatformIncludePlatforms'                = if ($pol.Conditions.Platforms.IncludePlatforms) { $pol.Conditions.Platforms.IncludePlatforms -join ',' } else { 'Not Configured' }
        'PlatformExcludePlatforms'                = if ($pol.Conditions.Platforms.ExcludePlatforms) { $pol.Conditions.Platforms.ExcludePlatforms -join ',' } else { 'Not Configured' }
        'DevicesFilterStatesMode'                 = if ($pol.Conditions.Devices.DeviceFilter.Mode) { $pol.Conditions.Devices.DeviceFilter.Mode -join "," } else { "Failed to Report" }
        'DevicesFilterStatesRule'                 = if ($pol.Conditions.Devices.DeviceFilter.Rule) { $pol.Conditions.Devices.DeviceFilter.Rule -join "," } else { "Failed to Report" }
        'ApplicationIncludeApplications'          = if ($pol.Conditions.Applications.IncludeApplications) { ($pol.Conditions.Applications.IncludeApplications | ForEach-Object { Report-DirectoryApps -AppID $_ }) -join ',' } else { 'Not Configured' }
        'ApplicationExcludeApplications'          = if ($pol.Conditions.Applications.ExcludeApplications) { ($pol.Conditions.Applications.ExcludeApplications | ForEach-Object { Report-DirectoryApps -AppID $_ }) -join ',' } else { 'Not Configured' }
        'ApplicationIncludeUserActions'           = if ($pol.Conditions.Applications.IncludeUserActions) { $pol.Conditions.Applications.IncludeUserActions -join ',' } else { 'Not Configured' }
        'LocationIncludeLocations'                = if ($pol.Conditions.Locations.IncludeLocations) { ($pol.Conditions.Locations.IncludeLocations | ForEach-Object { Report-NamedLocations -Id $_ }) -join ',' } else { 'Not Configured' }
        'LocationExcludeLocations'                = if ($pol.Conditions.Locations.ExcludeLocations) { ($pol.Conditions.Locations.ExcludeLocations | ForEach-Object { Report-NamedLocations -Id $_ }) -join ',' } else { 'Not Configured' }
        'GrantControlBuiltInControls'             = if ($pol.GrantControls.BuiltInControls) { $pol.GrantControls.BuiltInControls -join ',' } else { 'Not Configured' }
        'GrantControlTermsOfUse'                  = if ($pol.GrantControls.TermsOfUse) { $pol.GrantControls.TermsOfUse -join ',' } else { 'Not Configured' }
        'GrantControlOperator'                    = if ($pol.GrantControls.Operator) { $pol.GrantControls.Operator } else { 'Not Configured' }
        'GrantControlCustomAuthenticationFactors' = if ($pol.GrantControls.CustomAuthenticationFactors) { $pol.GrantControls.CustomAuthenticationFactors -join ',' } else { 'Not Configured' }
        'CloudAppSecurityCloudAppSecurityType'    = if ($pol.SessionControls.CloudAppSecurity.CloudAppSecurityType) { $pol.SessionControls.CloudAppSecurity.CloudAppSecurityType } else { 'Not Configured' }
        'ApplicationEnforcedRestrictions'         = if ($pol.SessionControls.ApplicationEnforcedRestrictions.IsEnabled) { $pol.SessionControls.ApplicationEnforcedRestrictions.IsEnabled } else { 'Not Configured' }
        'CloudAppSecurityIsEnabled'               = if ($pol.SessionControls.CloudAppSecurity.IsEnabled) { $pol.SessionControls.CloudAppSecurity.IsEnabled } else { 'Not Configured' }
        'PersistentBrowserIsEnabled'              = if ($pol.SessionControls.PersistentBrowser.IsEnabled) { $pol.SessionControls.PersistentBrowser.IsEnabled } else { 'Not Configured' }
        'PersistentBrowserMode'                   = if ($pol.SessionControls.PersistentBrowser.Mode) { $pol.SessionControls.PersistentBrowser.Mode } else { 'Not Configured' }
        'SignInFrequencyIsEnabled'                = if ($pol.SessionControls.SignInFrequency.IsEnabled) { $pol.SessionControls.SignInFrequency.IsEnabled } else { 'Not Configured' }
        'SignInFrequencyType'                     = if ($pol.SessionControls.SignInFrequency.Type) { $pol.SessionControls.SignInFrequency.Type } else { 'Not Configured' }
        'SignInFrequencyValue'                    = if ($pol.SessionControls.SignInFrequency.Value) { $pol.SessionControls.SignInFrequency.Value } else { 'Not Configured' }
    }
}


Write-Output 'Generating the Reports.'
$ReportData = $Report | Select-Object -Property Displayname, Description, State, ID, createdDateTime, ModifiedDateTime, UserIncludeUsers, UserExcludeUsers, UserIncludeGroups, UserExcludeGroups, ConditionSignInRiskLevels, ConditionClientAppTypes, PlatformIncludePlatforms, PlatformExcludePlatforms, DevicesFilterStatesMode, DevicesFilterStatesRule, ApplicationIncludeApplications, ApplicationExcludeApplications, ApplicationIncludeUserActions, LocationIncludeLocations, LocationExcludeLocations, GrantControlBuiltInControls, GrantControlTermsOfUse, GrantControlOperator, GrantControlCustomAuthenticationFactors, ApplicationEnforcedRestrictions, CloudAppSecurityCloudAppSecurityType, CloudAppSecurityIsEnabled, PersistentBrowserIsEnabled, PersistentBrowserMode, SignInFrequencyIsEnabled, SignInFrequencyType, SignInFrequencyValue | Sort-Object -Property Displayname
Write-Output ''
Write-Output "Generating the CSV Reports."
$ReportData | Export-Csv "$OutputCSVreport" -NoTypeInformation -Delimiter "," -Encoding $Encoding
$namedLocations | Export-Csv "$OutputCSVlocations" -NoTypeInformation -Delimiter "," -Encoding $Encoding

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"

exit
