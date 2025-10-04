#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-EntraIDAudieAndSignInLogs30-P1.ps1 - By Bitpusher/The Digital Fox
# v3.1.1 last updated 2025-09-17
# Function ConvertTo-FlatObject by https://github.com/EvotecIT
# Script to export Azure AD sign-in and audit logs for past 30 days
# (if they exist that far back)
# using AzureAD module (deprecated) and Microsoft Graph (beta).
#
# Requires minimum of Entra ID P1 licensing (will not work on Entra ID Free plan).
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-EntraIDAudieAndSignInLogs30-P1.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses Microsoft Graph commands (scopes "AuditLog.Read.All","Directory.Read.All").
# Deprecated AzureAD versions commented out.
#
#comp #m365 #security #bec #script #azure #entra #audit #sign-in #logs #p1

#Requires -Version 5.1

param(
    [string]$OutputPath = "Default",
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Get-EntraIDAudieAndSignInLogs30-P1",
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


function ConvertTo-FlatObject {
    <# https://evotec.xyz/powershell-converting-advanced-object-to-flat-object/
    .SYNOPSIS
    Flattens a nested object into a single level object.

    .DESCRIPTION
    Flattens a nested object into a single level object.

    .PARAMETER Objects
    The object (or objects) to be flatten.

    .PARAMETER Separator
    The separator used between the recursive property names

    .PARAMETER Base
    The first index name of an embedded array:
    - 1, arrays will be 1 based: <Parent>.1, <Parent>.2, <Parent>.3, ...
    - 0, arrays will be 0 based: <Parent>.0, <Parent>.1, <Parent>.2, ...
    - "", the first item in an array will be unnamed and than followed with 1: <Parent>, <Parent>.1, <Parent>.2, ...

    .PARAMETER Depth
    The maximal depth of flattening a recursive property. Any negative value will result in an unlimited depth and could cause a infinitive loop.

    .PARAMETER Uncut
    The maximal depth of flattening a recursive property. Any negative value will result in an unlimited depth and could cause a infinitive loop.

    .PARAMETER ExcludeProperty
    The properties to be excluded from the output.

    .EXAMPLE
    $Object3 = [PSCustomObject] @{
        "Name"    = "Przemyslaw Klys"
        "Age"     = "30"
        "Address" = @{
            "Street"  = "Kwiatowa"
            "City"    = "Warszawa"

            "Country" = [ordered] @{
                "Name" = "Poland"
            }
            List      = @(
                [PSCustomObject] @{
                    "Name" = "Adam Klys"
                    "Age"  = "32"
                }
                [PSCustomObject] @{
                    "Name" = "Justyna Klys"
                    "Age"  = "33"
                }
                [PSCustomObject] @{
                    "Name" = "Justyna Klys"
                    "Age"  = 30
                }
                [PSCustomObject] @{
                    "Name" = "Justyna Klys"
                    "Age"  = $null
                }
            )
        }
        ListTest  = @(
            [PSCustomObject] @{
                "Name" = "Slawa Klys"
                "Age"  = "33"
            }
        )
    }

    $Object3 | ConvertTo-FlatObject

    .NOTES
    Based on https://powersnippets.com/convertto-flatobject/
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeLine)] [Object[]]$Objects,
        [string]$Separator = ".",
        [ValidateSet("", 0, 1)] $Base = 1,
        [int]$Depth = 10,
        [string[]]$ExcludeProperty,
        [Parameter(DontShow)] [String[]]$Path,
        [Parameter(DontShow)] [System.Collections.IDictionary]$OutputObject
    )
    begin {
        $InputObjects = [System.Collections.Generic.List[Object]]::new()
    }
    process {
        foreach ($O in $Objects) {
            if ($null -ne $O) {
                $InputObjects.Add($O)
            }
        }
    }
    end {
        if ($PSBoundParameters.ContainsKey("OutputObject")) {
            $Object = $InputObjects[0]
            $Iterate = [ordered]@{}
            if ($null -eq $Object) {
                #Write-Output "ConvertTo-FlatObject - Object is null"
            } elseif ($Object.GetType().Name -in 'String', 'DateTime', 'TimeSpan', 'Version', 'Enum') {
                $Object = $Object.ToString()
            } elseif ($Depth) {
                $Depth --
                if ($Object -is [System.Collections.IDictionary]) {
                    $Iterate = $Object
                } elseif ($Object -is [array] -or $Object -is [System.Collections.IEnumerable]) {
                    $i = $Base
                    foreach ($Item in $Object.GetEnumerator()) {
                        $NewObject = [ordered]@{}
                        if ($Item -is [System.Collections.IDictionary]) {
                            foreach ($Key in $Item.Keys) {
                                if ($Key -notin $ExcludeProperty) {
                                    $NewObject[$Key] = $Item[$Key]
                                }
                            }
                        } elseif ($Item -isnot [array] -and $Item -isnot [System.Collections.IEnumerable]) {
                            foreach ($Prop in $Item.PSObject.Properties) {
                                if ($Prop.IsGettable -and $Prop.Name -notin $ExcludeProperty) {
                                    $NewObject["$($Prop.Name)"] = $Item.$($Prop.Name)
                                }
                            }
                        } else {
                            $NewObject = $Item
                        }
                        $Iterate["$i"] = $NewObject
                        $i += 1
                    }
                } else {
                    foreach ($Prop in $Object.PSObject.Properties) {
                        if ($Prop.IsGettable -and $Prop.Name -notin $ExcludeProperty) {
                            $Iterate["$($Prop.Name)"] = $Object.$($Prop.Name)
                        }
                    }
                }
            }
            if ($Iterate.Keys.Count) {
                foreach ($Key in $Iterate.Keys) {
                    if ($Key -notin $ExcludeProperty) {
                        ConvertTo-FlatObject -Objects @(, $Iterate["$Key"]) -Separator $Separator -Base $Base -Depth $Depth -Path ($Path + $Key) -OutputObject $OutputObject -ExcludeProperty $ExcludeProperty
                    }
                }
            } else {
                $Property = $Path -join $Separator
                if ($Property) {
                    # We only care if property is not empty
                    if ($Object -is [System.Collections.IDictionary] -and $Object.Keys.Count -eq 0) {
                        $OutputObject[$Property] = $null
                    } else {
                        $OutputObject[$Property] = $Object
                    }
                }
            }
        } elseif ($InputObjects.Count -gt 0) {
            foreach ($ItemObject in $InputObjects) {
                $OutputObject = [ordered]@{}
                ConvertTo-FlatObject -Objects @(, $ItemObject) -Separator $Separator -Base $Base -Depth $Depth -Path $Path -OutputObject $OutputObject -ExcludeProperty $ExcludeProperty
                [pscustomobject]$OutputObject
            }
        }
    }
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
Write-Output "Domain sub-directory will be `"$DomainName`"" | Tee-Object -FilePath $logFilePath -Append

## Get valid starting end ending dates
if (!$DaysAgo -and (!$StartDate -or !$EndDate)) {
    Write-Output ""
    $DaysAgo = Read-Host 'Enter how many days back to retrieve relevant UAL entries (default: 7, maximum: 30)'
    if ($DaysAgo -eq '') { $DaysAgo = "7" } elseif ($DaysAgo -gt 30) { $DaysAgo = "30" }
}

if ($DaysAgo) {
    if ($DaysAgo -gt 30) { $DaysAgo = "30" }
    Write-Output "`nScript will search Sign-in and Audit logs $DaysAgo days back from today." | Tee-Object -FilePath $logFilePath -Append
    $StartDate = (Get-Date).touniversaltime().AddDays(-$DaysAgo)
    $EndDate = (Get-Date).touniversaltime()
    Write-Output "StartDate: $StartDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "EndDate: $EndDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
} elseif ($StartDate -and $EndDate) {
    $StartDate = ($StartDate).touniversaltime()
    $EndDate = ($EndDate).touniversaltime()
    if ($StartDate -lt (Get-Date).touniversaltime().AddDays(-30)) { $StartDate = (Get-Date).touniversaltime().AddDays(-30) }
    if ($StartDate -ge $EndDate) { $EndDate = ($StartDate).AddDays(1) }
    Write-Output "`nScript will search Sign-in and Audit logs between StartDate and EndDate." | Tee-Object -FilePath $logFilePath -Append
    Write-Output "StartDate: $StartDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
    Write-Output "EndDate: $EndDate (UTC)" | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "Neither DaysAgo nor StartDate/EndDate specified. Ending." | Tee-Object -FilePath $logFilePath -Append
    exit
}

# Get-MgSubscribedSku | Select -Property Sku*, ConsumedUnits -ExpandProperty PrepaidUnits | Select-Object SkuPartNumber | Format-List
# (Get-MgSubscribedSku).ServicePlans | ? { $_.ServicePlanName -Like 'AAD_PREMIUM*' }
# https://portal.azure.com/#view/Microsoft_AAD_IAM/LicensesMenuBlade/~/Products

Write-Output "`nWARNING - Logs retrieved via AzureAD or Microsoft Graph do NOT contain the 'Authentication Protocol' field - https://www.invictus-ir.com/news/do-not-use-the-get-mgauditlogsignin-for-your-investigations"
Write-Output "This script will attempt to use the beta cmdlet versions to retrieve more sign-in data."

Write-Output "`nAttempting to retrieve Entra ID Audit logs (after $StartDate) via beta graph cmdlet..."

Write-Output "Get-MgBetaAuditLogDirectoryAudit -All -Filter `"activityDateTime gt $(($StartDate).ToString('yyyy-MM-dd'))`""
$EntraAuditLogs = Get-MgBetaAuditLogDirectoryAudit -All -Filter "activityDateTime gt $(($StartDate).ToString('yyyy-MM-dd'))"
$EntraAuditLogsJSON = $EntraAuditLogs | ConvertTo-Json -Depth 100
$EntraAuditLogsJSON | Out-File -FilePath "$OutputPath\$DomainName\EntraIDAuditLogsGraphBeta_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).json" -Encoding $Encoding
$EntraAuditLogs | ConvertTo-FlatObject -Base 1 -Depth 20 | Export-Csv -Path "$OutputPath\$DomainName\EntraIDAuditLogsGraphBeta_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
[io.file]::readalltext("$OutputPath\$DomainName\EntraIDAuditLogsGraphBeta_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv").replace("System.Object[]","") | Out-File "$OutputPath\$DomainName\EntraIDAuditLogsGraphBeta_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -Encoding utf8 –Force
Write-Output "`nDone..."

$License = (Get-MgSubscribedSku).ServicePlans | Where-Object { $_.ServicePlanName -like 'AAD_PREMIUM*' }
Write-Output "`n$License"

[bool]$LicenseBool = $License
if (!$LicenseBool) {
    Write-Output "`nRetrieval of Entra ID/AAD sign-in logs through AzureAD and Microsoft Graph API requires Entra ID premium license (P1 or P2)"
    Write-Output "License does not appear to be present - you will have to retrieve logs manually from:"
    Write-Output "`nhttps://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/SignIns"
} else {

    Write-Output "`nAttempting to retrieve Entra ID Sign-in logs (after $StartDate) via beta graph cmdlet..."

    Write-Output "Get-MgBetaAuditLogSignIn -All -Filter `"createdDateTime gt $(($StartDate).ToString('yyyy-MM-dd'))`""
    $EntraSignInLogs = Get-MgBetaAuditLogSignIn -All -Filter "createdDateTime gt $(($StartDate).ToString('yyyy-MM-dd'))"

    Write-Output "Get-MgBetaAuditLogSignIn -All -Filter `"(createdDateTime gt $(($StartDate).ToString('yyyy-MM-dd'))) and (signInEventTypes/any(t: t ne 'interactiveUser'))`""
    $EntraSignInLogsNonInteractive = Get-MgBetaAuditLogSignIn -Filter "(createdDateTime gt $(($StartDate).ToString('yyyy-MM-dd'))) and (signInEventTypes/any(t: t ne 'interactiveUser'))"

    # TO get ALL sign-in types in single query: Get-MgBetaAuditLogSignIn -Filter "(createdDateTime gt $(($StartDate).ToString('yyyy-MM-dd'))) and (signInEventTypes/any(t: t eq 'nonInteractiveUser' OR t eq 'interactiveUser' OR t eq 'servicePrincipal' OR t eq 'managedIdentity'))"

    
    $EntraSignInLogsJSON = $EntraSignInLogs | ConvertTo-Json -Depth 100
    $EntraSignInLogsJSON | Out-File -FilePath "$OutputPath\$DomainName\EntraIDSignInLogsGraphBeta_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).json" -Encoding $Encoding
    $EntraSignInLogs | ConvertTo-FlatObject -Base 1 -Depth 20 | Export-Csv -Path "$OutputPath\$DomainName\EntraIDSignInLogsGraphBeta_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
    [io.file]::readalltext("$OutputPath\$DomainName\EntraIDSignInLogsGraphBeta_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv").replace("System.Object[]","") | Out-File "$OutputPath\$DomainName\EntraIDSignInLogsGraphBeta_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -Encoding utf8 –Force

    $EntraSignInLogsJSONNonInteractive = $EntraSignInLogsNonInteractive | ConvertTo-Json -Depth 100
    $EntraSignInLogsJSONNonInteractive | Out-File -FilePath "$OutputPath\$DomainName\EntraIDSignInLogsGraphBetaNonInteractive_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).json" -Encoding $Encoding
    $EntraSignInLogsNonInteractive | ConvertTo-FlatObject -Base 1 -Depth 20 | Export-Csv -Path "$OutputPath\$DomainName\EntraIDSignInLogsGraphBetaNonInteractive_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -NoTypeInformation -Encoding $Encoding
    [io.file]::readalltext("$OutputPath\$DomainName\EntraIDSignInLogsGraphBetaNonInteractive_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv").replace("System.Object[]","") | Out-File "$OutputPath\$DomainName\EntraIDSignInLogsGraphBetaNonInteractive_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv" -Encoding utf8 –Force

    # Reload & sort CSVs into preferred column order
    $EntraLog = Import-Csv "$OutputPath\$DomainName\EntraIDSignInLogsGraphBeta_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv"
    $EntraLog = $EntraLog | Select-Object *, @{ n = 'DateOnly'; e = { $_.CreatedDateTime.Split(' ')[0] } }, @{ n = 'TimeOnly'; e = { $_.CreatedDateTime.Split(' ')[1] } }
    $EntraLog | Select-Object "CreatedDateTime", "DateOnly", "TimeOnly", "UserDisplayName", "UserPrincipalName", "IPAddress", "Location.City", "Location.State", "Location.CountryOrRegion", "UserType", "Status.ErrorCode", "Status.FailureReason", "Status.AdditionalDetails", "Status.AdditionalProperties", "AuthenticationRequirement", "ConditionalAccessStatus", "IncomingTokenType", "ResourceDisplayName", "ResourceId", "ClientAppUsed", "DeviceDetail.Browser", "DeviceDetail.OperatingSystem", "UserAgent", "DeviceDetail.DisplayName", "DeviceDetail.IsCompliant", "DeviceDetail.IsManaged", "DeviceDetail.TrustType", "SessionId", * -ErrorAction SilentlyContinue | Export-Csv -Path "$OutputPath\$DomainName\EntraIDSignInLogsGraphBeta_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date)_Processed.csv" -NoTypeInformation -Encoding $Encoding

    $EntraLogNonInteractive = Import-Csv "$OutputPath\$DomainName\EntraIDSignInLogsGraphBetaNonInteractive_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date).csv"
    $EntraLogNonInteractive = $EntraLogNonInteractive | Select-Object *, @{ n = 'DateOnly'; e = { $_.CreatedDateTime.Split(' ')[0] } }, @{ n = 'TimeOnly'; e = { $_.CreatedDateTime.Split(' ')[1] } }
    $EntraLogNonInteractive | Select-Object "CreatedDateTime", "DateOnly", "TimeOnly", "UserDisplayName", "UserPrincipalName", "IPAddress", "Location.City", "Location.State", "Location.CountryOrRegion", "UserType", "Status.ErrorCode", "Status.FailureReason", "Status.AdditionalDetails", "Status.AdditionalProperties", "AuthenticationRequirement", "ConditionalAccessStatus", "IncomingTokenType", "ResourceDisplayName", "ResourceId", "ClientAppUsed", "DeviceDetail.Browser", "DeviceDetail.OperatingSystem", "UserAgent", "DeviceDetail.DisplayName", "DeviceDetail.IsCompliant", "DeviceDetail.IsManaged", "DeviceDetail.TrustType", "SessionId", * -ErrorAction SilentlyContinue | Export-Csv -Path "$OutputPath\$DomainName\EntraIDSignInLogsGraphBetaNonInteractive_From_$(($StartDate).ToString("yyyyMMddHHmmss"))UTC_To_$(($EndDate).ToString("yyyyMMddHHmmss"))UTC_$($date)_Processed.csv" -NoTypeInformation -Encoding $Encoding

    Write-Output "`nDone..."
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"

exit
