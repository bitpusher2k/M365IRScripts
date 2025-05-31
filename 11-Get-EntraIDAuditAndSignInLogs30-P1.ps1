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
# v3.0 last updated 2025-05-31
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
                #Write-Verbose -Message "ConvertTo-FlatObject - Object is null"
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

if (!$DaysAgo) {
    $DaysAgo = Read-Host "Enter number of days back to retrieve Sign-in and Audit log entries (default: 7, max: 30)"
    if ($DaysAgo -eq '') { $DaysAgo = "7" } elseif ($DaysAgo -gt "30") { $DaysAgo = "30" }
}

$StartDate = $(Get-Date).AddDays(- $DaysAgo).ToString("yyyy-MM-dd")

# Get-MsolAccountSku
# Get-MgSubscribedSku | Select -Property Sku*, ConsumedUnits -ExpandProperty PrepaidUnits | Select-Object SkuPartNumber | Format-List
# Get-AzureADSubscribedSku | Select -Property Sku*,ConsumedUnits -ExpandProperty PrepaidUnits
# (Get-MgSubscribedSku).ServicePlans | ? { $_.ServicePlanName -Like 'AAD_PREMIUM*' }
# https://portal.azure.com/#view/Microsoft_AAD_IAM/LicensesMenuBlade/~/Products
# Get-AzureADDomain

Write-Output "`nWARNING - Logs retrieved via AzureAD or Microsoft Graph do NOT contain the 'Authentication Protocol' field - https://www.invictus-ir.com/news/do-not-use-the-get-mgauditlogsignin-for-your-investigations"
Write-Output "This script will attempt to use the beta cmdlet versions to retrieve more sign-in data."
Write-Output "`nAttempting to retrieve Entra ID Audit logs (past $DaysAgo days)..."

if ($host.version.Major -eq 5) {
    Write-Output "Running in AzureAD module native Windows PowerShell 5."
    Write-Output "Will parse AzureADAuditDirectoryLogs as serialized object..."
    Get-AzureADAuditDirectoryLogs -Filter "activityDateTime gt $StartDate" | Select-Object ActivityDateTime, @{ Name = "ActivityDateTimeISO"; expression = { $_.ActivityDateTime.ToUniversalTime().ToString("o") } }, ActivityDisplayName, ResultReason, @{ Name = "InitiatedBy.User.UserPrincipalName"; expression = { $_.InitiatedBy.User.UserPrincipalName } }, @{ Name = "InitiatedBy.User.IpAddress"; expression = { $_.InitiatedBy.User.IpAddress } }, @{ Name = "TargetResources.UserPrincipalName"; expression = { $_.TargetResources.UserPrincipalName } }, @{ Name = "TargetResources.DisplayName"; expression = { $_.TargetResources.DisplayName } }, Category, Result, LoggedByService, Id, CorrelationId, OperationType, @{ Name = "InitiatedBy"; expression = { $_.InitiatedBy -join ";" } }, @{ Name = "TargetResources"; expression = { $_.TargetResources -join ";" } }, @{ Name = "TargetResources.Type"; expression = { $_.TargetResources.Type } }, @{ Name = "Additionaldetails"; expression = { $_.Additionaldetails -join ";" } } | Export-Csv -Path "$OutputPath\$DomainName\EntraIDAuditLogs_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
} elseif ($host.version.Major -gt 5) {
    Write-Output "Running in PowerShell Core."
    Write-Output "Will parse AzureADAuditDirectoryLogs as deserialized object (splitting some values on line-feed - may mangle some cell values)..."
    Get-AzureADAuditDirectoryLogs -Filter "activityDateTime gt $StartDate" | Select-Object ActivityDateTime, @{ Name = "ActivityDateTimeISO"; expression = { $_.ActivityDateTime.ToUniversalTime().ToString("o") } }, ActivityDisplayName, ResultReason, @{ Name = "InitiatedBy.User.UserPrincipalName"; expression = { $_.InitiatedBy.Split("`n")[5].Split(":")[1].Trim() } }, @{ Name = "InitiatedBy.User.IpAddress"; expression = { $_.InitiatedBy.Split("`n")[4].Split(":")[1].Trim() } }, @{ Name = "TargetResources.UserPrincipalName"; expression = { $_.TargetResources.Split("`n")[4].Split(":")[1].Trim() } }, @{ Name = "TargetResources.DisplayName"; expression = { $_.TargetResources.Split("`n")[2].Split(":")[1].Trim() } }, Category, Result, LoggedByService, Id, CorrelationId, OperationType, @{ Name = "InitiatedBy"; expression = { $_.InitiatedBy -join ";" } }, @{ Name = "TargetResources"; expression = { $_.TargetResources -join ";" } }, @{ Name = "TargetResources.Type"; expression = { $_.TargetResources.Split("`n")[3].Split(":")[1].Trim() } }, @{ Name = "Additionaldetails"; expression = { $_.Additionaldetails -join ";" } } | Export-Csv -Path "$OutputPath\$DomainName\EntraIDAuditLogs_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
} else {
    Write-Output "Running in unsupported PowerShell version. Please run in PowerShell 5+."
}
Write-Output "`nDone..."


Write-Output "`nAttempting to retrieve Entra ID Audit logs (past $DaysAgo days) via beta graph cmdlet..."

$EntraAuditLogs = Get-MgBetaAuditLogDirectoryAudit -All -Filter "activityDateTime gt $StartDate"
$EntraAuditLogsJSON = $EntraAuditLogs | ConvertTo-Json -Depth 100
$EntraAuditLogsJSON | Out-File -FilePath "$OutputPath\$DomainName\EntraIDAuditLogsGraphBeta_Past_$($DaysAgo)_Days_From_$($date).json" -Encoding $Encoding
$EntraAuditLogs | ConvertTo-FlatObject -Base 1 -Depth 20 | Export-Csv -Path "$OutputPath\$DomainName\EntraIDAuditLogsGraphBeta_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
[io.file]::readalltext("$OutputPath\$DomainName\EntraIDAuditLogsGraphBeta_Past_$($DaysAgo)_Days_From_$($date).csv").replace("System.Object[]","") | Out-File "$OutputPath\$DomainName\EntraIDAuditLogsGraphBeta_Past_$($DaysAgo)_Days_From_$($date).csv" -Encoding utf8 –Force
Write-Output "`nDone..."

$License = (Get-MgSubscribedSku).ServicePlans | Where-Object { $_.ServicePlanName -like 'AAD_PREMIUM*' }
Write-Output "`n$License"

[bool]$LicenseBool = $License
if (!$LicenseBool) {
    Write-Output "`nRetrieval of Entra ID/AAD sign-in logs through AzureAD and Microsoft Graph API requires Entra ID premium license (P1 or P2)"
    Write-Output "License does not appear to be present - you will have to retrieve logs manually from:"
    Write-Output "`nhttps://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/SignIns"
} else {
    Write-Output "`nAttempting to retrieve Entra ID Sign-in logs (past $DaysAgo days)..."

    if ($host.version.Major -eq 5) {
        Write-Output "Running in AzureAD module native Windows PowerShell 5."
        Write-Output "Will parse AzureADAuditSignInLogs as serialized object..."
        Get-AzureADAuditSignInLogs -Filter "createdDateTime gt $StartDate" | Select-Object CreatedDateTime, UserPrincipalName, UserDisplayName, AppDisplayName, IpAddress, @{ Name = "Location.City"; expression = { $_.Location.City } }, @{ Name = "Location.State"; expression = { $_.Location.State } }, @{ Name = "Location.CountryOrRegion"; expression = { $_.Location.CountryOrRegion } }, @{ Name = "Status.ErrorCode"; expression = { $_.Status.ErrorCode } }, @{ Name = "Status.FailureReason"; expression = { $_.Status.FailureReason } }, ResourceDisplayName, @{ Name = "MfaDetail.AuthMethod"; expression = { $_.MfaDetail.AuthMethod } }, @{ Name = "MfaDetail.AuthDetail"; expression = { $_.MfaDetail.AuthDetail } }, Id, UserId, AppId, ClientAppUsed, CorrelationId, ConditionalAccessStatus, OriginalRequestId, IsInteractive, TokenIssuerName, TokenIssuerType, ProcessingTimeInMilliseconds, RiskDetail, RiskLevelAggregated, RiskLevelDuringSignIn, RiskState, RiskEventTypes, ResourceId, @{ Name = "AuthenticationMethodsUsed"; expression = { $_.AuthenticationMethodsUsed -join ";" } }, @{ Name = "Status"; expression = { $_.Status -join ";" } }, @{ Name = "Status.AdditionalDetails"; expression = { $_.Status.Additionaldetails } }, @{ Name = "DeviceDetail"; expression = { $_.DeviceDetail -join ";" } }, @{ Name = "DeviceDetail.DisplayName"; expression = { $_.DeviceDetail.DisplayName } }, @{ Name = "DeviceDetail.DeviceId"; expression = { $_.DeviceDetail.DeviceId } }, @{ Name = "DeviceDetail.OperatingSystem"; expression = { $_.DeviceDetail.OperatingSystem } }, @{ Name = "DeviceDetail.Browser"; expression = { $_.DeviceDetail.Browser } }, @{ Name = "DeviceDetail.IsCompliant"; expression = { $_.DeviceDetail.IsCompliant } }, @{ Name = "DeviceDetail.IsManaged"; expression = { $_.DeviceDetail.IsManaged } }, @{ Name = "DeviceDetail.TrustType"; expression = { $_.DeviceDetail.TrustType } }, @{ Name = "Location"; expression = { $_.Location -join ";" } }, @{ Name = "MfaDetail"; expression = { $_.MfaDetail -join ";" } }, @{ Name = "AppliedConditionalAccessPolicies"; expression = { $_.AppliedConditionalAccessPolicies -join ";" } }, @{ Name = "AuthenticationProcessingDetails"; expression = { $_.AuthenticationProcessingDetails -join ";" } }, @{ Name = "NetworkLocationDetails"; expression = { $_.NetworkLocationDetails -join ";" } } | Export-Csv -Path "$OutputPath\$DomainName\EntraIDSignInLogs_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    } elseif ($host.version.Major -gt 5) {
        Write-Output "Running in PowerShell Core."
        Write-Output "Will parse AzureADAuditSignInLogs as deserialized object (splitting some values on line feed - may mangle some cell values)..."
        Get-AzureADAuditSignInLogs -Filter "createdDateTime gt $StartDate" | Select-Object CreatedDateTime, UserPrincipalName, UserDisplayName, AppDisplayName, IpAddress, @{ Name = "Location.City"; expression = { $_.Location.Split("`n")[1].Split(":")[1].Trim() } }, @{ Name = "Location.State"; expression = { $_.Location.Split("`n")[2].Split(":")[1].Trim() } }, @{ Name = "Location.CountryOrRegion"; expression = { $_.Location.Split("`n")[3].Split(":")[1].Trim() } }, @{ Name = "Status.ErrorCode"; expression = { $_.Status.Split("`n")[1].Split(":")[1].Trim() } }, @{ Name = "Status.FailureReason"; expression = { $_.Status.Split("`n")[2].Split(":")[1].Trim() } }, ResourceDisplayName, @{ Name = "MfaDetail.AuthMethod"; expression = { $_.MfaDetail.Split("`n")[1].Split(":")[1].Trim() } }, @{ Name = "MfaDetail.AuthDetail"; expression = { $_.MfaDetail.Split("`n")[2].Split(":")[1].Trim() } }, Id, UserId, AppId, ClientAppUsed, CorrelationId, ConditionalAccessStatus, OriginalRequestId, IsInteractive, TokenIssuerName, TokenIssuerType, ProcessingTimeInMilliseconds, RiskDetail, RiskLevelAggregated, RiskLevelDuringSignIn, RiskState, RiskEventTypes, ResourceId, @{ Name = "AuthenticationMethodsUsed"; expression = { $_.AuthenticationMethodsUsed -join ";" } }, @{ Name = "Status"; expression = { $_.Status -join ";" } }, @{ Name = "Status.AdditionalDetails"; expression = { $_.Status.Split("`n")[3].Split(":")[1].Trim() } }, @{ Name = "DeviceDetail"; expression = { $_.DeviceDetail -join ";" } }, @{ Name = "DeviceDetail.DisplayName"; expression = { $_.DeviceDetail.Split("`n")[2].Split(":")[1].Trim() } }, @{ Name = "DeviceDetail.DeviceId"; expression = { $_.DeviceDetail.Split("`n")[1].Split(":")[1].Trim() } }, @{ Name = "DeviceDetail.OperatingSystem"; expression = { $_.DeviceDetail.Split("`n")[3].Split(":")[1].Trim() } }, @{ Name = "DeviceDetail.Browser"; expression = { $_.DeviceDetail.Split("`n")[4].Split(":")[1].Trim() } }, @{ Name = "DeviceDetail.IsCompliant"; expression = { $_.DeviceDetail.Split("`n")[5].Split(":")[1].Trim() } }, @{ Name = "DeviceDetail.IsManaged"; expression = { $_.DeviceDetail.Split("`n")[6].Split(":")[1].Trim() } }, @{ Name = "DeviceDetail.TrustType"; expression = { $_.DeviceDetail.Split("`n")[7].Split(":")[1].Trim() } }, @{ Name = "Location"; expression = { $_.Location -join ";" } }, @{ Name = "MfaDetail"; expression = { $_.MfaDetail -join ";" } }, @{ Name = "AppliedConditionalAccessPolicies"; expression = { $_.AppliedConditionalAccessPolicies -join ";" } }, @{ Name = "AuthenticationProcessingDetails"; expression = { $_.AuthenticationProcessingDetails -join ";" } }, @{ Name = "NetworkLocationDetails"; expression = { $_.NetworkLocationDetails -join ";" } } | Export-Csv -Path "$OutputPath\$DomainName\EntraIDSignInLogs_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    } else {
        Write-Output "Running in unsupported PowerShell version. Please run in PowerShell 5+."
    }
    Write-Output "`nDone..."

    Write-Output "`nAttempting to retrieve Entra ID Sign-in logs (past $DaysAgo days) via beta graph cmdlet..."

    # $EntraSignInLogs = Get-MgBetaAuditLogSignIn -Filter "createdDateTime gt $StartDate" # Limited to 1000 records
    $EntraSignInLogs = Get-MgBetaAuditLogSignIn -All -Filter "createdDateTime gt $StartDate"
    
    # Rough outline of potential code to retrieve pagenated sign-in logs through Invoke-MgGraphRequests, including non-interactive sign-ins.
    #
    # $Url = "https://graph.microsoft.com/beta/auditLogs/signIns"
    # $results = (Invoke-MgGraphRequest -Uri $Url -Method GET).value
    # 
    #  $AppId = <Get app-id from app registration>
    #  $AppSecret = <Get app secret from app registration>
    #  $TenantName = "<yourtenant>.onmicrosoft.com"
    # 
    # $Scope = "https://graph.microsoft.com/.default" $Url = "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token"
    # Add System.Web for urlencode
    # 
    # Add-Type -AssemblyName System.Web
    # 
    # $Body = @{ client_id = $AppId client_secret = $AppSecret scope = $Scope grant_type = 'client_credentials' }
    # Splat the parameters for Invoke-Restmethod for cleaner code
    # 
    # $PostSplat = @{ ContentType = 'application/x-www-form-urlencoded' Method = 'POST' # Create string by joining bodylist with '&' Body = $Body Uri = $Url }
    # 
    # $Request = Invoke-RestMethod @PostSplat
    # 
    # $Header = @{ Authorization = "$($Request.token_type) $($Request.access_token)" } $tokenttl = (Get-Date).AddSeconds(3599) $AADToken = @{ Header = $Header TTL = $tokenttl } 
    # 
    #  $filterQuery += " (signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser' or t eq 'servicePrincipal' or t eq 'managedIdentity'))"
    #  $Uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$encodedFilterQuery"
    #  Invoke-MgGraphRequest -Uri $Uri -Method Get -ContentType "application/json; odata.metadata=minimal; odata.streaming=true;" -OutputType Json
    #
    # $i = 1
    # $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?$filter=createdDateTime gt $($dates.filterstart) and createdDateTime lt $($dates.filterend)"
    # try {$output = Invoke-RestMethod -Uri $Uri -Headers $AADToken.Header -Method Get -ContentType "application/json"} catch {$err = $_; break} 
    # $Logs = $output.value 
    # $count = $logs.Count 
    # $currentprog = $output.value.createddatetime | Select-Object -Last 1 Write-Host "loop: $in $count items found `n Currently on $currentprog"
    # while ($null -ne $output.'@odata.nextLink') { $currenttime = Get-Date $ttl = ($AADToken.TTL - $currenttime).TotalMinutes if ($ttl -lt 3){
    #     $AADToken = GetToken
    # } 
    # try {$output = Invoke-RestMethod -Uri $output.'@odata.nextLink' -Headers $AADToken.Header -Method Get -ContentType "application/json"} catch {$err = $_; break} 
    # $Logs += $output.value 
    # $currentprog = $output.value.createddatetime | Select-Object -Last 1 
    # $count = $logs.count 
    # $i++ 
    # Write-Host "loop: $i n $count items foundn Currently on $currentprog" } 
    # $logs | ConvertTo-Json | Out-File -FilePath $dates.txt 
    
    
    $EntraSignInLogsJSON = $EntraSignInLogs | ConvertTo-Json -Depth 100
    $EntraSignInLogsJSON | Out-File -FilePath "$OutputPath\$DomainName\EntraIDSignInLogsGraphBeta_Past_$($DaysAgo)_Days_From_$($date).json" -Encoding $Encoding
    $EntraSignInLogs | ConvertTo-FlatObject -Base 1 -Depth 20 | Export-Csv -Path "$OutputPath\$DomainName\EntraIDSignInLogsGraphBeta_Past_$($DaysAgo)_Days_From_$($date).csv" -NoTypeInformation -Encoding $Encoding
    [io.file]::readalltext("$OutputPath\$DomainName\EntraIDSignInLogsGraphBeta_Past_$($DaysAgo)_Days_From_$($date).csv").replace("System.Object[]","") | Out-File "$OutputPath\$DomainName\EntraIDSignInLogsGraphBeta_Past_$($DaysAgo)_Days_From_$($date).csv" -Encoding utf8 –Force
    
    # Reload & sort CSV into preferred column order
    $EntraLog = Import-Csv "$OutputPath\$DomainName\EntraIDSignInLogsGraphBeta_Past_$($DaysAgo)_Days_From_$($date).csv"
    $EntraLog = $EntraLog | Select-Object *, @{ n = 'DateOnly'; e = { $_.CreatedDateTime.Split(' ')[0] } }, @{ n = 'TimeOnly'; e = { $_.CreatedDateTime.Split(' ')[1] } }
    $EntraLog | Select-Object "CreatedDateTime", "DateOnly", "TimeOnly", "UserDisplayName", "UserPrincipalName", "IPAddress", "Location.City", "Location.State", "Location.CountryOrRegion", "UserType", "Status.ErrorCode", "Status.FailureReason", "Status.AdditionalDetails", "Status.AdditionalProperties", "AuthenticationRequirement", "ConditionalAccessStatus", "IncomingTokenType", "ResourceDisplayName", "ResourceId", "ClientAppUsed", "DeviceDetail.Browser", "DeviceDetail.OperatingSystem", "UserAgent", "DeviceDetail.DisplayName", "DeviceDetail.IsCompliant", "DeviceDetail.IsManaged", "DeviceDetail.TrustType", "SessionId", * -ErrorAction SilentlyContinue | Export-Csv -Path "$OutputPath\$DomainName\EntraIDSignInLogsGraphBeta_Past_$($DaysAgo)_Days_From_$($date)_Processed.csv" -NoTypeInformation -Encoding $Encoding

    Write-Output "`nDone..."
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"

exit
