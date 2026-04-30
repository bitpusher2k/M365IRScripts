#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#          @VinceVulpes
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-EnterpriseApplications.ps1 - By Bitpusher/The Digital Fox
# v4.0.0 last updated 2026-04-27
# Script to report all Entra ID enterprise applications (Service Principals)
# configured on a tenant, from newest created to oldest, then check
# for suspicious apps (based on known name/App ID, non-alpha name, reply URL,
# "test" name, or name matching a user's name).
# Can then optionally block Enterprise Applications known to be used
# maliciously by AppID (adds them to tenant then disables them).
#
# View full list in your tenant at https://portal.azure.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview/applicationType/All
#
# Usage:
# powershell -executionpolicy bypass -f .\ Get-EnterpriseApplications.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses (ExchangePowerShell), Microsoft Graph commands.
# Minimally required tenant role(s):"Global Reader" or "Directory Reader" (to read app settings), "Application Administrator" or "Cloud App Admin" (writing app settings)
#
#comp #m365 #security #bec #script #irscript #powershell #enterprise #applications #list #entraid #azuread

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Applications, Microsoft.Graph.Users, Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement

param(
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$inoculate = "N",
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
    [string]$Encoding = "utf8NoBOM", # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM",
    [switch]$NoExplorer
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


function Assert-M365Connection {
    <#
    .SYNOPSIS
    Checks for active Exchange Online and/or MS Graph connections and attempts to connect if missing.
    Scoped to the minimum permissions required by this script.
    #>
    param(
        [switch]$RequireEXO,
        [switch]$RequireGraph,
        [switch]$RequireIPPS,
        [string[]]$GraphScopes
    )

    if ($RequireEXO) {
        $exoConnected = $false
        try { $exoConnected = [bool](Get-ConnectionInformation -ErrorAction SilentlyContinue) } catch {}
        if (-not $exoConnected) {
            Write-Output "Exchange Online not connected. Attempting connection..."
            try {
                Connect-ExchangeOnline -ShowBanner:$false
                Write-Output "Exchange Online connected."
            } catch {
                Write-Error "Failed to connect to Exchange Online: $_"
                exit 1
            }
        } else {
            Write-Output "Exchange Online connection verified."
        }
    }

    if ($RequireIPPS) {
        $ippsConnected = $false
        try { $ippsConnected = [bool](Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionUri -match "compliance" }) } catch {}
        if (-not $ippsConnected) {
            Write-Output "Security & Compliance (IPPS) not connected. Attempting connection..."
            try {
                Connect-IPPSSession -ShowBanner:$false
                Write-Output "IPPS connected."
            } catch {
                Write-Error "Failed to connect to IPPS: $_"
                exit 1
            }
        } else {
            Write-Output "IPPS connection verified."
        }
    }

    if ($RequireGraph) {
        $graphContext = $null
        try { $graphContext = Get-MgContext -ErrorAction SilentlyContinue } catch {}
        if (-not $graphContext) {
            Write-Output "MS Graph not connected. Attempting connection with scopes: $($GraphScopes -join ', ')..."
            try {
                Connect-MgGraph -Scopes $GraphScopes -NoWelcome
                Write-Output "MS Graph connected."
            } catch {
                Write-Error "Failed to connect to MS Graph: $_"
                exit 1
            }
        } else {
            # Verify required scopes are present
            $currentScopes = $graphContext.Scopes
            $missingScopes = $GraphScopes | Where-Object { $_ -notin $currentScopes }
            if ($missingScopes) {
                Write-Output "MS Graph connected but missing scopes: $($missingScopes -join ', '). Reconnecting..."
                try {
                    Connect-MgGraph -Scopes $GraphScopes -NoWelcome
                    Write-Output "MS Graph reconnected with required scopes."
                } catch {
                    Write-Warning "Could not reconnect with required scopes. Some operations may fail."
                }
            } else {
                Write-Output "MS Graph connection verified with required scopes."
            }
        }
    }
}

$sw = [Diagnostics.StopWatch]::StartNew()

Assert-M365Connection -RequireGraph -GraphScopes @("Application.Read.All", "Application.ReadWrite.All", "Domain.Read.All", "User.Read.All")

Write-Output "$scriptName started on $ComputerName by $ScriptUserName at  $(Get-TimeStamp)" | Tee-Object -FilePath $logFilePath -Append

$process = Get-Process -Id $pid
Write-Output "Setting process priority to `"$Priority`"" | Tee-Object -FilePath $logFilePath -Append
$process.PriorityClass = $Priority

#endregion initialization

$date = Get-Date -Format "yyyyMMddHHmmss"

$ScopeCheck = Get-MgContext | Select -Expandproperty Scopes
if (($ScopeCheck -notcontains "User.Read.All" -and $ScopeCheck -notcontains "User.ReadWrite.All") -or $ScopeCheck -notcontains "Directory.ReadWrite.All" -or $ScopeCheck -notcontains "Application.ReadWrite.All" -or $ScopeCheck -notcontains "AppRoleAssignment.ReadWrite.All") {
    Write-Output "Necessary graph scopes not found in current context. Press enter to connect with broader scopes, or press Ctrl+c to exit." | Tee-Object -FilePath $logFilePath -Append
    Pause
    Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All", "Directory.ReadWrite.All", "User.ReadWrite.All", "Group.ReadWrite.All", "GroupMember.Read.All", "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Application.ReadWrite.All", "Files.ReadWrite.All", "Sites.ReadWrite.All", "AuditLog.Read.All", "Agreement.Read.All", "IdentityRiskEvent.Read.All", "IdentityRiskyUser.ReadWrite.All", "Mail.Send", "Mail.Read", "SecurityEvents.ReadWrite.All", "Directory.AccessAsUser.All", "AppRoleAssignment.ReadWrite.All", "AuditLogsQuery.Read.All"
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


$OutputCSV = "$OutputPath\$DomainName\AllEnterpriseApplications_$($date).csv"
$OutputCSVSuspect = "$OutputPath\$DomainName\SuspectEnterpriseApplications_$($date).csv"

Write-Output "Listing all Enterprise Applications..."

# Get all Enterprise Apps
# $results = Invoke-MGGraphRequest -Method get -Uri 'https://graph.microsoft.com/v1.0/applications/?$select=id,displayName' -OutputType PSObject -Headers @{'ConsistencyLevel' = 'eventual' }
$results = Get-MgServicePrincipal -All

# alternative just application registrations: $results = Invoke-MGGraphRequest -Method get -Uri 'https://graph.microsoft.com/v1.0/applications/?$select=*' -OutputType PSObject -Headers @{'ConsistencyLevel' = 'eventual' }  # use $results.value in place of $results below
# alternative just application registrations: $resultes = Get-MgApplication -All
# $results | Sort-Object createdDateTime -desc | Select-Object createdDateTime,DisplayName | FT
# $results | Sort-Object createdDateTime -desc | Select-Object createdDateTime,DisplayName | FTion -Encoding $Encoding

# Show & save reports of all apps
$results | Select-Object DisplayName, @{ Name = "CreatedDateTime"; Expression = { $_.additionalproperties['createdDateTime'] } }, AccountEnabled, AppRoleAssignmentRequired, @{ Name = "TagList"; Expression = { $_.tags -join "," } }, @{ Name = "ReplyUrls"; Expression = { $_.ReplyUrls -join "," } }, ServicePrincipalType, Id | Sort-Object createdDateTime -desc | Format-Table
$results | Select-Object DisplayName, @{ Name = "CreatedDateTime"; Expression = { $_.additionalproperties['createdDateTime'] } }, AccountEnabled, AppRoleAssignmentRequired, @{ Name = "TagList"; Expression = { $_.tags -join "," } }, @{ Name = "ReplyUrls"; Expression = { $_.ReplyUrls -join "," } }, ServicePrincipalType, Id | Sort-Object createdDateTime -desc | Export-Csv $OutputCSV -Append -NoTypeInformation -Encoding $Encoding


# Check for suspicious applications

$SuspectList = @()

## Name/app ID matches known rogue app (derived from Huntress list & CrowdStrike rules)

$rogueAppNames = @('Perfectdata','Mail_Backup','eM Client','Newsletter Software Supermailer','rclone','CloudSponge','SigParser','PostBox','ZoomInfo Communitiez','Fastmail','Zoominfo','Spike')
$rogueAppIDs = @('ff8d92dc-3d82-41d6-bcbd-b9174d163620','2ef68ccc-8a4d-42ff-ae88-2d7bb89ad139','e9a7fea1-1cc0-4cd9-a31b-9137ca5deedd','a245e8c0-b53c-4b67-9b45-751d1dff8e6b','b15665d9-eda6-4092-8539-0eec376afd59','4761b959-9780-4c2d-87a3-512b4638f767','a43e5392-f48b-46a4-a0f1-098b5eeb4757','caffae8c-0882-4c81-9a27-d1803af53a40','179d5108-412b-4c95-8e34-06786784ab39','497ac034-5120-4c1a-929a-0351f5c09918','77468577-4f6e-40e7-b745-11d3d0c28095','858d7e42-35f0-44b7-9033-df309239a47f','946c777c-bc85-489e-b034-392389ae23d6')

$SuspectList += $results | Where-Object { $rogueAppNames -contains $_.DisplayName }
$SuspectList += $results | Where-Object { $rogueAppIDs -contains $_.AppId }

## Name is made up of non-alphanumeric characters

$nonAlphaNum = "^[^a-zA-Z0-9]+$"
$SuspectList += $results | Where-Object { $_.DisplayName -match $nonAlphaNum }

## Application has suspicious reply URL (from Proofpoint's MACT campaign 1445 intel - https://www.proofpoint.com/us/blog/cloud-security/revisiting-mact-malicious-applications-credible-cloud-tenants)

$SuspiciousUrl = "^http://localhost:\d+/access/"
$SuspectList += $results | Where-Object { $_.ReplyUrls -match $SuspiciousUrl }

## Name of app is "test"/"test app"/"app test"

$testAppName = "^(test|test app|app test|apptest)$"
$SuspectList += $results | Where-Object { $_.DisplayName -match $testAppName }

## App name matches a user's name

$Users = Get-MgUser -all | select DisplayName, UserPrincipalName

ForEach ($User in $Users) {
    if ($results.DisplayName -Contains $User.DisplayName) { $SuspectList += $results | Where-Object {$_.DisplayName -Contains $User.DisplayName} }
    if ($results.DisplayName -Contains $User.UserPrincipalName) { $SuspectList += $results | Where-Object {$_.DisplayName -Contains $User.UserPrincipalName} }
}


# Show & save reports of suspect apps
if ($SuspectList.length -gt 0) {
    Write-Output "`n`nSuspicious applications found - Please review:"
    $SuspectList | Select-Object DisplayName, @{ Name = "CreatedDateTime"; Expression = { $_.additionalproperties['createdDateTime'] } }, AccountEnabled, AppRoleAssignmentRequired, @{ Name = "TagList"; Expression = { $_.tags -join "," } }, @{ Name = "ReplyUrls"; Expression = { $_.ReplyUrls -join "," } }, ServicePrincipalType, Id -Unique | Sort-Object createdDateTime -desc | Format-Table
    $SuspectList | Select-Object DisplayName, @{ Name = "CreatedDateTime"; Expression = { $_.additionalproperties['createdDateTime'] } }, AccountEnabled, AppRoleAssignmentRequired, @{ Name = "TagList"; Expression = { $_.tags -join "," } }, @{ Name = "ReplyUrls"; Expression = { $_.ReplyUrls -join "," } }, ServicePrincipalType, Id -Unique | Sort-Object createdDateTime -desc | Export-Csv $OutputCSVSuspect -Append -NoTypeInformation -Encoding $Encoding
}


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


# Proactively disable known malicious Enterprise Applications (service principles) by AppID using Microsoft Graph PowerShell
# https://huntresslabs.github.io/rogueapps
# https://cybercorner.tech/common-oauth-apps-used-in-business-email-compromise/
# https://docs.datadoghq.com/security/default_rules/def-000-ihv/
# https://github.com/randomaccess3/detections/blob/main/M365_Oauth_Apps/MaliciousOauthAppDetections.json
# https://byteintocyber.com/microsoft-365-application-ids-bec-investigation-resources/
# https://github.com/MicrosoftDocs/entra-docs/blob/main/docs/identity/enterprise-apps/disable-user-sign-in-portal.md
Write-Output "`nKnown potentially malicious Enterprise Application Names & IDs:" | Tee-Object -FilePath $logFilePath -Append
Write-Output "* Perfectdata:                      'ff8d92dc-3d82-41d6-bcbd-b9174d163620'" | Tee-Object -FilePath $logFilePath -Append
Write-Output "* Mail_Backup:                      '2ef68ccc-8a4d-42ff-ae88-2d7bb89ad139'" | Tee-Object -FilePath $logFilePath -Append
Write-Output "* eM Client:                        'e9a7fea1-1cc0-4cd9-a31b-9137ca5deedd'" | Tee-Object -FilePath $logFilePath -Append
Write-Output "* Newsletter Software Supermailer:  'a245e8c0-b53c-4b67-9b45-751d1dff8e6b'" | Tee-Object -FilePath $logFilePath -Append
Write-Output "* rclone:                           'b15665d9-eda6-4092-8539-0eec376afd59'" | Tee-Object -FilePath $logFilePath -Append
Write-Output "* rclone:                           '4761b959-9780-4c2d-87a3-512b4638f767'" | Tee-Object -FilePath $logFilePath -Append
Write-Output "* CloudSponge:                      'a43e5392-f48b-46a4-a0f1-098b5eeb4757'" | Tee-Object -FilePath $logFilePath -Append
Write-Output "* SigParser:                        'caffae8c-0882-4c81-9a27-d1803af53a40'" | Tee-Object -FilePath $logFilePath -Append
Write-Output "* PostBox:                          '179d5108-412b-4c95-8e34-06786784ab39'" | Tee-Object -FilePath $logFilePath -Append
Write-Output "* ZoomInfo Communitiez Login:       '497ac034-5120-4c1a-929a-0351f5c09918'" | Tee-Object -FilePath $logFilePath -Append
Write-Output "* Fastmail:                         '77468577-4f6e-40e7-b745-11d3d0c28095'" | Tee-Object -FilePath $logFilePath -Append
Write-Output "* Zoominfo Login:                   '858d7e42-35f0-44b7-9033-df309239a47f'" | Tee-Object -FilePath $logFilePath -Append
Write-Output "* Spike:                            '946c777c-bc85-489e-b034-392389ae23d6'" | Tee-Object -FilePath $logFilePath -Append

if ($null -eq $inoculate) {
    $inoculate = Read-Host 'Enter Y to proactivly inoculate this tenant against use of these applications'
}
if ($inoculate -eq "Y") {
    # Requires Microsoft Graph PowerShell connection with permission to write application information - Connect-MgGraph -Scopes "Application.ReadWrite.All"
    foreach ($AppID in $rogueAppIDs) {
        $servicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$AppID'"
        if ($null -eq $servicePrincipal) { New-MgServicePrincipal -AppID $AppID ; $servicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$AppID'" }
        # Disable, restrict assignment, and hide each service principal
        Update-MgServicePrincipal -ServicePrincipalId $servicePrincipal.Id -AccountEnabled:$false -AppRoleAssignmentRequired:$true -Tags "HideApp"
    }
    Write-Output "`nKnown potentially malicious Enterprise Applications listed above have been blocked from use by AppID on this tenant.`n" | Tee-Object -FilePath $logFilePath -Append
} elseif ($inoculate -eq "N") {
    Write-Output "`nRun this script again with the '-inoculate Y' attribute to block these applications from being used on this tenant.`n" | Tee-Object -FilePath $logFilePath -Append
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
if (-not $NoExplorer) { Invoke-Item "$OutputPath\$DomainName" }

exit
