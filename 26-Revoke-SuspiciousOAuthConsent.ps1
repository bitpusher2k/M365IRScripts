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
# Revoke-SuspiciousOAuthConsent.ps1 - By Bitpusher/The Digital Fox
# v3.2 last updated 2026-03-29
# Script to enumerate OAuth2 permission grants (delegated consent) for
# specified user(s) or all users on a tenant, flag grants with high-risk
# permissions commonly abused in BEC (Mail.Read, Mail.ReadWrite, Mail.Send,
# Files.ReadWrite.All, etc.), and optionally revoke them.
#
# Also checks for known-malicious application IDs (PerfectData, eM Client,
# rclone, etc.) matching the same list used in 22-Get-EnterpriseApplications.ps1.
#
# Usage:
# powershell -executionpolicy bypass -f .\Revoke-SuspiciousOAuthConsent.ps1 -OutputPath "Default"
# powershell -executionpolicy bypass -f .\Revoke-SuspiciousOAuthConsent.ps1 -OutputPath "Default" -UserIds "compromised@contoso.com"
# powershell -executionpolicy bypass -f .\Revoke-SuspiciousOAuthConsent.ps1 -OutputPath "Default" -UserIds "compromised@contoso.com" -RevokeConfirmed "Y"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses Microsoft Graph commands.
# Minimally required tenant role(s): "Application Administrator" or "Cloud App Admin"
#
# References:
# https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant
# https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account
# https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-consent-requests
# https://huntresslabs.github.io/rogueapps
#
#comp #m365 #security #bec #script #irscript #powershell #oauth #consent #revoke

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement

param(
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [string]$RevokeConfirmed = "N",
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Revoke-SuspiciousOAuthConsent",
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

Assert-M365Connection -RequireGraph -GraphScopes @("Application.Read.All", "DelegatedPermissionGrant.ReadWrite.All", "Domain.Read.All", "User.Read.All")

Write-Output "$scriptName started on $ComputerName by $ScriptUserName at $(Get-TimeStamp)" | Tee-Object -FilePath $logFilePath -Append
$process = Get-Process -Id $pid
Write-Output "Setting process priority to `"$Priority`"" | Tee-Object -FilePath $logFilePath -Append
$process.PriorityClass = $Priority
#endregion initialization

$date = Get-Date -Format "yyyyMMddHHmmss"

$ScopeCheck = Get-MgContext | Select -ExpandProperty Scopes
if ($ScopeCheck -notcontains "Directory.ReadWrite.All" -or $ScopeCheck -notcontains "Application.ReadWrite.All") {
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

$OutputCSV = "$OutputPath\$DomainName\OAuthConsentGrants_$($date).csv"
$OutputCSVSuspect = "$OutputPath\$DomainName\SuspiciousOAuthConsentGrants_$($date).csv"

## Known malicious App IDs (same list as 22-Get-EnterpriseApplications.ps1)
$rogueAppIDs = @(
    'ff8d92dc-3d82-41d6-bcbd-b9174d163620',  # Perfectdata
    '2ef68ccc-8a4d-42ff-ae88-2d7bb89ad139',  # Mail_Backup
    'e9a7fea1-1cc0-4cd9-a31b-9137ca5deedd',  # eM Client
    'a245e8c0-b53c-4b67-9b45-751d1dff8e6b',  # Newsletter Software Supermailer
    'b15665d9-eda6-4092-8539-0eec376afd59',  # rclone
    '4761b959-9780-4c2d-87a3-512b4638f767',  # rclone
    'a43e5392-f48b-46a4-a0f1-098b5eeb4757',  # CloudSponge
    'caffae8c-0882-4c81-9a27-d1803af53a40',  # SigParser
    '179d5108-412b-4c95-8e34-06786784ab39',  # PostBox
    '497ac034-5120-4c1a-929a-0351f5c09918',  # ZoomInfo Communitiez Login
    '77468577-4f6e-40e7-b745-11d3d0c28095',  # Fastmail
    '858d7e42-35f0-44b7-9033-df309239a47f',  # Zoominfo Login
    '946c777c-bc85-489e-b034-392389ae23d6'   # Spike
)

## High-risk scopes that are commonly abused in BEC
$highRiskScopes = @(
    'Mail.Read', 'Mail.ReadWrite', 'Mail.Send', 'Mail.ReadBasic',
    'MailboxSettings.ReadWrite',
    'Files.ReadWrite.All', 'Files.Read.All',
    'User.ReadWrite.All', 'Directory.ReadWrite.All',
    'Contacts.ReadWrite', 'Contacts.Read',
    'Notes.ReadWrite.All',
    'Sites.ReadWrite.All',
    'full_access_as_app'
)

Write-Output "`nRetrieving all OAuth2 permission grants (delegated consent)..." | Tee-Object -FilePath $logFilePath -Append

## Build a Service Principal lookup table (AppId -> DisplayName)
Write-Output "Building Service Principal lookup table..." | Tee-Object -FilePath $logFilePath -Append
$spLookup = @{}
$allSPs = Get-MgServicePrincipal -All
foreach ($sp in $allSPs) {
    $spLookup[$sp.Id] = $sp
}

## Get all OAuth2 permission grants
$allGrants = Get-MgOAuth2PermissionGrant -All

## If UserIds is specified, resolve to user object IDs for filtering
$targetUserIds = @()
if ($UserIds) {
    foreach ($uid in ($UserIds -split ',')) {
        $uid = $uid.Trim()
        try {
            $userObj = Get-MgUser -UserId $uid -Property Id, UserPrincipalName -ErrorAction Stop
            $targetUserIds += $userObj.Id
            Write-Output "Targeting user: $($userObj.UserPrincipalName) ($($userObj.Id))" | Tee-Object -FilePath $logFilePath -Append
        } catch {
            Write-Output "WARNING: Could not resolve user '$uid' - skipping." | Tee-Object -FilePath $logFilePath -Append
        }
    }
    # Filter grants to target users
    $grants = $allGrants | Where-Object { $targetUserIds -contains $_.PrincipalId }
} else {
    $grants = $allGrants
}

Write-Output "Found $($grants.Count) OAuth2 permission grant(s) to evaluate." | Tee-Object -FilePath $logFilePath -Append

$allResults = @()
$suspiciousResults = @()

foreach ($grant in $grants) {
    $sp = $spLookup[$grant.ClientId]
    $appDisplayName = if ($sp) { $sp.DisplayName } else { "Unknown" }
    $appId = if ($sp) { $sp.AppId } else { "Unknown" }
    $appEnabled = if ($sp) { $sp.AccountEnabled } else { "Unknown" }

    # Resolve principal (user) display name
    $principalName = "AllPrincipals"
    if ($grant.PrincipalId) {
        try {
            $principal = Get-MgUser -UserId $grant.PrincipalId -Property DisplayName, UserPrincipalName -ErrorAction SilentlyContinue
            $principalName = if ($principal) { $principal.UserPrincipalName } else { $grant.PrincipalId }
        } catch {
            $principalName = $grant.PrincipalId
        }
    }

    # Resolve resource (API) display name
    $resourceName = "Unknown"
    $resourceSP = $spLookup[$grant.ResourceId]
    if ($resourceSP) { $resourceName = $resourceSP.DisplayName }

    # Check suspicion traits
    $suspectTraits = @()
    $grantedScopes = $grant.Scope -split ' '

    # Check for high-risk scopes
    $riskyScopes = $grantedScopes | Where-Object { $highRiskScopes -contains $_ }
    if ($riskyScopes) { $suspectTraits += "HighRiskScopes" }

    # Check for known malicious app ID
    if ($rogueAppIDs -contains $appId) { $suspectTraits += "KnownMaliciousAppID" }

    # Check for admin consent (consentType = "AllPrincipals") which is very powerful
    if ($grant.ConsentType -eq "AllPrincipals") { $suspectTraits += "AdminConsentAllPrincipals" }

    $grantHash = [ordered]@{
        PrincipalName    = $principalName
        PrincipalId      = $grant.PrincipalId
        AppDisplayName   = $appDisplayName
        AppId            = $appId
        AppEnabled       = $appEnabled
        ResourceName     = $resourceName
        ConsentType      = $grant.ConsentType
        Scope            = $grant.Scope
        GrantId          = $grant.Id
        SuspectTraits    = ($suspectTraits -join ", ")
    }

    $grantObject = New-Object PSObject -Property $grantHash
    $allResults += $grantObject

    if ($suspectTraits.Count -gt 0) {
        $suspiciousResults += $grantObject
    }
}

# Export all grants
if ($allResults.Count -gt 0) {
    $allResults | Format-Table PrincipalName, AppDisplayName, ConsentType, Scope -AutoSize
    $allResults | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding $Encoding
    Write-Output "Exported $($allResults.Count) total OAuth2 grant(s) to report." | Tee-Object -FilePath $logFilePath -Append
}

# Export and display suspicious grants
if ($suspiciousResults.Count -gt 0) {
    Write-Output "`n`n===== SUSPICIOUS OAuth2 CONSENT GRANTS FOUND =====" | Tee-Object -FilePath $logFilePath -Append
    $suspiciousResults | Format-Table PrincipalName, AppDisplayName, SuspectTraits, Scope -AutoSize
    $suspiciousResults | Export-Csv -Path $OutputCSVSuspect -NoTypeInformation -Encoding $Encoding
    Write-Output "Exported $($suspiciousResults.Count) suspicious grant(s) to review." | Tee-Object -FilePath $logFilePath -Append

    # Optionally revoke
    if ($RevokeConfirmed -ne "Y") {
        Write-Output "`nTo revoke suspicious grants, run again with -RevokeConfirmed Y" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "Or manually revoke with: Remove-MgOAuth2PermissionGrant -OAuth2PermissionGrantId <GrantId>" | Tee-Object -FilePath $logFilePath -Append
    } else {
        Write-Output "`nRevoking suspicious OAuth2 consent grants..." | Tee-Object -FilePath $logFilePath -Append
        foreach ($suspect in $suspiciousResults) {
            try {
                Remove-MgOAuth2PermissionGrant -OAuth2PermissionGrantId $suspect.GrantId -ErrorAction Stop
                Write-Output "REVOKED: $($suspect.AppDisplayName) for $($suspect.PrincipalName) (Grant: $($suspect.GrantId))" | Tee-Object -FilePath $logFilePath -Append
            } catch {
                Write-Output "ERROR revoking grant $($suspect.GrantId) for $($suspect.AppDisplayName): $_" | Tee-Object -FilePath $logFilePath -Append
            }
        }
        Write-Output "Revocation complete. Verify by re-running this script." | Tee-Object -FilePath $logFilePath -Append
    }
} else {
    Write-Output "`nNo suspicious OAuth2 consent grants found." | Tee-Object -FilePath $logFilePath -Append
}

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output "`n The Output file is available at:" | Tee-Object -FilePath $logFilePath -Append
    Write-Output $OutputCSV | Tee-Object -FilePath $logFilePath -Append
}
if ((Test-Path -Path $OutputCSVSuspect) -eq "True") {
    Write-Output " Suspicious grants report:" | Tee-Object -FilePath $logFilePath -Append
    Write-Output $OutputCSVSuspect | Tee-Object -FilePath $logFilePath -Append
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append
Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
if (-not $NoExplorer) { Invoke-Item "$OutputPath\$DomainName" }
Exit
