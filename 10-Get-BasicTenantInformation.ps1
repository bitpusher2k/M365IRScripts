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
# Get-BasicTenantInformation.ps1 - By Bitpusher/The Digital Fox
# v4.0.0 last updated 2026-04-27
# Script to collect basic Tenant information at outset of investigation.
#
# Allows quickly verifying the tenant name, subscriptions, auditing status - and saving info to files.
# Also sets global variable "$IRoutput" to %UserProfile\Desktop\Investigation\<Tenant Domain Name>
# For use as output parameter in other investigative modules and scripts.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-BasicTenantInformation.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell, Microsoft Graph commands.
# Minimally required tenant role(s): "Security Reader", Exchange RBAC "View-Only Org Mgmt" (read) or "Org Mgmt" (for Set-AdminAuditLogConfig)
#
#comp #m365 #security #bec #script #info #tenant

#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Users

param(
    [string]$OutputPath = "Default",
    [string]$scriptName = "Get-BasicTenantInformation",
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
    [string]$Encoding = "utf8bom", # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM",
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

Assert-M365Connection -RequireEXO -RequireGraph -GraphScopes @("Domain.Read.All", "Organization.Read.All", "Policy.Read.All", "RoleManagement.Read.Directory", "User.Read.All")

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

$global:IROutput = "$OutputPath\$DomainName"
Write-Output "`nGlobal Variable '`$IRoutput' has been set to '$IRoutput'."
Write-Output "Use with the output directory parameter of other investigative modules for this session."
Write-Output "(e.g., for Invictus IR Microsoft Extractor Suite commands: Get-TransportRules -OutputDir `$IRoutput)"

$admins = Get-MgDirectoryRole | Select-Object DisplayName, Id | ForEach-Object {$role = $_.DisplayName; Get-MgDirectoryRoleMember -DirectoryRoleId $_.id | where-object {$_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.user"} | ForEach-Object {Get-MgUser -userid $_.id } } | Select @{Name="Role"; Expression = {$role}}, DisplayName, UserPrincipalName, Mail, Id | Sort-Object -Property Mail -Unique
$info = Get-MgOrganization # Old: Get-MsolCompanyInformation
$orgconfig = Get-OrganizationConfig
$orgconfigGraph = Get-MgOrganization
$SecurityDefaultsInfo = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
$logconfig = Get-AdminAuditLogConfig
$connectors = Get-InboundConnector
$rules = Get-TransportRule
$licenses = Get-MgSubscribedSku

$FormatEnumerationLimit = 100

$admins | Out-File -FilePath "$OutputPath\$DomainName\TenantAdmins_$($date).txt" -Encoding $Encoding
$info | Format-List | Out-File -FilePath "$OutputPath\$DomainName\TenantCompanyInfo_$($date).txt" -Encoding $Encoding
$orgconfig | Format-List | Out-File -FilePath "$OutputPath\$DomainName\TenantOrgConfig_$($date).txt" -Encoding $Encoding
$orgconfigGraph | Format-List | Out-File -FilePath "$OutputPath\$DomainName\TenantOrgConfig_Graph_$($date).txt" -Encoding $Encoding
$logconfig | Format-List | Out-File -FilePath "$OutputPath\$DomainName\TenantAuditLogConfig_$($date).txt" -Encoding $Encoding
$connectors | Format-List | Out-File -FilePath "$OutputPath\$DomainName\ConnectorConfig_$($date).txt" -Encoding $Encoding
$rules | Format-Table -AutoSize -Wrap | Out-File -FilePath "$OutputPath\$DomainName\TransportRuleConfig_$($date).txt" -Encoding $Encoding
$rules | Format-List | Out-File -FilePath "$OutputPath\$DomainName\TransportRuleConfig_Detailed_$($date).txt" -Encoding $Encoding
$licenses  | Format-List | Out-File -FilePath "$OutputPath\$DomainName\Licenses_$($date).txt" -Encoding $Encoding


Write-Output "`nTenant details:"
Get-MgOrganization # Old: Get-AzureADTenantDetail

Write-Output "`nEntra ID subscriptions (look for AAD premium):"
(Get-MgSubscribedSku).ServicePlans | Where-Object serviceplanname -Like "*aad*"

Write-Output "`nLast directory sync time:"
Get-MgOrganization | Select-Object OnPremisesLastSyncDateTime

Write-Output "`nMailbox auditing should be enabled by default."
Write-Output "Checking the value of 'AuditDisabled' (this should be `"False`"):"
$OrgConfig.AuditDisabled | Format-List

Write-Output "Security Defaults enabled: $($SecurityDefaultsInfo.IsEnabled)"

Write-Output "`nInbound connectors:"
$connectors | Format-Table

Write-Output "`nTransport rules:"
$rules | Format-Table

# If mailbox auditing is disabled it can be enabled with these commands:
# Get-Mailbox -Identity "UserName" | Format-List
# Set-Mailbox -Identity "UserName" -AuditEnabled $true
# $UserMailboxes= Get-mailbox-Filter {(RecipientTypeDetails-eq 'UserMailbox')} ; $UserMailboxes | ForEach {Set-Mailbox $_.Identity -AuditEnabled$true}

Write-Output "`nChecking if Unified Audit Log is enabled - value of 'UnifiedAuditLogIngestionEnabled' (this should be `"True`"):"
$AuditLogEnabled = Get-AdminAuditLogConfig
$AuditLogEnabled.UnifiedAuditLogIngestionEnabled | Format-List
if (!$AuditLogEnabled.UnifiedAuditLogIngestionEnabled) {
    Write-Output "Unified Audit Log does NOT appear to be enabled on tenant. This value will always be 'False' if run from the IPPS (Security & Compliance) PowerShell"
    Write-Output "session instead of Exchange Online Powershell (https://learn.microsoft.com/en-us/purview/audit-log-enable-disable)."
    Write-Output "Check https://compliance.microsoft.com/auditlogsearch and see if searching the audit log from there is possible before"
    Write-Output "attempting to enable the UAC from here."
    $Answer = Read-Host "Enter 'Y' to attempt to enable the UAC now, or simply press enter to continue"
    if ($Answer -eq "Y") {
        Enable-OrganizationCustomization
        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
        Write-Output "Commands to enable the Unified Audit Log have been run, but if it really was not yet enabled data from the UAC will not be available for this investigation."
    }
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
if (-not $NoExplorer) { Invoke-Item "$OutputPath\$DomainName" }

exit
