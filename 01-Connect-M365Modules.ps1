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
# Connect-M365Modules.ps1 - By Bitpusher/The Digital Fox
# v4.0.0 last updated 2026-04-27
# Script to connect PowerShell session to all needed M365 modules before
# running other investigation & remediation scripts.
#
# Usage:
# powershell -executionpolicy bypass -f .\Connect-M365Modules.ps1
#
# powershell -executionpolicy bypass -f .\Connect-M365Modules.ps1 -ReadOnly
#
# Run with admin privileges
# (M$ Graph module seems to connects more reliably from elevated PowerShell prompt)
#
# Attempts to connect to MS Graph, IPPS, Exchange Online (MSOL and Azure AD are now obsolete)
#
#comp #m365 #security #bec #script #connect #powershell #exchangeonline #IPPS #msol #graph #azuread

#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement, Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement

param(
    [switch]$ReadOnly,
    [string]$DebugPreference = "SilentlyContinue",
    [string]$VerbosePreference = "SilentlyContinue",
    [string]$InformationPreference = "Continue"
)

$modules = @("Microsoft.Graph", "Microsoft.Graph.Beta", "ExchangeOnlineManagement", "Microsoft-Extractor-Suite")

foreach ($module in $modules) {
    $ModuleInfo = Get-Module -ListAvailable -Name $module
    if ($ModuleInfo) {
        Write-Output "$module already installed - Version $($ModuleInfo[0].version)"
    } else {
        Write-Output "Installing $module"
        Install-Module $module -Force -SkipPublisherCheck -Scope CurrentUser -ErrorAction Stop | Out-Null
    }
}

$modules = @("Microsoft.Graph", "ExchangeOnlineManagement", "Microsoft-Extractor-Suite")

foreach ($module in $modules) {
    if (Get-Module -Name $module -ListAvailable) {
        Write-Output "$module already loaded"
    } else {
        Write-Output "Loading $module"
        Import-Module $module -Force -Scope Local | Out-Null
    }
}

Write-Output "Script will initiate connections to several M365 modules - Graph, IPPS, Exchange..."
Write-Output "You will need to enter Global Administrator account credentials to the desired tenant a few times for full functionality."
Write-Output "`nFor an IR analyst role with reduced permissions, combine:"
Write-Output "- *Security Reader* (Entra audit/sign-in logs, risk data, secure score, CA policies)"
Write-Output "- *View-Only Organization Management* in Exchange (UAL search, mailbox rules, message trace, permissions)"
Write-Output "  - Included in *Global Reader*"
Write-Output "- OR *Organization Management* in Exchange"
Write-Output "  - Included in *Exchange Administrator*"
Write-Output "- *Compliance Search* in Exchange (if content search needed)"
Write-Output "  - Included in *eDiscovery Manager* (if purge needed)"
Write-Output "`nStarting..."
Write-Output "Press F5 if sign-in window opens but does not load..."


Write-Output "`n ** MS Graph (connecting to Graph first works better)..."
# Import-Module Microsoft.Graph
# Install-Module Microsoft.Graph.Beta
# Import-Module Microsoft.Graph.Beta
if ($ReadOnly) {
    Write-Output "Connecting with read-only scopes..."
    Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All", "Directory.Read.All", "User.Read.All", "Group.Read.All", "GroupMember.Read.All", "Policy.Read.All", "Policy.Read.ConditionalAccess", "Application.Read.All", "Files.Read.All", "Sites.Read.All", "AuditLog.Read.All", "Agreement.Read.All", "IdentityRiskEvent.Read.All", "IdentityRiskyUser.Read.All", "SecurityEvents.Read.All","Directory.AccessAsUser.All", "AppRoleAssignment.Read.All", "AuditLogsQuery.Read.All"
} else {
    Write-Output "Connecting with read-write scopes..."
    Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All", "Directory.ReadWrite.All", "User.ReadWrite.All", "Group.ReadWrite.All", "GroupMember.Read.All", "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Application.ReadWrite.All", "Files.ReadWrite.All", "Sites.ReadWrite.All", "AuditLog.Read.All", "Agreement.Read.All", "IdentityRiskEvent.Read.All", "IdentityRiskyUser.ReadWrite.All", "Mail.Send", "Mail.Read", "SecurityEvents.ReadWrite.All","Directory.AccessAsUser.All", "AppRoleAssignment.ReadWrite.All", "AuditLogsQuery.Read.All"
}

# list of all scopes:
# Find-MgGraphPermission | ? {$_.Name -match "\bRead\b"}
# Find-MgGraphPermission | ? {$_.Name -match "\bReadWrite\b"}
# https://learn.microsoft.com/en-us/graph/permissions-reference
# If connection fails with error "Could not load file or assembly 'Microsoft.Identity.Client, Version=4.44.0.0..."
# run PS as admin and/or run: Install-Module -Name Microsoft.Identity.Client -RequiredVersion 4.44.0.0

$Test = $Null
$Test = Get-MgDomain -ErrorAction SilentlyContinue
if ($Test) {
    Write-Output "`nMS Graph module connected."
} else {
    Write-Output "`n*** MS Graph failed to connect - Try to connect again with: Connect-MgGraph -Scopes `"UserAuthenticationMethod.ReadWrite.All`",`"Directory.ReadWrite.All`",`"User.ReadWrite.All`",`"Group.ReadWrite.All`",`"GroupMember.Read.All`",`"Policy.Read.All`",`"Policy.ReadWrite.ConditionalAccess`",`"Application.ReadWrite.All`",`"Files.ReadWrite.All`",`"Sites.ReadWrite.All`",`"AuditLog.Read.All`",`"Agreement.Read.All`",`"IdentityRiskEvent.Read.All`",`"IdentityRiskyUser.ReadWrite.All`",`"Mail.Send`",`"Mail.Read`",`"SecurityEvents.ReadWrite.All`",`"Directory.AccessAsUser.All`",`"AppRoleAssignment.ReadWrite.All`""
}

# To connect to GCC High/DOD the -Environment parameter needs to be specified:
# GCC
# Connect-MgGraph
# GCC High
# Connect-MgGraph -Environment USGov
# DOD
# Connect-MgGraph -Environment USGovDoD
# List available environments -  Get-MgEnvironment


Write-Output "`n ** IPPS (Security & Compliance - note that version 3.9.0 or greater is required for compliance search operations)..."
# Import-Module ExchangeOnlineManagement
Connect-IPPSSession -EnableSearchOnlySession

Write-Output "`n ** Exchange Online (after IPPS so UAC logging check works)..."
if ($host.version.major -gt 5) {
    Write-Output "Opening Edge browser window to sign in by device. Use code that appears below..."
    Start-Process msedge.exe -ArgumentList "https://login.microsoftonline.com/common/oauth2/deviceauth"
    Connect-ExchangeOnline -Device
} else {
    Connect-ExchangeOnline
}

$EOSessions = Get-PSSession | Select-Object -Property State, Name
$isconnected = (@($EOSessions) -like '@{State=Opened; Name=ExchangeOnlineInternalSession*').Count -gt 0
if ($isconnected) {
    $EOInfo = Get-ConnectionInformation
    $EOInfo | Select-Object State, Name, UserPrincipalName, ConnectionUri, IsEopSession
    Write-Output "`nExchange Online/IPPS module connected."
} else {
    Write-Output "`n*** Exchange Online/IPPS failed to connect - Try to connect again with: Connect-IPPSSession ; Connect-ExchangeOnline"
}

# To connect to GCC High/DOD the -ExchangeEnvironmentName parameter needs to be specified:
# GCC
# Connect-IPPSSession ; Connect-ExchangeOnline
# GCC High
# Connect-IPPSSession -ExchangeEnvironmentName O365USGovGCCHigh ; Connect-ExchangeOnline -ExchangeEnvironmentName O365USGovGCCHigh
# DOD
# Connect-IPPSSession -ExchangeEnvironmentName O365USGovDoD ; Connect-ExchangeOnline -ExchangeEnvironmentName O365USGovDoD


Write-Output "`nDone!"

$EXOInfo = Get-ConnectionInformation
$GraphInfo = Get-MgContext

if ($EXOInfo) {
    Write-Output "Exchange Online connection status:"
    $EXOInfo.State
    $EXOInfo.TenantID
    $EXOInfo.UserPrincipalName
} else {
    Write-Output "Exchange Online Management module not connected."
    Write-Output "Run .\01-Connect-M365Modules.ps1 or Connect-ExchangeOnline to connect."
}

if ($GraphInfo) {
    Write-Output "Graph connection status:"
    $GraphInfo.AuthType
    $GraphInfo.TenantID
    $GraphInfo.Account
    $GraphInfo.Scopes
} else {
    Write-Output "MS Graph module not connected."
    Write-Output "Run .\01-Connect-M365Modules.ps1 or Connect-MgGraph with proper scopes to connect."
}


Write-Output "`nAddress any connection failures or errors above and"
Write-Output "proceed with investigation scripts."
