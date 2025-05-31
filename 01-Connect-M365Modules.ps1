#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Connect-M365Modules.ps1 - By Bitpusher/The Digital Fox
# v3.0 last updated 2025-05-31
# Script to connect PowerShell session to all needed M365 modules before
# running other investigation & remediation scripts.
#
# Usage:
# powershell -executionpolicy bypass -f .\Connect-M365Modules.ps1
#
# Run with admin privileges
# (M$ Graph module seems to connects more reliably from elevated PowerShell prompt)
#
# Attempts to connect to MS Graph, MSOL, IPPS, Exchange Online, Azure AD
#
#comp #m365 #security #bec #script #connect #powershell #exchangeonline #IPPS #msol #graph #azuread

#Requires -Version 5.1


Write-Output "Script will initiate connections to several M365 modules - Graph, IPPS, Exchange, & AzureAD."
Write-Output "You will need to enter Global Admin credentials to the desired tenant a few times."
if ($host.version.major -gt 5) {
    Write-Output "`nNot running in Windows PowerShell (5)."
    Write-Output "Some older modules may have connection issues or have output deserialized"
}
Write-Output "`nStarting..."
Write-Output "Press F5 if sign-in window opens but does not load..."


Write-Output "`nPart 1 of 5. MS Graph (connecting to Graph first works better)..."
# Import-Module Microsoft.Graph
# Install-Module Microsoft.Graph.Beta
# Import-Module Microsoft.Graph.Beta
Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All", "Directory.ReadWrite.All", "User.ReadWrite.All", "Group.ReadWrite.All", "GroupMember.Read.All", "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Application.ReadWrite.All", "Files.ReadWrite.All", "Sites.ReadWrite.All", "AuditLog.Read.All", "Agreement.Read.All", "IdentityRiskEvent.Read.All", "IdentityRiskyUser.ReadWrite.All", "Mail.Send", "Mail.Read", "SecurityEvents.ReadWrite.All","Directory.AccessAsUser.All", "AppRoleAssignment.ReadWrite.All"

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


Write-Output "`nPart 2 of 5. MSOL Service (Deprecated - skipping)..."
# if ($host.version.major -gt 5) { Import-Module MSonline -UseWindowsPowerShell } # else {Import-Module MSonline}
# # if ( $host.version.major -gt 5 ) {Import-Module MSonline -SkipEditionCheck}
# try {
#     Connect-MsolService
# } catch {
#     Write-Output "*** Error calling Connect-MsolService."
# }


# try {
#     $Test = $Null
#     $Test = Get-MsolDomain -ErrorAction SilentlyContinue
#     if ($Test) {
#         Write-Output "`nMSOL module connected."
#     } else {
#         Write-Output "`n*** MSOL failed to connect - Try to connect again with: Connect-MsolService"
#     }
# } catch {
#     Write-Output "`nMSOL failed to connect - Try to connect again with: Connect-MsolService"
# }


Write-Output "`nPart 3 of 5. IPPS (Security & Compliance)..."
# Import-Module ExchangeOnlineManagement
Connect-IPPSSession
Write-Output "`nPart 4 of 5. Exchange Online (after IPPS so UAC logging check works)..."
Connect-ExchangeOnline

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
-ExchangeEnvironmentName


Write-Output "`nPart 5 of 5. Azure AD (Deprecated)."
if ($host.version.major -gt 5) { Import-Module AzureAD -UseWindowsPowerShell } # else { Import-Module AzureAD }
# if ( $host.version.major -gt 5 ) { Import-Module AzureADPreview -UseWindowsPowerShell } # else { Import-Module AzureAD }
# if ( $host.version.major -gt 5 ) {Import-Module AzureADPreview -SkipEditionCheck} else { Import-Module AzureAD }
#AzureADPreview\Connect-AzureAD
# Start-Sleep -Seconds 2
try {
    Connect-AzureAD
} catch {
    Write-Output "Error calling Connect-AzureAD."
}

try {
    $Test = $Null
    $Test = Get-AzureADTenantDetail -ErrorAction SilentlyContinue
    if ($Test) {
        Write-Output "`nAzureAD module connected."
    } else {
        Write-Output "`n*** AzureAD failed to connect - Try to connect again with: Connect-AzureAD"
    }
} catch {
    Write-Output "`nAzureAD failed to connect - Try to connect again with: Connect-AzureAD"
}


# ---------------------------------------
# If AzureAD commands do not work try repairing the module:
#
# Uninstall-Module AzureADPreview
# Uninstall-Module azuread
# install-module -name azureadpreview
# install-module azureadpreview -AllowClobber
# AzureADPreview\Connect-AzureAD
# man get-azureaddirectory*
# Get-Module AzureAD
# ------------------


Write-Output "`nDone!"
$ConnectedUser = (Get-ConnectionInformation).UserPrincipalName
if (!$ConnectedUser) {
    Write-Output "Connection attempt seems to have failed."
} else {
    Write-Output "Connected as:"
    $ConnectedUser
}
Get-MgContext
(Get-MgContext).Scopes
Write-Output "`nAddress any connection failures or errors above and"
Write-Output "proceed with investigation scripts."
