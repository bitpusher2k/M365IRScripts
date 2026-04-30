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
# Update-M365Modules.ps1
# Created by https://github.com/directorcia @directorcia
# Modified by Bitpusher/The Digital Fox
# v4.0.0 last updated 2026-04-27
# Script to install/update M365 PowerShell modules,
# remove deprecated/obsolete modules, and clean up old module versions.
#
# Usage:
# powershell -executionpolicy bypass -f .\UpdateM365Modules.ps1
#
# Run as admin.
#
# Changes from v3.1:
# - Added automatic removal of deprecated modules (AzureAD, AzureADPreview, MSOnline, AADRM, SharePointPnPPowerShellOnline)
# - Old module versions are now automatically removed after install or update
# - Added NuGet package provider bootstrap
# - Improved error handling and logging
# - Cleaned up obsolete commented-out module blocks
#
#comp #m365 #security #bec #script #update #powershell #modules #install #graph

#Requires -Version 5.1
#Requires -RunAsAdministrator

param(
    ## if no parameters used then don't prompt to install missing modules, just install them
    [switch]$prompt = $false ## if -prompt used then prompt to install missing modules
)

<# CIAOPS
Script provided as is. Use at own risk. No guarantees or warranty provided.

Description - Update all the relevant Microsoft Online PowerShell modules

Source - https://github.com/directorcia/Office365/blob/master/o365-update.ps1

## Prerequisites = 1
## 1. Run PowerShell environment as an administrator

More scripts available by joining http://www.ciaopspatron.com

#>

## --------------------------------------------------------------------------
## Deprecated modules to detect and remove
## - AzureAD: Deprecated 2024-03-30, retired Q3 2025 (Microsoft Entra Blog)
## - AzureADPreview: Same timeline as AzureAD (Microsoft Entra Blog)
## - MSOnline: Deprecated 2024-03-30, retired April-May 2025 (Microsoft Entra Blog)
## - AADRM: Support ended 2020-07-15, replaced by AIPService (Microsoft Learn)
## - SharePointPnPPowerShellOnline: Replaced by PnP.PowerShell
## --------------------------------------------------------------------------
$DeprecatedModules = @(
    @{ Name = "AzureAD";                        Replacement = "Microsoft.Graph / Microsoft.Graph.Beta" }
    @{ Name = "AzureADPreview";                  Replacement = "Microsoft.Graph / Microsoft.Graph.Beta" }
    @{ Name = "MSOnline";                        Replacement = "Microsoft.Graph / Microsoft.Graph.Beta" }
    @{ Name = "AADRM";                           Replacement = "AIPService" }
    @{ Name = "SharePointPnPPowerShellOnline";   Replacement = "PnP.PowerShell" }
)

## --------------------------------------------------------------------------
## Active modules to install/update
## --------------------------------------------------------------------------
$ActiveModules = @(
    @{ Label = "Exchange Online";                       Name = "ExchangeOnlineManagement" }
    @{ Label = "Microsoft Graph";                       Name = "Microsoft.Graph" }
    @{ Label = "Microsoft Graph Beta";                  Name = "Microsoft.Graph.Beta" }
    @{ Label = "Azure (Az)";                            Name = "Az" }
    @{ Label = "Invictus IR Microsoft Extractor Suite";  Name = "Microsoft-Extractor-Suite" }
    ## Uncomment any of the following as needed:
    # @{ Label = "Azure Information Protection";        Name = "AIPService" }
    # @{ Label = "Microsoft Teams";                     Name = "MicrosoftTeams" }
    # @{ Label = "SharePoint Online";                   Name = "Microsoft.Online.SharePoint.PowerShell" }
    # @{ Label = "SharePoint PnP";                      Name = "PnP.PowerShell" }
    # @{ Label = "Windows Autopilot";                   Name = "WindowsAutoPilotIntune" }
    # @{ Label = "Centralized Add-in Deployment";       Name = "O365CentralizedAddInDeployment" }
    # @{ Label = "PowerApps";                           Name = "Microsoft.PowerApps.PowerShell" }
    # @{ Label = "PowerApps Administration";            Name = "Microsoft.PowerApps.Administration.PowerShell" }
    # @{ Label = "Microsoft 365 Commerce";              Name = "MSCommerce" }
)

## ==========================================================================
## Functions
## ==========================================================================

function Test-PackageProvider {
    <#
    .SYNOPSIS
        Ensures a package provider (e.g. NuGet, PowerShellGet) is installed and up-to-date.
    #>
    param([string]$PackageName)

    Write-Output "  Checking package provider: $PackageName"
    try {
        $found = Get-PackageProvider -Name $PackageName -ErrorAction SilentlyContinue
    } catch {
        $found = $null
    }

    if ($found) {
        $localVersion = ($found | Sort-Object Version -Descending | Select-Object -First 1).Version
        try {
            $onlineVersion = (Find-PackageProvider -Name $PackageName -ErrorAction Stop |
                Sort-Object Version -Descending | Select-Object -First 1).Version
        } catch {
            Write-Output "    [Warning] Unable to query online version for $PackageName - skipping update check"
            return
        }

        if ([version]$localVersion -ge [version]$onlineVersion) {
            Write-Output "    Local $localVersion >= online $onlineVersion - no update required`n"
        } else {
            Write-Output "    Local $localVersion < online $onlineVersion - updating..."
            Update-PackageProvider -Name $PackageName -Force -Confirm:$false
            Write-Output "    Updated.`n"
        }
    } else {
        Write-Output "    [Warning] $PackageName not found."
        if ($prompt) {
            do {
                $result = Read-Host -Prompt "    Install this package provider (Y/N)?"
            } until (-not [string]::IsNullOrEmpty($result))
            if ($result -notin @('Y', 'y')) { return }
        }
        Write-Output "    Installing $PackageName..."
        Install-PackageProvider -Name $PackageName -Force -Confirm:$false
        Write-Output "    Installed.`n"
    }
}

function Remove-OldModuleVersions {
    <#
    .SYNOPSIS
        Removes all versions of a module except the specified current version.
    #>
    param(
        [string]$ModuleName,
        [version]$CurrentVersion
    )

    $oldVersions = Get-InstalledModule -Name $ModuleName -AllVersions -ErrorAction SilentlyContinue |
        Where-Object { $_.Version -ne $CurrentVersion }

    if ($oldVersions) {
        $count = @($oldVersions).Count
        Write-Output "    Removing $count old version(s)..."
        foreach ($old in $oldVersions) {
            try {
                Write-Output "      Removing v$($old.Version)..."
                $old | Uninstall-Module -Force -Confirm:$false -ErrorAction Stop
            } catch {
                Write-Output "      [Warning] Could not remove v$($old.Version): $($_.Exception.Message)"
            }
        }
    }
}

function Install-OrUpdateModule {
    <#
    .SYNOPSIS
        Installs a module if missing, updates it if outdated, and removes old versions.
    #>
    param([string]$ModuleName)

    try {
        $installed = Get-InstalledModule -Name $ModuleName -ErrorAction SilentlyContinue
    } catch {
        $installed = $null
    }

    if ($installed) {
        ## Module exists - check for update
        $localVersion = ($installed | Sort-Object Version -Descending | Select-Object -First 1).Version
        try {
            $onlineVersion = (Find-Module -Name $ModuleName -ErrorAction Stop |
                Sort-Object Version -Descending | Select-Object -First 1).Version
        } catch {
            Write-Output "    [Warning] Unable to query PSGallery for $ModuleName - skipping update check"
            return
        }

        if ([version]$localVersion -ge [version]$onlineVersion) {
            Write-Output "    Local v$localVersion >= online v$onlineVersion - no update required"
            ## Still clean up any stale old versions that may be lingering
            Remove-OldModuleVersions -ModuleName $ModuleName -CurrentVersion $localVersion
            Write-Output ""
        } else {
            Write-Output "    Local v$localVersion < online v$onlineVersion - updating..."
            try {
                Update-Module -Name $ModuleName -Force -Confirm:$false -ErrorAction Stop
                Write-Output "    Updated to v$onlineVersion."
            } catch {
                Write-Output "    [Error] Update failed: $($_.Exception.Message)"
                Write-Output ""
                return
            }
            Remove-OldModuleVersions -ModuleName $ModuleName -CurrentVersion $onlineVersion
            Write-Output ""
        }
    } else {
        ## Module not found - install it
        Write-Output "    [Warning] $ModuleName not found."
        if ($prompt) {
            do {
                $result = Read-Host -Prompt "    Install this module (Y/N)?"
            } until (-not [string]::IsNullOrEmpty($result))
            if ($result -notin @('Y', 'y')) { return }
        }
        Write-Output "    Installing $ModuleName..."
        try {
            Install-Module -Name $ModuleName -Force -Confirm:$false -AllowClobber -ErrorAction Stop
            Write-Output "    Installed."
            ## Clean up if multiple versions were somehow pulled in
            $current = (Get-InstalledModule -Name $ModuleName -ErrorAction SilentlyContinue |
                Sort-Object Version -Descending | Select-Object -First 1).Version
            if ($current) {
                Remove-OldModuleVersions -ModuleName $ModuleName -CurrentVersion $current
            }
        } catch {
            Write-Output "    [Error] Install failed: $($_.Exception.Message)"
        }
        Write-Output ""
    }
}

function Remove-DeprecatedModule {
    <#
    .SYNOPSIS
        Detects and removes a deprecated module (all versions), with optional prompt.
    #>
    param(
        [string]$ModuleName,
        [string]$Replacement
    )

    $found = Get-Module -ListAvailable -Name $ModuleName
    if ($found) {
        Write-Output "  [Deprecated] $ModuleName is still installed."
        Write-Output "    Replacement: $Replacement"
        if ($prompt) {
            do {
                $result = Read-Host -Prompt "    Uninstall all versions of $ModuleName (Y/N)?"
            } until (-not [string]::IsNullOrEmpty($result))
            if ($result -notin @('Y', 'y')) {
                Write-Output "    Skipped.`n"
                return
            }
        }
        Write-Output "    Uninstalling all versions of $ModuleName..."
        try {
            ## Try Uninstall-Module first (works for PSGallery-installed modules)
            $installedVersions = Get-InstalledModule -Name $ModuleName -AllVersions -ErrorAction SilentlyContinue
            if ($installedVersions) {
                $installedVersions | Uninstall-Module -Force -Confirm:$false -ErrorAction Stop
                Write-Output "    Removed via Uninstall-Module.`n"
            } else {
                ## Module found by Get-Module but not Get-InstalledModule - likely MSI/manual install
                Write-Output "    [Warning] Module was not installed via PSGallery."
                Write-Output "    You may need to remove it manually via Add/Remove Programs or delete the module folder.`n"
            }
        } catch {
            Write-Output "    [Warning] Could not fully remove $ModuleName`: $($_.Exception.Message)"
            Write-Output "    Try manually: Uninstall-Module $ModuleName -AllVersions -Force`n"
        }
    } else {
        Write-Output "  $ModuleName - not installed (OK)`n"
    }
}

## ==========================================================================
## Main
## ==========================================================================

Write-Output "PowerShell version:"
$PSVersionTable
Write-Output "`nInstalled modules:"
Get-Module -ListAvailable | Format-Table Name, Version -AutoSize
Write-Output ""

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Output "Prompt to install missing modules = $prompt`n"

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "*** ERROR *** - Please re-run PowerShell as Administrator`n"
    Write-Output "Start-Process PowerShell -Verb RunAs"
    exit 1
}

## --- Phase 1: Package providers -------------------------------------------
Write-Output "=========================================="
Write-Output " Phase 1: Package Providers"
Write-Output "==========================================`n"

Test-PackageProvider -PackageName "NuGet"
Test-PackageProvider -PackageName "PowerShellGet"

## --- Phase 2: Remove deprecated modules -----------------------------------
Write-Output "=========================================="
Write-Output " Phase 2: Remove Deprecated Modules"
Write-Output "==========================================`n"

foreach ($dep in $DeprecatedModules) {
    Remove-DeprecatedModule -ModuleName $dep.Name -Replacement $dep.Replacement
}

## --- Phase 3: Install / update active modules -----------------------------
Write-Output "=========================================="
Write-Output " Phase 3: Install / Update Active Modules"
Write-Output "==========================================`n"

foreach ($mod in $ActiveModules) {
    Write-Output "  ** $($mod.Label) module ($($mod.Name))"
    Install-OrUpdateModule -ModuleName $mod.Name
}

Write-Output "`nScript completed."
