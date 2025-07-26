#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# UpdateM365Modules.ps1
# Created by https://github.com/directorcia @directorcia
# Modified by Bitpusher/The Digital Fox
# v3.1 last updated 2025-07-26
# Script to install/update MSOL PowerShell modules.
#
# Usage:
# powershell -executionpolicy bypass -f .\UpdateM365Modules.ps1
#
# Run as admin.
#
#comp #m365 #security #bec #script #update #powershell #modules #install #graph

#Requires -Version 5.1

param(## if no parameters used then don't prompt to install missing modules, just install them
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

Write-Output "Powershell version is:"
$PSVersionTable
Write-Output "Installed modules:"
Get-Module -ListAvailable
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Output "`n`nIf you get an error you may need to run: Install-Module -Name Microsoft.Identity.Client -RequiredVersion 4.44.0.0"
Write-Output "`n`nWill now attempt to install/update M365 modules..."


function test-package ($packagename) {
    try {
        $found = Get-PackageProvider -Name $packagename -ErrorAction SilentlyContinue
    } catch {
        $found = $false
    }
    if ($found) {
        ## If module exists then update
        #get version of the module (selects the first if there are more versions installed)
        $version = (Get-PackageProvider -Name $packagename) | Sort-Object Version -Descending | Select-Object Version -First 1
        #get version of the module in psgallery
        $psgalleryversion = Find-PackageProvider -Name $packagename | Sort-Object Version -Descending | Select-Object Version -First 1
        #convert to string for comparison
        $stringver = $version | Select-Object @{ n = 'Version'; e = { $_.Version -as [string] } }
        $a = $stringver | Select-Object version -ExpandProperty version
        #convert to string for comparison
        $onlinever = $psgalleryversion | Select-Object @{ n = 'Version'; e = { $_.Version -as [string] } }
        $b = $onlinever | Select-Object Version -ExpandProperty Version
        #version compare
        if ([version]"$a" -ge [version]"$b") {
            Write-Output "    Local package $a greater or equal to Gallery package $b"
            Write-Output "    No update required`n"
        } else {
            Write-Output "    Local package $a lower version than Gallery package $b"
            Write-Output "    Will be updated"
            update-packageprovider -Name $packagename -Force -confirm:$false
            Write-Output ""
        }
    } else {
        ## If module doesn't exist then prompt to update
        Write-Output -NoNewline "    [Warning]" $pacakgename" package not found.`n"
        if ($prompt) {
            do {
                $result = Read-Host -Prompt "Install this package (Y/N)?"
            } until (-not [string]::IsNullOrEmpty($result))
            if ($result -eq 'Y' -or $result -eq 'y') {
                Write-Output "Installing package", $packagename"`n"
                Install-PackageProvider -Name $packagename -Force -Confirm:$false
            }
        } else {
            Write-Output "Installing package", $packagename"`n"
            Install-PackageProvider -Name $packagename -Force -Confirm:$false
        }
    }
}


function test-install ($modulename) {
    try {
        $found = Get-InstalledModule -Name $modulename -ErrorAction SilentlyContinue
    } catch {
        $found = $false
    }
    if ($found) {
        ## If module exists then update
        #get version of the module (selects the first if there are more versions installed)
        $version = (Get-InstalledModule -Name $modulename) | Sort-Object Version -Descending | Select-Object Version -First 1
        #get version of the module in psgallery
        $psgalleryversion = Find-Module -Name $modulename | Sort-Object Version -Descending | Select-Object Version -First 1
        #convert to string for comparison
        $stringver = $version | Select-Object @{ n = 'ModuleVersion'; e = { $_.Version -as [string] } }
        $a = $stringver | Select-Object Moduleversion -ExpandProperty Moduleversion
        #convert to string for comparison
        $onlinever = $psgalleryversion | Select-Object @{ n = 'OnlineVersion'; e = { $_.Version -as [string] } }
        $b = $onlinever | Select-Object OnlineVersion -ExpandProperty OnlineVersion
        #version compare
        if ([version]"$a" -ge [version]"$b") {
            Write-Output "    Local module $a greater or equal to Gallery module $b"
            Write-Output "    No update required`n"
        } else {
            Write-Output "    Local module $a lower version than Gallery module $b"
            Write-Output "    Will be updated"
            Update-Module -Name $modulename -Force -Confirm:$false
            Write-Output ""
        }
    } else {
        ## If module doesn't exist then prompt to update
        Write-Output -NoNewline "    [Warning]" $modulename" module not found.`n"
        if ($prompt) {
            do {
                $result = Read-Host -Prompt "    Install this module (Y/N)?"
            } until (-not [string]::IsNullOrEmpty($result))
            if ($result -eq 'Y' -or $result -eq 'y') {
                Write-Output "    Installing module", $modulename"`n"
                Install-Module -Name $modulename -Force -Confirm:$false -AllowClobber
            }
        } else {
            Write-Output "    Installing module", $modulename"`n"
            Install-Module -Name $modulename -Force -Confirm:$false -AllowClobber
        }
    }
}

## If you have running scripts that don't have a certificate, run this command once to disable that level of security
## set-executionpolicy -executionpolicy bypass -scope currentuser -force

Write-Output "Prompt to install missing modules =", $prompt"`n"

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "(1 of 16) Update package provider"
    # test-package -packagename NuGet
    test-package -packagename PowerShellGet
    # Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    Write-Output "(2 of 16) Update Azure AD module - Obsolete - Skipping"
    # test-install -ModuleName AzureAD
    Write-Output "(3 of 16) Update Azure Information Protection module"
    $aadrmcheck = Get-Module -ListAvailable -Name aadrm
    if ($aadrmcheck) {
        Write-Output "    [Warning] Older module Azure AD Rights management module (AADRM) is still installed"
        Write-Output "    Uninstalling AADRM module as support ended July 15, 2020 "
        Uninstall-Module aadrm -AllVersions -Force -Confirm:$false
        Write-Output "    Now Azure Information Protection module will now be installed"
    }
    test-install -ModuleName AIPService
    Write-Output "(4 of 16) Update Teams Module"
    test-install -ModuleName MicrosoftTeams
    Write-Output "(5 of 16) Update SharePoint Online module"
    test-install -ModuleName Microsoft.Online.SharePoint.PowerShell
    Write-Output "(6 of 16) Update Microsoft Online module - Obsolete - Skipping"
    # test-install -ModuleName MSOnline
    Write-Output "(7 of 16) Update PowerShellGet module"
    test-install -ModuleName PowershellGet
    Write-Output "(8 of 16) Update Exchange Online module"
    test-install -ModuleName ExchangeOnlineManagement
    Write-Output "(9 of 16) Update Azure module"
    test-install -ModuleName Az
    Write-Output "(10 of 16) Update SharePoint PnP module"
    $pnpcheck = Get-Module -ListAvailable -Name SharePointPnPPowerShellOnline
    if ($pnpcheck) {
        Write-Output "    [Warning] Older SharePoint PnP module is still installed"
        Write-Output "    Uninstalling older SharePoint PnP module"
        Uninstall-Module SharePointPnPPowerShellOnline -AllVersions -Force -Confirm:$false
        Write-Output "    New SharePoint PnP module will now be installed"
    }
    test-install -ModuleName PnP.PowerShell
    Write-Output "(11 of 16) Update Microsoft Graph module"
    test-install -ModuleName Microsoft.Graph # Update-Module Microsoft.Graph
    Write-Output "(11.5 of 16) Update Microsoft Graph Beta module"
    test-install -ModuleName Microsoft.Graph.Beta # Update-Module Microsoft.Graph.Beta
    Write-Output "(12 of 16) Update Windows Autopilot Module"
    ## will also update dependent AzureAD and Microsoft.Graph.Intune modules
    test-install -ModuleName WindowsAutoPilotIntune
    Write-Output "(13 of 16) Centralised Add-in Deployment"
    test-install -ModuleName O365CentralizedAddInDeployment
    Write-Output "(14 of 16) PowerApps"
    test-install -ModuleName Microsoft.PowerApps.PowerShell
    Write-Output "(15 of 16) PowerApps Administration module"
    test-install -ModuleName Microsoft.PowerApps.Administration.PowerShell
    Write-Output "(16 of 16) Microsoft 365 Commerce module"
    test-install -ModuleName MSCommerce
} else {
    Write-Output "*** ERROR *** - Please re-run PowerShell environment as Administrator`n"
    Write-Output "Start-Process PowerShell -Verb RunAs"
}
Write-Output "`nScript completed"
