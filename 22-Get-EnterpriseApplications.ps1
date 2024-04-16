#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-EnterpriseApplications.ps1 - By Bitpusher/The Digital Fox
# v2.7 last updated 2024-02-26
# Script to list all Entra ID enterprise applications (really all Service Principals)
# configured on a tenant, from newest created to oldest.
#
# Usage:
# powershell -executionpolicy bypass -f .\ Get-EnterpriseApplications.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses (ExchangePowerShell), Microsoft Graph commands.
#
#comp #m365 #security #bec #script #irscript #powershell #enterprise #applications #list #entraid #azuread

#Requires -Version 5.1

param(
    [string]$OutputPath,
    [string]$Encoding = "utf8" # "ascii","ansi","bigendianunicode","unicode","utf8","utf8","utf8NoBOM","utf32"
)

if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }

$date = Get-Date -Format "yyyyMMddHHmmss"

## If OutputPath variable is not defined, prompt for it
if (!$OutputPath) {
    Write-Output ""
    $OutputPath = Read-Host "Enter the output base path, e.g. $($env:userprofile)\Desktop\Investigation (default)"
    if ($OutputPath -eq '') { $OutputPath = "$($env:userprofile)\Desktop\Investigation" }
    Write-Output "Output base path will be in $OutputPath"
} elseif ($OutputPath -eq 'Default') {
    Write-Output ""
    $OutputPath = "$($env:userprofile)\Desktop\Investigation"
    Write-Output "Output base path will be in $OutputPath"
}

## If OutputPath does not exist, create it
$CheckOutputPath = Get-Item $OutputPath -ErrorAction SilentlyContinue
if (!$CheckOutputPath) {
    Write-Output ""
    Write-Output "Output path does not exist. Directory will be created."
    mkdir $OutputPath
}

## Get Primary Domain Name for output subfolder
# $PrimaryDomain = Get-AcceptedDomain | Where-Object Default -eq $true
# $DomainName = $PrimaryDomain.DomainName
$PrimaryDomain = Get-MgDomain | Where-Object { $_.isdefault -eq $True } | Select-Object -Property ID
$DomainName = $PrimaryDomain.ID

$CheckSubDir = Get-Item $OutputPath\$DomainName -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
    Write-Output ""
    Write-Output "Domain sub-directory does not exist. Sub-directory `"$DomainName`" will be created."
    mkdir $OutputPath\$DomainName
}

$OutputCSV = "$OutputPath\$DomainName\AllEnterpriseApplications_$($date).csv"

Write-Output "Listing all Enterprise Applications..."

# $apps = Get-AzureADServicePrincipal -All:$true | ? {$_.Tags -eq "WindowsAzureActiveDirectoryIntegratedApp"}
# $apps

# $ServicePrincipalList = Get-MgServicePrincipal -all

# foreach($servicePrincipal in $ServicePrincipalList){
#	Get-AzureADServiceAppRoleAssignment -ObjectId $ServicePrincipal.objectId | Select-Object ResourceDisplayName, ResourceId, PrincipalDisplayName, PrincipalType | Export-Csv -Path $PathCsv -NoTypeInformation -Append
# }

# Get all Enterprise Apps
# $results = Invoke-MGGraphRequest -Method get -Uri 'https://graph.microsoft.com/v1.0/applications/?$select=id,displayName' -OutputType PSObject -Headers @{'ConsistencyLevel' = 'eventual' }
$results = Get-MgServicePrincipal -All

# alternative just application registrations: $results = Invoke-MGGraphRequest -Method get -Uri 'https://graph.microsoft.com/v1.0/applications/?$select=*' -OutputType PSObject -Headers @{'ConsistencyLevel' = 'eventual' }  # use $results.value in place of $results below
# alternative just application registrations: $resultes = Get-MgApplication -All
# $results | Sort-Object createdDateTime -desc | Select-Object createdDateTime,DisplayName | FT
# $results | Sort-Object createdDateTime -desc | Select-Object createdDateTime,DisplayName | FTion -Encoding $Encoding


$results | Select-Object DisplayName, ServicePrincipalType, @{ Name = "CreatedDateTime"; Expression = { $_.additionalproperties['createdDateTime'] } }, AccountEnabled, Id | Sort-Object createdDateTime -desc | Format-Table
$results | Select-Object DisplayName, ServicePrincipalType, @{ Name = "CreatedDateTime"; Expression = { $_.additionalproperties['createdDateTime'] } }, AccountEnabled, Id | Sort-Object createdDateTime -desc | Export-Csv $OutputCSV -Append -notypeinformat -Encoding $Encoding

# Additional info:
#  Get-MgServicePrincipal -ServicePrincipalId XXXX-xxx-xx-xx-XXXX | Select samlSingleSignOnSettings, loginUrl, logoutUrl, notificationEmailAddresses
#  Get-MgServicePrincipalOwner -ServicePrincipalId XXXX-xxx-xx-xx-XXXX
#  Get-MgServicePrincipalAppRoleAssignment -serviceprincipalid XXXX-xxx-xx-xx-XXXX
#  Remove-MgServicePrincipal -ServicePrincipalId XXXX-xxx-xx-xx-XXXX


if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:"
    Write-Output $OutputCSV
    $Prompt = New-Object -ComObject wscript.shell
    $UserInput = $Prompt.popup("Do you want to open output file?", 0, "Open Output File", 4)
    if ($UserInput -eq 6) {
        Invoke-Item "$OutputCSV"
    }
}
Write-Output "`nDone! Check output path for results."
Invoke-Item "$OutputPath\$DomainName"

exit
