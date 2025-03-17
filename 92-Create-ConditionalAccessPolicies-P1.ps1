#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Create-ConditionalAccessPolicies.ps1 - By Bitpusher/The Digital Fox
# v2.9 last updated 2025-01-29
# Script to backup current Named Locations/Conditional Access Policies and
# to set up basic set of Named Locations and Conditional Access Policies in report-only mode.
#
# CAP info from Microsoft:
# https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa
# https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access
# https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-insights-reporting
# https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation
#
#
# Prompts for creation of:
# *'Allowed Sign-in Countries' Named Location
# *'Blocked High Risk Countries' Named Location
# *'Blocked High Risk IP Addresses' Named Location
# *'Allow Sign-in from Specific Countries Only' Conditional Access Policy
# *'Block Sign-in from High Risk Countries' Conditional Access Policy
# *'Block Sign-in from High Risk IPs' Conditional Access Policy
# *'Require MFA for Device Registration' Conditional Access Policy
# *'Block Legacy Authentication All Apps' Conditional Access Policy
# *'Block sign-in from unused operating systems' ('Windows Phone', 'MacOS', and 'Linux') Conditional Access Policy
# *'Require Multifactor Authentication for Admin Roles' conditional access policy (1 hour)
# *'Require Multifactor Authentication for Azure management' conditional access policy (1 hour)
# *'Require Multifactor Authentication for All Users' conditional access policy (30 days)
# *'Require Hybrid Azure AD joined device (Windows devices need to be on domain and Entra ID)'
# *'Require phishing-resistant MFA for administrators' conditional access policy (new style recommended by Microsoft)
# *'Require MFA authentication strength for all users' conditional access policy (new style recommended by Microsoft)
# *'Require MFA authentication strength for guests' conditional access policy (new style recommended by Microsoft)
# *'Secure security info registration' conditional access policy (new style recommended by Microsoft)
# *'Require authentication strength for device registration' conditional access policy (new style recommended by Microsoft)
# *'Require device compliance' conditional access policy
# *'Restrict device code flow and authentication transfer' conditional access policy
# *'Require MFA for risky sign-in (P2)' conditional access policy (new style recommended by Microsoft)
# *'Require password change for risky users (P2)' conditional access policy (new style recommended by Microsoft)
# *'Block High-Risk Sign-ins (P2)' conditional access policy (only works with Entra ID P2 subscription)
# *'Block High-Risk Users (P2)' conditional access policy (only works with Entra ID P2 subscription)
#
# Enforcing these four policies recreates the protection provided by Microsoft "Security Defaults" through Conditional Access Policies:
# 'Block Legacy Authentication All Apps'
# 'Require Multifactor Authentication for Admin Roles'
# 'Require Multifactor Authentication for Azure management'
# 'Require Multifactor Authentication for All Users'
#
# The ten policies recommended by Microsoft are:
# 'Block legacy authentication'
# 'Require phishing-resistant MFA for administrators'
# 'Require MFA authentication strength for all users'
# 'Require MFA authentication strength for guests'
# 'Secure security info registration'
# 'Require MFA for risky sign-in'
# 'Require password change for risky users'
# 'Require authentication strength for device registration'
# 'Require device compliance'
# 'Restrict device code flow and authentication transfer'
#
#
# Note that conditional access policies are not applied in any particular order. All matching policies apply and the resulting access controls required by the policies are merged. If both "grant" and "block" policies match, block will always win. If multiple policies match and they have different Access Controls like Require MFA, Require Compliant Device or Require Azure AD Joined, the requirements will all be merged and all the access controls from all matching policies have to be met.
#
#
# Usage:
# powershell -executionpolicy bypass -f .\Create-ConditionalAccessPolicies.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses (ExchangePowerShell), Microsoft Graph commands.
# If not connected:
# Connect-MgGraph -Scopes "Policy.Read.All","Policy.ReadWrite.ConditionalAccess","Application.Read.All"
# To check needed permissions for a command:
# (Find-MgGraphCommand -Command New-MgIdentityConditionalAccessNamedLocation)[0].Permissions.name
#
#comp #m365 #security #bec #script #irscript #powershell #conditional #access #policies #CAP #named #location #MFA

#Requires -Version 5.1

param(
    [string]$OutputPath,
    [string]$Encoding = "utf8bom" # "ascii","ansi","bigendianunicode","unicode","utf8","utf8","utf8NoBOM","utf32"
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
    Write-Output "Domain sub-directory does not exist. Sub-directory will be created."
    mkdir $OutputPath\$DomainName
}


Write-Output ""
Write-Output "Current Graph context:"
$Context = Get-MgContext
$Context
Write-Output "Current Graph user:"
$User = Get-MgUser -UserId $Context.Account
$User.DisplayName
$User.UserPrincipalName
$User.ID
$UserID = $User.ID
Write-Output ""
Write-Output "Tenant Entra ID licenses (Conditional Access Policies require at least 'P1' license)."
$LicenseStatus = (Get-MgSubscribedSku).ServicePlans | Where-Object { $_.ServicePlanName -like 'AAD_PREMIUM*' }
if ($LicenseStatus) {
    Write-Output "Connected tenant appears to be license for at least Entra ID P1:"
    $LicenseStatus
} else {
    Write-Output "Tenant does not appear to be licensed to use Conditional Access Policies."
}
Write-Output ""
Write-Output "Script will attempt to backup any currently configured named locations and conditional access policies, then create a basic set of same."
Write-Output "All created policies will initially be in report-only mode, and the current user will be excluded from all created policies."


Write-Output ""
# Write-Output "Number of named location currently configured in tenant:"
# Get-MgIdentityConditionalAccessNamedLocationCount
# (Get-MgIdentityConditionalAccessNamedLocation).AdditionalProperties
# (Get-MgIdentityConditionalAccessPolicy).Conditions.Users

[array]$ConfiguredNamedLocations = Get-MgIdentityConditionalAccessNamedLocation | Sort-Object DisplayName
if ($ConfiguredNamedLocations) {
    Write-Output "Configured Named Locations in tenant:"
    $ConfiguredNamedLocations.DisplayName
    Write-Output ""
    $Continue = Read-Host "Enter 'Y' to backup current Named Locations to JSON"
    if ($Continue -eq "Y") {
        Write-Output "Backing up current Named Locations to JSON..."
        $ConfiguredNamedLocations | ConvertTo-Json -Depth 100 | Out-File "$OutputPath\$DomainName\NamedLocationsExport_$($date).json" -Encoding $Encoding
    }
}

Write-Output ""
[array]$ConfiguredPolicies = Get-MgIdentityConditionalAccessPolicy | Sort-Object DisplayName
if ($ConfiguredPolicies) {
    Write-Output "Configured Conditional Access Policies in tenant:"
    Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, ID, CreatedDateTime, State

    Write-Output ""
    $Continue = Read-Host "Enter 'Y' to backup current Conditional Access Policies to JSON"
    if ($Continue -eq "Y") {
        Write-Output "Backing up current Conditional Access Policies to JSON..."
        $ConfiguredPolicies | ConvertTo-Json -Depth 100 | Out-File "$OutputPath\$DomainName\ConditionalAccessPoliciesExport_$($date).json" -Encoding $Encoding
    }
}


# https://andrewstaylor.com/2022/09/13/securing-azure-ad-quickly-and-programatically/

# ## Create Azure AD Breakglass user
# $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
# $bgpassword = Get-RandomPassword -Length 20
# $PasswordProfile.Password = $bgpassword
# $breakglass = New-MgUser -DisplayName "Azure BreakGlass Account" -PasswordProfile $PasswordProfile -UserPrincipalName "breakglass@$suffix" -AccountEnabled -MailNickName "BreakGlass" -PasswordPolicies "DisablePasswordExpiration"

## Create allowed countries named location
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Allowed Sign-in Countries' Named Location (US only)"
if ($Continue -eq "Y") {
    $params = @{
        "@odata.type"                     = "#microsoft.graph.countryNamedLocation"
        DisplayName                       = "Allowed Sign-in Countries"
        CountriesAndRegions               = @(
            "US"
        )
        IncludeUnknownCountriesAndRegions = $false
    }
    New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params
    Write-Output "Named location created."
    Write-Output ""
}

## Create blocked countries named location
Write-Output ""
Write-Output "High-risk countries - Russia, Nigeria, South Africa, UAE, The Netherlands"
$Continue = Read-Host "Enter 'Y' to create 'Blocked High Risk Countries' Named Location"
if ($Continue -eq "Y") {
    $params = @{
        "@odata.type"                     = "#microsoft.graph.countryNamedLocation"
        DisplayName                       = "Blocked High Risk Countries"
        CountriesAndRegions               = @(# 2022 BEC sources: https://static.fortra.com/agari/pdfs/guide/ag-acid-geography-of-bec-gd.pdf - Percentages by location:
            "RU" # Russia - less than 1%, but it's high signal and low noise
            "NG" # Nigeria - 50% (!)
            "ZA" # South Africa - 9%
            "AE" # United Arab Emirates - 2%
            "NL" # The Netherlands - 4% of Europe's 5%
            # United States - 25%, UK - 3%, Canada 3%
        )
        IncludeUnknownCountriesAndRegions = $false
    }
    New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params
    Write-Output "Named Location created."
    Write-Output ""
}

## Create blocked IP address named location
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Blocked High Risk IP Addresses' Named Location"
if ($Continue -eq "Y") {
    $params = @{
        "@odata.type" = "#microsoft.graph.ipNamedLocation"
        DisplayName   = "Blocked High Risk IP Addresses"
        IsTrusted     = $false
        IpRanges      = @()
    }
    # [array]$Location4 = Read-Host "Enter slash-formatted IPv4 ranges to add to the block list, comma separated (e.g.: '97.98.134.100/32','98.114.200.24/32','98.47.98.66/32','99.115.38.155/32')" # Need to split input into array
    Write-Output "Enter slash-formatted IPv4 range to add to the block list (if any) (e.g.: '97.98.134.100/32')"
    $Location4 = do {
        $IPv4 = Read-Host "Enter IP range, or leave blank to finish"
        $IPv4
    } while ($IPv4 -ne '')
    if (!$Location4.count) { $Location4 = @('97.98.134.100/32') }
    foreach ($IP in $Location4) {
        if ($IP.Length -gt 7 -and $IP -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$') {
            #  -match '^[\d\.\/]{9,18}$'
            $IpRanges = @{}
            $IpRanges.Add("@odata.type", "#microsoft.graph.iPv4CidrRange")
            $IpRanges.Add("CidrAddress", $IP)
            $params.IpRanges += $IpRanges
            # Write-output "IP: $IP"
        }
    }
    # [array]$Location6 = Read-Host "Enter slash-formatted IPv6 ranges to add to the block list (if any), comma separated (e.g.: '2603:8001:bf40:f00:855a:4064:fd77:abcd/128')" # Need to split input into array
    Write-Output "Enter slash-formatted IPv6 range to add to the block list (if any) (e.g.: '2603:8001:bf40:f00:855a:4064:fd77:abcd/128', '2603:8001:bf40:f00:855a:::/64)"
    $Location6 = do {
        $IPv6 = Read-Host "Enter IP range, or leave blank to finish"
        $IPv6
    } while ($IPv6 -ne '')
    if ($Location6.count) {
        foreach ($IP in $Location6) {
            if ($IP.Length -gt 9 -and $IP -match '^[a-f\d\.\:\/]{10,49}$') {
                $IpRanges = @{}
                $IpRanges.Add("@odata.type", "#microsoft.graph.iPv6CidrRange")
                $IpRanges.Add("CidrAddress", $IP)
                $params.IpRanges += $IpRanges
            }
        }
    }
    # $params.IpRanges
    New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params
    Write-Output "Named Location created."
    Write-Output ""
}

## Create allowed countries conditional access policy
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Allow Sign-in from Specific Countries Only' Conditional Access Policy"
if ($Continue -eq "Y") {
    $location = Get-MgIdentityConditionalAccessNamedLocation | Where-Object DisplayName -EQ "Allowed Sign-in Countries"
    $locationid = $location.ID
    $conditions = @{
        Applications   = @{
            includeApplications = 'All'
        };
        Users          = @{
            includeUsers = @(
                "All"
            )
            excludeUsers = @(
                "$UserID"
            )
        };
        ClientAppTypes = @(
            'All'
        );
        Locations      = @{
            includeLocations = @(
                "All"
            );
            excludeLocations = @(
                "$locationid"
            )
        };
    }
    $grantcontrols = @{
        BuiltInControls = @('Block');
        Operator        = 'OR'
    }
    $name = "Allow Sign-in from Specific Countries Only"
    $state = "enabledForReportingButNotEnforced"
    New-MgIdentityConditionalAccessPolicy -DisplayName $name -State $state -Conditions $conditions -GrantControls $grantcontrols
    Write-Output "Policy created."
    Write-Output ""
}

## Create blocked countries conditional access policy
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Block Sign-in from High Risk Countries' Conditional Access Policy"
if ($Continue -eq "Y") {
    $location = Get-MgIdentityConditionalAccessNamedLocation | Where-Object DisplayName -EQ "Blocked High Risk Countries"
    $locationid = $location.ID
    $conditions = @{
        Applications   = @{
            includeApplications = 'All'
        };
        Users          = @{
            includeUsers = @(
                "All"
            )
            excludeUsers = @(
                "$UserID"
            )
        };
        ClientAppTypes = @(
            'All'
        );
        Locations      = @{
            includeLocations = @(
                "$locationid"
            )
        };
    }
    $grantcontrols = @{
        BuiltInControls = @('Block');
        Operator        = 'OR'
    }
    $name = "Block Sign-in from High Risk Countries"
    $state = "enabledForReportingButNotEnforced"
    New-MgIdentityConditionalAccessPolicy -DisplayName $name -State $state -Conditions $conditions -GrantControls $grantcontrols
    Write-Output "Policy created."
    Write-Output ""
}

## Create blocked IPs conditional access policy
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Block Sign-in from High Risk IPs' Conditional Access Policy"
if ($Continue -eq "Y") {
    $location = Get-MgIdentityConditionalAccessNamedLocation | Where-Object DisplayName -EQ "Blocked High Risk IP Addresses"
    $locationid = $location.ID
    $conditions = @{
        Applications   = @{
            includeApplications = 'All'
        };
        Users          = @{
            includeUsers = @(
                "All"
            )
            excludeUsers = @(
                "$UserID"
            )
        };
        ClientAppTypes = @(
            'All'
        );
        Locations      = @{
            includeLocations = @(
                "$locationid"
            )
        };
    }
    $grantcontrols = @{
        BuiltInControls = @('Block');
        Operator        = 'OR'
    }
    $name = "Block Sign-in from High Risk IPs"
    $state = "enabledForReportingButNotEnforced"
    New-MgIdentityConditionalAccessPolicy -DisplayName $name -State $state -Conditions $conditions -GrantControls $grantcontrols
    Write-Output "Policy created."
    Write-Output ""
}

## Create conditional access policy to require MFA for device registration/enrollment
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Require MFA for Device Registration' Conditional Access Policy"
# https://learn.microsoft.com/en-us/mem/intune/enrollment/multi-factor-authentication
if ($Continue -eq "Y") {
    $conditions = @{
        Users          = @{
            includeUsers = @(
                "All"
            )
            excludeUsers = @(
                "$UserID"
            )
        };
        Applications = @{
            IncludeUserActions = @(
                'urn:user:registerdevice'
            );
        }
    }
    $grantcontrols = @{
        Operator        = 'OR'
        BuiltInControls = @(
            "mfa"
        )
    }
    $name = "Require MFA for Device Registration"
    $state = "enabledForReportingButNotEnforced"
    New-MgIdentityConditionalAccessPolicy -DisplayName $name -State $state -Conditions $conditions -GrantControls $grantcontrols
    Write-Output "Policy created."
    Write-Output ""
}

## Create conditional access policy to block legacy authentication
Write-Output ""
Write-Output "Blocked Legacy Protocols include POP, IMAP, SMTP, Older Office Clients and ActiveSync using Basic authentication."
$Continue = Read-Host "Enter 'Y' to create 'Block Legacy Authentication All Apps' Conditional Access Policy"
if ($Continue -eq "Y") {
    $conditions = @{
        Applications   = @{
            includeApplications = 'All'
        };
        Users          = @{
            includeUsers = @(
                "All"
            )
            excludeUsers = @(
                "$UserID"
            )
        };
        ClientAppTypes = @(
            'ExchangeActiveSync',
            'Other'
        );
    }
    $grantcontrols = @{
        BuiltInControls = @('Block');
        Operator        = 'OR'
    }
    $name = "Block Legacy Authentication All Apps"
    $state = "enabledForReportingButNotEnforced"
    New-MgIdentityConditionalAccessPolicy -DisplayName $name -State $state -Conditions $conditions -GrantControls $grantcontrols
    Write-Output "Policy created."
    Write-Output ""
}

## Create conditional access policy to block unused operating system authentication
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Block sign-in from unused operating systems' Conditional Access Policy (includes 'Windows Phone', 'MacOS', and 'Linux')"
if ($Continue -eq "Y") {
    $conditions = @{
        Applications   = @{
            includeApplications = 'All'
        };
        Users          = @{
            includeUsers = @(
                "All"
            )
            excludeUsers = @(
                "$UserID"
            )
        };
        ClientAppTypes = @(
            'All'
        );
        Platforms      = @{
            IncludePlatforms = @(
                "windowsPhone",
                "macOS",
                "linux"
            )
        };
    }
    $grantcontrols = @{
        BuiltInControls = @('Block');
        Operator        = 'OR'
    }
    $name = "Block sign-in from unused operating systems"
    $state = "enabledForReportingButNotEnforced"
    New-MgIdentityConditionalAccessPolicy -DisplayName $name -State $state -Conditions $conditions -GrantControls $grantcontrols
    Write-Output "Policy created."
    Write-Output ""
}

## Create MFA enforcing policy for admins
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Require Multifactor Authentication for Admin Roles' conditional access policy"
if ($Continue -eq "Y") {
    $PolicySettings = @{
        DisplayName     = "Require Multifactor Authentication for Admin Roles"
        state           = "enabledForReportingButNotEnforced"
        conditions      = @{
            ClientAppTypes = @(
                "all"
            )
            Applications   = @{
                includeApplications = @(
                    "All"
                )
            }
            Users          = @{
                excludeUsers = @(
                    "$UserID"
                )
                includeRoles = @(
                    "62e90394-69f5-4237-9190-012177145e10" # Global Administrator role
                    "d2562ede-74db-457e-a7b6-544e236ebb61" # AI Administrator
                    "194ae4cb-b126-40b2-bd5b-6091b380977d" # Security Administrator role
                    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" # SharePoint Administrator role
                    "29232cdf-9323-42fd-ade2-1d097af3e4de" # Exchange Administrator role
                    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" # Conditional Access Administrator role
                    "729827e3-9c14-49f7-bb1b-9608f156bbb8" # Helpdesk Administrator role
                    "b0f54661-2d74-4c50-afa3-1ec803f12efe" # Billing Administrator role
                    "fe930be7-5e62-47db-91af-98c3a49a38b1" # User Administrator role
                    "c4e39bd9-1100-46d3-8c65-fb160da0071f" # Authentication Administrator role
                    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" # Application Administrator role
                    "158c047a-c907-4556-b7ef-446551a6b5f7" # Cloud Application Administrator role
                    "966707d0-3269-4727-9be2-8c3a10f19b9d" # Password Administrator role
                    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" # Privileged Authentication Administrator role
                    "e8611ab8-c189-46e8-94e1-60213ab1f814" # Privileged Role Administrator role
                ) # https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
            }
        }
        grantControls   = @{
            Operator        = "OR"
            BuiltInControls = @(
                "mfa"
            )
        }
        sessionControls = @{
            signInFrequency = @{
                value     = 1
                type      = "hours"
                isEnabled = $true
            }
        }
    }
    New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicySettings
    Write-Output "Policy created."
    Write-Output ""
}

## Create MFA enforcing policy for Azure management access
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Require Multifactor Authentication for Azure management' conditional access policy"
if ($Continue -eq "Y") {
    $PolicySettings = @{
        DisplayName     = "Require Multifactor Authentication for Azure management"
        state           = "enabledForReportingButNotEnforced"
        conditions      = @{
            Applications   = @{
                includeApplications = @(
                    "797f4846-ba00-4fd7-ba43-dac1f8f63013" # Windows Azure Service Management API (Azure portal, Azure PowerShell, Azure CLI)
                )
            }
            Users          = @{
                includeUsers = @(
                    "All"
                )
                excludeUsers = @(
                    "$UserID"
                )
            }
            ClientAppTypes = @(
                "all"
            )
        }
        grantControls   = @{
            Operator        = "AND"
            BuiltInControls = @(
                "mfa"
            )
        }
        sessionControls = @{
            signInFrequency = @{
                value     = 1
                type      = "hours"
                isEnabled = $true
            }
        }
    }
    New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicySettings
    Write-Output "Policy created."
    Write-Output ""
}

## Create MFA enforcing policy for all users
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Require Multifactor Authentication for All Users' conditional access policy"
if ($Continue -eq "Y") {
    $PolicySettings = @{
        DisplayName     = "Require Multifactor Authentication for All Users"
        state           = "enabledForReportingButNotEnforced"
        conditions      = @{
            Applications   = @{
                includeApplications = @(
                    "All"
                )
            }
            Users          = @{
                includeUsers = @(
                    "All"
                )
                excludeUsers = @(
                    "$UserID"
                )
            }
            ClientAppTypes = @(
                "all"
            )
        }
        grantControls   = @{
            Operator        = "AND"
            BuiltInControls = @(
                "mfa"
            )
        }
        sessionControls = @{
            signInFrequency = @{
                value     = 30
                type      = "days"
                isEnabled = $true
            }
        }
    }
    New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicySettings
    Write-Output "Policy created."
    Write-Output ""
}

## Create Require Hybrid Azure AD joined device policy
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Require Hybrid Azure AD joined device' conditional access policy"
if ($Continue -eq "Y") {
    $PolicySettings = @{
        DisplayName     = "Require Hybrid Azure AD joined device"
        state           = "enabledForReportingButNotEnforced"
        conditions      = @{
            Applications   = @{
                includeApplications = @(
                    "All"
                )
            }
            Users          = @{
                includeUsers = @(
                    "All"
                )
                excludeUsers = @(
                    "$UserID"
                )
            }
            ClientAppTypes = @(
                "all"
            )
        }
        grantControls   = @{
            Operator        = "AND"
            BuiltInControls = @(
                "domainJoinedDevice"
            )
        }
    }
    New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicySettings
    Write-Output "Policy created."
    Write-Output ""
}

## Create Require phishing-resistant MFA for administrators policy - If you use external authentication methods, these are currently incompatible with authentication strength and you should use the Require multifactor authentication grant control.
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Require phishing-resistant MFA for administrators' conditional access policy"
if ($Continue -eq "Y") {
    $PolicySettings = @{
        DisplayName     = "Require phishing-resistant MFA for administrators"
        state           = "enabledForReportingButNotEnforced"
        conditions      = @{
            ClientAppTypes = @(
                "all"
            )
            Applications   = @{
                includeApplications = @(
                    "All"
                )
            }
            Users          = @{
                excludeUsers = @(
                    "$UserID"
                )
                includeRoles = @(
                    "62e90394-69f5-4237-9190-012177145e10" # Global Administrator role
                    "d2562ede-74db-457e-a7b6-544e236ebb61" # AI Administrator
                    "194ae4cb-b126-40b2-bd5b-6091b380977d" # Security Administrator role
                    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" # SharePoint Administrator role
                    "29232cdf-9323-42fd-ade2-1d097af3e4de" # Exchange Administrator role
                    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" # Conditional Access Administrator role
                    "729827e3-9c14-49f7-bb1b-9608f156bbb8" # Helpdesk Administrator role
                    "b0f54661-2d74-4c50-afa3-1ec803f12efe" # Billing Administrator role
                    "fe930be7-5e62-47db-91af-98c3a49a38b1" # User Administrator role
                    "c4e39bd9-1100-46d3-8c65-fb160da0071f" # Authentication Administrator role
                    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" # Application Administrator role
                    "158c047a-c907-4556-b7ef-446551a6b5f7" # Cloud Application Administrator role
                    "966707d0-3269-4727-9be2-8c3a10f19b9d" # Password Administrator role
                    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" # Privileged Authentication Administrator role
                    "e8611ab8-c189-46e8-94e1-60213ab1f814" # Privileged Role Administrator role
                ) # https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
            }
        }
        grantControls   = @{
            Operator        = "OR"
            AuthenticationStrength = @{
                Id = "00000000-0000-0000-0000-000000000004"
            }
        }
    }
    New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicySettings
    Write-Output "Policy created."
    Write-Output ""
}

## Create Require MFA authentication strength for all users policy - If you use external authentication methods, these are currently incompatable with authentication strength and you should use the Require multifactor authentication grant control.
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Require MFA authentication strength for all users' conditional access policy"
if ($Continue -eq "Y") {
    $PolicySettings = @{
        DisplayName     = "Require MFA authentication strength for all users"
        state           = "enabledForReportingButNotEnforced"
        conditions      = @{
            Applications   = @{
                includeApplications = @(
                    "All"
                )
            }
            Users          = @{
                includeUsers = @(
                    "All"
                )
                excludeUsers = @(
                    "$UserID"
                )
            }
            ClientAppTypes = @(
                "all"
            )
        }
        grantControls   = @{
            Operator        = "OR"
            AuthenticationStrength = @{
                Id = "00000000-0000-0000-0000-000000000002"
            }
        }
    }
    New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicySettings
    Write-Output "Policy created."
    Write-Output ""
}   
    
## Create Require MFA authentication strength for guests policy - Currently, you can only apply authentication strength policies to external users who authenticate with Microsoft Entra ID. For email one-time passcode, SAML/WS-Fed, and Google federation users, use the MFA grant control to require MFA.
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Require MFA authentication strength for guests' conditional access policy"
if ($Continue -eq "Y") {
    $PolicySettings = @{
        DisplayName     = "Require MFA authentication strength for guests"
        state           = "enabledForReportingButNotEnforced"
        conditions      = @{
            Applications   = @{
                includeApplications = @(
                    MembershipKind = "All"
                )
            }
            Users          = @{
                IncludeGuestsOrExternalUsers = @{
                    ExternalTenants = @(
                        "All"
                    )
                    GuestOrExternalUserTypes = "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider"
                }
                excludeUsers = @(
                    "$UserID"
                )
            }
            ClientAppTypes = @(
                "all"
            )
        }
        grantControls   = @{
            Operator        = "OR"
            AuthenticationStrength = @{
                Id = "00000000-0000-0000-0000-000000000002"
            }
        }
    }
    New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicySettings
    Write-Output "Policy created."
    Write-Output ""
}   

## Create Secure security info registration policy - If you use external authentication methods, these are currently incompatable with authentication strength and you should use the Require multifactor authentication grant control.
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Secure security info registration policy' conditional access policy"
if ($Continue -eq "Y") {
    $conditions = @{
        Users          = @{
            includeUsers = @(
                "All"
            )
            excludeUsers = @(
                "$UserID"
            )
            "ExcludeGuestsOrExternalUsers" = @{
				"ExternalTenants" = @{
					MembershipKind = "all"
				}
				GuestOrExternalUserTypes = "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider"
			}
        };
        Applications = @{
            IncludeUserActions = @(
                'urn:user:registerdevice'
            );
        }
        Locations      = @{
            includeLocations = @(
                "All"
            );
            excludeLocations = @(
                "AllTrusted"
            )
        }
    }
    $grantControls   = @{
        Operator        = "OR"
        AuthenticationStrength = @{
            Id = "00000000-0000-0000-0000-000000000002"
        }
    }
    $name = "Secure security info registration policy"
    $state = "enabledForReportingButNotEnforced"
    New-MgIdentityConditionalAccessPolicy -DisplayName $name -State $state -Conditions $conditions -GrantControls $grantcontrols
    Write-Output "Policy created."
    Write-Output ""
}

## Create Require authentication strength for device registration policy - If you use external authentication methods, these are currently incompatible with authentication strength and you should use the Require multifactor authentication grant control.
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Require authentication strength for device registration' conditional access policy"
if ($Continue -eq "Y") {
    $conditions = @{
        Users          = @{
            includeUsers = @(
                "All"
            )
            excludeUsers = @(
                "$UserID"
            )
        };
        Applications = @{
            IncludeUserActions = @(
                'urn:user:registerdevice'
            );
        }
    }
    $grantControls   = @{
        Operator        = "OR"
        AuthenticationStrength = @{
            Id = "00000000-0000-0000-0000-000000000002"
        }
    }
    $name = "Require authentication strength for device registration"
    $state = "enabledForReportingButNotEnforced"
    New-MgIdentityConditionalAccessPolicy -DisplayName $name -State $state -Conditions $conditions -GrantControls $grantcontrols
    Write-Output "Policy created."
    Write-Output ""
}

## Create Require device compliance policy - Without a compliance policy created in Microsoft Intune this Conditional Access policy will not function as intended. Create a compliance policy first and ensure you have at least one compliant device before proceeding.
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Require device compliance' conditional access policy"
if ($Continue -eq "Y") {
    $PolicySettings = @{
        DisplayName     = "Require device compliance"
        state           = "enabledForReportingButNotEnforced"
        conditions      = @{
            Applications   = @{
                includeApplications = @(
                    "All"
                )
            }
            Platforms          = @{
                IncludePlatforms = @(
                    "All"
                )
                ExcludePlatforms = @(
                    "android"
                    "iOS"
                    "macOS"
                    "linux"
                )
            }
            Users          = @{
                includeUsers = @(
                    "All"
                )
                excludeUsers = @(
                    "$UserID"
                )
            }
            ClientAppTypes = @(
                "all"
            )
        }
        grantControls   = @{
            Operator        = "OR"
            BuiltInControls = @(
                "compliantDevice"
            )
        }
    }
    New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicySettings
    Write-Output "Policy created."
    Write-Output ""
}

## Create Restrict device code flow and authentication transfer policy
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Restrict device code flow and authentication transfer' conditional access policy (manual completion of configuration required)"
if ($Continue -eq "Y") {
    $PolicySettings = @{
        DisplayName     = "Restrict device code flow and authentication transfer"
        state           = "enabledForReportingButNotEnforced"
        conditions      = @{
            Applications   = @{
                includeApplications = @(
                    "All"
                )
            }
            Users          = @{
                includeUsers = @(
                    "All"
                )
                excludeUsers = @(
                    "$UserID"
                )
            }
            ClientAppTypes = @(
                "all"
            )
        }
        grantControls   = @{
            Operator        = "AND"
            BuiltInControls = @(
                "block"
            )
        }
    }
    New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicySettings
    Write-Output "Policy created."
    Write-Output "NOTE: Authentication Flows is in preview and NOT FULLY CONFIGURABLE FROM POWERSHELL - Go to this policy > Conditions > Authentication Flows, set Configure to Yes, Select Device code flow and Authentication transfer, and Save to finish configuration."
    Write-Output "Opening Edge browser window to finish policy configuration..."
    Write-Output "https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies"
    Start-Process msedge.exe -ArgumentList "https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies"
    Write-Output ""
}

## Create Require MFA for risky sign-in (P2) policy
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Require MFA for risky sign-in (P2)' conditional access policy (only works with Entra ID P2 subscription)"
if ($Continue -eq "Y") {
    $PolicySettings = @{
        DisplayName     = "Require MFA for risky sign-in (P2)"
        state         = "enabledForReportingButNotEnforced"
        conditions    = @{
            Applications     = @{
                includeApplications = @(
                    "All"
                )
            }
            Users            = @{
                includeUsers = @(
                    "All"
                )
                excludeUsers = @(
                    "$UserID"
                )
            }
            ClientAppTypes   = @(
                "all"
            )
            signInRiskLevels = @(
                "high"
                "medium"
            )
        }
        grantControls   = @{
            Operator        = "OR"
            AuthenticationStrength = @{
                Id = "00000000-0000-0000-0000-000000000002"
            }
        }
        sessionControls = @{
            signInFrequency = @{
                AuthenticationType = "primaryAndSecondaryAuthentication"
                FrequencyInterval = "everyTime"
                isEnabled = $true
            }
        }
    }
    New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicySettings
    Write-Output "Policy created."
    Write-Output ""
}

## Create Require password change for risky users (P2) policy
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Require password change for risky users (P2)' conditional access policy (only works with Entra ID P2 subscription)"
if ($Continue -eq "Y") {
    $PolicySettings = @{
        DisplayName     = "Require password change for risky users (P2)"
        state         = "enabledForReportingButNotEnforced"
        conditions    = @{
            Applications     = @{
                includeApplications = @(
                    "All"
                )
            }
            Users            = @{
                includeUsers = @(
                    "All"
                )
                excludeUsers = @(
                    "$UserID"
                )
            }
            ClientAppTypes   = @(
                "all"
            )
            userRiskLevels = @(
                "high"
            )
        }
        grantControls   = @{
            Operator        = "AND"
            AuthenticationStrength = @{
                Id = "00000000-0000-0000-0000-000000000002"
            }
            BuiltInControls = @(
                "passwordChange"
            )
        }
        sessionControls = @{
            signInFrequency = @{
                AuthenticationType = "primaryAndSecondaryAuthentication"
                FrequencyInterval = "everyTime"
                isEnabled = $true
            }
        }
    }
    New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicySettings
    Write-Output "Policy created."
    Write-Output ""
}

## Create policy to block high-risk sign-ins (P2)
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Block High-Risk Sign-ins (P2)' conditional access policy (only works with Entra ID P2 subscription)"
if ($Continue -eq "Y") {
    $PolicySettings = @{
        DisplayName   = "Block High-Risk Sign-ins (P2)"
        state         = "enabledForReportingButNotEnforced"
        conditions    = @{
            Applications     = @{
                includeApplications = @(
                    "All"
                )
            }
            Users            = @{
                includeUsers = @(
                    "All"
                )
                excludeUsers = @(
                    "$UserID"
                )
            }
            ClientAppTypes   = @(
                "all"
            )
            signInRiskLevels = @(
                "high"
            )
        }
        grantControls = @{
            Operator        = "OR"
            BuiltInControls = @(
                "block"
            )
        }
    }
    New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicySettings
    Write-Output "Policy created."
    Write-Output ""
}

## Create policy to block high-risk users (P2)
Write-Output ""
$Continue = Read-Host "Enter 'Y' to create 'Block High-Risk Users (P2)' conditional access policy (only works with Entra ID P2 subscription)"
if ($Continue -eq "Y") {
    $PolicySettings = @{
        DisplayName   = "Block High-Risk Users (P2)"
        state         = "enabledForReportingButNotEnforced"
        conditions    = @{
            Applications   = @{
                includeApplications = @(
                    "All"
                )
            }
            Users          = @{
                includeUsers = @(
                    "All"
                )
                excludeUsers = @(
                    "$UserID"
                )
            }
            ClientAppTypes = @(
                "all"
            )
            userRiskLevels = @(
                "high"
            )
        }
        grantControls = @{
            Operator        = "OR"
            BuiltInControls = @(
                "block"
            )
        }
    }
    New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicySettings
    Write-Output "Policy created."
    Write-Output ""
}

## Exclude a break-glass account from all Conditional Access Policies
Write-Output ""
$Continue = Read-Host "Enter 'Y' if you have a break-glass account or another additional account to exclude from all Conditional Access Policies"
if ($Continue -eq "Y") {
    $UserUPN = Read-Host "Enter UserPrincipalName of account to exclude from all Conditional Access Policies"
    $User = Get-MgUser -UserId $UserUPN
    $User.DisplayName
    $User.UserPrincipalName
    $User.ID
    $UserID = $User.ID
    $Parameters = @{
        conditions = @{
            Users = @{
                excludeUsers = @(
                    "$UserID"
                )
            }
        }
    }
    [array]$Policies = Get-MgIdentityConditionalAccessPolicy | Sort-Object DisplayName
    foreach ($Policy in $Policies) {
        Write-Output ("Checking conditional access policy {0}" -f $Policy.DisplayName)
        [array]$ExcludedUsers = $Policy.conditions.Users.excludeUsers
        if ($UserID -notin $ExcludedUsers) {
            Write-Output ("Can't find user $UserUPN in CA policy {0}" -f $Policy.DisplayName)
            Write-Output "Updating policy with account to exclude"
            Update-MgIdentityConditionalAccessPolicy -BodyParameter $Parameters -ConditionalAccessPolicyId $Policy.ID
        }
    }
    Write-Output "Account excluded from policies."
    Write-Output ""
}

Write-Output "`nDone! Check output path for any JSON backups created."
Write-Output ""
Write-Output "Configured Named Locations in tenant:"
(Get-MgIdentityConditionalAccessNamedLocation).DisplayName
Write-Output ""
Write-Output "Configured Conditional Access Policies in tenant (those created by this script are created in 'report-only' mode):"
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, ID, CreatedDateTime, State
Write-Output ""
Write-Output "To enable a policy above use the command: Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId 'XXXX-XXXX-XXXX-XXXXXX' -State enabled"
Write-Output "Or go to https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies to review and enable policies in the Admin Center."
Write-Output ""
Write-Output "For additional policies view Microsoft templates - https://aka.ms/ConditionalAccessTemplateDocs"
Write-Output ""
Write-Output "To view Microsoft Conditional Access templates in PowerShell:"
Write-Output "Get-MgBetaIdentityConditionalAccessTemplate"
Write-Output ""
Write-Output "To deploy Conditional Access policy from template in PowerShell:"
Write-Output '$catemplate = Get-MgBetaIdentityConditionalAccessTemplate -ConditionalAccessTemplateId XXXX-XXXX-XXXX-XXXXXX'
Write-Output 'New-MgIdentityConditionalAccessPolicy -TemplateId $catemplate.Id -DisplayName $catemplate.Name -State enabledForReportingButNotEnforce' # https://ourcloudnetwork.com/how-to-deploy-conditional-access-templates-with-graph-powershell/
Write-Output ""
Invoke-Item "$OutputPath\$DomainName"

exit
