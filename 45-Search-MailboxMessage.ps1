#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Search-MailboxMessage.ps1 - By Bitpusher/The Digital Fox
# v3.1.1 last updated 2025-09-22 - STILL EXPERIMENTAL and commands may need review during run
# Script to search Exchange Online mailbox(s) using Graph API by Message IDs, subject, sender, date.
# Retrieval in this manner is faster than eDiscovery/content searches.
# Use on a mailbox restored from backup for searches that include messages which have been deleted by threat actor.
# Saves found messages to folder along with a CSV formatted index of message metadata.
#
# Script can create the needed Enterprise App Registration with Mail.Read scope, or 
# pass -TenantID, -ClientID, and -ClientSecret parameters to use an already created app.
# Requires MgGraph connection with Application.ReadWrite.All & User.Read.All scopes to do this, 
# and will create secret for application that expires 10 days from creation.
# Connection information from a previously created application by this script will be in MailAppInfo.json.
#
# https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps
#
#
# Retrieving all InternetMessageId's from "AuditData" blocks in a UAL log export:
# $Ual = Import-CSV .\UALexport.csv
# $UalJson = $Ual.auditdata
# $UalJson = $UalJson | ConvertFrom-Json
# $InternetMessageId = $UalJson.folders.folderitems.internetmessageid
# $InternetMessageId | Out-File .\QueryList.txt -Encoding Utf8NoBom
#
# Be sure to include the full Message ID string (which may include angle brackets) and enclose the value in quotation marks (for example, "d9683b4c-127b-413a-ae2e-fa7dfb32c69d@DM3NAM06BG401.Eop-nam06.prod.protection.outlook.com").
#
# ----------------------
#
# Alternative options for retrieving similar/related information:
#
# eDiscovery/Content Search (no timeframe limit, but slow and clunky to use)
#
# Message trace logs (limited to 10 DAYS):
# Get-MessageTrace -MessageId XSERVER1Tbj1Dj2C700000523@xserver1-ppp-.com| Get-MessageTraceDetail | Select  MessageID, Date, Event, Action, Detail, Data | Out-GridView
#
# Historical message trace logs (limited to past 90 days):
# Start-HistoricalSearch -ReportTitle "Fabrikam Search" -StartDate 1/1/2023 -EndDate 1/7/2023 -MessageID $INetMessageID
#
# Get-Message (Exchange On-prem ONLY)
# Get-messagetrackinglog -MessageID $INetMessageID (Exchange On-prem ONLY)
#
# ----------------------
#
# Usage:
# powershell -executionpolicy bypass -f .\Search-MailboxMessage.ps1 -InputFile ".\QueryList.txt"
#
# powershell -executionpolicy bypass -f .\Search-MailboxMessage.ps1 -InputFile ".\QueryList.txt" -OutputPath "C:\temp" -TenantID "XXX-XXX-XXX" -ClientID "XXX-XXX-XXX" -ClientSecret "XxXxXxX" -UserID "XXX@ZZZ.com"
#
# powershell -executionpolicy bypass -f .\Search-MailboxMessage.ps1 -InputQuery "Phishing Message Subject" -OutputPath "C:\temp" -SearchParam "Subject" -TenantID "XXX-XXX-XXX" -ClientID "XXX-XXX-XXX" -ClientSecret "XxXxXxX" -UserID "XXX@ZZZ.com"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules, or already registered Enterprise Application.
#
# Use with DropShim.bat to allow drag-and-drop processing of an Internet Message ID list.
# Recommended workflow is to run this script initially from the command line in the course of and investigation
# where it will create Entra app, and subsequently use the shim drag-and-drop for message retrieval.
#
# Uses Microsoft Graph commands.
#
#comp #m365 #security #bec #script #irscript #powershell #graph #message #retrieve #search

#Requires -Version 5.1

Param (
    [string]$InputFile,
    [string]$InputQuery,
    [string]$OutputPath = "Default",
    [string]$SearchParam = "MessageID",
    [string]$TenantID,
    [string]$ClientID,
    [string]$ClinetSecret,
    [string]$AppInfo = "MailAppInfo.json",
    [string]$UserId, # UPN of mailbox to search
    [string]$scriptName = "Search-MailboxMessage",
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
    [string]$Encoding = "utf8NoBOM" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
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
$ScopeCheck = (Get-MgContext).Scopes

if (!$InputFile) {
    Get-MgContext
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
} else {
    $OutputPath = $InputFile | split-path -Parent | Split-Path -Parent
    $DomainName = $InputFile | split-path -Parent | Split-Path -Leaf
    $MailAppInfo = Get-Content "$OutputPath\$DomainName\$AppInfo" -ErrorAction SilentlyContinue | Convertfrom-Json
    if (!$MailAppInfo) {
        Get-MgContext
        if (($ScopeCheck -notcontains "User.Read.All" -and $ScopeCheck -notcontains "User.ReadWrite.All") -or $ScopeCheck -notcontains "Directory.ReadWrite.All" -or $ScopeCheck -notcontains "Application.ReadWrite.All" -or $ScopeCheck -notcontains "AppRoleAssignment.ReadWrite.All") {
            Write-Output "Necessary graph scopes not found in current context. Press enter to connect with broader scopes, or press Ctrl+c to exit." | Tee-Object -FilePath $logFilePath -Append
            Pause
            Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All", "Directory.ReadWrite.All", "User.ReadWrite.All", "Group.ReadWrite.All", "GroupMember.Read.All", "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Application.ReadWrite.All", "Files.ReadWrite.All", "Sites.ReadWrite.All", "AuditLog.Read.All", "Agreement.Read.All", "IdentityRiskEvent.Read.All", "IdentityRiskyUser.ReadWrite.All", "Mail.Send", "Mail.Read", "SecurityEvents.ReadWrite.All", "Directory.AccessAsUser.All", "AppRoleAssignment.ReadWrite.All", "AuditLogsQuery.Read.All"
        }
    }
}

$CheckSubDir = Get-Item $OutputPath\$DomainName\Messages_$date -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
    Write-Output ""
    Write-Output "Domain/Messages sub-directory does not exist. Sub-directory `"$DomainName\Messages_$date`" will be created." | Tee-Object -FilePath $logFilePath -Append
    mkdir $OutputPath\$DomainName\Messages_$date
}
Write-Output "Domain/Messages sub-directory will be `"$DomainName\Messages_$date`"" | Tee-Object -FilePath $logFilePath -Append

## If UserId variable is not defined, prompt for it
if (!$UserId) {
    Write-Output ""
    $UserId = Read-Host 'Enter the UPN (email address) of the mailbox(s) to search/retrieve messages from (seaparate multiple with commas, leave blank to search all mailboxes)'
}
if (([string]::IsNullOrEmpty($UserId))) {
    if ($ScopeCheck -contains "User.Read.All" -or $ScopeCheck -contains "User.ReadWrite.All") {
        Write-Output "`nWill attempt to search ALL licensed mailboxes for each query. This could take a long time..." | Tee-Object -FilePath $logFilePath -Append
        $UserId = "ALL"
        $UserList = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,AssignedLicenses"
        $LicensedUsers = $UserList | Where-Object { $_.AssignedLicenses.Count -gt 0 }
        $UnlicensedUsers = $UserList | Where-Object { $_.AssignedLicenses.Count -eq 0 }
        Write-Output "`nList of licensed users on tenant:" | Tee-Object -FilePath $logFilePath -Append
        $licensedUsers | Select-Object DisplayName, UserPrincipalName, ID | Tee-Object -FilePath $logFilePath -Append
        Write-Output "`nThere are $($LicensedUsers.count) licensed users on tenant." | Tee-Object -FilePath $logFilePath -Append
        $LicensedUsers = $LicensedUsers | Select-Object -ExpandProperty UserPrincipalName
    } else {
        Write-Output "`nNot connected to graph with needed scopes. Ending." | Tee-Object -FilePath $logFilePath -Append
        exit 91
    }
} else {
    $UserIds = $UserId -split ','
    if ($ScopeCheck -contains "User.Read.All" -or $ScopeCheck -contains "User.ReadWrite.All") {
        Write-Output "Checking tenant for specified licensed user(s)..." | Tee-Object -FilePath $logFilePath -Append
        $LicensedUsers = @()
        ForEach ($Id in $UserIds) {
            $LicensedUsers = $LicensedUsers + $(Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,AssignedLicenses" | Where-Object { $_.UserPrincipalName -eq $Id -and $_.AssignedLicenses.Count -gt 0})
        }
        if ($LicensedUsers) {
            Write-Output "Licensed user(s) found in tenant." | Tee-Object -FilePath $logFilePath -Append
            $LicensedUsers
            $LicensedUsers = $LicensedUsers | Select-Object -ExpandProperty UserPrincipalName
        } else {
            Write-Output "Licensed user not found in tenant." | Tee-Object -FilePath $logFilePath -Append
        }
    } else {
        Write-Output "Not connected to graph. Assuming UPN(s) are correct..." | Tee-Object -FilePath $logFilePath -Append
        $LicensedUsers = $UserIds
    }
}

if (!$LicensedUsers) {
    Write-Output "No licensed users listed. Ending." | Tee-Object -FilePath $logFilePath -Append
    exit 92
}

if ($SearchParam) {
     Write-Output "Will search using '$SearchParam' query type"
} else {
    Write-Output "`nEnter query type ('MessageID', 'Sender', 'Subject', 'SentAfter') to use"
    $SearchParam = Read-Host "or leave blank to use default 'MessageID' search"
    if ($SearchParam.length -eq 0) {
        $SearchParam = 'MessageID'
    }
}

if ($inputFile) {
    Write-Output "Reading '$InputFile' for query list..."
    $QueryList = Get-Content $inputFile
} elseif ($InputQuery) {
    Write-Output "Will search for '$InputQuery'"
    $QueryList = $InputQuery
} else {
    Write-Output "`nEnter search string of type '$SearchParam' to search individually (be sure to include angle brackets on MessageIDs),"
    Write-Output "enter filename of query list located in $OutputPath\$DomainName\, preceded by an '*' to load specific list,"
    $QueryList = Read-Host "or leave blank to attempt to read default file - $OutputPath\$DomainName\MessageIDList.txt"
    if ($QueryList.length -gt 0 -and $QueryList[0] -eq "*") {
        $QueryList = $QueryList.Substring(1)
        if (Test-Path "$OutputPath\$DomainName\$QueryList") {
            $QueryList = Get-Content "$OutputPath\$DomainName\$QueryList"
        } else {
            Write-Output "Unable to load file."
        }
    } elseif ($QueryList.length -eq 0 -and $(Test-Path "$OutputPath\$DomainName\MessageIDList.txt")) {
        $QueryList = Get-Content "$OutputPath\$DomainName\MessageIDList.txt"
    }
}
if ($QueryList.count -eq 0) {
    Write-Output "Query list not specified. Ending." | Tee-Object -FilePath $logFilePath -Append
    exit 95
}

Write-Output "`nFirst entry of query list:" | Tee-Object -FilePath $logFilePath -Append
$QueryList | Select-Object -first 1 | Tee-Object -FilePath $logFilePath -Append
Write-Output "`nQuery list is $($QueryList.count) items long..." | Tee-Object -FilePath $logFilePath -Append

function Parse-JWTtoken {
    # https://jwt.io/
    [cmdletbinding()]
    param([Parameter(Mandatory=$true)][string]$token)
 
    #Validate as per https://tools.ietf.org/html/rfc7519
    #Access and ID tokens are fine, Refresh tokens will not work
    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }
 
    #Header
    $tokenheader = $token.Split(".")[0].Replace('-', '+').Replace('_', '/')
    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenheader.Length % 4) { Write-Output "Invalid length for a Base-64 char array or string, adding ="; $tokenheader += "=" }
    Write-Output "Base64 encoded (padded) header:"
    Write-Output $tokenheader
    #Convert from Base64 encoded string to PSObject all at once
    Write-Output "Decoded header:"
    [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json | fl | Out-Default
 
    #Payload
    $tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')
    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenPayload.Length % 4) { Write-Output "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
    Write-Output "Base64 encoded (padded) payoad:"
    Write-Output $tokenPayload
    #Convert to Byte array
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    #Convert to string array
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    Write-Output "Decoded array in JSON format:"
    Write-Output $tokenArray
    #Convert from JSON to PSObject
    $tokobj = $tokenArray | ConvertFrom-Json
    Write-Output "Decoded Payload:"
    
    return $tokobj
}

$TokenTime = ''
$token = ''
$MessageInfoIndex = @()

foreach ($UPN in $LicensedUsers) {
    foreach ($QueryString in $QueryList) {

        # Create/renew authorization header token is not set or has not be refreshed in over 30 minutes
        if (!$TokenTime -or $TokenTime.elapsed.totalseconds -gt 1800) {
            Write-Output "`nGetting authentication token..." | Tee-Object -FilePath $logFilePath -Append
            $TokenTime = [Diagnostics.StopWatch]::StartNew()
        
            $MailAppInfo = Get-Content "$OutputPath\$DomainName\$AppInfo" -ErrorAction SilentlyContinue | Convertfrom-Json
            if ($MailAppInfo) {
                Write-Output "`nReading app info from saved $AppInfo..." | Tee-Object -FilePath $logFilePath -Append
                $TenantID = $MailAppInfo.tenantid
                $ClientID = $MailAppInfo.clientid
                $ClientSecret = $MailAppInfo.clientsecret
            }
        
            # https://smsagent.blog/2024/03/19/the-quest-for-a-microsoft-graph-access-token/
            # https://goodworkaround.com/2020/09/14/easiest-ways-to-get-an-access-token-to-the-microsoft-graph/
            # https://rakhesh.com/aside/easiest-ways-to-get-access-tokens/
            # https://morgantechspace.com/2022/03/azure-ad-get-access-token-for-delegated-permissions-using-powershell.html
            # https://smsagent.blog/2024/03/19/the-quest-for-a-microsoft-graph-access-token/
            if ($TenantID -and $ClientID -and $ClientSecret) {
                # Generate token through previously registered enterprise application credentials (https://lazyadmin.nl/powershell/get-msaltoken/):
                # (Client credentials auth flow)
                Write-Output "`nRetrieving token from logon.microsoftonline.com..." | Tee-Object -FilePath $logFilePath -Append
                $AzureBody = @{
                    Grant_Type      = "client_credentials"
                    Scope           = "https://graph.microsoft.com/.default" # "https://graph.microsoft.com/.default+offline_access"
                    Client_Id       = $ClientID
                    Client_Secret   = $ClientSecret
                }
                $token = (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$($tenantID)/oauth2/v2.0/token" -Body $AzureBody)
                $Token = $token.access_token
            } elseif ([Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance.AuthContext.Scopes) {
                Write-Output "`nApplication not created/known. Will attempt to create application with Mail.Read permissions..." | Tee-Object -FilePath $logFilePath -Append

                # Variables for application
                $appName = "PowerShellMailRead"
                $supportedAccountTypes = "AzureADMyOrg"
                $redirectUri = "http://localhost"
                $RequiredApiPermissions = [PSCustomObject]@{roles = @("User.Read.All","Mail.Read")}
                # https://graphpermissions.merill.net/permission/Mail.Read?tabs=apiv1%2CadministrativeUnit1


                # # Connect to Microsoft Graph - Should already be connected at this point if tenant/client/secret is not defined
                # Write-Output "Connecting to Microsoft Graph..."
                # Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All", "AppRoleAssignment.ReadWrite.All"

                # Create the app registration
                Write-Output "Creating app registration..."
                $app = New-MgApplication -DisplayName $appName -SignInAudience $supportedAccountTypes -Web @{ RedirectUris = @($redirectUri) }

                # Create a client secret
                Write-Output "Creating client secret..."
                $passwordCredential = @{
                    displayName = "ClientSecret"
                    endDateTime = (Get-Date).AddDays(10)
                }
                $secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential $passwordCredential

                # Configure the authentication settings
                Write-Output "Configuring authentication settings..."
                $webSettings = @{
                    RedirectUris = @($redirectUri)
                }
                Update-MgApplication -ApplicationId $app.Id -Web $webSettings

                # Add API permissions
                Write-Output "Adding API permissions..."

                $app = Get-MgApplication | Where-Object { $_.displayName -eq $appName }
                $servicePrincipal = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'" # Microsoft Graph

                $appId = $app.Id
                $servicePrincipalId = $servicePrincipal.Id

                $AppPermissions = $RequiredApiPermissions.roles

                $appRoles = $servicePrincipal.AppRoles

                $permissions = $appRoles | Where-Object { $_.Value -in $AppPermissions } | Select-Object ID

                $ServicePrincipalID2=@{
                    "AppId" = $app.appid
                }
                New-MgServicePrincipal -BodyParameter $ServicePrincipalID2
                $spn = Get-MgServicePrincipalByAppId -AppId $app.appid

                foreach ($permission in $permissions) {
                    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spn.id -PrincipalId $spn.id -ResourceId $servicePrincipalId -AppRoleId $permission.id
                }

                $TenantID = Get-MgOrganization | Select-Object -ExpandProperty Id

                # Export the client secret to a text file
                Write-Output "Exporting client app information to text file..."
                # $secretFilePath = Join-Path -Path (Split-Path -Path $FilePath) -ChildPath "clientSecret.txt"
                # Set-Content -Path $secretFilePath -Value $secret.SecretText

                # MailAppInfo.json
                $tenantId
                $spn.appid # (?)
                $secret.SecretText

                $MailAppInfo = [PSCustomObject]@{
                                'tenantid' = $TenantID
                                'clientid' = $spn.appid
                                'clientsecret' = $secret.SecretText
                            }
                $MailAppInfo | ConvertTo-Json -Depth 100 | Out-File -FilePath "$OutputPath\$DomainName\MailAppInfo.json"

                # Retrieve token from current MgGraph module session - DELEGATED permissions (only works for accessing your own messages):
                # (authorization code auth flow - can access items that account can interact with through Microsoft 365 apps, but can't access items owned by other users)
                # $Parameters = @{
                #     Method = "GET"
                #     URI = "/v1.0/me"
                #     OutputType = "HttpResponseMessage"
                # }
                # $Response = Invoke-GraphRequest @Parameters
                # $Headers = $Response.RequestMessage.Headers
                # $Token = $Headers.Authorization.Parameter
                # OR:
                # $token = (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/me" -OutputType "HttpResponseMessage").RequestMessage.Headers.Authorization.Parameter
                
                # Generate token using built-in Azure Powershell application - Register app, add scope, sign-in and retrieve token:
                # (To use application permissions need to use the client credentials auth flow)
                
                # $TenantID = Get-MgOrganization | Select-Object -ExpandProperty Id
                
                Import-Module Microsoft.Graph.Identity.SignIns
                New-MgServicePrincipal -AppId "1950a258-227b-4e31-a9cf-717495945fc2" -DisplayName "Microsoft Azure PowerShell"
                # Add or update the Oath2 permissions with "Mail.Read" 
                
                # Add-AzADAppPermission -ApplicationId "1950a258-227b-4e31-a9cf-717495945fc2" -ApiId "00000003-0000-0000-c000-000000000000" -PermissionId "810c84a8-4a9e-49e6-bf7d-12d183f40d01"
                
                $EnterpriseAppName = "Microsoft Azure PowerShell"
                $GraphSp = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"
                $AppSp = Get-MgServicePrincipal -Filter "DisplayName eq '$EnterpriseAppName'"
                $pgs = Get-MgOauth2PermissionGrant -All | Where-Object {$_.ClientId -eq $AppSp.Id}
                $GraphPgs = $pgs | Where {$_.ResourceId -eq $GraphSp.Id}
                if ($null -ne $GraphPgs) {
                    $ExistingScope = $GraphPgs.Scope
                    $NewScope = $ExistingScope + " Mail.Read"
                    $pgid = $GraphPgs.id
                    $params = @{
                       Scope = $NewScope
                    }
                    Update-MgOauth2PermissionGrant -OAuth2PermissionGrantId $pgid -BodyParameter $params
                } else {
                    $params = @{
                        clientId = $AppSp.Id
                        consentType = "AllPrincipals"
                        resourceId = $GraphSp.Id
                        scope = "Mail.Read"
                    }
                    New-MgOauth2PermissionGrant -BodyParameter $params
                }
                # Connect-AzAccount
                # $token = (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com').Token
                Write-Output "`nRetrieving token from logon.microsoftonline.com..." | Tee-Object -FilePath $logFilePath -Append
                $AzureBody = @{
                    Grant_Type      = "client_credentials"
                    Scope           = "https://graph.microsoft.com/.default" # "https://graph.microsoft.com/.default+offline_access"
                    Client_Id       = $spn.appid
                    Client_Secret   = $secret.SecretText
                }                
                $token = (Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$($tenantID)/oauth2/v2.0/token" -Body $AzureBody)
                $Token = $token.access_token
                
                # MSAL.PS testing....
                # $connectionDetails = @{
                #     'TenantId'    = "$TenantID"
                #     'ClientId'    = '14d82eec-204b-4c2f-b7e8-296a70dab67e' # Microsoft Graph PowerShell
                #     'Scope'       = 'https://graph.microsoft.com/.default'
                #     'Interactive' = $true
                # }
                # $token = (Get-MsalToken @connectionDetails).AccessToken
            } else {
                Write-Output "Unable to obtain token. Ending"
                exit 93
            }

            $AuthHeaders = @{
                "Authorization" = "Bearer $($token)"
                "Content-type"  = "application/json"
            }
            $AuthHeaders
        }

        # https://learn.microsoft.com/en-us/odata/concepts/queryoptions-overview
        # https://learn.microsoft.com/en-us/graph/filter-query-parameter?tabs=http
        # https://learn.microsoft.com/en-us/graph/api/message-get?view=graph-rest-1.0&tabs=http

        $TokenRole = $(Parse-JWTtoken $Token).roles -contains "Mail.Read"

        if (!$TokenRole) {
            Write-Output "Missing M365 token role - Correct and re-run"
            exit 95
        }

        # Only handles single/first result properly at present. Need to test with varying responses to queries - no message, single message, multiple message - and update to handle properly.

        if ($SearchParam -eq "MessageID") {
            # Search for the message by "internetMessageId"
            $SearchUri = "https://graph.microsoft.com/v1.0/users/$($Upn)/messages/?`$filter=internetMessageId eq '$QueryString'"
            # https://graph.microsoft.com/v1.0/me/messages?$filter=internetMessageId eq 'Message_Id_Including_Brackets'
        } elseif ($SearchParam -eq "Sender") {
            # Search for the message by "address"
            $SearchUri = "https://graph.microsoft.com/v1.0/users/$($Upn)/messages/?`$filter=sender/emailAddress/address eq $QueryString'"
            # $SearchUri = "https://graph.microsoft.com/v1.0/users/$($Upn)/messages/?`$filter=sender/emailAddress/address eq '$SenderAddress'"
        } elseif ($SearchParam -eq "Subject") {
            # Search for the message by "Subject"
            $SearchUri = "https://graph.microsoft.com/v1.0/users/$($Upn)/messages/?`$filter=subject eq '$QueryString'"
            # $SearchUri = "https://graph.microsoft.com/v1.0/users/$($Upn)/messages/?`$filter=subject eq '$subject'"
        } elseif ($SearchParam -eq "SentAfter") {
            # Search for the message by "sentDateTime"
            $SearchUri = "https://graph.microsoft.com/v1.0/users/$($Upn)/messages/?`$filter=sentDateTime ge $($QueryString.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
            # $SearchUri = "https://graph.microsoft.com/v1.0/users/$($Upn)/messages/?`$filter=sentDateTime ge $($StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
        } else {
            Write-Output "`nInvalid search parameter '$SearchParam'. Ending"
            exit 96
        }

            # DELETE message by "internetMessageId" - needs Mail.ReadWrite
            # $SearchUri = "https://graph.microsoft.com/v1.0/users/$($Upn)/messages/?`$filter=internetMessageId eq '$QueryString'"
            # $Response = Invoke-WebRequest -Method Delete -Uri $SearchUri -Headers $AuthHeaders

        # $SearchUri = "https://graph.microsoft.com/v1.0/me/messages?$filter=subject eq '$subject' and sender/emailAddress/address eq '$SenderAddress' and sentDateTime ge $($StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
        Write-Output "`nSearching for $($QueryString) in $($Upn)..." | Tee-Object -FilePath $logFilePath -Append

        $SearchUri = [uri]::EscapeUriString($SearchUri)
        $Response = ""
        $Content = ""
        $MessageContent = ""
        # Query when using WebRequest or RestMethod with above auth header & token (instead of MgGraphRequest):
        $Response = Invoke-WebRequest -Method Get -Uri $SearchUri -Headers $AuthHeaders
        # $Response = Invoke-MgGraphRequest -Method Get -Uri $SearchUri
        $Content = $Response.Content | Convertfrom-Json
        if (!([string]::IsNullOrEmpty($Content.value.internetMessageId))) {
            Write-Output "Message found. Parsing metadata & attempting to retrieving message content..." | Tee-Object -FilePath $logFilePath -Append

            $OutputName = $Content.value.internetMessageId -replace "[^a-zA-Z0-9_\.,@ -]" # Make the output name as close to the original Message ID as possible given file name limitations
            if ($Content.value.createdDateTime -ne $null) { $CreatedDateTime = $($Content.value.createdDateTime | Select-Object -First 1 | Get-Date).ToString('yyyy-MM-dd HH:mm:ss') } else { $CreatedDateTime = "N/A" }
            if ($Content.value.sentDateTime -ne $null) { $SentDateTime = $($Content.value.sentDateTime | Select-Object -First 1 | Get-Date).ToString('yyyy-MM-dd HH:mm:ss') } else { $SentDateTime = "N/A" }
            if ($Content.value.receivedDateTime -ne $null) { $ReceivedDateTime = $($Content.value.receivedDateTime | Select-Object -First 1 | Get-Date).ToString('yyyy-MM-dd HH:mm:ss') } else { $ReceivedDateTime = "N/A" }
            if ($Content.value.sender.emailAddress -ne $null) { $Sender = $($Content.value.sender.emailAddress | Select-Object -First 1).address } else { $Sender = "N/A" }
            if ($Content.value.from.emailAddress -ne $null) { $From = $($Content.value.from.emailAddress | Select-Object -First 1).address } else { $From = "N/A" }
            if ($Content.value.toRecipients.emailAddress -ne $null) { $To = $($Content.value.toRecipients.emailAddress | foreach-object {$_.address}) -join "," } else { $To = "N/A" }
            if ($Content.value.replyTo.emailAddress -ne $null) { $ReplyTo = $($Content.value.replyTo.emailAddress | Select-Object -First 1).address } else { $ReplyTo = "N/A" }
            if ($Content.value.ccRecipients.emailAddress -ne $null) { $CC = $($Content.value.ccRecipients.emailAddress | foreach-object {$_.address}) -join "," } else { $CC = "N/A" }
            if ($Content.value.bccRecipients.emailAddress -ne $null) { $BCC = $($Content.value.bccRecipients.emailAddress | foreach-object {$_.address}) -join "," } else { $BCC = "N/A" }
            if ($Content.value.subject -ne $null) { $Subject = $Content.value.subject | Select-Object -First 1 } else { $Subject = "N/A" }
            if ($Content.value.bodyPreview -ne $null) { $BodyPreview = $Content.value.bodyPreview | Select-Object -First 1 } else { $BodyPreview = "N/A" }
            if ($Content.value.isRead -ne $null) { $IsRead = $($Content.value.isRead | Select-Object -First 1) } else { $IsRead = "N/A" }
            if ($Content.value.isDraft -ne $null) { $IsDraft = $($Content.value.isDraft | Select-Object -First 1) } else { $IsDraft = "N/A" }
            if ($Content.value.hasAttachments -ne $null) { $HasAttachments = $($Content.value.hasAttachments | Select-Object -First 1) } else { $HasAttachments = "N/A" }
            if ($Content.value.flag.flagStatus -ne $null) { $FlagStatus = $Content.value.flag.flagStatus | Select-Object -First 1 } else { $FlagStatus = "N/A" }
            if ($Content.value.webLink -ne $null) { $WebLink = $Content.value.webLink | Select-Object -First 1 } else { $WebLink = "N/A" }
            if ($Content.value.internetMessageId -ne $null) { $InternetMessageId = $Content.value.internetMessageId | Select-Object -First 1 } else { $InternetMessageId = "N/A" }
            if ($Content.value.id -ne $null) { $ID = $Content.value.id | Select-Object -First 1 } else { $ID = "" }
            if ($Content.value.parentFolderId -ne $null) { $ParentFolderId = $Content.value.parentFolderId | Select-Object -First 1 } else { $ParentFolderId = "N/A" }
            if ($Content.value.conversationId -ne $null) { $ConversationId = $Content.value.conversationId | Select-Object -First 1 } else { $ConversationId = "N/A" }
            
            $MessageInfo = [PSCustomObject]@{
                'InternetMessageId' = $InternetMessageId
                'FileName' = $Upn + "_" + $OutputName
                'Mailbox' = $Upn
                'CreatedDateTime' = $CreatedDateTime
                'SentDateTime' = $SentDateTime
                'ReceivedDateTime' = $ReceivedDateTime
                'Sender' = $Sender
                'From' = $From
                'To' = $To
                'ReplyTo' = $ReplyTo
                'CC' = $CC
                'BCC' = $BCC
                'Subject' = $Subject
                'BodyPreview' = $BodyPreview
                'IsRead' = $IsRead
                'IsDraft' = $IsDraft
                'HasAttachments' = $HasAttachments
                'FlagStatus' = $FlagStatus
                'WebLink' = $WebLink
                'ID' = $ID
                'ParentFolderId' = $ParentFolderId
                'ConversationId' = $ConversationId
            }
            
            # If returned ID is not null get the message "value" and save the content to a file
            if(!([string]::IsNullOrEmpty($ID))) {
                $BodyUri = "https://graph.microsoft.com/v1.0/users/$($Upn)/messages/$($ID)/`$value"
                $BodyUri = [uri]::EscapeUriString($BodyUri)
                # Query when using WebRequest or RestMethod with above auth header & token (instead of MgGraphRequest):
                $MessageContent = Invoke-WebRequest -Method Get -Uri $BodyUri -Headers $AuthHeaders -ErrorAction SilentlyContinue
                # $MessageContent = Invoke-MgGraphRequest -Method Get -Uri $BodyUri -ErrorAction SilentlyContinue
                if (!([string]::IsNullOrEmpty($MessageContent.Content))) {
                    Write-Output "Message message content retrieved." | Tee-Object -FilePath $logFilePath -Append
                    $MessageContent.Content | out-file "$OutputPath\$DomainName\Messages_$date\$($Upn)_$($OutputName).eml" -Encoding $Encoding
                } else {
                    Write-Output "Message content unavailable." | Tee-Object -FilePath $logFilePath -Append
                    $MessageInfo.FileName = 'ContentUnavailable'
                }                
            }

            $MessageInfoIndex = $MessageInfoIndex + $MessageInfo
            # $MessageInfo.InternetMessageId | fl

        } else {
            Write-Output "$($QueryString) not found in $Upn." | Tee-Object -FilePath $logFilePath -Append

            $MessageInfo = [PSCustomObject]@{
                'InternetMessageId' = $QueryString
                'FileName' = 'NotFound'
                'Mailbox' = $Upn
                'CreatedDateTime' = ''
                'SentDateTime' = ''
                'ReceivedDateTime' = ''
                'Sender' = ''
                'From' = ''
                'To' = ''
                'ReplyTo' = ''
                'CC' = ''
                'BCC' = ''
                'Subject' = ''
                'BodyPreview' = ''
                'IsRead' = ''
                'IsDraft' = ''
                'HasAttachments' = ''
                'FlagStatus' = ''
                'WebLink' = ''
                'ID' = ''
                'ParentFolderId' = ''
                'ConversationId' = ''
            }
            $MessageInfoIndex = $MessageInfoIndex + $MessageInfo
        }
    }
}

$OutputCSV = "$OutputPath\$DomainName\$($($UserId | Select-Object -First 1).Replace(',','-'))_MessageIndex_$($date).csv"


$MessageInfoIndex | Export-Csv -Path $OutputCSV -NoTypeInformation -Append -Encoding $Encoding

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" Message metadata index file is available at:" | Tee-Object -FilePath $logFilePath -Append
    Write-Output $OutputCSV | Tee-Object -FilePath $logFilePath -Append
    # $Prompt = New-Object -ComObject wscript.shell
    # $UserInput = $Prompt.popup("Do you want to open output file?", 0, "Open Output File", 4)
    # if ($UserInput -eq 6) {
    #     Invoke-Item "$OutputCSV"
    # }
}

Write-Output "Search & retrieval of messages by ID complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"

Exit
