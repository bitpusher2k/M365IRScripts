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
# Lookup-IPInfoCSV.ps1 - By Bitpusher/The Digital Fox
# v3.0 last updated 2025-05-31
# Processes an exported CSV with a column of IP addresses, adding "IP_Country", "IP_Region",
# "IP_City", "IP_ISP", "IP_Org", "IP_ProxyType", "IP_Score" columns and populating these
# columns with available information from one of several online services.
# The addition of this information supports identification of activity patterns
# during manual review of logs.
# Script uses a hash table for IP information to increase speed and reduce API calls.
# Saves IP information to "IPAddressData.xml" in script directory to save on API
# calls when processing multiple files in a row.
#
# It is recommended that "IPAddressData.xml" be periodically deleted to keep data current.
#
# Currently includes syntax to lookup & add IP information from these services:
# * scamalytics.com - 5,000 requests/month free - need to sign up for API key
# * ipapi.co - 1,000 requests/day free
# * ip-api.com - free for non-commercial use - 45 requests/minute rate limit
# * ip2location.io - 50,000 requests/month free - need to sign up for API key
# * hostip.info - free location information
# * iphub.info 1,000 requests/day free - need to sign up for API key
# * abuseipdb.com 1,000 requests/day free - need to sign up for API key
# * ipqualityscore.com 5,000 requests/month free - need to sign up for API key
#
# Usage:
# powershell -executionpolicy bypass -f .\Lookup-IPInfoCSV.ps1 -inputFile "Path\to\input\log.csv" -outputFile "Path\to\output\file.csv" -IPcolumn "IP Column Name" -InfoSource "IP service to use" -APIKey "API key if required for service"
#
# Use with DropShim.bat to allow drag-and-drop processing of downloaded logs.
#
#comp #m365 #security #bec #script #logs #entraid #IP #proxy #vpn #location #osint #csv #scamalytics #irscript #powershell

#Requires -Version 5.1

param(
    [string]$inputFile = "UALexport.csv",
    [string]$outputFile = "UALexport_Processed.csv",
    [string]$IPcolumn,
    [string]$InfoSource = "scamalytics", # Currently supports: scamalytics, ipapico, ipapicom, ip2location, hostipinfo, iphubinfo
    [string]$APIKey = (Get-Content "$PSScriptRoot\test\api.txt" -First 1), # Load API key required for scamalytics/ip2location/iphubinfo
    [string]$scriptName = "Lookup-IPInfoCSV",
    [string]$Priority = "Normal",
    [int]$RandMax = "500",
    [string]$DebugPreference = "SilentlyContinue",
    [string]$VerbosePreference = "SilentlyContinue",
    [string]$InformationPreference = "Continue",
    [string]$logFileFolderPath = "C:\temp\log",
    [string]$ComputerName = $env:computername,
    [string]$ScriptUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
    [string]$logFilePrefix = "$scriptName" + "_" + "$ComputerName" + "_",
    [string]$logFileDateFormat = "yyyyMMdd_HHmmss",
    [int]$logFileRetentionDays = 30
)

$RowCount = 0
$LookupCount = 0

if (Test-Path "$PSScriptRoot\IPAddressData.xml") {
    $IPAddressHash = Import-CliXml "$PSScriptRoot\IPAddressData.xml"
} else {
    $IPAddressHash = @{}
}

$sw = [Diagnostics.StopWatch]::StartNew()

Write-Output "$scriptName started"
if (($InfoSource -eq "scamalytics" -or $InfoSource -eq "ip2location" -or $InfoSource -eq "iphubinfo") -and $APIKey -eq "") {
    $InfoSource = "ipapico"
}
Write-Output "`nIP information service specified: $InfoSource"
Write-Output "API key specified: $APIKey"

# Load spreadsheet
$Spreadsheet = Import-Csv -Path "$inputFile"
$Headers = $Spreadsheet | Get-Member -MemberType NoteProperty | Select-Object Name
Write-Output "`nColumn headers found in CSV:"
$Headers.Name

if (!$IPcolumn) {
    if ($Headers.name -contains "IPaddress") {
        $IPcolumn = "IPaddress"
    } elseif ($Headers.name -contains "ClientIP") {
        $IPcolumn = "ClientIP"
    } elseif ($Headers.name -contains "IP address") {
        $IPcolumn = "IP address"
    } elseif ($Headers.name -match "IP") {
        $ColumnNumber = [array]::indexof($Headers.Name,$($Headers.name -match "IP"))
        $IPcolumn = $Headers[$ColumnNumber[0]].name
    } else {
        $IPcolumn = $Headers[0].name
    }
    $IPcolumnInput = Read-Host "`nWhat CSV column should be used for IP addresses (default: `"$IPcolumn`")?"
    if ($IPcolumnInput) {
        $IPcolumn = $IPcolumnInput
    }
}

if ($Headers.Name -notcontains $IPcolumn) {
    Write-Output "Indicated column not found in CSV - exiting."
    exit
}

# Add IP information columns to end of spreadsheet data
$Spreadsheet | Add-Member -NotePropertyName "IP_Country" -NotePropertyValue $null # Country code
$Spreadsheet | Add-Member -NotePropertyName "IP_Region" -NotePropertyValue $null # State/Region name - scamalytics.com/ipapi.co/ip-api.com only
$Spreadsheet | Add-Member -NotePropertyName "IP_City" -NotePropertyValue $null # City name - included in most services
$Spreadsheet | Add-Member -NotePropertyName "IP_ISP" -NotePropertyValue $null # ISP name - scamalytics.com/ip-api.com/iphub.info only
$Spreadsheet | Add-Member -NotePropertyName "IP_Org" -NotePropertyValue $null # Organization name - scamalytics.com/ip-api.com/ip2location only
$Spreadsheet | Add-Member -NotePropertyName "IP_ProxyType" -NotePropertyValue $null # Proxy type (Anon VPN - VPN, Tor exit node - TOR, Server - DCH, Pub Proxy, Web Proxy, Search Robot - SES) - scamalytics.com only, proxy True/False from ip2location
$Spreadsheet | Add-Member -NotePropertyName "IP_Score" -NotePropertyValue $null # Risk value from 0(low) to 100 (high) - scamalytics.com only

# Loop through each row in spreadsheet data
foreach ($Row in $Spreadsheet) {

    $IP = $Row.$IPcolumn

    # Check if valid IP, and lookup info if so
    if (($IP.Length -gt 7 -and $IP -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') -or ($IP.Length -gt 9 -and $IP -match '^[a-f\d\.\:\/]{10,49}$')) {
        Write-Output "Looking up info for `"$IP`""

        $IPInfo = $Null
        $IPContent = $Null
        $IPObject = $Null
        if (!($IPAddressHash[$IP])) {
            Write-Output "Looking up IP info"
            if ($InfoSource -eq "scamalytics") {
                $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api11.scamalytics.com/vc3/?key=$APIKey&ip=$IP"
            } elseif ($InfoSource -eq "ipapico") {
                $IPInfo = Invoke-WebRequest -Method Get -Uri "https://ipapi.co/$IP/json/" # Supported formats: json, jsonp, xml, csv, yaml
            } elseif ($InfoSource -eq "ipapicom") {
                $IPInfo = Invoke-WebRequest -Method Get -Uri "http://ip-api.com/json/$IP"
                # Slow down to avoid throttling issues with the web service
                Start-Sleep -Seconds 1.5
            } elseif ($InfoSource -eq "ip2location") {
                $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.ip2location.io/?key=$APIKey&ip=$IP"
            } elseif ($InfoSource -eq "hostipinfo") {
                $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.hostip.info/get_json.php?ip=$IP"
            } elseif ($InfoSource -eq "iphubinfo") {
                $IPInfo = Invoke-WebRequest -Method Get -Uri "http://v2.api.iphub.info/ip/$IP" -Headers @{ "X-Key" = "$APIKey" }
            } elseif ($InfoSource -eq "abuseipdbcom") {
                $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.abuseipdb.com/api/v2/check/?ipAddress=$IP&maxAgeInDays=90" -AllowInsecureRedirect -Headers @{ "Accept" = "application/json"; "key" = "$APIKey" }
            } elseif ($InfoSource -eq "ipqualityscorecom") {
                $IPInfo = Invoke-WebRequest -Method Get -Uri "https://www.ipqualityscore.com/api/json/ip/$APIKey/$IP/?strictness=0&allow_public_access_points=true"
            }
            $IPAddressHash.Add([string]$IP, $IPInfo.content)
            $IPContent = $IPInfo.content
            $LookupCount++
        } else {
            # Get the IP information from the hash table if we've already looked it up
            Write-Output "IP Already in hash table - using cached data"
            $IPContent = $IpAddressHash[$IP]
        }

        # $IPContent
        $IPObject = ConvertFrom-Json -InputObject $IPContent

        # Set the IP info values for this record
        if ($InfoSource -eq "scamalytics") {
            $scamalytics = $IPObject
            $Row.IP_Country = $scamalytics.ip_country_code
            $Row.IP_Region = $scamalytics.ip_state_name
            $Row.IP_City = $scamalytics.IP_City
            $Row.IP_ISP = $scamalytics.{isp name}
            $Row.IP_Org = $scamalytics.{Organization Name}
            $Row.IP_ProxyType = $scamalytics.proxy_type
            $Row.IP_Score = $scamalytics.score
        } elseif ($InfoSource -eq "ipapico") {
            $ipapico = $IPObject
            $Row.IP_Country = $ipapico.country_code
            $Row.IP_Region = $ipapico.region
            $Row.IP_City = $ipapico.city
            $Row.IP_ISP = $ipapico.org
            $Row.IP_Org = ""
            $Row.IP_ProxyType = ""
            $Row.IP_Score = ""
        } elseif ($InfoSource -eq "ipapicom") {
            $ipapicom = $IPObject
            $Row.IP_Country = $ipapicom.countryCode
            $Row.IP_Region = $ipapicom.regionname
            $Row.IP_City = $ipapicom.city
            $Row.IP_ISP = $ipapicom.isp
            $Row.IP_Org = $ipapicom.org
            $Row.IP_ProxyType = ""
            $Row.IP_Score = ""
        } elseif ($InfoSource -eq "ip2location") {
            $ip2location = $IPObject
            $Row.IP_Country = $ip2location.country_code
            $Row.IP_Region = $ip2location.region_name
            $Row.IP_City = $ip2location.city_name
            $Row.IP_ISP = ""
            $Row.IP_Org = $ip2location.as
            $Row.IP_ProxyType = $ip2location.is_proxy
            $Row.IP_Score = ""
        } elseif ($InfoSource -eq "hostipinfo") {
            $hostipinfo = $IPObject
            $Row.IP_Country = $hostipinfo.country_code
            $Row.IP_Region = ""
            $Row.IP_City = $hostipinfo.city
            $Row.IP_ISP = ""
            $Row.IP_Org = ""
            $Row.IP_ProxyType = ""
            $Row.IP_Score = ""
        } elseif ($InfoSource -eq "iphubinfo") {
            $iphubinfo = $IPObject
            $Row.IP_Country = $iphubinfo.countryCode
            $Row.IP_Region = ""
            $Row.IP_City = ""
            $Row.IP_ISP = $iphubinfo.isp
            $Row.IP_Org = ""
            $Row.IP_ProxyType = ""
            $Row.IP_Score = ""
        } elseif ($InfoSource -eq "abuseipdbcom") {
            $abuseipdbcom = $IPObject
            $Row.IP_Country = $abuseipdbcom.data.countryCode
            $Row.IP_Region = ""
            $Row.IP_City = ""
            $Row.IP_ISP = $abuseipdbcom.data.isp
            $Row.IP_Org = $abuseipdbcom.data.domain
            $Row.IP_ProxyType = $abuseipdbcom.data.usageType
            $Row.IP_Score = ""
        } elseif ($InfoSource -eq "ipqualityscorecom") {
            $ipqualityscorecom = $IPObject
            $Row.IP_Country = $ipqualityscorecom.country_code
            $Row.IP_Region = $ipqualityscorecom.region
            $Row.IP_City = $ipqualityscorecom.city
            $Row.IP_ISP = $ipqualityscorecom.isp
            $Row.IP_Org = $ipqualityscorecom.organization
            # Grab subset of the properties related to proxy info that are "true" and smash them into a string
            $subset = $ipqualityscorecom | Select-Object -Property proxy, vpn, tor, active_vpn, active_tor, recent_abuse, bot_status
            $proxyInfo = $subset.psobject.properties | Select-Object name, value | Where-Object { $_.value } | join-string -Property name -DoubleQuote -Separator ','
            $Row.IP_ProxyType = $proxyInfo
            $Row.IP_Score = ""
        }

        Write-Output "`n"
    } else {
        Write-Output "INVALID IP address - skipping `"$IP`""
        Write-Output "`n"
    }

    $RowCount++
}

$IPAddressHash | Export-Clixml -path "$PSScriptRoot\IPAddressData.xml" -Force

Write-Output "Processed $RowCount rows using $LookupCount lookups"

# Export updated spreadsheet data to CSV file
[string]$outputFolder = Split-Path -Path $inputFile -Parent
[string]$outputFile = (Get-Item $inputFile).BaseName
[string]$outputPath = $outputFolder + "\" + $outputFile + "_IPEnriched.csv"
$Spreadsheet | Export-Csv -Path "$outputPath" -NoTypeInformation

Write-Output "Seconds elapsed for CSV processing: $($sw.elapsed.totalseconds)"

exit
