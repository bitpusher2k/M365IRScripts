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
# v3.1.1 last updated 2025-11-17
# Processes an exported CSV with a column of IP addresses, adding "IP_Country", "IP_Region",
# "IP_City", "IP_ISP", "IP_Org", "IP_Type", "IP_Score" columns and populating these
# columns with available information from one of 20-ish online services.
# The addition of this information supports identification of activity patterns
# during manual review of logs.
# Script identifies valid public IPv4/IPv6 addresses, and skips lookup of private/invalid
# addresses to increase speed and reduce API calls.
# Script uses a hash table for IP information to increase speed and reduce API calls.
#
# Script saves IP information to "IPAddressData.xml" in script directory to save on API
# calls when processing multiple files in a row. It is recommended that this file be
# deleted every few months so fresh IP information is retrieved.
#
# Currently includes syntax to lookup & add IP information from these services:
# * scamalytics.com - 5,000 requests/month free - need to sign up for API key, now have paywalled geo/threat/asn information and is no longer worth using
# * ipapi.co - 1,000 requests/day free
# * ip-api.com - free for non-commercial use - 45 requests/minute rate limit
# * ip2location.io - 50,000 requests/month free - need to sign up for API key
# * hostip.info - free location information
# * iphub.info 1,000 requests/day free - need to sign up for API key
# * abuseipdb.com 1,000 requests/day free - need to sign up for API key
# * ipqualityscore.com 5,000 requests/month free - need to sign up for API key
# * freeipapi.com - Limited to 60 requests per minute
# * findip.net - need to sign up for API key
# * 1ip.io
# * ipinfo.io/lite - need to sign up for API key
# * ipwho.org
# * apibundle.io - 10,000 requests/day free - requires api key
# * ip-score.com - Slow responses
# * virustotal.com - 500 requests/day - need to sign up for API key
# * ipgeolocation.io - 1,000 requests/day - need to sign up for API key
# * ipapi.is - 1,000 requests/day - need to sign up for API key
# * ipdata.co - 1,500 requests/day - need to sign up for API key
# * fraudlogix.com - 1,000 requests/month - need to sign up for API key
#
# Usage:
# powershell -executionpolicy bypass -f .\Lookup-IPInfoCSV.ps1 -inputFile "Path\to\input\log.csv" -outputFile "Path\to\output\file.csv" -IPcolumn "IP Column Name" -InfoSource "IP service to use" -APIKey "API key if required for service"
#
# Recommended services: ipqualityscorecom (5000/month), freeipapicom (rate limited), findipnet, ipapiis (1000/day)
#
# Use with DropShim.bat to allow drag-and-drop processing of CSV files (logs, etc.) with an IP column, either singly or in bulk.
#
#comp #m365 #security #bec #script #logs #entraid #IP #proxy #vpn #location #osint #csv #scamalytics #irscript #powershell

#Requires -Version 5.1

param(
    [string[]]$inputFiles = @("UALexport.csv"),
    [string]$outputFile = "UALexport_Processed.csv",
    [string]$IPcolumn,
    [string]$InfoSource = "ipapiis", # Currently supports: scamalytics, ipapico, ipapicom, ip2locationio, hostipinfo, iphubinfo, abuseipdbcom, ipqualityscorecom, freeipapicom, findipnet, 1ipio, ipinfoiolite, ipwhoorg, apibundleio, ipscorecom, virustotalcom, ipgeolocationio, ipapiis, ipdataco, fraudlogixcom
    [string]$APIKey = $(Import-Csv "$PSScriptRoot\test\api.txt" | Select APIKey, Service | Where {$_.Service -like "*$InfoSource*"} | Select -ExpandProperty APIKey), # Load API key - required for scamalytics, ip2locationio, iphubinfo, abuseipdbcom, ipqualityscorecom, findipnet, ipinfoiolite, apibundleio, virustotalcom, ipgeolocationio, ipapiis, ipdataco, fraudlogixcom
    [string]$IPv6NetworkInfoOnly = 1, # Only lookup network-level information for IPv6 addresses - true by default to reduce API calls
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

$total = [Diagnostics.StopWatch]::StartNew()
Write-Output "$scriptName started"
if ($APIKey -eq "") {
    Write-Output "API key not set - can only use a subset of services."
} else {
    Write-Output "API key set."
}
if (($InfoSource -eq "scamalytics" -or $InfoSource -eq "ip2locationio" -or $InfoSource -eq "iphubinfo" -or $InfoSource -eq "abuseipdbcom" -or $InfoSource -eq "ipqualityscorecom" -or $InfoSource -eq "findipnet" -or $InfoSource -eq "ipinfoiolite" -or $InfoSource -eq "apibundleio" -or $InfoSource -eq "virustotalcom" -or $InfoSource -eq "ipgeolocationio" -or $InfoSource -eq "ipapiis" -or $InfoSource -eq "ipdataco" -or $InfoSource -eq "" -or $InfoSource -eq "fraudlogixcom") -and $APIKey -eq "") {
    $InfoSource = "freeipapicom"
    Write-Output "Using fallback source $InfoSource due to lack of API key."
}
Write-Output "`nIP information service specified: $InfoSource"

foreach ($inputFile in $inputfiles) {
    # Load spreadsheet
    Write-Output "`nLoading $inputFile..."
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
    $Spreadsheet | Add-Member -NotePropertyName "IP_Region" -NotePropertyValue $null # State/Region name
    $Spreadsheet | Add-Member -NotePropertyName "IP_City" -NotePropertyValue $null # City name
    $Spreadsheet | Add-Member -NotePropertyName "IP_ISP" -NotePropertyValue $null # ISP name
    $Spreadsheet | Add-Member -NotePropertyName "IP_Org" -NotePropertyValue $null # Organization name
    $Spreadsheet | Add-Member -NotePropertyName "IP_Type" -NotePropertyValue $null # Extra IP information (VPN, TOR, DCH, Proxy, Blacklists) - service dependant
    $Spreadsheet | Add-Member -NotePropertyName "IP_Score" -NotePropertyValue $null # Risk value from 0(low) to 100 (high) - service dependant

    if ($IPv6NetworkInfoOnly) {
        Write-Output "Only looking up network-level information for IPv6 addresses (saves API calls)"
    }

    # Loop through each row in spreadsheet data
    foreach ($Row in $Spreadsheet) {

        $IP = $Row.$IPcolumn

        if ($IP.Length -gt 7 -and $IP -match '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$') {
            if ($IP -notmatch "^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})$") {
                Write-Output "IP appears to be a valid public IPv4 address..."
            } else {
                Write-Output "IP $IP is not a valid public address - skipping."
                $IP = 0
            }
        } elseif ($IP.Length -gt 9 -and $IP -match '^[a-f\d\.\:\/]{10,49}$') {
            if ($IP -match '^2[0-9a-fA-F]{3}:(([0-9a-fA-F]{1,4}[:]{1,2}){1,6}[0-9a-fA-F]{1,4})') {
                Write-Output "IP appears to be a valid IPv6 GUA..."
                if ($IPv6NetworkInfoOnly) {
                    Write-Output "Selecting network prefix of address for lookup..."
                    $regex = '^([0-9a-fA-F]{1,4}:){3}[0-9a-fA-F]{1,4}'
                    $IP = "$(($IP | Select-String -Pattern $regex).Matches.Value)::"
                }
            } else {
                Write-Output "IP $IP is not a valid GUA - skipping."
                $IP = 0
            }
        }

        # Check if valid IP, and lookup info if so
        if (($IP.Length -gt 7 -and $IP -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') -or ($IP.Length -gt 9 -and $IP -match '^[a-f\d\.\:\/]{10,49}$')) {
            Write-Output "Looking up info for `"$IP`""

            $IPInfo = $Null
            $IPContent = $Null
            $IPObject = $Null
            if (!($IPAddressHash[$IP])) {
                Write-Output "Querying online service."
                if ($InfoSource -eq "scamalytics") {
                    $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api11.scamalytics.com/vc3/?key=$APIKey&ip=$IP"
                } elseif ($InfoSource -eq "ipapico") {
                    $IPInfo = Invoke-WebRequest -Method Get -Uri "https://ipapi.co/$IP/json/" # Supported formats: json, jsonp, xml, csv, yaml
                } elseif ($InfoSource -eq "ipapicom") {
                    write-output "before"
                    write-output "Invoke-WebRequest -Method Get -Uri `"http://ip-api.com/json/$IP`""
                    $IPInfo = Invoke-WebRequest -Method Get -Uri "http://ip-api.com/json/$IP"
                    write-output "after"
                    Start-Sleep -Seconds 1.5 # Slow down to avoid throttling/rate limiting issues with the web service
                } elseif ($InfoSource -eq "ip2locationio") {
                    $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.ip2location.io/?key=$APIKey&ip=$IP"
                } elseif ($InfoSource -eq "hostipinfo") {
                    $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.hostip.info/get_json.php?ip=$IP"
                } elseif ($InfoSource -eq "iphubinfo") {
                    $IPInfo = Invoke-WebRequest -Method Get -Uri "http://v2.api.iphub.info/ip/$IP" -Headers @{ "X-Key" = "$APIKey" }
                } elseif ($InfoSource -eq "abuseipdbcom") {
                    $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.abuseipdb.com/api/v2/check/?ipAddress=$IP&maxAgeInDays=90" -Headers @{ "Accept" = "application/json"; "key" = "$APIKey" }
                } elseif ($InfoSource -eq "ipqualityscorecom") {
                    $IPInfo = Invoke-WebRequest -Method Get -Uri "https://www.ipqualityscore.com/api/json/ip/$APIKey/$IP/?strictness=0&allow_public_access_points=true"
                } elseif ($InfoSource -eq "freeipapicom") {
                    $IPInfo = Invoke-WebRequest -Method Get -Uri "https://free.freeipapi.com/api/json/$IP"
                    Start-Sleep -Seconds 1 # Slow down to avoid throttling/rate limiting issues with the web service
                } elseif ($InfoSource -eq "findipnet") {
                    $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.findip.net/$IP/?token=$APIKey"
                } elseif ($InfoSource -eq "1ipio") {
                    $IPInfo = Invoke-WebRequest -Method Get -Uri "https://1ip.io/api/$IP"
                } elseif ($InfoSource -eq "ipinfoiolite") {
                    $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.ipinfo.io/lite/$IP/?token=$APIKey"
                } elseif ($InfoSource -eq "ipwhoorg") {
                    $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.ipwho.org/ip/$IP"
                } elseif ($InfoSource -eq "apibundleio") {
                    $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.apibundle.io/ip-lookup?apikey=$APIKey&ip=$IP"
                } elseif ($InfoSource -eq "ipscorecom") {
                    $IPInfo = Invoke-WebRequest -Method Post -Uri "https://ip-score.com/fulljson" -Body @{ ip="$IP" }
                } elseif ($InfoSource -eq "virustotalcom") {
                    $IPInfo = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$IP" -Method Get -Headers @{ "Accept" = "application/json" ; "x-apikey" = "$APIKey" }
                } elseif ($InfoSource -eq "ipgeolocationio") {
                    $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.ipgeolocation.io/v2/ipgeo?apiKey=$APIKey&ip=$IP"
                } elseif ($InfoSource -eq "ipapiis") {
                    $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.ipapi.is?q=$IP&key=$APIKey"
                } elseif ($InfoSource -eq "ipdataco") {
                    $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.ipdata.co/$IP/?api-key=$APIKey"
                } elseif ($InfoSource -eq "fraudlogixcom") {
                    $IPInfo = Invoke-RestMethod -Uri "https://iplist.fraudlogix.com/v5?ip=$IP" -Method Get -Headers @{ "x-api-key" = "$APIKey" ; "Content-Type" = "application/json" }
                }
                if ($InfoSource -ne "fraudlogixcom") {
                    $IPAddressHash.Add([string]$IP, $IPInfo.content)
                    $IPContent = $IPInfo.content
                } else {
                    $IPAddressHash.Add([string]$IP, $IPInfo)
                    $IPContent = $IPInfo
                }
                $LookupCount++
            } else {
                # Get the IP information from the hash table if we've already looked it up
                Write-Output "IP Already in hash table - using cached data."
                $IPContent = $IpAddressHash[$IP]
            }

            # $IPContent
            if ($InfoSource -ne "fraudlogixcom") {
                $IPObject = ConvertFrom-Json -InputObject $IPContent
            } else {
                $IPObject = $IPContent
            }

            # Set the IP info values for this record
            if ($InfoSource -eq "scamalytics") {
                $scamalytics = $IPObject
                $Row.IP_Country = $scamalytics.ip_country_code # Paywalled
                $Row.IP_Region = $scamalytics.ip_state_name # Paywalled
                $Row.IP_City = $scamalytics.IP_City # Paywalled
                $Row.IP_ISP = $scamalytics.{isp name} # Paywalled
                $Row.IP_Org = $scamalytics.{Organization Name} # Paywalled
                $Row.IP_Type = $scamalytics.proxy_type # Paywalled
                $Row.IP_Score = $scamalytics.score
            } elseif ($InfoSource -eq "ipapico") {
                $ipapico = $IPObject
                $Row.IP_Country = $ipapico.country_code
                $Row.IP_Region = $ipapico.region
                $Row.IP_City = $ipapico.city
                $Row.IP_ISP = ""
                $Row.IP_Org = $ipapico.org
                $Row.IP_Type = ""
                $Row.IP_Score = ""
            } elseif ($InfoSource -eq "ipapicom") {
                $ipapicom = $IPObject
                $Row.IP_Country = $ipapicom.countryCode
                $Row.IP_Region = $ipapicom.regionname
                $Row.IP_City = $ipapicom.city
                $Row.IP_ISP = $ipapicom.isp
                $Row.IP_Org = $ipapicom.org
                $Row.IP_Type = ""
                $Row.IP_Score = ""
            } elseif ($InfoSource -eq "ip2locationio") {
                $ip2location = $IPObject
                $Row.IP_Country = $ip2location.country_code
                $Row.IP_Region = $ip2location.region_name
                $Row.IP_City = $ip2location.city_name
                $Row.IP_ISP = ""
                $Row.IP_Org = $ip2location.as
                $Row.IP_Type = if ($ip2location.is_proxy) {"Proxy"} else {""}
                $Row.IP_Score = ""
            } elseif ($InfoSource -eq "hostipinfo") {
                $hostipinfo = $IPObject
                $Row.IP_Country = $hostipinfo.country_code
                $Row.IP_Region = ""
                $Row.IP_City = $hostipinfo.city
                $Row.IP_ISP = ""
                $Row.IP_Org = ""
                $Row.IP_Type = ""
                $Row.IP_Score = ""
            } elseif ($InfoSource -eq "iphubinfo") {
                $iphubinfo = $IPObject
                $Row.IP_Country = $iphubinfo.countryCode
                $Row.IP_Region = ""
                $Row.IP_City = ""
                $Row.IP_ISP = $iphubinfo.isp
                $Row.IP_Org = ""
                $Row.IP_Type = ""
                $Row.IP_Score = ""
            } elseif ($InfoSource -eq "abuseipdbcom") {
                $abuseipdbcom = $IPObject
                $Row.IP_Country = $abuseipdbcom.data.countryCode
                $Row.IP_Region = ""
                $Row.IP_City = ""
                $Row.IP_ISP = $abuseipdbcom.data.isp
                $Row.IP_Org = $abuseipdbcom.data.domain
                $Row.IP_Type = $abuseipdbcom.data.usageType
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
                # $ipInfo = $subset.psobject.properties | Select-Object name, value | Where-Object { $_.value } | join-string -Property name -DoubleQuote -Separator ',' # PowerShell 7
                $ipInfo = ($subset.psobject.properties | Select-Object name, value | Where-Object { $_.value } | ForEach-Object { "`"$($_.name)`"" }) -join ',' # PowerShell 5
                $Row.IP_Type = $ipInfo
                $Row.IP_Score = ""
            } elseif ($InfoSource -eq "freeipapicom") {
                $freeipapicom = $IPObject
                $Row.IP_Country = $freeipapicom.countryCode
                $Row.IP_Region = $freeipapicom.regionName
                $Row.IP_City = $freeipapicom.cityName
                $Row.IP_ISP = ""
                $Row.IP_Org = $freeipapicom.asnOrganization
                $Row.IP_Type = $freeipapicom.aisProxy
                $Row.IP_Score = ""
            } elseif ($InfoSource -eq "findipnet") {
                $findipnet = $IPObject
                $Row.IP_Country = $findipnet.country.iso_code
                $Row.IP_Region = ($findipnet.subdivisions.names | select en | foreach-object { "$($_.en)" }) -join ', '
                $Row.IP_City = $findipnet.city.names.en
                $Row.IP_ISP = $findipnet.traits.isp
                $Row.IP_Org = $findipnet.traits.organization
                $Row.IP_Type = $findipnet.traits.user_type
                $Row.IP_Score = ""
            } elseif ($InfoSource -eq "1ipio") {
                $1ipio = $IPObject
                $Row.IP_Country = $1ipio.country_code
                $Row.IP_Region = $1ipio.region
                $Row.IP_City = $1ipio.city
                $Row.IP_ISP = ""
                $Row.IP_Org = ""
                $Row.IP_Type = ""
                $Row.IP_Score = ""
            } elseif ($InfoSource -eq "ipinfoiolite") {
                $ipinfoiolite = $IPObject
                $Row.IP_Country = $ipinfoiolite.country_code
                $Row.IP_Region = ""
                $Row.IP_City = ""
                $Row.IP_ISP = ""
                $Row.IP_Org = $ipinfoiolite.as_name
                $Row.IP_Type = ""
                $Row.IP_Score = ""
            } elseif ($InfoSource -eq "ipwhoorg") {
                $ipwhoorg = $IPObject
                $Row.IP_Country = $ipwhoorg.data.countryCode
                $Row.IP_Region = $ipwhoorg.data.region
                $Row.IP_City = $ipwhoorg.data.city
                $Row.IP_ISP = ""
                $Row.IP_Org = ""
                # Grab subset of the properties related to proxy info that are "true" and not "low" and smash them into a string
                $subset = $ipwhoorg.data.security | Select-Object -Property isVpn, isTor, isThreat
                # $ipInfo = $subset.psobject.properties | Select-Object name, value | Where-Object { $_.value -and $_.value -ne "low" } | join-string -Property name -DoubleQuote -Separator ',' # PowerShell 7
                $ipInfo = ($subset.psobject.properties | Select-Object name, value | Where-Object { $_.value -and $_.value -ne "low" } | ForEach-Object { "`"$($_.name)`"" }) -join ',' # PowerShell 5
                $Row.IP_Type = $ipInfo
                $Row.IP_Score = ""
            } elseif ($InfoSource -eq "apibundleio") {
                $apibundleio = $IPObject
                $Row.IP_Country = $apibundleio.country.iso_2_code
                $Row.IP_Region = ""
                $Row.IP_City = $apibundleio.city.name
                $Row.IP_ISP = ""
                $Row.IP_Org = $apibundleio.connection.aso
                $Row.IP_Type = ""
                $Row.IP_Score = ""
            } elseif ($InfoSource -eq "ipscorecom") {
                $ipscorecom = $IPObject
                $Row.IP_Country = $ipscorecom.geoip2.countrycode
                $Row.IP_Region = $ipscorecom.geoip1.region
                $Row.IP_City = $ipscorecom.geoip1.city
                $Row.IP_ISP = $ipscorecom.isp
                $Row.IP_Org = $ipscorecom.org
                # Grab subset of the properties related to blacklist info that are "listed" and smash them into a string
                $subset = $ipscorecom.blacklists | Select-Object -Property spamhaus, sorbs, spamcop, southkoreannbl, barracuda
                # $blacklistInfo = $subset.psobject.properties | Select-Object name, value | Where-Object { $_.value -eq "listed" } | join-string -Property name -DoubleQuote -Separator ',' # PowerShell 7
                $blacklistInfo = ($subset.psobject.properties | Select-Object name, value | Where-Object { $_.value -eq "listed" } | ForEach-Object { "`"$($_.name)`"" }) -join ',' # PowerShell 5
                $Row.IP_Type = $blacklistInfo
                $Row.IP_Score = ""
            } elseif ($InfoSource -eq "virustotalcom") {
                $virustotalcom = $IPObject
                $Row.IP_Country = $virustotalcom.data.attributes.rdap.country
                $Row.IP_Region = ""
                $Row.IP_City = ""
                $Row.IP_ISP = ""
                $Row.IP_Org = $virustotalcom.data.attributes.as_owner
                # Grab subset of the properties related to last analysis info that are not zero and smash them into a string
                $subset = $virustotalcom.data.attributes.last_analysis_stats | Select-Object -Property malicious, suspicious, undetected, harmless, timeout
                # $statsInfo = $subset.psobject.properties | Select-Object name, value | Where-Object { $_.value -gt 0 } | join-string -Property name -DoubleQuote -Separator ',' # PowerShell 7
                $statsInfo = ($subset.psobject.properties | Select-Object name, value | Where-Object { $_.value -gt 0 } | ForEach-Object { "`"$($_.name)`"" }) -join ',' # PowerShell 5
                $Row.IP_Type = $statsInfo
                $Row.IP_Score = ""
            } elseif ($InfoSource -eq "ipgeolocationio") {
                $ipgeolocationio = $IPObject
                $Row.IP_Country = $ipgeolocationio.location.country_code2
                $Row.IP_Region = $ipgeolocationio.location.state_prov
                $Row.IP_City = $ipgeolocationio.location.city
                $Row.IP_ISP = ""
                $Row.IP_Org = ""
                $Row.IP_Type = ""
                $Row.IP_Score = ""
            } elseif ($InfoSource -eq "ipapiis") {
                $ipapiis = $IPObject
                $Row.IP_Country = $ipapiis.location.country_code
                $Row.IP_Region = $ipapiis.location.state
                $Row.IP_City = $ipapiis.location.city
                $Row.IP_ISP = $ipapiis.asn.org
                $Row.IP_Org = $ipapiis.company.name
                # Grab subset of the properties related to proxy info that are "true" and smash them into a string
                $subset = $ipapiis | Select-Object -Property is_bogon, is_mobile, is_satellite, is_crawler, is_datacenter, is_tor, is_proxy, is_vpn, is_abuser
                # $ipInfo = $subset.psobject.properties | Select-Object name, value | Where-Object { $_.value } | join-string -Property name -DoubleQuote -Separator ',' # PowerShell 7
                $ipInfo = ($subset.psobject.properties | Select-Object name, value | Where-Object { $_.value } | ForEach-Object { "`"$($_.name)`"" }) -join ',' # PowerShell 5
                $Row.IP_Type = $ipInfo
                $Row.IP_Score = $ipapiis.asn.abuser_score
            } elseif ($InfoSource -eq "ipdataco") {
                $ipdataco = $IPObject
                $Row.IP_Country = $ipdataco.country_code
                $Row.IP_Region = $ipdataco.region
                $Row.IP_City = $ipdataco.city
                $Row.IP_ISP = ""
                $Row.IP_Org = $ipdataco.asn.name
                # Grab subset of the properties related to proxy info that are "true" and smash them into a string
                $subset = $ipdataco.threat | Select-Object -Property is_tor, is_icloud_relay, is_proxy, is_datacenter, is_anonymous, is_known_attacker, is_known_abuser, is_threat, is_bogon 
                # $ipInfo = $subset.psobject.properties | Select-Object name, value | Where-Object { $_.value } | join-string -Property name -DoubleQuote -Separator ',' # PowerShell 7
                $ipInfo = ($subset.psobject.properties | Select-Object name, value | Where-Object { $_.value } | ForEach-Object { "`"$($_.name)`"" }) -join ',' # PowerShell 5
                $Row.IP_Type = $ipInfo
                $Row.IP_Score = ""
            } elseif ($InfoSource -eq "fraudlogixcom") {
                $fraudlogixcom = $IPObject
                $Row.IP_Country = $fraudlogixcom.CountryCode
                $Row.IP_Region = $fraudlogixcom.region
                $Row.IP_City = $fraudlogixcom.city
                $Row.IP_ISP = $fraudlogixcom.isp
                $Row.IP_Org = $fraudlogixcom.organization
                # Grab subset of the properties related to proxy info that are "true" and smash them into a string
                $subset = $fraudlogixcom | Select-Object -Property MaskedDevices, Proxy, TOR, VPN, DataCenter, SearchEngineBot, AbnormalTraffic
                # $proxyInfo = $subset.psobject.properties | Select-Object name, value | Where-Object { $_.value } | join-string -Property name -DoubleQuote -Separator ',' # PowerShell 7
                $proxyInfo = ($subset.psobject.properties | Select-Object name, value | Where-Object { $_.value } | ForEach-Object { "`"$($_.name)`"" }) -join ',' # PowerShell 5
                $Row.IP_Type = $proxyInfo
                $Row.IP_Score = $fraudlogixcom.RiskScore
            }
            Write-Output "`n"
        } elseif ($IP -eq 0) {
            Write-Output "`n"
        } else {
            Write-Output "INVALID IP address - skipping `"$IP`""
            Write-Output "`n"
        }

        $RowCount++
    }

    # Export updated spreadsheet data to CSV file
    [string]$outputFolder = Split-Path -Path $inputFile -Parent
    [string]$outputFile = (Get-Item $inputFile).BaseName
    [string]$outputPath = $outputFolder + "\" + $outputFile + "_IPEnriched_$($InfoSource).csv"
    $Spreadsheet | Export-Csv -Path "$outputPath" -NoTypeInformation
}

$IPAddressHash | Export-Clixml -path "$PSScriptRoot\IPAddressData.xml" -Force

Write-Output "Processed a total of $RowCount rows using $LookupCount lookups."

Write-Output "`nTotal time for script execution: $($total.elapsed.totalseconds)"
Write-Output "Script complete!"

exit
