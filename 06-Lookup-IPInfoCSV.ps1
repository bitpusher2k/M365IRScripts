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
# v4.0.0 last updated 2026-04-27
# Processes an exported CSV with a column of IP addresses, adding "IP_Country", "IP_Region",
# "IP_City", "IP_ISP", "IP_Org", "IP_Type", "IP_Score", "IP_ASN", "IP_Range" columns
# and populating these columns with available information from one or more of 20-ish
# online services OR from the local GeoLite2 database (no API key or internet required
# for the local option).
# The addition of this information supports identification of activity patterns
# during manual review of logs.
# Script identifies valid public IPv4/IPv6 addresses, and skips lookup of private/invalid
# addresses to increase speed and reduce API calls.
# Script uses a hash table for IP information to increase speed and reduce API calls.
#
# Script saves IP information to "IPAddressData_XXX.xml" files in script directory to
# save on API calls when processing multiple files in a row. It is recommended that
# this file be deleted every few months so fresh IP information is retrieved.
#
# Currently includes syntax to lookup & add IP information from these services:
# * geolite2local - LOCAL lookup using GeoLite2 City + ASN databases from ip-location-db
#     (https://github.com/sapics/ip-location-db) - No API key required, no rate limits,
#     fully offline after initial database download. Downloads databases automatically
#     on first run. Databases sourced from jsDelivr CDN.
#     City DB format: ip_range_start, ip_range_end, country_code, state1, state2, city,
#                     postcode, latitude, longitude, timezone
#     ASN DB format:  ip_range_start, ip_range_end, autonomous_system_number,
#                     autonomous_system_organization
#     GeoLite2 data created by MaxMind (https://www.maxmind.com), available under
#     CC BY-SA 4.0. See: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
# * scamalytics.com - 5,000 requests/month free - need to sign up for API key, now have paywalled geo/threat/asn information and is only good for IP score
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
# Can retrieve IP information from multiple services in a row to further enrich data available.
#
# Usage:
# powershell -executionpolicy bypass -f .\Lookup-IPInfoCSV.ps1 -inputFile "Path\to\input\log.csv" -outputFile "Path\to\output\file.csv" -IPcolumn "IP Column Name" -InfoSource "IP service to use" -APIKey "API key if required for service"
#
# Recommended services: geolite2local (offline, unlimited), ipqualityscorecom (5000/month), freeipapicom (rate limited), findipnet, ipapiis (1000/day)
#
# Use with DropShim.bat to allow drag-and-drop processing of CSV files (logs, etc.) with an IP column, either singly or in bulk.
#
#comp #m365 #security #bec #script #logs #entraid #IP #proxy #vpn #location #osint #csv #scamalytics #geolite2 #irscript #powershell

#Requires -Version 5.1

param(
    [string[]]$inputFiles = @("UALexport.csv"),
    [string]$outputFile = "UALexport_Processed.csv",
    [string]$IPcolumn,
    [string[]]$InfoSources = @("geolite2local","ipapiis","scamalytics","findipnet"), # Currently supports: geolite2local, scamalytics, ipapico, ipapicom, ip2locationio, hostipinfo, iphubinfo, abuseipdbcom, ipqualityscorecom, freeipapicom, findipnet, 1ipio, ipinfoiolite, ipwhoorg, apibundleio, ipscorecom, virustotalcom, ipgeolocationio, ipapiis, ipdataco, fraudlogixcom
    [string]$APIKey,
    [string]$IPv6NetworkInfoOnly = 1, # Only lookup network-level information for IPv6 addresses - true by default to reduce API calls
    [string]$GeoLite2Path = "C:\Temp\GeoLite2Data", # Path to store GeoLite2 database files - defaults to $PSScriptRoot\GeoLite2Data
    [int]$GeoLite2MaxAgeDays = 30, # Re-download GeoLite2 databases if older than this many days
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

# GeoLite2 Local Database Functions
# References:
#   - ip-location-db project: https://github.com/sapics/ip-location-db
#   - GeoLite2 City CSV format: ip_range_start, ip_range_end, country_code,
#     state1, state2, city, postcode, latitude, longitude, timezone
#     (https://github.com/sapics/ip-location-db/tree/main/geolite2-city)
#   - GeoLite2 ASN CSV format: ip_range_start, ip_range_end,
#     autonomous_system_number, autonomous_system_organization
#     (https://github.com/sapics/ip-location-db/tree/main/geolite2-asn)
#   - GeoLite2 data by MaxMind under CC BY-SA 4.0
#     (https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
#   - jsDelivr CDN hosting: https://www.jsdelivr.com/
#   - IPv4/IPv6 binary search for local range-based CSV lookups
#     (https://en.wikipedia.org/wiki/Binary_search_algorithm)

function ConvertTo-IPv4Integer {
    # Converts dotted-decimal IPv4 string to a [double] for numeric comparison.
    # Using [double] instead of [uint32] for safer arithmetic in PS 5.1.
    # Reference: IPv4 addressing (RFC 791 - https://www.rfc-editor.org/rfc/rfc791)
    param([string]$IP)
    $octets = $IP.Split('.')
    return [double]([double]$octets[0] * 16777216 + [double]$octets[1] * 65536 + [double]$octets[2] * 256 + [double]$octets[3])
}

function Initialize-GeoLite2Databases {
    # Downloads and extracts GeoLite2 City and ASN CSV databases from jsDelivr CDN
    # if they do not exist locally or are older than $GeoLite2MaxAgeDays.
    # City databases are .csv.gz (gzip-compressed); ASN databases are plain .csv.
    # References:
    #   - jsDelivr CDN for npm packages: https://www.jsdelivr.com/
    #   - @ip-location-db/geolite2-city npm package:
    #     https://www.npmjs.com/package/@ip-location-db/geolite2-city
    #   - @ip-location-db/geolite2-asn npm package:
    #     https://www.npmjs.com/package/@ip-location-db/geolite2-asn
    #   - System.IO.Compression.GZipStream for .gz decompression:
    #     https://learn.microsoft.com/en-us/dotnet/api/system.io.compression.gzipstream
    param(
        [string]$DataPath
    )
    if (!(Test-Path -PathType Container -Path $DataPath)) {
        New-Item -ItemType Directory -Force -Path $DataPath | Out-Null
    }

    # Define database URLs and local filenames
    $databases = @(
        @{
            Url = "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-city/geolite2-city-ipv4.csv.gz"
            LocalFile = Join-Path $DataPath "geolite2-city-ipv4.csv"
            Compressed = $true
        },
        @{
            Url = "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-city/geolite2-city-ipv6.csv.gz"
            LocalFile = Join-Path $DataPath "geolite2-city-ipv6.csv"
            Compressed = $true
        },
        @{
            Url = "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-asn/geolite2-asn-ipv4.csv"
            LocalFile = Join-Path $DataPath "geolite2-asn-ipv4.csv"
            Compressed = $false
        },
        @{
            Url = "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-asn/geolite2-asn-ipv6.csv"
            LocalFile = Join-Path $DataPath "geolite2-asn-ipv6.csv"
            Compressed = $false
        }
    )

    foreach ($db in $databases) {
        $needsDownload = $false
        if (!(Test-Path $db.LocalFile)) {
            $needsDownload = $true
            Write-Output "GeoLite2 database not found: $($db.LocalFile)"
        } elseif ($GeoLite2MaxAgeDays -gt 0) {
            $fileAge = (Get-Date) - (Get-Item $db.LocalFile).LastWriteTime
            if ($fileAge.TotalDays -gt $GeoLite2MaxAgeDays) {
                $needsDownload = $true
                Write-Output "GeoLite2 database is $([math]::Round($fileAge.TotalDays)) days old (max $GeoLite2MaxAgeDays): $($db.LocalFile)"
            }
        }

        if ($needsDownload) {
            Write-Output "Downloading: $($db.Url)"
            try {
                if ($db.Compressed) {
                    # Download .csv.gz and decompress using GZipStream
                    $tempGz = "$($db.LocalFile).gz"
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    Invoke-WebRequest -Uri $db.Url -OutFile $tempGz -UseBasicParsing
                    Write-Output "Extracting gzip: $tempGz"
                    $gzStream = [System.IO.File]::OpenRead($tempGz)
                    $decompStream = New-Object System.IO.Compression.GZipStream($gzStream, [System.IO.Compression.CompressionMode]::Decompress)
                    $outStream = [System.IO.File]::Create($db.LocalFile)
                    $decompStream.CopyTo($outStream)
                    $outStream.Close()
                    $decompStream.Close()
                    $gzStream.Close()
                    Remove-Item $tempGz -Force -ErrorAction SilentlyContinue
                } else {
                    # Download plain CSV directly
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    Invoke-WebRequest -Uri $db.Url -OutFile $db.LocalFile -UseBasicParsing
                }
                Write-Output "Download successful: $($db.LocalFile)"
            } catch {
                Write-Output "Failed to download $($db.Url): $_"
                Write-Output "GeoLite2 local lookups may fail or be incomplete."
            }
        } else {
            Write-Output "GeoLite2 database up to date: $($db.LocalFile)"
        }
    }
}


function Build-GeoLite2Index {
    # Builds a smaller in-memory index for a GeoLite2 CSV file.
    # Stores two flat arrays:
    #   - StartNums: [double[]] numeric start-IP for binary search
    #   - Offsets:   [long[]] byte position where each CSV row begins
    # Saves to a .idx binary cache file so subsequent runs load in seconds.
    #
    # Uses System.IO.StreamReader line-by-line with manual byte-offset tracking.
    # First build of the IPv4 city file (~3.5M records) takes 2-5 minutes in
    # PowerShell; subsequent runs load the cached .idx in ~5 seconds.
    #
    # References:
    #   - Binary search: https://en.wikipedia.org/wiki/Binary_search_algorithm
    #   - StreamReader: https://learn.microsoft.com/en-us/dotnet/api/system.io.streamreader
    #   - ip-location-db CSV format: https://github.com/sapics/ip-location-db
    param(
        [string]$FilePath,
        [string]$IPVersion # "4" or "6"
    )
    $label = "IPv$IPVersion $(Split-Path $FilePath -Leaf)"
    $idxFile = "$FilePath.idx"

    # Index cache version - increment when format or offset logic changes
    [int]$idxVersion = 4

    # --- Try loading from .idx binary cache ---
    # Binary format: [int32 version][int32 count][double[] startNums][long[] offsets]
    # ~16 bytes per record vs ~100+ bytes per record with Export-Clixml XML.
    # Reference: BinaryReader - https://learn.microsoft.com/en-us/dotnet/api/system.io.binaryreader
    if ((Test-Path $idxFile) -and (Test-Path $FilePath)) {
        $csvAge = (Get-Item $FilePath).LastWriteTimeUtc
        $idxAge = (Get-Item $idxFile).LastWriteTimeUtc
        if ($idxAge -ge $csvAge) {
            Write-Output "  Loading cached index: $(Split-Path $idxFile -Leaf)"
            $loadTimer = [Diagnostics.Stopwatch]::StartNew()
            try {
                $idxFs = [System.IO.File]::OpenRead($idxFile)
                $br = New-Object System.IO.BinaryReader($idxFs)
                $cachedVersion = $br.ReadInt32()
                if ($cachedVersion -ne $idxVersion) {
                    $br.Close(); $idxFs.Close()
                    Write-Output "  Cached index is version $cachedVersion, need $idxVersion - rebuilding..."
                } else {
                    $cachedCount = $br.ReadInt32()
                    if ($cachedCount -lt 100) {
                        $br.Close(); $idxFs.Close()
                        Write-Output "  Cached index has only $cachedCount records - rebuilding..."
                    } else {
                        # Read double[] startNums
                        $startBytes = $br.ReadBytes($cachedCount * 8)
                        $cachedStarts = New-Object 'double[]' $cachedCount
                        [System.Buffer]::BlockCopy($startBytes, 0, $cachedStarts, 0, $startBytes.Length)
                        # Read long[] offsets
                        $offsetBytes = $br.ReadBytes($cachedCount * 8)
                        $cachedOffsets = New-Object 'long[]' $cachedCount
                        [System.Buffer]::BlockCopy($offsetBytes, 0, $cachedOffsets, 0, $offsetBytes.Length)
                        $br.Close(); $idxFs.Close()
                        $loadTimer.Stop()

                        Write-Output "  Loaded $cachedCount records from cache in $([math]::Round($loadTimer.Elapsed.TotalSeconds, 1))s ($([math]::Round((Get-Item $idxFile).Length / 1MB, 1)) MB)"
                        $indexData = [PSCustomObject]@{
                            Version   = [int]$idxVersion
                            IPVersion = $IPVersion
                            StartNums = $cachedStarts
                            Offsets   = $cachedOffsets
                            RecordCount = [int]$cachedCount
                            FilePath  = $FilePath
                        }
                        return $indexData
                    }
                }
            } catch {
                Write-Output "  Cached index unreadable - rebuilding: $_"
            }
        } else {
            Write-Output "  CSV is newer than cached index - rebuilding..."
        }
    }

    Write-Output "  Building index for $label (first run only - will be cached for future use)..."
    Write-Output "  This may take a few minutes for large databases..."
    $indexTimer = [Diagnostics.Stopwatch]::StartNew()

    # --- Detect line ending length (CRLF=2, LF=1) ---
    [int]$newlineBytes = 1
    $detectFs = [System.IO.File]::OpenRead($FilePath)
    $detectBuf = New-Object byte[] 8192
    $detectRead = $detectFs.Read($detectBuf, 0, 8192)
    $detectFs.Close()
    for ($di = 0; $di -lt $detectRead; $di++) {
        if ($detectBuf[$di] -eq 10) { # LF
            if ($di -gt 0 -and $detectBuf[$di - 1] -eq 13) { $newlineBytes = 2 }
            break
        }
    }

    # --- Check for UTF-8 BOM (EF BB BF) ---
    [long]$bomOffset = 0
    if ($detectRead -ge 3 -and $detectBuf[0] -eq 0xEF -and $detectBuf[1] -eq 0xBB -and $detectBuf[2] -eq 0xBF) {
        $bomOffset = 3
        Write-Output "    UTF-8 BOM detected - adjusting offsets by 3 bytes"
    }
    Write-Output "    Line endings: $(if ($newlineBytes -eq 2) { 'CRLF (2 bytes)' } else { 'LF (1 byte)' })"

    # --- Build index ---
    $startNumsList = New-Object 'System.Collections.Generic.List[double]'
    $offsetsList = New-Object 'System.Collections.Generic.List[long]'

    # Open with BOM detection enabled so StreamReader consumes BOM properly
    $fs = New-Object System.IO.FileStream($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read, 1048576)
    $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8, $true, 1048576)

    [long]$byteOffset = $bomOffset
    [int]$count = 0
    [int]$lineNum = 0
    [int]$errors = 0
    $progressTimer = [Diagnostics.Stopwatch]::StartNew()

    while ($null -ne ($line = $sr.ReadLine())) {
        $lineNum++
        [long]$thisLineStart = $byteOffset
        $byteOffset += [long][System.Text.Encoding]::UTF8.GetByteCount($line) + $newlineBytes

        if ($line.Length -lt 7) { continue }
        if ($line.StartsWith("ip_range_start")) { continue }

        $commaPos = $line.IndexOf(',')
        if ($commaPos -le 0) { continue }

        $startIPStr = $line.Substring(0, $commaPos)

        try {
            [double]$num = 0
            if ($IPVersion -eq "4") {
                $octets = $startIPStr.Split('.')
                if ($octets.Count -ne 4) { continue }
                $num = [double]$octets[0] * 16777216.0 + [double]$octets[1] * 65536.0 + [double]$octets[2] * 256.0 + [double]$octets[3]
            } else {
                $num = ConvertTo-IPv6Double $startIPStr
            }

            $startNumsList.Add($num)
            $offsetsList.Add($thisLineStart)
            $count++

            # Progress output every 5 seconds
            if ($progressTimer.Elapsed.TotalSeconds -ge 5) {
                Write-Output "    Indexed $count records (line $lineNum)..."
                $progressTimer.Restart()
            }
        } catch {
            $errors++
            if ($errors -le 5) {
                Write-Output "    Parse error on line $lineNum [$startIPStr]: $_"
            }
        }
    }

    $sr.Close()
    $fs.Close()

    $indexTimer.Stop()
    Write-Output "  Indexed $count records for $label in $([math]::Round($indexTimer.Elapsed.TotalSeconds, 1))s (from $lineNum lines$(if ($errors -gt 0) { ", $errors errors" }))"

    if ($count -eq 0) {
        Write-Output "  No records indexed from $FilePath - local lookups will fail."
        return $null
    }

    # Verify first offset reads back correctly
    $verifyLine = Read-GeoLite2Line -FilePath $FilePath -Offset $offsetsList[0]
    if ($verifyLine -match '^\d') {
        Write-Output "  Offset verification OK: first record reads as '$($verifyLine.Substring(0, [Math]::Min($verifyLine.Length, 50)))...'"
    } else {
        Write-Output "  Offset verification FAILED: first record reads as '$($verifyLine.Substring(0, [Math]::Min($verifyLine.Length, 50)))' - offsets may be wrong"
    }

    $indexObj = [PSCustomObject]@{
        Version   = [int]$idxVersion
        IPVersion = $IPVersion
        StartNums = $startNumsList.ToArray()
        Offsets   = $offsetsList.ToArray()
        RecordCount = [int]$count
        FilePath  = $FilePath
    }

    # Cache the index to disk as compact binary
    # Format: [int32 version][int32 count][double[] startNums][long[] offsets]
    # ~16 bytes/record → ~56 MB for 3.5M records
    # Reference: BinaryWriter - https://learn.microsoft.com/en-us/dotnet/api/system.io.binarywriter
    Write-Output "  Saving index cache: $(Split-Path $idxFile -Leaf)"
    try {
        $idxFs = [System.IO.File]::Create($idxFile)
        $bw = New-Object System.IO.BinaryWriter($idxFs)
        $bw.Write([int]$idxVersion)
        $bw.Write([int]$count)
        # Write startNums as raw bytes via Buffer.BlockCopy
        $startBytes = New-Object byte[] ($count * 8)
        [System.Buffer]::BlockCopy($indexObj.StartNums, 0, $startBytes, 0, $startBytes.Length)
        $bw.Write($startBytes)
        # Write offsets as raw bytes
        $offsetBytes = New-Object byte[] ($count * 8)
        [System.Buffer]::BlockCopy($indexObj.Offsets, 0, $offsetBytes, 0, $offsetBytes.Length)
        $bw.Write($offsetBytes)
        $bw.Close()
        $idxFs.Close()
        Write-Output "  Index cached: $([math]::Round((Get-Item $idxFile).Length / 1MB, 1)) MB"
    } catch {
        Write-Output "  Failed to cache index: $_"
    }

    return $indexObj
}

function Search-GeoLite2Index {
    # Binary search through the pre-built index to find the range containing $IPNum,
    # then read and parse just that one line from the CSV file on disk.
    # Returns a hashtable of parsed fields, or $null if no match.
    #
    # The ip-location-db CSVs are sorted by start IP and ranges are contiguous
    # (non-overlapping), so we find the last entry whose StartNum <= $IPNum,
    # then verify $IPNum <= that entry's EndNum by reading the full line.
    #
    # Reference: Binary search algorithm
    #   https://en.wikipedia.org/wiki/Binary_search_algorithm
    param(
        [PSCustomObject]$Index,
        [double]$IPNum,
        [string]$Type # "city" or "asn"
    )
    if ($null -eq $Index -or $Index.RecordCount -eq 0) {
        Write-Verbose "  SEARCH-DEBUG: Index is null or empty"
        return $null
    }

    $starts = $Index.StartNums
    [int]$low = 0
    [int]$high = $Index.RecordCount - 1

    # Find the rightmost entry where StartNum <= IPNum
    [int]$candidate = -1
    while ($low -le $high) {
        [int]$mid = [math]::Floor(($low + $high) / 2)
        if ($starts[$mid] -le $IPNum) {
            $candidate = $mid
            $low = $mid + 1
        } else {
            $high = $mid - 1
        }
    }
    if ($candidate -eq -1) {
        Write-Verbose "  SEARCH-DEBUG: No candidate found (IPNum=$IPNum < all start values)"
        return $null
    }

    Write-Verbose "  SEARCH-DEBUG: candidate=$candidate offset=$($Index.Offsets[$candidate]) startNum=$($starts[$candidate])"

    # Read the candidate line from disk
    $line = Read-GeoLite2Line -FilePath $Index.FilePath -Offset $Index.Offsets[$candidate]
    Write-Verbose "  SEARCH-DEBUG: line='$($line.Substring(0, [Math]::Min($line.Length, 80)))'"
    if ([string]::IsNullOrWhiteSpace($line)) {
        Write-Verbose "  SEARCH-DEBUG: Read-GeoLite2Line returned empty"
        return $null
    }

    $fields = $line.Split(',')
    if ($fields.Count -lt 3) {
        Write-Verbose "  SEARCH-DEBUG: Too few fields ($($fields.Count))"
        return $null
    }

    # Verify the IP falls within the range (check EndNum)
    if ($Index.IPVersion -eq "4") {
        $endNum = ConvertTo-IPv4Integer $fields[1]
    } else {
        $endNum = ConvertTo-IPv6Double $fields[1]
    }
    Write-Verbose "  SEARCH-DEBUG: fields[0]=$($fields[0]) fields[1]=$($fields[1]) endNum=$endNum IPNum=$IPNum inRange=$($IPNum -le $endNum)"
    if ($IPNum -gt $endNum) { return $null } # IP is in a gap between ranges

    # Parse fields based on database type
    # City: ip_range_start, ip_range_end, country_code, state1, state2, city,
    #       postcode, latitude, longitude, timezone
    # ASN:  ip_range_start, ip_range_end, autonomous_system_number,
    #       autonomous_system_organization
    if ($Type -eq "city") {
        return @{
            RangeStart  = $fields[0]
            RangeEnd    = $fields[1]
            CountryCode = if ($fields.Count -gt 2) { $fields[2] } else { "" }
            State1      = if ($fields.Count -gt 3) { $fields[3] } else { "" }
            State2      = if ($fields.Count -gt 4) { $fields[4] } else { "" }
            City        = if ($fields.Count -gt 5) { $fields[5] } else { "" }
            Postcode    = if ($fields.Count -gt 6) { $fields[6] } else { "" }
            Latitude    = if ($fields.Count -gt 7) { $fields[7] } else { "" }
            Longitude   = if ($fields.Count -gt 8) { $fields[8] } else { "" }
            Timezone    = if ($fields.Count -gt 9) { $fields[9] } else { "" }
        }
    } else {
        # ASN - org name may contain commas so rejoin fields 3+
        $asnOrg = ""
        if ($fields.Count -gt 3) {
            $asnOrg = ($fields[3..($fields.Count - 1)]) -join ','
        }
        return @{
            RangeStart = $fields[0]
            RangeEnd   = $fields[1]
            ASN        = $fields[2]
            ASNOrg     = $asnOrg
        }
    }
}

function Read-GeoLite2Line {
    # Reads a single line from a GeoLite2 CSV file at the given byte offset.
    # Opens the file with FileShare.Read, seeks to $Offset, reads bytes until
    # LF (or EOF), and returns the decoded UTF-8 string.
    # Reference: FileStream.Seek - https://learn.microsoft.com/en-us/dotnet/api/system.io.filestream.seek
    param(
        [string]$FilePath,
        [long]$Offset
    )
    $fs = New-Object System.IO.FileStream($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    [void]$fs.Seek($Offset, [System.IO.SeekOrigin]::Begin)
    $buf = New-Object byte[] 2048
    $len = 0
    while ($true) {
        $b = $fs.ReadByte()
        if ($b -eq -1 -or $b -eq 10) { break } # EOF or LF
        if ($b -ne 13 -and $len -lt $buf.Length) { # skip CR
            $buf[$len] = [byte]$b
            $len++
        }
    }
    $fs.Close()
    if ($len -eq 0) { return "" }
    return [System.Text.Encoding]::UTF8.GetString($buf, 0, $len)
}

function ConvertTo-IPv6Double {
    # Converts an IPv6 address string to a [double] for comparison.
    # Same algorithm as the C# ParseIPv6ToDouble - expands :: notation,
    # converts 8 groups to a double. Precision is limited to ~53 bits
    # but sufficient for range lookups against GeoLite2 allocations.
    # Reference: IPv6 addressing (RFC 4291 - https://www.rfc-editor.org/rfc/rfc4291)
    param([string]$IP)
    $IP = $IP.Trim()
    $groups = New-Object 'UInt16[]' 8
    if ($IP -match '::') {
        $halves = $IP -split '::', 2
        $left = if ($halves[0]) { $halves[0].Split(':') } else { @() }
        $right = if ($halves[1]) { $halves[1].Split(':') } else { @() }
        for ($i = 0; $i -lt $left.Count; $i++) {
            $groups[$i] = [Convert]::ToUInt16($left[$i], 16)
        }
        for ($i = 0; $i -lt $right.Count; $i++) {
            $groups[8 - $right.Count + $i] = [Convert]::ToUInt16($right[$i], 16)
        }
    } else {
        $parts = $IP.Split(':')
        for ($i = 0; $i -lt [Math]::Min($parts.Count, 8); $i++) {
            $groups[$i] = [Convert]::ToUInt16($parts[$i], 16)
        }
    }
    [double]$result = 0
    for ($i = 0; $i -lt 8; $i++) {
        $result = $result * 65536.0 + [double]$groups[$i]
    }
    return $result
}

# Main Script Logic

$RowCount = 0
$LookupCount = 0
$GeoLiteLookupCount = 0
$total = [Diagnostics.StopWatch]::StartNew()
Write-Output "$scriptName started"

# Add System.Numerics for BigInteger (IPv6 support)
# Reference: https://learn.microsoft.com/en-us/dotnet/api/system.numerics.biginteger
Add-Type -AssemblyName System.Numerics

# GeoLite2 index variables (loaded once, reused across files)
# These hold lightweight index objects (start-IP arrays + byte offsets)
# instead of full PSObject arrays, cutting RAM from ~200MB+ to ~30-50MB.
$GeoLite2Loaded = $false
$CityIPv4Index = $null
$CityIPv6Index = $null
$ASNIPv4Index = $null
$ASNIPv6Index = $null

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

    $APIfailflag = 0

    foreach ($InfoSource in $InfoSources) {
        $servicetime = [Diagnostics.StopWatch]::StartNew()

        # GeoLite2 Local Database Initialization
        # Load databases on first use of "geolite2local" source.
        if ($InfoSource -eq "geolite2local") {
            if (!$GeoLite2Loaded) {
                if ($GeoLite2Path -eq "") {
                    $GeoLite2Path = Join-Path $PSScriptRoot "GeoLite2Data"
                }
                Write-Output "`nInitializing GeoLite2 local databases in: $GeoLite2Path"
                $initTimer = [Diagnostics.Stopwatch]::StartNew()
                Initialize-GeoLite2Databases -DataPath $GeoLite2Path

                $cityV4File = Join-Path $GeoLite2Path "geolite2-city-ipv4.csv"
                $cityV6File = Join-Path $GeoLite2Path "geolite2-city-ipv6.csv"
                $asnV4File  = Join-Path $GeoLite2Path "geolite2-asn-ipv4.csv"
                $asnV6File  = Join-Path $GeoLite2Path "geolite2-asn-ipv6.csv"

                if ((Test-Path $cityV4File) -and (Test-Path $asnV4File)) {
                    Write-Output "`nLoading IPv4 City index..."
                    $CityIPv4Index = Build-GeoLite2Index -FilePath $cityV4File -IPVersion "4"
                    Write-Output "Loading IPv4 ASN index..."
                    $ASNIPv4Index  = Build-GeoLite2Index -FilePath $asnV4File -IPVersion "4"
                } else {
                    Write-Output "GeoLite2 IPv4 database files not found - IPv4 local lookups will fail."
                }
                if ((Test-Path $cityV6File) -and (Test-Path $asnV6File)) {
                    Write-Output "Loading IPv6 City index..."
                    $CityIPv6Index = Build-GeoLite2Index -FilePath $cityV6File -IPVersion "6"
                    Write-Output "Loading IPv6 ASN index..."
                    $ASNIPv6Index  = Build-GeoLite2Index -FilePath $asnV6File -IPVersion "6"
                } else {
                    Write-Output "GeoLite2 IPv6 database files not found - IPv6 local lookups will fail."
                }
                $initTimer.Stop()
                $GeoLite2Loaded = $true
                Write-Output "`nGeoLite2 initialization complete in $([math]::Round($initTimer.Elapsed.TotalSeconds, 1))s`n"
            }
        } else {
            # Load API key for online services
            $APIKey = $(Import-Csv "$PSScriptRoot\test\api.txt" | Select APIKey, Service | Where-Object {$_.Service -like "*$InfoSource*"} | Select-Object -ExpandProperty APIKey) # Load API key
            # API key required for scamalytics, ip2locationio, iphubinfo, abuseipdbcom, ipqualityscorecom, findipnet, ipinfoiolite, apibundleio, virustotalcom, ipgeolocationio, ipapiis, ipdataco, fraudlogixcom
            if ($APIKey -eq "") {
                Write-Output "API key not set - can only use a subset of services."
            } else {
                Write-Output "API key set."
            }

            if (($InfoSource -eq "scamalytics" -or $InfoSource -eq "ip2locationio" -or $InfoSource -eq "iphubinfo" -or $InfoSource -eq "abuseipdbcom" -or $InfoSource -eq "ipqualityscorecom" -or $InfoSource -eq "findipnet" -or $InfoSource -eq "ipinfoiolite" -or $InfoSource -eq "apibundleio" -or $InfoSource -eq "virustotalcom" -or $InfoSource -eq "ipgeolocationio" -or $InfoSource -eq "ipapiis" -or $InfoSource -eq "ipdataco" -or $InfoSource -eq "" -or $InfoSource -eq "fraudlogixcom") -and $APIKey -eq "") {
                if ($APIfailflag -eq 0) {
                    $InfoSource = "freeipapicom"
                    Write-Output "Using fallback source $InfoSource due to lack of API key."
                    $APIfailflag = 1
                } else {
                    Write-Output "No API key available. Ending run."
                    break
                }
            }
        }

        Write-Output "`nIP information service specified: $InfoSource"

        # For online services, load/create hash table cache
        if ($InfoSource -ne "geolite2local") {
            if (Test-Path "$PSScriptRoot\IPAddressData_$($InfoSource).xml") {
                $IPAddressHash = Import-CliXml "$PSScriptRoot\IPAddressData_$($InfoSource).xml"
            } else {
                $IPAddressHash = @{}
            }
        }

        # Add IP information columns to end of spreadsheet data
        $Spreadsheet | Add-Member -NotePropertyName "IP_Country_$($InfoSource)" -NotePropertyValue $null # Country code
        $Spreadsheet | Add-Member -NotePropertyName "IP_Region_$($InfoSource)" -NotePropertyValue $null # State/Region name
        $Spreadsheet | Add-Member -NotePropertyName "IP_City_$($InfoSource)" -NotePropertyValue $null # City name
        $Spreadsheet | Add-Member -NotePropertyName "IP_ISP_$($InfoSource)" -NotePropertyValue $null # ISP name
        $Spreadsheet | Add-Member -NotePropertyName "IP_Org_$($InfoSource)" -NotePropertyValue $null # Organization name
        $Spreadsheet | Add-Member -NotePropertyName "IP_Type_$($InfoSource)" -NotePropertyValue $null # Extra IP information (VPN, TOR, DCH, Proxy, Blacklists) - service dependent
        $Spreadsheet | Add-Member -NotePropertyName "IP_Score_$($InfoSource)" -NotePropertyValue $null # Risk value from 0(low) to 100 (high) - service dependent
        $Spreadsheet | Add-Member -NotePropertyName "IP_ASN_$($InfoSource)" -NotePropertyValue $null # ASN number - service dependent
        $Spreadsheet | Add-Member -NotePropertyName "IP_Range_$($InfoSource)" -NotePropertyValue $null # ASN IP block range - service dependent

        if ($IPv6NetworkInfoOnly) {
            Write-Output "Only looking up network-level information for IPv6 addresses (saves API calls)"
        }

        # Loop through each row in spreadsheet data
        foreach ($Row in $Spreadsheet) {
            $IP = $Row.$IPcolumn
            $OrigIP = $IP
            $IsIPv6 = $false

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
                    $IsIPv6 = $true
                    if ($IPv6NetworkInfoOnly -and $InfoSource -ne "geolite2local") {
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

                # GeoLite2 Local Lookups
                if ($InfoSource -eq "geolite2local") {
                    $cityResult = $null
                    $asnResult = $null

                    if ($IsIPv6) {
                        # IPv6 lookup using double-precision binary search against index
                        if ($null -ne $CityIPv6Index -and $null -ne $ASNIPv6Index) {
                            $ipNum = ConvertTo-IPv6Double $OrigIP
                            $cityResult = Search-GeoLite2Index -Index $CityIPv6Index -IPNum $ipNum -Type "city"
                            $asnResult = Search-GeoLite2Index -Index $ASNIPv6Index -IPNum $ipNum -Type "asn"
                        } else {
                            Write-Output "IPv6 indexes not loaded - skipping."
                        }
                    } else {
                        # IPv4 lookup using double binary search against index
                        if ($null -ne $CityIPv4Index -and $null -ne $ASNIPv4Index) {
                            [double]$ipNum = ConvertTo-IPv4Integer $IP
                            Write-Verbose "  DEBUG: IP=$IP ipNum=$ipNum IndexCount=$($CityIPv4Index.RecordCount)"
                            $cityResult = Search-GeoLite2Index -Index $CityIPv4Index -IPNum $ipNum -Type "city"
                            $asnResult = Search-GeoLite2Index -Index $ASNIPv4Index -IPNum $ipNum -Type "asn"
                            Write-Verbose "  DEBUG: cityResult=$($null -ne $cityResult) asnResult=$($null -ne $asnResult)"
                            if ($null -ne $cityResult) {
                                Write-Verbose "  DEBUG: Country=$($cityResult.CountryCode) City=$($cityResult.City)"
                            }
                        } else {
                            Write-Output "IPv4 indexes not loaded - skipping."
                        }
                    }

                    # Populate columns from local City database results
                    if ($null -ne $cityResult) {
                        $Row."IP_Country_$InfoSource" = $cityResult.CountryCode
                        # Combine state1 and state2 for region (state2 is sub-region, e.g. county)
                        $regionParts = @($cityResult.State1, $cityResult.State2) | Where-Object { $_ -ne "" }
                        $Row."IP_Region_$InfoSource" = $regionParts -join ', '
                        $Row."IP_City_$InfoSource" = $cityResult.City
                    } else {
                        $Row."IP_Country_$InfoSource" = ""
                        $Row."IP_Region_$InfoSource" = ""
                        $Row."IP_City_$InfoSource" = ""
                    }

                    # Populate columns from local ASN database results
                    if ($null -ne $asnResult) {
                        $Row."IP_ISP_$InfoSource" = $asnResult.ASNOrg
                        $Row."IP_Org_$InfoSource" = $asnResult.ASNOrg
                        $Row."IP_ASN_$InfoSource" = "AS$($asnResult.ASN)"
                        $Row."IP_Range_$InfoSource" = "$($asnResult.RangeStart)-$($asnResult.RangeEnd)"
                    } else {
                        $Row."IP_ISP_$InfoSource" = ""
                        $Row."IP_Org_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    }

                    $Row."IP_Type_$InfoSource" = "" # Not available from GeoLite2 City/ASN
                    $Row."IP_Score_$InfoSource" = "" # Not available from GeoLite2 City/ASN

                    $GeoLiteLookupCount++

                # Online Service Lookups
                } else {
                    $IPInfo = $Null
                    $IPContent = $Null
                    $IPObject = $Null

                    if (!($IPAddressHash[$IP])) {
                        Write-Output "Querying online service."
                        if ($InfoSource -eq "scamalytics") {
                            $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api11.scamalytics.com/vc3/?key=$APIKey&ip=$IP" -UseBasicParsing
                        } elseif ($InfoSource -eq "ipapico") {
                            $IPInfo = Invoke-WebRequest -Method Get -Uri "https://ipapi.co/$IP/json/" -UseBasicParsing # Supported formats: json, jsonp, xml, csv, yaml
                        } elseif ($InfoSource -eq "ipapicom") {
                            write-output "before"
                            write-output "Invoke-WebRequest -Method Get -Uri `"http://ip-api.com/json/$IP`" -UseBasicParsing"
                            $IPInfo = Invoke-WebRequest -Method Get -Uri "http://ip-api.com/json/$IP" -UseBasicParsing
                            write-output "after"
                            Start-Sleep -Seconds 1.5 # Slow down to avoid throttling/rate limiting issues with the web service
                        } elseif ($InfoSource -eq "ip2locationio") {
                            $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.ip2location.io/?key=$APIKey&ip=$IP" -UseBasicParsing
                        } elseif ($InfoSource -eq "hostipinfo") {
                            $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.hostip.info/get_json.php?ip=$IP" -UseBasicParsing
                        } elseif ($InfoSource -eq "iphubinfo") {
                            $IPInfo = Invoke-WebRequest -Method Get -Uri "http://v2.api.iphub.info/ip/$IP" -Headers @{ "X-Key" = "$APIKey" } -UseBasicParsing
                        } elseif ($InfoSource -eq "abuseipdbcom") {
                            $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.abuseipdb.com/api/v2/check/?ipAddress=$IP&maxAgeInDays=90" -Headers @{ "Accept" = "application/json"; "key" = "$APIKey" } -UseBasicParsing
                        } elseif ($InfoSource -eq "ipqualityscorecom") {
                            $IPInfo = Invoke-WebRequest -Method Get -Uri "https://www.ipqualityscore.com/api/json/ip/$APIKey/$IP/?strictness=0&allow_public_access_points=true" -UseBasicParsing
                        } elseif ($InfoSource -eq "freeipapicom") {
                            $IPInfo = Invoke-WebRequest -Method Get -Uri "https://free.freeipapi.com/api/json/$IP" -UseBasicParsing
                            Start-Sleep -Seconds 1 # Slow down to avoid throttling/rate limiting issues with the web service
                        } elseif ($InfoSource -eq "findipnet") {
                            $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.findip.net/$IP/?token=$APIKey" -UseBasicParsing
                        } elseif ($InfoSource -eq "1ipio") {
                            $IPInfo = Invoke-WebRequest -Method Get -Uri "https://1ip.io/api/$IP" -UseBasicParsing
                        } elseif ($InfoSource -eq "ipinfoiolite") {
                            $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.ipinfo.io/lite/$IP/?token=$APIKey" -UseBasicParsing
                        } elseif ($InfoSource -eq "ipwhoorg") {
                            $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.ipwho.org/ip/$IP" -UseBasicParsing
                        } elseif ($InfoSource -eq "apibundleio") {
                            $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.apibundle.io/ip-lookup?apikey=$APIKey&ip=$IP" -UseBasicParsing
                        } elseif ($InfoSource -eq "ipscorecom") {
                            $IPInfo = Invoke-WebRequest -Method Post -Uri "https://ip-score.com/fulljson" -Body @{ ip="$IP" } -UseBasicParsing
                        } elseif ($InfoSource -eq "virustotalcom") {
                            $IPInfo = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$IP" -Method Get -Headers @{ "Accept" = "application/json" ; "x-apikey" = "$APIKey" }
                        } elseif ($InfoSource -eq "ipgeolocationio") {
                            $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.ipgeolocation.io/v2/ipgeo?apiKey=$APIKey&ip=$IP" -UseBasicParsing
                        } elseif ($InfoSource -eq "ipapiis") {
                            $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.ipapi.is?q=$IP&key=$APIKey" -UseBasicParsing
                        } elseif ($InfoSource -eq "ipdataco") {
                            $IPInfo = Invoke-WebRequest -Method Get -Uri "https://api.ipdata.co/$IP/?api-key=$APIKey" -UseBasicParsing
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
                        $Row."IP_Country_$InfoSource" = $scamalytics.ip_country_code # Paywalled
                        $Row."IP_Region_$InfoSource" = $scamalytics.ip_state_name # Paywalled
                        $Row."IP_City_$InfoSource" = $scamalytics.IP_City # Paywalled
                        $Row."IP_ISP_$InfoSource" = $scamalytics.{isp name} # Paywalled
                        $Row."IP_Org_$InfoSource" = $scamalytics.{Organization Name} # Paywalled
                        $Row."IP_Type_$InfoSource" = $scamalytics.proxy_type # Paywalled
                        $Row."IP_Score_$InfoSource" = $scamalytics.score
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "ipapico") {
                        $ipapico = $IPObject
                        $Row."IP_Country_$InfoSource" = $ipapico.country_code
                        $Row."IP_Region_$InfoSource" = $ipapico.region
                        $Row."IP_City_$InfoSource" = $ipapico.city
                        $Row."IP_ISP_$InfoSource" = ""
                        $Row."IP_Org_$InfoSource" = $ipapico.org
                        $Row."IP_Type_$InfoSource" = ""
                        $Row."IP_Score_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "ipapicom") {
                        $ipapicom = $IPObject
                        $Row."IP_Country_$InfoSource" = $ipapicom.countryCode
                        $Row."IP_Region_$InfoSource" = $ipapicom.regionname
                        $Row."IP_City_$InfoSource" = $ipapicom.city
                        $Row."IP_ISP_$InfoSource" = $ipapicom.isp
                        $Row."IP_Org_$InfoSource" = $ipapicom.org
                        $Row."IP_Type_$InfoSource" = ""
                        $Row."IP_Score_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "ip2locationio") {
                        $ip2location = $IPObject
                        $Row."IP_Country_$InfoSource" = $ip2location.country_code
                        $Row."IP_Region_$InfoSource" = $ip2location.region_name
                        $Row."IP_City_$InfoSource" = $ip2location.city_name
                        $Row."IP_ISP_$InfoSource" = ""
                        $Row."IP_Org_$InfoSource" = $ip2location.as
                        $Row."IP_Type_$InfoSource" = if ($ip2location.is_proxy) {"Proxy"} else {""}
                        $Row."IP_Score_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "hostipinfo") {
                        $hostipinfo = $IPObject
                        $Row."IP_Country_$InfoSource" = $hostipinfo.country_code
                        $Row."IP_Region_$InfoSource" = ""
                        $Row."IP_City_$InfoSource" = $hostipinfo.city
                        $Row."IP_ISP_$InfoSource" = ""
                        $Row."IP_Org_$InfoSource" = ""
                        $Row."IP_Type_$InfoSource" = ""
                        $Row."IP_Score_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "iphubinfo") {
                        $iphubinfo = $IPObject
                        $Row."IP_Country_$InfoSource" = $iphubinfo.countryCode
                        $Row."IP_Region_$InfoSource" = ""
                        $Row."IP_City_$InfoSource" = ""
                        $Row."IP_ISP_$InfoSource" = $iphubinfo.isp
                        $Row."IP_Org_$InfoSource" = ""
                        $Row."IP_Type_$InfoSource" = ""
                        $Row."IP_Score_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "abuseipdbcom") {
                        $abuseipdbcom = $IPObject
                        $Row."IP_Country_$InfoSource" = $abuseipdbcom.data.countryCode
                        $Row."IP_Region_$InfoSource" = ""
                        $Row."IP_City_$InfoSource" = ""
                        $Row."IP_ISP_$InfoSource" = $abuseipdbcom.data.isp
                        $Row."IP_Org_$InfoSource" = $abuseipdbcom.data.domain
                        $Row."IP_Type_$InfoSource" = $abuseipdbcom.data.usageType
                        $Row."IP_Score_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "ipqualityscorecom") {
                        $ipqualityscorecom = $IPObject
                        $Row."IP_Country_$InfoSource" = $ipqualityscorecom.country_code
                        $Row."IP_Region_$InfoSource" = $ipqualityscorecom.region
                        $Row."IP_City_$InfoSource" = $ipqualityscorecom.city
                        $Row."IP_ISP_$InfoSource" = $ipqualityscorecom.isp
                        $Row."IP_Org_$InfoSource" = $ipqualityscorecom.organization
                        # Grab subset of the properties related to proxy info that are "true" and smash them into a string
                        $subset = $ipqualityscorecom | Select-Object -Property proxy, vpn, tor, active_vpn, active_tor, recent_abuse, bot_status
                        # $ipInfo = $subset.psobject.properties | Select-Object name, value | Where-Object { $_.value } | join-string -Property name -DoubleQuote -Separator ',' # PowerShell 7
                        $ipInfo = ($subset.psobject.properties | Select-Object name, value | Where-Object { $_.value } | ForEach-Object { "`"$($_.name)`"" }) -join ',' # PowerShell 5
                        $Row."IP_Type_$InfoSource" = $ipInfo
                        $Row."IP_Score_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "freeipapicom") {
                        $freeipapicom = $IPObject
                        $Row."IP_Country_$InfoSource" = $freeipapicom.countryCode
                        $Row."IP_Region_$InfoSource" = $freeipapicom.regionName
                        $Row."IP_City_$InfoSource" = $freeipapicom.cityName
                        $Row."IP_ISP_$InfoSource" = ""
                        $Row."IP_Org_$InfoSource" = $freeipapicom.asnOrganization
                        $Row."IP_Type_$InfoSource" = $freeipapicom.aisProxy
                        $Row."IP_Score_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "findipnet") {
                        $findipnet = $IPObject
                        $Row."IP_Country_$InfoSource" = $findipnet.country.iso_code
                        $Row."IP_Region_$InfoSource" = ($findipnet.subdivisions.names | select en | foreach-object { "$($_.en)" }) -join ', '
                        $Row."IP_City_$InfoSource" = $findipnet.city.names.en
                        $Row."IP_ISP_$InfoSource" = $findipnet.traits.isp
                        $Row."IP_Org_$InfoSource" = $findipnet.traits.organization
                        $Row."IP_Type_$InfoSource" = $findipnet.traits.user_type
                        $Row."IP_Score_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "1ipio") {
                        $1ipio = $IPObject
                        $Row."IP_Country_$InfoSource" = $1ipio.country_code
                        $Row."IP_Region_$InfoSource" = $1ipio.region
                        $Row."IP_City_$InfoSource" = $1ipio.city
                        $Row."IP_ISP_$InfoSource" = ""
                        $Row."IP_Org_$InfoSource" = ""
                        $Row."IP_Type_$InfoSource" = ""
                        $Row."IP_Score_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "ipinfoiolite") {
                        $ipinfoiolite = $IPObject
                        $Row."IP_Country_$InfoSource" = $ipinfoiolite.country_code
                        $Row."IP_Region_$InfoSource" = ""
                        $Row."IP_City_$InfoSource" = ""
                        $Row."IP_ISP_$InfoSource" = ""
                        $Row."IP_Org_$InfoSource" = $ipinfoiolite.as_name
                        $Row."IP_Type_$InfoSource" = ""
                        $Row."IP_Score_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "ipwhoorg") {
                        $ipwhoorg = $IPObject
                        $Row."IP_Country_$InfoSource" = $ipwhoorg.data.countryCode
                        $Row."IP_Region_$InfoSource" = $ipwhoorg.data.region
                        $Row."IP_City_$InfoSource" = $ipwhoorg.data.city
                        $Row."IP_ISP_$InfoSource" = ""
                        $Row."IP_Org_$InfoSource" = ""
                        # Grab subset of the properties related to proxy info that are "true" and not "low" and smash them into a string
                        $subset = $ipwhoorg.data.security | Select-Object -Property isVpn, isTor, isThreat
                        # $ipInfo = $subset.psobject.properties | Select-Object name, value | Where-Object { $_.value -and $_.value -ne "low" } | join-string -Property name -DoubleQuote -Separator ',' # PowerShell 7
                        $ipInfo = ($subset.psobject.properties | Select-Object name, value | Where-Object { $_.value -and $_.value -ne "low" } | ForEach-Object { "`"$($_.name)`"" }) -join ',' # PowerShell 5
                        $Row."IP_Type_$InfoSource" = $ipInfo
                        $Row."IP_Score_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "apibundleio") {
                        $apibundleio = $IPObject
                        $Row."IP_Country_$InfoSource" = $apibundleio.country.iso_2_code
                        $Row."IP_Region_$InfoSource" = ""
                        $Row."IP_City_$InfoSource" = $apibundleio.city.name
                        $Row."IP_ISP_$InfoSource" = ""
                        $Row."IP_Org_$InfoSource" = $apibundleio.connection.aso
                        $Row."IP_Type_$InfoSource" = ""
                        $Row."IP_Score_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "ipscorecom") {
                        $ipscorecom = $IPObject
                        $Row."IP_Country_$InfoSource" = $ipscorecom.geoip2.countrycode
                        $Row."IP_Region_$InfoSource" = $ipscorecom.geoip1.region
                        $Row."IP_City_$InfoSource" = $ipscorecom.geoip1.city
                        $Row."IP_ISP_$InfoSource" = $ipscorecom.isp
                        $Row."IP_Org_$InfoSource" = $ipscorecom.org
                        # Grab subset of the properties related to blacklist info that are "listed" and smash them into a string
                        $subset = $ipscorecom.blacklists | Select-Object -Property spamhaus, sorbs, spamcop, southkoreannbl, barracuda
                        # $blacklistInfo = $subset.psobject.properties | Select-Object name, value | Where-Object { $_.value -eq "listed" } | join-string -Property name -DoubleQuote -Separator ',' # PowerShell 7
                        $blacklistInfo = ($subset.psobject.properties | Select-Object name, value | Where-Object { $_.value -eq "listed" } | ForEach-Object { "`"$($_.name)`"" }) -join ',' # PowerShell 5
                        $Row."IP_Type_$InfoSource" = $blacklistInfo
                        $Row."IP_Score_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "virustotalcom") {
                        $virustotalcom = $IPObject
                        $Row."IP_Country_$InfoSource" = $virustotalcom.data.attributes.rdap.country
                        $Row."IP_Region_$InfoSource" = ""
                        $Row."IP_City_$InfoSource" = ""
                        $Row."IP_ISP_$InfoSource" = ""
                        $Row."IP_Org_$InfoSource" = $virustotalcom.data.attributes.as_owner
                        # Grab subset of the properties related to last analysis info that are not zero and smash them into a string
                        $subset = $virustotalcom.data.attributes.last_analysis_stats | Select-Object -Property malicious, suspicious, undetected, harmless, timeout
                        # $statsInfo = $subset.psobject.properties | Select-Object name, value | Where-Object { $_.value -gt 0 } | join-string -Property name -DoubleQuote -Separator ',' # PowerShell 7
                        $statsInfo = ($subset.psobject.properties | Select-Object name, value | Where-Object { $_.value -gt 0 } | ForEach-Object { "`"$($_.name)`"" }) -join ',' # PowerShell 5
                        $Row."IP_Type_$InfoSource" = $statsInfo
                        $Row."IP_Score_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "ipgeolocationio") {
                        $ipgeolocationio = $IPObject
                        $Row."IP_Country_$InfoSource" = $ipgeolocationio.location.country_code2
                        $Row."IP_Region_$InfoSource" = $ipgeolocationio.location.state_prov
                        $Row."IP_City_$InfoSource" = $ipgeolocationio.location.city
                        $Row."IP_ISP_$InfoSource" = ""
                        $Row."IP_Org_$InfoSource" = ""
                        $Row."IP_Type_$InfoSource" = ""
                        $Row."IP_Score_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "ipapiis") {
                        $ipapiis = $IPObject
                        $Row."IP_Country_$InfoSource" = $ipapiis.location.country_code
                        $Row."IP_Region_$InfoSource" = $ipapiis.location.state
                        $Row."IP_City_$InfoSource" = $ipapiis.location.city
                        $Row."IP_ISP_$InfoSource" = $ipapiis.asn.org
                        $Row."IP_Org_$InfoSource" = $ipapiis.company.name
                        # Grab subset of the properties related to proxy info that are "true" and smash them into a string
                        $subset = $ipapiis | Select-Object -Property is_bogon, is_mobile, is_satellite, is_crawler, is_datacenter, is_tor, is_proxy, is_vpn, is_abuser
                        # $ipInfo = $subset.psobject.properties | Select-Object name, value | Where-Object { $_.value } | join-string -Property name -DoubleQuote -Separator ',' # PowerShell 7
                        $ipInfo = ($subset.psobject.properties | Select-Object name, value | Where-Object { $_.value } | ForEach-Object { "`"$($_.name)`"" }) -join ',' # PowerShell 5
                        $Row."IP_Type_$InfoSource" = $ipInfo
                        $Row."IP_Score_$InfoSource" = $ipapiis.asn.abuser_score
                        $Row."IP_ASN_$InfoSource" = $ipapiis.asn.asn
                        $Row."IP_Range_$InfoSource" = $ipapiis.asn.route
                    } elseif ($InfoSource -eq "ipdataco") {
                        $ipdataco = $IPObject
                        $Row."IP_Country_$InfoSource" = $ipdataco.country_code
                        $Row."IP_Region_$InfoSource" = $ipdataco.region
                        $Row."IP_City_$InfoSource" = $ipdataco.city
                        $Row."IP_ISP_$InfoSource" = ""
                        $Row."IP_Org_$InfoSource" = $ipdataco.asn.name
                        # Grab subset of the properties related to proxy info that are "true" and smash them into a string
                        $subset = $ipdataco.threat | Select-Object -Property is_tor, is_icloud_relay, is_proxy, is_datacenter, is_anonymous, is_known_attacker, is_known_abuser, is_threat, is_bogon
                        # $ipInfo = $subset.psobject.properties | Select-Object name, value | Where-Object { $_.value } | join-string -Property name -DoubleQuote -Separator ',' # PowerShell 7
                        $ipInfo = ($subset.psobject.properties | Select-Object name, value | Where-Object { $_.value } | ForEach-Object { "`"$($_.name)`"" }) -join ',' # PowerShell 5
                        $Row."IP_Type_$InfoSource" = $ipInfo
                        $Row."IP_Score_$InfoSource" = ""
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    } elseif ($InfoSource -eq "fraudlogixcom") {
                        $fraudlogixcom = $IPObject
                        $Row."IP_Country_$InfoSource" = $fraudlogixcom.CountryCode
                        $Row."IP_Region_$InfoSource" = $fraudlogixcom.region
                        $Row."IP_City_$InfoSource" = $fraudlogixcom.city
                        $Row."IP_ISP_$InfoSource" = $fraudlogixcom.isp
                        $Row."IP_Org_$InfoSource" = $fraudlogixcom.organization
                        # Grab subset of the properties related to proxy info that are "true" and smash them into a string
                        $subset = $fraudlogixcom | Select-Object -Property MaskedDevices, Proxy, TOR, VPN, DataCenter, SearchEngineBot, AbnormalTraffic
                        # $proxyInfo = $subset.psobject.properties | Select-Object name, value | Where-Object { $_.value } | join-string -Property name -DoubleQuote -Separator ',' # PowerShell 7
                        $proxyInfo = ($subset.psobject.properties | Select-Object name, value | Where-Object { $_.value } | ForEach-Object { "`"$($_.name)`"" }) -join ',' # PowerShell 5
                        $Row."IP_Type_$InfoSource" = $proxyInfo
                        $Row."IP_Score_$InfoSource" = $fraudlogixcom.RiskScore
                        $Row."IP_ASN_$InfoSource" = ""
                        $Row."IP_Range_$InfoSource" = ""
                    }
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

        # Save hash table cache for online services
        if ($InfoSource -ne "geolite2local") {
            $IPAddressHash | Export-Clixml -path "$PSScriptRoot\IPAddressData_$($InfoSource).xml" -Force
        }

        Write-Output "Processed a total of $RowCount rows using $GeoLiteLookupCount local GeoLite2 lookups and $LookupCount internet lookups in $($servicetime.elapsed.totalseconds) seconds to retrieve data from $InfoSource."
    }

    # Export updated spreadsheet data to CSV file
    [string]$outputFolder = Split-Path -Path $inputFile -Parent
    [string]$outputFile = (Get-Item $inputFile).BaseName
    [string]$outputPath = $outputFolder + "\" + $outputFile + "_IPEnriched_$($InfoSources -join('_')).csv"
    $Spreadsheet | Export-Csv -Path "$outputPath" -NoTypeInformation
}

Write-Output "`nTotal time for script execution: $($total.elapsed.totalseconds)"
Write-Output "Script complete!"
# Attribution: This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com
# GeoLite2 databases provided under CC BY-SA 4.0 license via https://github.com/sapics/ip-location-db

exit
