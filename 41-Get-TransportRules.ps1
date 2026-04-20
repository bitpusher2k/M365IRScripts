#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Get-TransportRules.ps1 - By Bitpusher/The Digital Fox
# v3.2 last updated 2026-03-29
# Script to export all Exchange Online transport rules (mail flow rules)
# for review during an investigation. Transport rules operate at the
# organization level and can be manipulated by threat actors with admin access to:
# - BCC copies of all mail to an external address
# - Bypass spam filtering for specific senders/domains
# - Redirect mail matching certain patterns
# - Strip headers or modify messages
# - Delete messages matching certain criteria
# - Accept and broadcast spam/phishing messages from an external source
#
# Flags rules with suspicious characteristics for manual review.
#
# Usage:
# powershell -executionpolicy bypass -f .\Get-TransportRules.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell (Get-TransportRule) commands.
#
# References:
# https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules
# https://learn.microsoft.com/en-us/powershell/module/exchange/get-transportrule
# https://www.crowdstrike.com/blog/crowdstrike-launches-free-tool-to-identify-and-help-mitigate-risks-in-azure-ad/
#
#comp #m365 #security #bec #script #irscript #powershell #transport #rules #mailflow

#Requires -Version 5.1

param(
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Get-TransportRules",
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
    [string]$Encoding = "utf8NoBOM"
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
Write-Output "$scriptName started on $ComputerName by $ScriptUserName at $(Get-TimeStamp)" | Tee-Object -FilePath $logFilePath -Append
$process = Get-Process -Id $pid
Write-Output "Setting process priority to `"$Priority`"" | Tee-Object -FilePath $logFilePath -Append
$process.PriorityClass = $Priority
#endregion initialization

$date = Get-Date -Format "yyyyMMddHHmmss"

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
$PrimaryDomain = Get-AcceptedDomain | Where-Object Default -EQ $true
$DomainName = $PrimaryDomain.DomainName

$CheckSubDir = Get-Item $OutputPath\$DomainName -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
    Write-Output ""
    Write-Output "Domain sub-directory does not exist. Sub-directory `"$DomainName`" will be created." | Tee-Object -FilePath $logFilePath -Append
    mkdir $OutputPath\$DomainName
}
Write-Output "Domain sub-directory will be `"$DomainName`"" | Tee-Object -FilePath $logFilePath -Append

$OutputCSV = "$OutputPath\$DomainName\TransportRules_$($date).csv"
$OutputCSVSuspect = "$OutputPath\$DomainName\SuspiciousTransportRules_$($date).csv"

## Get accepted domains for external detection
$domains = Get-AcceptedDomain

Write-Output "`nRetrieving all Exchange Online transport rules (mail flow rules)..." | Tee-Object -FilePath $logFilePath -Append

$rules = Get-TransportRule -IncludeRecoverable

if ($rules.Count -eq 0) {
    Write-Output "No transport rules found on this tenant." | Tee-Object -FilePath $logFilePath -Append
} else {
    Write-Output "Found $($rules.Count) transport rule(s).`n" | Tee-Object -FilePath $logFilePath -Append

    $allResults = @()
    $suspiciousResults = @()

    foreach ($rule in $rules) {
        $suspectTraits = @()

        # Check for BCC to external address
        if ($rule.BlindCopyTo) {
            $bccAddresses = $rule.BlindCopyTo -join ", "
            foreach ($bcc in $rule.BlindCopyTo) {
                $bccDomain = ($bcc -split "@")[-1]
                if ($domains.DomainName -notcontains $bccDomain) {
                    $suspectTraits += "ExternalBCC"
                }
            }
            if ($suspectTraits -notcontains "ExternalBCC") {
                $suspectTraits += "BCCConfigured"
            }
        }

        # Check for redirect to external address
        if ($rule.RedirectMessageTo) {
            foreach ($redirect in $rule.RedirectMessageTo) {
                $redirectDomain = ($redirect -split "@")[-1]
                if ($domains.DomainName -notcontains $redirectDomain) {
                    $suspectTraits += "ExternalRedirect"
                }
            }
        }

        # Check for spam filter bypass
        if ($rule.SetSCL -eq -1) {
            $suspectTraits += "SpamFilterBypass"
        }

        # Check for header removal/modification
        if ($rule.RemoveHeader) {
            $suspectTraits += "HeaderRemoval"
        }

        # Check for message deletion
        if ($rule.DeleteMessage -eq $true) {
            $suspectTraits += "MessageDeletion"
        }

        # Check for recently created rules (within last 30 days)
        if ($rule.WhenChanged -and $rule.WhenChanged -gt (Get-Date).AddDays(-30)) {
            $suspectTraits += "RecentlyModified"
        }

        # Check for rule that applies to all messages (no conditions)
        $hasConditions = $false
        if ($rule.FromAddressContainsWords -or $rule.SubjectContainsWords -or $rule.SubjectOrBodyContainsWords -or
            $rule.From -or $rule.SentTo -or $rule.FromMemberOf -or $rule.SentToMemberOf -or
            $rule.RecipientAddressContainsWords -or $rule.AnyOfToHeader -or $rule.AnyOfCcHeader -or
            $rule.HasClassification -or $rule.AttachmentContainsWords -or $rule.AttachmentIsUnsupported) {
            $hasConditions = $true
        }
        if (!$hasConditions -and ($rule.BlindCopyTo -or $rule.RedirectMessageTo)) {
            $suspectTraits += "NoConditions"
        }

        # Check for rule name that looks suspicious (very short, dots, random chars)
        if ($rule.Name.Length -lt 3 -or $rule.Name -match '^\.+$' -or $rule.Name -match '^[^a-zA-Z0-9\s]+$') {
            $suspectTraits += "SuspiciousName"
        }

        $ruleHash = [ordered]@{
            Name                       = $rule.Name
            State                      = $rule.State
            Priority                   = $rule.Priority
            WhenChanged                = $rule.WhenChanged
            SuspectTraits              = ($suspectTraits -join ", ")
            Description                = $rule.Description
            FromAddressContainsWords   = ($rule.FromAddressContainsWords -join "; ")
            SubjectContainsWords       = ($rule.SubjectContainsWords -join "; ")
            SubjectOrBodyContainsWords = ($rule.SubjectOrBodyContainsWords -join "; ")
            From                       = ($rule.From -join "; ")
            SentTo                     = ($rule.SentTo -join "; ")
            BlindCopyTo                = ($rule.BlindCopyTo -join "; ")
            RedirectMessageTo          = ($rule.RedirectMessageTo -join "; ")
            SetSCL                     = $rule.SetSCL
            DeleteMessage              = $rule.DeleteMessage
            RemoveHeader               = $rule.RemoveHeader
            ModifySubject              = $rule.PrependSubject
            SetHeaderName              = $rule.SetHeaderName
            SetHeaderValue             = $rule.SetHeaderValue
            Guid                       = $rule.Guid
        }

        $ruleObject = New-Object PSObject -Property $ruleHash
        $allResults += $ruleObject

        if ($suspectTraits.Count -gt 0) {
            $suspiciousResults += $ruleObject
        }
    }

    # Export all rules
    $allResults | Format-Table Name, State, Priority, SuspectTraits, BlindCopyTo, RedirectMessageTo -AutoSize
    $allResults | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding $Encoding

    # Export and highlight suspicious rules
    if ($suspiciousResults.Count -gt 0) {
        Write-Output "`n===== SUSPICIOUS TRANSPORT RULES FOUND =====" | Tee-Object -FilePath $logFilePath -Append
        $suspiciousResults | Format-Table Name, State, SuspectTraits, BlindCopyTo, RedirectMessageTo, SetSCL, DeleteMessage -AutoSize
        $suspiciousResults | Export-Csv -Path $OutputCSVSuspect -NoTypeInformation -Encoding $Encoding
        Write-Output "$($suspiciousResults.Count) suspicious transport rule(s) flagged for review." | Tee-Object -FilePath $logFilePath -Append
        Write-Output "" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "Remediation commands:" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "  Disable rule:  Disable-TransportRule -Identity '<RuleName>'" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "  Remove rule:   Remove-TransportRule -Identity '<RuleName>'" | Tee-Object -FilePath $logFilePath -Append
        Write-Output "  View details:  Get-TransportRule -Identity '<RuleName>' | Format-List" | Tee-Object -FilePath $logFilePath -Append
    } else {
        Write-Output "`nNo transport rules flagged as suspicious." | Tee-Object -FilePath $logFilePath -Append
    }
}

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:" | Tee-Object -FilePath $logFilePath -Append
    Write-Output $OutputCSV | Tee-Object -FilePath $logFilePath -Append
}
if ((Test-Path -Path $OutputCSVSuspect) -eq "True") {
    Write-Output " Suspicious rules report:" | Tee-Object -FilePath $logFilePath -Append
    Write-Output $OutputCSVSuspect | Tee-Object -FilePath $logFilePath -Append
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append
Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
Invoke-Item "$OutputPath\$DomainName"
Exit
