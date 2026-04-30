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
# Search-MailboxSuspiciousRules.ps1 - By Bitpusher/The Digital Fox
# v4.0.0 last updated 2026-04-27
# Script to check all mailbox rules on a domain for suspicious entries.
# Entries are identified as suspicious based on several basic heuristic rules:
# Forwarding, suspicious names, suspicious moving, suspicious keywords, deleting messages
#
# Usage:
# powershell -executionpolicy bypass -f .\Search-MailboxSuspiciousRules.ps1 -OutputPath "Default"
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell commands.
# Minimally required tenant role(s): Exchange RBAC "View-Only Org Mgmt"
#
#comp #m365 #security #bec #script #forwarding #rules #suspicious

#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

param(
    [string]$OutputPath = "Default",
    [string]$UserIds,
    [int]$DaysAgo,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$scriptName = "Search-MailboxSuspiciousRules",
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
    [string]$Encoding = "utf8NoBOM", # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM",
    [switch]$NoExplorer
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


function Assert-M365Connection {
    <#
    .SYNOPSIS
    Checks for active Exchange Online and/or MS Graph connections and attempts to connect if missing.
    Scoped to the minimum permissions required by this script.
    #>
    param(
        [switch]$RequireEXO,
        [switch]$RequireGraph,
        [switch]$RequireIPPS,
        [string[]]$GraphScopes
    )

    if ($RequireEXO) {
        $exoConnected = $false
        try { $exoConnected = [bool](Get-ConnectionInformation -ErrorAction SilentlyContinue) } catch {}
        if (-not $exoConnected) {
            Write-Output "Exchange Online not connected. Attempting connection..."
            try {
                Connect-ExchangeOnline -ShowBanner:$false
                Write-Output "Exchange Online connected."
            } catch {
                Write-Error "Failed to connect to Exchange Online: $_"
                exit 1
            }
        } else {
            Write-Output "Exchange Online connection verified."
        }
    }

    if ($RequireIPPS) {
        $ippsConnected = $false
        try { $ippsConnected = [bool](Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionUri -match "compliance" }) } catch {}
        if (-not $ippsConnected) {
            Write-Output "Security & Compliance (IPPS) not connected. Attempting connection..."
            try {
                Connect-IPPSSession -ShowBanner:$false
                Write-Output "IPPS connected."
            } catch {
                Write-Error "Failed to connect to IPPS: $_"
                exit 1
            }
        } else {
            Write-Output "IPPS connection verified."
        }
    }

    if ($RequireGraph) {
        $graphContext = $null
        try { $graphContext = Get-MgContext -ErrorAction SilentlyContinue } catch {}
        if (-not $graphContext) {
            Write-Output "MS Graph not connected. Attempting connection with scopes: $($GraphScopes -join ', ')..."
            try {
                Connect-MgGraph -Scopes $GraphScopes -NoWelcome
                Write-Output "MS Graph connected."
            } catch {
                Write-Error "Failed to connect to MS Graph: $_"
                exit 1
            }
        } else {
            # Verify required scopes are present
            $currentScopes = $graphContext.Scopes
            $missingScopes = $GraphScopes | Where-Object { $_ -notin $currentScopes }
            if ($missingScopes) {
                Write-Output "MS Graph connected but missing scopes: $($missingScopes -join ', '). Reconnecting..."
                try {
                    Connect-MgGraph -Scopes $GraphScopes -NoWelcome
                    Write-Output "MS Graph reconnected with required scopes."
                } catch {
                    Write-Warning "Could not reconnect with required scopes. Some operations may fail."
                }
            } else {
                Write-Output "MS Graph connection verified with required scopes."
            }
        }
    }
}

$sw = [Diagnostics.StopWatch]::StartNew()

Assert-M365Connection -RequireEXO

Write-Output "$scriptName started on $ComputerName by $ScriptUserName at  $(Get-TimeStamp)" | Tee-Object -FilePath $logFilePath -Append

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

$date = Get-Date -Format "yyyyMMddHHmmss"
$domains = Get-AcceptedDomain

Write-Output "`nRetrieving list of all mailboxes on tenant..."
$mailboxes = Get-Mailbox -ResultSize Unlimited

$OutputCSV = "$OutputPath\$DomainName\SuspiciousInboxRulesForManualReview_$($date).csv"

Write-Output "`n`nChecking mailbox rules in each mailbox for suspicious entries..."
Write-Output "(based on forwarding, rule names, message moving, keywords, message deletion)"
Write-Output "...`n"

foreach ($mailbox in $mailboxes) {

    $forwardRules = $null
    $nameRules = $null
    $moveRules = $null
    $deleteRules = $null
    $keywordRules = $null
    $sizeRules = $null

    Write-Output "Checking rules for $($mailbox.displayname) - $($mailbox.primarysmtpaddress) - $($mailbox.guid)"
    # $rules = get-inboxrule -Mailbox $mailbox.primarysmtpaddress # May not be unique - could be interpreted as Email Address, Display Name, Alias, or UPN and there could be a collision among these values
    $rules = get-inboxrule -Mailbox $mailbox.GUID -IncludeHidden

    $forwardRules = $rules | Where-Object { $_.forwardto -or $_.forwardasattachmentto -or $_.RedirectTo } # ForwardTo or ForwardAttachmentTo or RedirectTo
    $nameRules = $rules | Where-Object { $_.Name -eq '...' -or $_.Name -like '*..*' -or $_.Name -like '*,,*' -or $_.Name.Length -lt 3 } # Name = ., Name = ,, Name = .., Name = ..., Name = //, Name = 1, any other really short name
    $moveRules = $rules | Where-Object { $_.MoveToFolder -like 'RSS*' -or $_.MoveToFolder -like '*Archive*' -or $_.MoveToFolder -like '*History*' -or $_.MoveToFolder -like '*Junk*' -or $_.MoveToFolder -like '*Conversation*' -or $_.MoveToFolder -like '*Calendar*' } # MoveToFolder = RSS Subscriptions, MoveToFolder = RSS Feeds, MoveToFolder = Conversation History, MoveToFolder = Archive, MoveToFolder = Junk Email
    $deleteRules = $rules | Where-Object { $_.DeleteMessage -or $_.SoftDeleteMessage -or $_.MoveToFolder -like '*Deleted*' } # DeleteMessage = True, MoveToFolder = Deleted Items
    $keywords = @("docusign", "invoice", "payment", "bank", "fraud", "compromise", "password", "helpdesk", "w2", "mfa", "wire", "scam", "hack", "phish", "a;", "e;", "i;", "o;", "u;", "RE:", "ACH", "routing", "venmo", "zelle", "bitcoin", "crypto")
    $keywordRules = $rules | Where-Object { $_.BodyContainsWords -eq " " -or $_.BodyContainsWords -eq "`0" -or $_.SubjectContainsWords -eq " " -or $_.SubjectOrBodyContainsWords -eq " " -or $_.BodyContainsWords -in $keywords -or $_.SubjectContainsWords -in $keywords -or $_.SubjectOrBodyContainsWords -in $keywords } # Subject Or Body Contains Words = a blank space, Subject Or Body Contains Words = docusign, invoice, payment, bank, fraud, compromise, helpdesk, password, w2, mfa, wire, scam, hack, phish, "RE:", semicolon-separated vowel list (will match on all messages)
    $sizeRules = $rules | Where-Object { $null -ne $_.WithinSizeRangeMinimum -and $_.WithinSizeRangeMinimum -le 1023 } # WithinSizeRangeMinimum set to value that will round down and equal everything

    foreach ($rule in $forwardRules) { Add-Member -InputObject $rule -MemberType NoteProperty -Name SuspectTrait -Value "MessageForwarding" -Force }
    foreach ($rule in $deleteRules) { Add-Member -InputObject $rule -MemberType NoteProperty -Name SuspectTrait -Value "MessageDeletion" -Force }
    foreach ($rule in $keywordRules) { Add-Member -InputObject $rule -MemberType NoteProperty -Name SuspectTrait -Value "RuleContainsKeywords" -Force }
    foreach ($rule in $moveRules) { Add-Member -InputObject $rule -MemberType NoteProperty -Name SuspectTrait -Value "MessageMoveFolder" -Force }
    foreach ($rule in $nameRules) { Add-Member -InputObject $rule -MemberType NoteProperty -Name SuspectTrait -Value "RuleName" -Force }
    foreach ($rule in $sizeRules) { Add-Member -InputObject $rule -MemberType NoteProperty -Name SuspectTrait -Value "RuleSize" -Force }

    $suspiciousRules = @()
    $suspiciousRules += $forwardRules
    $suspiciousRules += $nameRules
    $suspiciousRules += $moveRules
    $suspiciousRules += $deleteRules
    $suspiciousRules += $keywordRules
    $suspiciousRules += $sizeRules

    foreach ($rule in $suspiciousRules) {
        $recipients = @()
        $recipients = $rule.forwardto | Where-Object { $_ -match "SMTP" }
        $recipients += $rule.forwardasattachmentto | Where-Object { $_ -match "SMTP" }

        $externalRecipients = @()

        foreach ($recipient in $recipients) {
            $email = ($recipient -split "SMTP:")[1].Trim("]")
            $domain = ($email -split "@")[1]

            if ($domains.DomainName -notcontains $domain) {
                $externalRecipients += $email
            }
        }

        $extRecString = $externalRecipients -join ", "
        $ruleHash = $null
        $ruleHash = [ordered]@{
            SuspectTrait              = $rule.SuspectTrait
            DisplayName               = $mailbox.DisplayName
            PrimarySmtpAddress        = $mailbox.PrimarySmtpAddress
            MailboxGuid               = $mailbox.GUID
            RuleName                  = $rule.Name
            RulePriority              = $rule.Priority
            RuleIdentity              = $rule.RuleIdentity
            RuleDescription           = $rule.Description
            RuleEnabled               = $rule.Enabled
            RuleForwardTo             = $rule.forwardto
            RuleForwardAttTo          = $rule.forwardasattachmentto
            ExternalRecipients        = $extRecString
            RuleMoveTo                = $rule.MoveToFolder
            RuleDelete                = $rule.DeleteMessage
            RuleSoftDelete            = $rule.SoftDeleteMessage
            RuleBodyContains          = $rule.BodyContainsWords
            RuleSubjectContains       = $rule.SubjectContainsWords
            RuleSubjectOrBodyContains = $rule.SubjectOrBodyContainsWords
            RuleFrom                  = $rule.From
            RuleFromContains          = $rule.FromAddressContainsWords
        }
        $ruleObject = New-Object PSObject -Property $ruleHash
        $ruleObject | Select-Object SuspectTrait,DisplayName,PrimarySmtpAddress,RuleName | Format-Table
        $ruleObject | Export-Csv $OutputCSV -Append -NoTypeInformation -Encoding $Encoding
    }
}

if ((Test-Path -Path $OutputCSV) -eq "True") {
    Write-Output `n" The Output file is available at:" | Tee-Object -FilePath $logFilePath -Append
    Write-Output $OutputCSV | Tee-Object -FilePath $logFilePath -Append
    # $Prompt = New-Object -ComObject wscript.shell
    # $UserInput = $Prompt.popup("Do you want to open output file?", 0, "Open Output File", 4)
    # if ($UserInput -eq 6) {
    #     Invoke-Item "$OutputCSV"
    # }
}

Write-Output "Script complete." | Tee-Object -FilePath $logFilePath -Append
Write-Output "Seconds elapsed for script execution: $($sw.elapsed.totalseconds)" | Tee-Object -FilePath $logFilePath -Append

Write-Output "`nDone! Check output path for results." | Tee-Object -FilePath $logFilePath -Append
if (-not $NoExplorer) { Invoke-Item "$OutputPath\$DomainName" }

exit
