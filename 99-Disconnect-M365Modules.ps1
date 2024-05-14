#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# Disconnect-M365Modules.ps1 - By Bitpusher/The Digital Fox
# v2.8 last updated 2024-05-12
# Script to disconnect from all M365 modules/sessions.
#
# Usage:
# powershell -executionpolicy bypass -f .\Disconnect-M365Modules.ps1
#
# Run with already existing connection to M365 tenant through
# PowerShell modules.
#
# Uses ExchangePowerShell, MSOnline, AzureAD, Microsoft Graph commands.
#
#comp #m365 #security #bec #script #irscript #powershell #disconnect

#Requires -Version 5.1

Write-Output "Currently connected as:"
(Get-ConnectionInformation).UserPrincipalName
Get-PSSession

Write-Output "`nDisconnecting all M365 modules..."


Disconnect-MgGraph -InformationAction Ignore -ErrorAction SilentlyContinue
Get-MgContext -ErrorAction SilentlyContinue
$Test = $Null
$Test = Get-MgDomain -ErrorAction SilentlyContinue
if ($Test) {
    Write-Output "`nMS Graph still connected."
} else {
    Write-Output "`nMS Graph disconnected."
}


try { [Microsoft.Online.Administration.Automation.ConnectMsolService]::ClearUserSessionState(); Write-Output "`nMSOL session state cleared." } catch { Write-Output "`nUnable to clear MSOL session state - close PS window to ensure it is cleared." }
try {
    $Test = $Null
    $Test = Get-MsolDomain -ErrorAction SilentlyContinue
    if ($Test) {
        Write-Output "`nMSOL still connected."
    } else {
        Write-Output "`nMSOL disconnected."
    }
} catch {
    Write-Output "`nMSOL disconnected."
}


Disconnect-ExchangeOnline -Confirm:$false -InformationAction Ignore -ErrorAction SilentlyContinue
$EOSessions = Get-PSSession | Select-Object -Property State, Name
$isconnected = (@($EOSessions) -like '@{State=Opened; Name=ExchangeOnlineInternalSession*').Count -gt 0
if ($isconnected) {
    $EOInfo = Get-ConnectionInformation
    $EOInfo | Select-Object State, Name, UserPrincipalName, ConnectionUri, IsEopSession
    Write-Output "`nExchange Online/IPPS still connected."
} else {
    Write-Output "`nExchange Online/IPPS disconnected."
}


try {
    Disconnect-AzureAD -InformationAction Ignore -ErrorAction SilentlyContinue
} catch {
    Write-Output "Error calling Disconnect-AzureAD."
}
try {
    $Test = $Null
    $Test = Get-AzureADTenantDetail -ErrorAction SilentlyContinue
    if ($Test) {
        Write-Output "`nAzureAD still connected."
    } else {
        Write-Output "`nAzureAD disconnected."
    }
} catch {
    Write-Output "`nAzureAD disconnected."
}


Get-PSSession | Remove-PSSession

Write-Output "`nDone."
Write-Output '__________________________________'
Write-Output "`n`n"

$exitUTF = @'
░█▀▀░█▀▀░█▀▀░░█░█░█▀█░█░█░░█▀▀░█▀█░█▀█░█▀▀░█▀▀░░█▀▀░█▀█░█░█░█▀▄░█▀█░█░█░░░░░░░
░▀▀█░█▀▀░█▀▀░░░█░░█░█░█░█░░▀▀█░█▀▀░█▀█░█░░░█▀▀░░█░░░█░█░█▄█░█▀▄░█░█░░█░░░░░░░░
░▀▀▀░▀▀▀░▀▀▀░░░▀░░▀▀▀░▀▀▀░░▀▀▀░▀░░░▀░▀░▀▀▀░▀▀▀░░▀▀▀░▀▀▀░▀░▀░▀▀░░▀▀▀░░▀░░▀░▀░▀░
'@

$exitANSI = @'
..%%%%...%%%%%%..%%%%%%..........%%..%%...%%%%...%%..%%.
.%%......%%......%%...............%%%%...%%..%%..%%..%%.
..%%%%...%%%%....%%%%..............%%....%%..%%..%%..%%.
.....%%..%%......%%................%%....%%..%%..%%..%%.
..%%%%...%%%%%%..%%%%%%............%%.....%%%%....%%%%..
........................................................
..%%%%...%%%%%....%%%%....%%%%...%%%%%%.
.%%......%%..%%..%%..%%..%%..%%..%%.....
..%%%%...%%%%%...%%%%%%..%%......%%%%...
.....%%..%%......%%..%%..%%..%%..%%.....
..%%%%...%%......%%..%%...%%%%...%%%%%%.
........................................
..%%%%....%%%%...%%...%%..%%%%%....%%%%...%%..%%.........................
.%%..%%..%%..%%..%%...%%..%%..%%..%%..%%...%%%%..........................
.%%......%%..%%..%%.%.%%..%%%%%...%%..%%....%%...........................
.%%..%%..%%..%%..%%%%%%%..%%..%%..%%..%%....%%......%%......%%......%%...
..%%%%....%%%%....%%.%%...%%%%%....%%%%.....%%......%%......%%......%%...
'@

# Check whether this file was read as UTF-8 or ANSI. If UTF-8 the length of the string will be 1 ('ä'). If encoding got screwed up and it was read as ANSI the length will be 2 ('Ã¤').
# Windows PowerShell will misinterpret a UTF-8 file without a BOM as ACSI, while PowerShell Core v6+ by default assumes such files are UTF-8.
if ('ä'.length -eq 1) {
    $Foreground = $host.ui.RawUI.ForegroundColor
    $host.ui.RawUI.ForegroundColor = "DarkYellow"
    Write-Output "$exitUTF"
    $host.ui.RawUI.ForegroundColor = $Foreground
} else {
    $Foreground = $host.ui.RawUI.ForegroundColor
    $host.ui.RawUI.ForegroundColor = "DarkYellow"
    Write-Output "$exitANSI"
    $host.ui.RawUI.ForegroundColor = $Foreground
}
Write-Output "`n`n"
