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
# SelectUniquePairsCSV.ps1 - By Bitpusher/The Digital Fox
# v3.1 last updated 2025-07-26
# Imports a CSV, prompts for the names of two columns in the CSV, and exports
# a new CSV containing unique pairs of values from those two columns.
# Useful for manually finding patterns in logs, correlating things like IPs with Sessions.
#
# Usage:
# powershell -executionpolicy bypass -f .\SelectUniquePairsCSV.ps1 -inputFile "Path\to\input\log.csv" -outputFile "Path\to\output\file.csv" -IPcolumn "IP Column Name" -InfoSource "IP service to use" -APIKey "API key if required for service"
#
# Use with DropShim.bat to allow drag-and-drop processing of CSV files (logs, etc.) with an IP column, either singly or in bulk.
#
#comp #m365 #security #bec #script #logs #IP #csv #unique #sort #rows #irscript #powershell

#Requires -Version 5.1

param(
    [string[]]$inputFiles = @("UALexport.csv"),
    [string]$outputFile = "UALexport_Processed.csv",
    [string]$FirstColumn,
    [string]$SecondColumn,
    [string]$scriptName = "SelectUniquePairsCSV",
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

$total = [Diagnostics.StopWatch]::StartNew()

foreach ($inputFile in $inputfiles) {
    # Load spreadsheet
    Write-Output "`nLoading $inputFile..."
    $Spreadsheet = Import-Csv -Path "$inputFile"
    $Headers = $Spreadsheet | Get-Member -MemberType NoteProperty | Select-Object Name
    Write-Output "`nColumn headers found in CSV:"
    $Headers.Name

    Write-Output "Enter two column headers to pull from CSV and filter for unique combinations."
    if (!$FirstColumn) {
        $FirstColumn = Read-Host "`nFirst column"
    }
    if (!$SecondColumn) {
        $SecondColumn = Read-Host "Second column"
    }
    Write-Output "`nColumns '$FirstColumn' and '$SecondColumn' selected..."

    if ($Headers.Name -notcontains $FirstColumn) {
        Write-Output "`n$FirstColumn column not found in CSV - exiting."
        exit
    }

    if ($Headers.Name -notcontains $SecondColumn) {
        Write-Output "`n$SecondColumn column not found in CSV - exiting."
        exit
    }

    $Selection = $Spreadsheet | Select-Object $FirstColumn,$SecondColumn

    $UniqueRows = $Selection | Sort-Object $FirstColumn,$SecondColumn -Unique

    # Export updated spreadsheet data to CSV file
    [string]$outputFolder = Split-Path -Path $inputFile -Parent
    [string]$outputFile = (Get-Item $inputFile).BaseName
    [string]$outputPath = $outputFolder + "\" + $outputFile + "_$($FirstColumn)_$($SecondColumn)_UniqueRows.csv"
    $UniqueRows | Export-Csv -Path "$outputPath" -NoTypeInformation
}

Write-Output "`nTotal time for script execution: $($total.elapsed.totalseconds)"
Write-Output "Script complete!"

exit
