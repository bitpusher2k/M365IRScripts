#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# ProcessUnifiedAuditLogFlatten.ps1 - By Bitpusher/The Digital Fox
# Flatten-Object function created by iRon
# v2.8 last updated 2024-05-12
# Processes an exported CSV of Unified Audit Log entries that contains cells with arrays/hash tables/objects and flattens it for ease of manual processing.
#
# Usage:
# powershell -executionpolicy bypass -f .\05-ProcessUnifiedAuditLogFlatten.ps1 -inputFile "Path\to\input\log.csv"
#
# Use with DropShim.bat to allow drag-and-drop processing of downloaded logs.
#
#comp #m365 #security #bec #script #json #csv #unified #audit #log #irscript #powershell

#Requires -Version 5.1


<#

Flatten-Object
Recursively flattens objects containing arrays, hash tables and (custom) objects. All added properties of the supplied objects will be aligned with the rest of the objects.

Requires PowerShell version 2 or higher.

Cmdlet
Function Flatten-Object {                                       # Version 00.02.12, by iRon
    [CmdletBinding()]Param (
        [Parameter(ValueFromPipeLine = $True)][Object[]]$Objects,
        [String]$Separator = ".", [ValidateSet("", 0, 1)]$Base = 1, [Int]$Depth = 5, [Int]$Uncut = 1,
        [String[]]$ToString = ([String], [DateTime], [TimeSpan]), [String[]]$Path = @()
    )
    $PipeLine = $Input | ForEach {$_}; If ($PipeLine) {$Objects = $PipeLine}
    If (@(Get-PSCallStack)[1].Command -eq $MyInvocation.MyCommand.Name -or @(Get-PSCallStack)[1].Command -eq "<position>") {
        $Object = @($Objects)[0]; $Iterate = New-Object System.Collections.Specialized.OrderedDictionary
        If ($ToString | Where {$Object -is $_}) {$Object = $Object.ToString()}
        ElseIf ($Depth) {$Depth--
            If ($Object.GetEnumerator.OverloadDefinitions -match "[\W]IDictionaryEnumerator[\W]") {
                $Iterate = $Object
            } ElseIf ($Object.GetEnumerator.OverloadDefinitions -match "[\W]IEnumerator[\W]") {
                $Object.GetEnumerator() | ForEach -Begin {$i = $Base} {$Iterate.($i) = $_; $i += 1}
            } Else {
                $Names = If ($Uncut) {$Uncut--} Else {$Object.PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames}
                If (!$Names) {$Names = $Object.PSObject.Properties | Where {$_.IsGettable} | Select -Expand Name}
                If ($Names) {$Names | ForEach {$Iterate.$_ = $Object.$_}}
            }
        }
        If (@($Iterate.Keys).Count) {
            $Iterate.Keys | ForEach {
                Flatten-Object @(,$Iterate.$_) $Separator $Base $Depth $Uncut $ToString ($Path + $_)
            }
        }  Else {$Property.(($Path | Where {$_}) -Join $Separator) = $Object}
    } ElseIf ($Objects -ne $Null) {
        @($Objects) | ForEach -Begin {$Output = @(); $Names = @()} {
            New-Variable -Force -Option AllScope -Name Property -Value (New-Object System.Collections.Specialized.OrderedDictionary)
            Flatten-Object @(,$_) $Separator $Base $Depth $Uncut $ToString $Path
            $Output += New-Object PSObject -Property $Property
            $Names += $Output[-1].PSObject.Properties | Select -Expand Name
        }
        $Output | Select ([String[]]($Names | Select -Unique))
    }
}; Set-Alias Flatten Flatten-Object
Syntax
<Object[]> Flatten-Object [-Separator <String>] [-Base "" | 0 | 1] [-Depth <Int>] [-Uncut<Int>] [ToString <Type[]>]
or:

Flatten-Object <Object[]> [[-Separator] <String>] [[-Base] "" | 0 | 1] [[-Depth] <Int>] [[-Uncut] <Int>] [[ToString] <Type[]>]
Parameters
-Object[] <Object[]>
The object (or objects) to be flatten.

-Separator <String> (Default: .)
The separator used between the recursive property names. .

-Depth <Int> (Default: 5)
The maximal depth of flattening a recursive property. Any negative value will result in an unlimited depth and could cause a infinitive loop.

-Uncut <Int> (Default: 1)
The number of object iterations that will left uncut further object properties will be limited to just the DefaultDisplayPropertySet. Any negative value will reveal all properties of all objects.

-Base "" | 0 | 1 (Default: 1)
The first index name of an embedded array:

1, arrays will be 1 based: <Parent>.1, <Parent>.2, <Parent>.3, ...
0, arrays will be 0 based: <Parent>.0, <Parent>.1, <Parent>.2, ...
"", the first item in an array will be unnamed and than followed with 1: <Parent>, <Parent>.1, <Parent>.2, ...
-ToString <Type[]= [String], [DateTime], [TimeSpan]>
A list of value types (default [String], [DateTime], [TimeSpan]) that will be converted to string rather the further flattened. E.g. a [DateTime] could be flattened with additional properties like Date, Day, DayOfWeek etc. but will be converted to a single (String) property instead.

Note:
The parameter -Path is for internal use but could but used to prefix property names.

Examples
Answering the specific question:

(Get-Content "PATH_TO\test.json" -Raw | ConvertFrom-Json) | Flatten-Object | Convertto-CSV -NoTypeInformation | Set-Content "PATH_TO\test.csv"
Result:

{
    "url":  "http://test.test",
    "slug":  "slug",
    "id":  10011,
    "link":  "http://test.er",
    "level":  1,
    "areas.2":  "area_b",
    "areas.1":  "area_a",
    "disciplines.3":  "discipline_c",
    "disciplines.2":  "discipline_b",
    "disciplines.1":  "discipline_a",
    "subject":  "testing",
    "title":  "Test procedure",
    "email":  "test@test.com"
}
Stress testing a more complex custom object:

New-Object PSObject @{
    String    = [String]"Text"
    Char      = [Char]65
    Byte      = [Byte]66
    Int       = [Int]67
    Long      = [Long]68
    Null      = $Null
    Booleans  = $False, $True
    Decimal   = [Decimal]69
    Single    = [Single]70
    Double    = [Double]71
    Array     = @("One", "Two", @("Three", "Four"), "Five")
    HashTable = @{city="New York"; currency="Dollar"; postalCode=10021; Etc = @("Three", "Four", "Five")}
    Object    = New-Object PSObject -Property @{Name = "One";   Value = 1; Text = @("First", "1st")}
} | Flatten
Result:

Double               : 71
Decimal              : 69
Long                 : 68
Array.1              : One
Array.2              : Two
Array.3.1            : Three
Array.3.2            : Four
Array.4              : Five
Object.Name          : One
Object.Value         : 1
Object.Text.1        : First
Object.Text.2        : 1st
Int                  : 67
Byte                 : 66
HashTable.postalCode : 10021
HashTable.currency   : Dollar
HashTable.Etc.1      : Three
HashTable.Etc.2      : Four
HashTable.Etc.3      : Five
HashTable.city       : New York
Booleans.1           : False
Booleans.2           : True
String               : Text
Char                 : A
Single               : 70
Null                 :
Flatting grouped objects:

$csv | Group Name | Flatten | Format-Table # https://stackoverflow.com/a/47409634/1701026

Flatting common objects:

(Get-Process)[0] | Flatten-Object

Or a list (array) of objects:

Get-Service | Flatten-Object -Depth 3 | Export-CSV Service.csv

Note that a command as below takes hours to compute:

Get-Process | Flatten-Object | Export-CSV Process.csv

Why? because it results in a table with a few hundred rows and several thousand columns. So if you if would like to use this for flatting process, you better limit the number of rows (using the Where-Object cmdlet) or the number of columns (using the Select-Object cmdlet).

#>

param(
    [string]$inputFile = "UALexport.csv",
    [string]$outputFile = "UALexport_Processed.csv",
    [string]$scriptName = "ProcessUnifiedAuditLogFlatten",
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

function Flatten-Object { # Version 00.02.12, by iRon
    [CmdletBinding()] param(
        [Parameter(ValueFromPipeLine = $True)] [Object[]]$Objects,
        [string]$Separator = ".",[ValidateSet("",0,1)] $Base = 1,[int]$Depth = 5,[int]$Uncut = 1,
        [String[]]$ToString = ([string],[datetime],[timespan]),[String[]]$Path = @()
    )
    $PipeLine = $Input | ForEach-Object { $_ }; if ($PipeLine) { $Objects = $PipeLine }
    if (@(Get-PSCallStack)[1].Command -eq $MyInvocation.MyCommand.Name -or @(Get-PSCallStack)[1].Command -eq "<position>") {
        $Object = @($Objects)[0]; $Iterate = New-Object System.Collections.Specialized.OrderedDictionary
        if ($ToString | Where-Object { $Object -is $_ }) { $Object = $Object.ToString() }
        elseif ($Depth) { $Depth --
            if ($Object.GetEnumerator.OverloadDefinitions -match "[\W]IDictionaryEnumerator[\W]") {
                $Iterate = $Object
            } elseif ($Object.GetEnumerator.OverloadDefinitions -match "[\W]IEnumerator[\W]") {
                $Object.GetEnumerator() | ForEach-Object -Begin { $i = $Base } { $Iterate.($i) = $_; $i += 1 }
            } else {
                $Names = if ($Uncut) { $Uncut -- } else { $Object.PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames }
                if (!$Names) { $Names = $Object.PSObject.Properties | Where-Object { $_.IsGettable } | Select-Object -Expand Name }
                if ($Names) { $Names | ForEach-Object { $Iterate.$_ = $Object.$_ } }
            }
        }
        if (@($Iterate.Keys).Count) {
            $Iterate.Keys | ForEach-Object {
                Flatten-Object @(,$Iterate.$_) $Separator $Base $Depth $Uncut $ToString ($Path + $_)
            }
        } else { $Property.(($Path | Where-Object { $_ }) -join $Separator) = $Object }
    } elseif ($Objects -ne $Null) {
        @($Objects) | ForEach-Object -Begin { $Output = @(); $Names = @() } {
            New-Variable -Force -Option AllScope -Name Property -Value (New-Object System.Collections.Specialized.OrderedDictionary)
            Flatten-Object @(,$_) $Separator $Base $Depth $Uncut $ToString $Path
            $Output += New-Object PSObject -Property $Property
            $Names += $Output[-1].PSObject.Properties | Select-Object -Expand Name
        }
        $Output | Select-Object ([String[]]($Names | Select-Object -Unique))
    }
}; Set-Alias Flatten Flatten-Object

#(Get-Content "UALexport.csv" -Raw | ConvertFrom-Json) | Flatten-Object | Convertto-CSV -NoTypeInformation | Set-Content "test.csv"

[string]$outputFolder = Split-Path -Path $inputFile -Parent
[string]$outputFile = (Get-Item $inputFile).BaseName
[string]$outputPath = $outputFolder + "\" + $outputFile + "_Processed.csv"

Import-Csv -Path $inputFile | ForEach-Object { $_.AuditData } | ConvertFrom-Json | Flatten-Object | Sort-Object "CreationTime" | Export-Csv -Path "$outputPath" -NoTypeInformation

exit
