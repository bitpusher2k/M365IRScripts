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
# Flatten-Object function created by iRon, ConvertTo-FlatObject function created by EvotecIT,
# ConvertTo-FlatObject2 function created by RamblingCookieMonster, Convert-OutputForCSV function created by proxb
# v2.9 last updated 2024-06-24
# Processes an exported CSV of Unified Audit Log entries that contains cells with arrays/hash tables/objects and flattens it for ease of manual processing.
#
# Included are four functions for flattening complex objects found online. I have not settled on and optimized a preferred function yet - try each and see which works better for you.
#
# Usage:
# powershell -executionpolicy bypass -f .\05-ProcessUnifiedAuditLogFlatten.ps1 -inputFile "Path\to\input\log.csv" -function "iRon"
#
# Use with DropShim.bat to allow drag-and-drop processing of downloaded logs.
#
#comp #m365 #security #bec #script #json #csv #unified #audit #log #irscript #powershell

#Requires -Version 5.1

param(
    [string]$inputFile = "UALexport.csv",
    [string]$outputFile = "UALexport_Processed.csv",
    [string]$function = "proxb", # Can be "iRon", "EvotecIT", "RamblingCookieMonster", "proxb", or "all"
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
function Flatten-Object {
    # Version 00.02.12, by iRon
    [CmdletBinding()] param(
        [Parameter(ValueFromPipeLine = $True)] [Object[]]$Objects,
        [string]$Separator = ".", [ValidateSet("", 0, 1)] $Base = 1, [int]$Depth = 10, [int]$Uncut = 1,
        [String[]]$ToString = ([string], [datetime], [timespan]), [String[]]$Path = @()
    )
    $PipeLine = $Input | ForEach-Object { $_ }; if ($PipeLine) { $Objects = $PipeLine }
    if (@(Get-PSCallStack)[1].Command -eq $MyInvocation.MyCommand.Name -or @(Get-PSCallStack)[1].Command -eq "<position>") {
        $Object = @($Objects)[0]; $Iterate = New-Object System.Collections.Specialized.OrderedDictionary
        if ($ToString | Where-Object { $Object -is $_ }) { $Object = $Object.ToString() }
        elseif ($Depth) {
            $Depth --
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
                Flatten-Object @(, $Iterate.$_) $Separator $Base $Depth $Uncut $ToString ($Path + $_)
            }
        } else { $Property.(($Path | Where-Object { $_ }) -join $Separator) = $Object }
    } elseif ($Objects -ne $Null) {
        @($Objects) | ForEach-Object -Begin { $Output = @(); $Names = @() } {
            New-Variable -Force -Option AllScope -Name Property -Value (New-Object System.Collections.Specialized.OrderedDictionary)
            Flatten-Object @(, $_) $Separator $Base $Depth $Uncut $ToString $Path
            $Output += New-Object PSObject -Property $Property
            $Names += $Output[-1].PSObject.Properties | Select-Object -Expand Name
        }
        $Output | Select-Object ([String[]]($Names | Select-Object -Unique))
    }
}; Set-Alias Flatten Flatten-Object


function ConvertTo-FlatObject {
    <#
    .SYNOPSIS
    Flattends a nested object into a single level object.

    .DESCRIPTION
    Flattends a nested object into a single level object.

    .PARAMETER Objects
    The object (or objects) to be flatten.

    .PARAMETER Separator
    The separator used between the recursive property names

    .PARAMETER Base
    The first index name of an embedded array:
    - 1, arrays will be 1 based: <Parent>.1, <Parent>.2, <Parent>.3, ?
    - 0, arrays will be 0 based: <Parent>.0, <Parent>.1, <Parent>.2, ?
    - "", the first item in an array will be unnamed and than followed with 1: <Parent>, <Parent>.1, <Parent>.2, ?

    .PARAMETER Depth
    The maximal depth of flattening a recursive property. Any negative value will result in an unlimited depth and could cause a infinitive loop.

    .PARAMETER Uncut
    The maximal depth of flattening a recursive property. Any negative value will result in an unlimited depth and could cause a infinitive loop.

    .PARAMETER ExcludeProperty
    The propertys to be excluded from the output.

    .EXAMPLE
    $Object3 = [PSCustomObject] @{
        "Name"    = "Przemyslaw Klys"
        "Age"     = "30"
        "Address" = @{
            "Street"  = "Kwiatowa"
            "City"    = "Warszawa"

            "Country" = [ordered] @{
                "Name" = "Poland"
            }
            List      = @(
                [PSCustomObject] @{
                    "Name" = "Adam Klys"
                    "Age"  = "32"
                }
                [PSCustomObject] @{
                    "Name" = "Justyna Klys"
                    "Age"  = "33"
                }
                [PSCustomObject] @{
                    "Name" = "Justyna Klys"
                    "Age"  = 30
                }
                [PSCustomObject] @{
                    "Name" = "Justyna Klys"
                    "Age"  = $null
                }
            )
        }
        ListTest  = @(
            [PSCustomObject] @{
                "Name" = "S?awa Klys"
                "Age"  = "33"
            }
        )
    }

    $Object3 | ConvertTo-FlatObject

    .NOTES
    Based on https://powersnippets.com/convertto-flatobject/
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeLine)] [Object[]]$Objects,
        [string]$Separator = ".",
        [ValidateSet("", 0, 1)] $Base = 1,
        [int]$Depth = 10,
        [string[]]$ExcludeProperty,
        [Parameter(DontShow)] [String[]]$Path,
        [Parameter(DontShow)] [System.Collections.IDictionary]$OutputObject
    )
    begin {
        $InputObjects = [System.Collections.Generic.List[Object]]::new()
    }
    process {
        foreach ($O in $Objects) {
            if ($null -ne $O) {
                $InputObjects.Add($O)
            }
        }
    }
    end {
        if ($PSBoundParameters.ContainsKey("OutputObject")) {
            $Object = $InputObjects[0]
            $Iterate = [ordered]@{}
            if ($null -eq $Object) {
                #Write-Verbose -Message "ConvertTo-FlatObject - Object is null"
            } elseif ($Object.GetType().Name -in 'String', 'DateTime', 'TimeSpan', 'Version', 'Enum') {
                $Object = $Object.ToString()
            } elseif ($Depth) {
                $Depth --
                if ($Object -is [System.Collections.IDictionary]) {
                    $Iterate = $Object
                } elseif ($Object -is [array] -or $Object -is [System.Collections.IEnumerable]) {
                    $i = $Base
                    foreach ($Item in $Object.GetEnumerator()) {
                        $NewObject = [ordered]@{}
                        if ($Item -is [System.Collections.IDictionary]) {
                            foreach ($Key in $Item.Keys) {
                                if ($Key -notin $ExcludeProperty) {
                                    $NewObject[$Key] = $Item[$Key]
                                }
                            }
                        } elseif ($Item -isnot [array] -and $Item -isnot [System.Collections.IEnumerable]) {
                            foreach ($Prop in $Item.PSObject.Properties) {
                                if ($Prop.IsGettable -and $Prop.Name -notin $ExcludeProperty) {
                                    $NewObject["$($Prop.Name)"] = $Item.$($Prop.Name)
                                }
                            }
                        } else {
                            $NewObject = $Item
                        }
                        $Iterate["$i"] = $NewObject
                        $i += 1
                    }
                } else {
                    foreach ($Prop in $Object.PSObject.Properties) {
                        if ($Prop.IsGettable -and $Prop.Name -notin $ExcludeProperty) {
                            $Iterate["$($Prop.Name)"] = $Object.$($Prop.Name)
                        }
                    }
                }
            }
            if ($Iterate.Keys.Count) {
                foreach ($Key in $Iterate.Keys) {
                    if ($Key -notin $ExcludeProperty) {
                        ConvertTo-FlatObject -Objects @(, $Iterate["$Key"]) -Separator $Separator -Base $Base -Depth $Depth -Path ($Path + $Key) -OutputObject $OutputObject -ExcludeProperty $ExcludeProperty
                    }
                }
            } else {
                $Property = $Path -join $Separator
                if ($Property) {
                    # We only care if property is not empty
                    if ($Object -is [System.Collections.IDictionary] -and $Object.Keys.Count -eq 0) {
                        $OutputObject[$Property] = $null
                    } else {
                        $OutputObject[$Property] = $Object
                    }
                }
            }
        } elseif ($InputObjects.Count -gt 0) {
            foreach ($ItemObject in $InputObjects) {
                $OutputObject = [ordered]@{}
                ConvertTo-FlatObject -Objects @(, $ItemObject) -Separator $Separator -Base $Base -Depth $Depth -Path $Path -OutputObject $OutputObject -ExcludeProperty $ExcludeProperty
                [pscustomobject]$OutputObject
            }
        }
    }
}


function ConvertTo-FlatObject2 {
    <#
    .SYNOPSIS
        Flatten an object to simplify discovery of data

    .DESCRIPTION
        Flatten an object.  This function will take an object, and flatten the properties using their full path into a single object with one layer of properties.

        You can use this to flatten XML, JSON, and other arbitrary objects.

        This can simplify initial exploration and discovery of data returned by APIs, interfaces, and other technologies.

        NOTE:
            Use tools like Get-Member, Select-Object, and Show-Object to further explore objects.
            This function does not handle certain data types well.  It was original designed to expand XML and JSON.

    .PARAMETER InputObject
        Object to flatten

    .PARAMETER Exclude
        Exclude any nodes in this list.  Accepts wildcards.

        Example:
            -Exclude price, title

    .PARAMETER ExcludeDefault
        Exclude default properties for sub objects.  True by default.

        This simplifies views of many objects (e.g. XML) but may exclude data for others (e.g. if flattening a process, ProcessThread properties will be excluded)

    .PARAMETER Include
        Include only leaves in this list.  Accepts wildcards.

        Example:
            -Include Author, Title

    .PARAMETER Value
        Include only leaves with values like these arguments.  Accepts wildcards.

    .PARAMETER MaxDepth
        Stop recursion at this depth.

    .INPUTS
        Any object

    .OUTPUTS
        System.Management.Automation.PSCustomObject

    .EXAMPLE

        #Pull unanswered PowerShell questions from StackExchange, Flatten the data to date a feel for the schema
        Invoke-RestMethod "https://api.stackexchange.com/2.0/questions/unanswered?order=desc&sort=activity&tagged=powershell&pagesize=10&site=stackoverflow" |
            ConvertTo-FlatObject -Include Title, Link, View_Count

            $object.items[0].owner.link : http://stackoverflow.com/users/1946412/julealgon
            $object.items[0].view_count : 7
            $object.items[0].link       : http://stackoverflow.com/questions/26910789/is-it-possible-to-reuse-a-param-block-across-multiple-functions
            $object.items[0].title      : Is it possible to reuse a &#39;param&#39; block across multiple functions?
            $object.items[1].owner.link : http://stackoverflow.com/users/4248278/nitin-tyagi
            $object.items[1].view_count : 8
            $object.items[1].link       : http://stackoverflow.com/questions/26909879/use-powershell-to-retreive-activated-features-for-sharepoint-2010
            $object.items[1].title      : Use powershell to retreive Activated features for sharepoint 2010
            ...

    .EXAMPLE

        #Set up some XML to work with
        $object = [xml]'
            <catalog>
               <book id="bk101">
                  <author>Gambardella, Matthew</author>
                  <title>XML Developers Guide</title>
                  <genre>Computer</genre>
                  <price>44.95</price>
               </book>
               <book id="bk102">
                  <author>Ralls, Kim</author>
                  <title>Midnight Rain</title>
                  <genre>Fantasy</genre>
                  <price>5.95</price>
               </book>
            </catalog>'

        #Call the flatten command against this XML
            ConvertTo-FlatObject $object -Include Author, Title, Price

            #Result is a flattened object with the full path to the node, using $object as the root.
            #Only leaf properties we specified are included (author,title,price)

                $object.catalog.book[0].author : Gambardella, Matthew
                $object.catalog.book[0].title  : XML Developers Guide
                $object.catalog.book[0].price  : 44.95
                $object.catalog.book[1].author : Ralls, Kim
                $object.catalog.book[1].title  : Midnight Rain
                $object.catalog.book[1].price  : 5.95

        #Invoking the property names should return their data if the orginal object is in $object:
            $object.catalog.book[1].price
                5.95

            $object.catalog.book[0].title
                XML Developers Guide

    .EXAMPLE

        #Set up some XML to work with
            [xml]'<catalog>
               <book id="bk101">
                  <author>Gambardella, Matthew</author>
                  <title>XML Developers Guide</title>
                  <genre>Computer</genre>
                  <price>44.95</price>
               </book>
               <book id="bk102">
                  <author>Ralls, Kim</author>
                  <title>Midnight Rain</title>
                  <genre>Fantasy</genre>
                  <price>5.95</price>
               </book>
            </catalog>' |
                ConvertTo-FlatObject -exclude price, title, id

        Result is a flattened object with the full path to the node, using XML as the root.  Price and title are excluded.

            $Object.catalog                : catalog
            $Object.catalog.book           : {book, book}
            $object.catalog.book[0].author : Gambardella, Matthew
            $object.catalog.book[0].genre  : Computer
            $object.catalog.book[1].author : Ralls, Kim
            $object.catalog.book[1].genre  : Fantasy

    .EXAMPLE
        #Set up some XML to work with
            [xml]'<catalog>
               <book id="bk101">
                  <author>Gambardella, Matthew</author>
                  <title>XML Developers Guide</title>
                  <genre>Computer</genre>
                  <price>44.95</price>
               </book>
               <book id="bk102">
                  <author>Ralls, Kim</author>
                  <title>Midnight Rain</title>
                  <genre>Fantasy</genre>
                  <price>5.95</price>
               </book>
            </catalog>' |
                ConvertTo-FlatObject -Value XML*, Fantasy

        Result is a flattened object filtered by leaves that matched XML* or Fantasy

            $Object.catalog.book[0].title : XML Developers Guide
            $Object.catalog.book[1].genre : Fantasy

    .EXAMPLE
        #Get a single process with all props, flatten this object.  Don't exclude default properties
        Get-Process | select -first 1 -skip 10 -Property * | ConvertTo-FlatObject -ExcludeDefault $false

        #NOTE - There will likely be bugs for certain complex objects like this.
                For example, $Object.StartInfo.Verbs.SyncRoot.SyncRoot... will loop until we hit MaxDepth. (Note: SyncRoot is now addressed individually)

    .NOTES
        I have trouble with algorithms.  If you have a better way to handle this, please let me know!

    .FUNCTIONALITY
        General Command
    #>
    [CmdletBinding()]
    param(

        [Parameter(Mandatory = $True,
            ValueFromPipeLine = $True)]
        [PSObject[]]$InputObject,

        [string[]]$Exclude = "",

        [bool]$ExcludeDefault = $True,

        [string[]]$Include = $null,

        [string[]]$Value = $null,

        [int]$MaxDepth = 10
    )
    begin {
        #region FUNCTIONS

        #Before adding a property, verify that it matches a Like comparison to strings in $Include...
        function IsIn-Include {
            param($prop)
            if (-not $Include) { $True }
            else {
                foreach ($Inc in $Include) {
                    if ($Prop -like $Inc) {
                        $True
                    }
                }
            }
        }

        #Before adding a value, verify that it matches a Like comparison to strings in $Value...
        function IsIn-Value {
            param($val)
            if (-not $Value) { $True }
            else {
                foreach ($string in $Value) {
                    if ($val -like $string) {
                        $True
                    }
                }
            }
        }

        function Get-Exclude {
            [CmdletBinding()]
            param($obj)

            #Exclude default props if specified, and anything the user specified.  Thanks to Jaykul for the hint on [type]!
            if ($ExcludeDefault) {
                try {
                    $DefaultTypeProps = @($obj.GetType().GetProperties() | Select-Object -ExpandProperty Name -ErrorAction Stop)
                    if ($DefaultTypeProps.Count -gt 0) {
                        Write-Verbose "Excluding default properties for $($obj.gettype().Fullname):`n$($DefaultTypeProps | Out-String)"
                    }
                } catch {
                    Write-Verbose "Failed to extract properties from $($obj.gettype().Fullname): $_"
                    $DefaultTypeProps = @()
                }
            }

            @($Exclude + $DefaultTypeProps) | Select-Object -Unique
        }

        #Function to recurse the Object, add properties to object
        function Recurse-Object {
            [CmdletBinding()]
            param(
                $Object,
                [string[]]$path = '$Object',
                [psobject]$Output,
                $depth = 0
            )

            # Handle initial call
            Write-Verbose "Working in path $Path at depth $depth"
            Write-Debug "Recurse Object called with PSBoundParameters:`n$($PSBoundParameters | Out-String)"
            $Depth++

            #Exclude default props if specified, and anything the user specified.
            $ExcludeProps = @(Get-Exclude $object)

            #Get the children we care about, and their names
            $Children = $object.PSObject.Properties | Where-Object { $ExcludeProps -notcontains $_.Name }
            Write-Debug "Working on properties:`n$($Children | select -ExpandProperty Name | Out-String)"

            #Loop through the children properties.
            foreach ($Child in @($Children)) {
                $ChildName = $Child.Name
                $ChildValue = $Child.Value

                Write-Debug "Working on property $ChildName with value $($ChildValue | Out-String)"
                # Handle special characters...
                if ($ChildName -match '[^a-zA-Z0-9_]') {
                    $FriendlyChildName = "'$ChildName'"
                } else {
                    $FriendlyChildName = $ChildName
                }

                #Add the property.
                if ((IsIn-Include $ChildName) -and (IsIn-Value $ChildValue) -and $Depth -le $MaxDepth) {
                    $ThisPath = @($Path + $FriendlyChildName) -join "."
                    $Output | Add-Member -MemberType NoteProperty -Name $ThisPath -Value $ChildValue
                    Write-Verbose "Adding member '$ThisPath'"
                }

                #Handle null...
                if ($ChildValue -eq $null) {
                    Write-Verbose "Skipping NULL $ChildName"
                    continue
                }

                #Handle evil looping.  Will likely need to expand this.  Any thoughts on a better approach?
                if (
                    (
                        $ChildValue.GetType() -eq $Object.GetType() -and
                        $ChildValue -is [datetime]
                    ) -or
                    (
                        $ChildName -eq "SyncRoot" -and
                        -not $ChildValue
                    )
                ) {
                    Write-Verbose "Skipping $ChildName with type $($ChildValue.GetType().fullname)"
                    continue
                }

                #Check for arrays by checking object type (this is a fix for arrays with 1 object) otherwise check the count of objects
                if (($ChildValue.GetType()).BaseType.Name -eq "Array") {
                    $IsArray = $true
                } else {
                    $IsArray = @($ChildValue).Count -gt 1
                }

                $count = 0

                #Set up the path to this node and the data...
                $CurrentPath = @($Path + $FriendlyChildName) -join "."

                #Exclude default props if specified, and anything the user specified.
                $ExcludeProps = @(Get-Exclude $ChildValue)

                #Get the children's children we care about, and their names.  Also look for signs of a hashtable like type
                $ChildrensChildren = $ChildValue.PSObject.Properties | Where-Object { $ExcludeProps -notcontains $_.Name }
                $HashKeys = if ($ChildValue.Keys -notlike $null -and $ChildValue.Values) {
                    $ChildValue.Keys
                } else {
                    $null
                }
                Write-Debug "Found children's children $($ChildrensChildren | select -ExpandProperty Name | Out-String)"

                #If we aren't at max depth or a leaf...
                if (
                    (@($ChildrensChildren).Count -ne 0 -or $HashKeys) -and
                    $Depth -lt $MaxDepth
                ) {
                    #This handles hashtables.  But it won't recurse...
                    if ($HashKeys) {
                        Write-Verbose "Working on hashtable $CurrentPath"
                        foreach ($key in $HashKeys) {
                            Write-Verbose "Adding value from hashtable $CurrentPath['$key']"
                            $Output | Add-Member -MemberType NoteProperty -Name "$CurrentPath['$key']" -Value $ChildValue["$key"]
                            $Output = Recurse-Object -Object $ChildValue["$key"] -Path "$CurrentPath['$key']" -Output $Output -Depth $depth
                        }
                    }
                    #Sub children?  Recurse!
                    else {
                        if ($IsArray) {
                            foreach ($item in @($ChildValue)) {
                                Write-Verbose "Recursing through array node '$CurrentPath'"
                                $Output = Recurse-Object -Object $item -Path "$CurrentPath[$count]" -Output $Output -Depth $depth
                                $Count++
                            }
                        } else {
                            Write-Verbose "Recursing through node '$CurrentPath'"
                            $Output = Recurse-Object -Object $ChildValue -Path $CurrentPath -Output $Output -Depth $depth
                        }
                    }
                }
            }

            $Output
        }

        #endregion FUNCTIONS
    }
    process {
        foreach ($Object in $InputObject) {
            #Flatten the XML and write it to the pipeline
            Recurse-Object -Object $Object -Output $(New-Object -TypeName PSObject)
        }
    }
}


function Convert-OutputForCSV {
    <#
        .SYNOPSIS
            Provides a way to expand collections in an object property prior
            to being sent to Export-Csv.

        .DESCRIPTION
            Provides a way to expand collections in an object property prior
            to being sent to Export-Csv. This helps to avoid the object type
            from being shown such as system.object[] in a spreadsheet.

        .PARAMETER InputObject
            The object that will be sent to Export-Csv

        .PARAMETER OutPropertyType
            This determines whether the property that has the collection will be
            shown in the CSV as a comma delimmited string or as a stacked string.

            Possible values:
            Stack
            Comma

            Default value is: Stack

        .NOTES
            Name: Convert-OutputForCSV
            Author: Boe Prox
            Created: 24 Jan 2014
            Version History:
                1.1 - 02 Feb 2014
                    -Removed OutputOrder parameter as it is no longer needed; inputobject order is now respected
                    in the output object
                1.0 - 24 Jan 2014
                    -Initial Creation

        .EXAMPLE
            $Output = 'PSComputername','IPAddress','DNSServerSearchOrder'

            Get-WMIObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled='True'" |
            Select-Object $Output | Convert-OutputForCSV |
            Export-Csv -NoTypeInformation -Path NIC.csv

            Description
            -----------
            Using a predefined set of properties to display ($Output), data is collected from the
            Win32_NetworkAdapterConfiguration class and then passed to the Convert-OutputForCSV
            funtion which expands any property with a collection so it can be read properly prior
            to being sent to Export-Csv. Properties that had a collection will be viewed as a stack
            in the spreadsheet.

    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeLine)]
        [psobject]$InputObject,
        [Parameter()]
        [ValidateSet('Stack', 'Comma')]
        [string]$OutputPropertyType = 'Stack'
    )
    begin {
        $PSBoundParameters.GetEnumerator() | ForEach-Object {
            Write-Verbose "$($_)"
        }
        $FirstRun = $True
    }
    process {
        if ($FirstRun) {
            $OutputOrder = $InputObject.PSObject.Properties.Name
            Write-Verbose "Output Order:`n $($OutputOrder -join ', ' )"
            $FirstRun = $False
            #Get properties to process
            $Properties = Get-Member -InputObject $InputObject -MemberType *Property
            #Get properties that hold a collection
            $Properties_Collection = @(($Properties | Where-Object {
                        $_.Definition -match "Collection|\[\]"
                    }).Name)
            #Get properties that do not hold a collection
            $Properties_NoCollection = @(($Properties | Where-Object {
                        $_.Definition -notmatch "Collection|\[\]"
                    }).Name)
            Write-Verbose "Properties Found that have collections:`n $(($Properties_Collection) -join ', ')"
            Write-Verbose "Properties Found that have no collections:`n $(($Properties_NoCollection) -join ', ')"
        }

        $InputObject | ForEach-Object {
            $Line = $_
            $stringBuilder = New-Object Text.StringBuilder
            $Null = $stringBuilder.AppendLine("[pscustomobject] @{")

            $OutputOrder | ForEach-Object {
                if ($OutputPropertyType -eq 'Stack') {
                    $Null = $stringBuilder.AppendLine("`"$($_)`" = `"$(($line.$($_) | Out-String).Trim())`"")
                } elseif ($OutputPropertyType -eq "Comma") {
                    $Null = $stringBuilder.AppendLine("`"$($_)`" = `"$($line.$($_) -join ', ')`"")
                }
            }
            $Null = $stringBuilder.AppendLine("}")

            Invoke-Expression $stringBuilder.ToString()
        }
    }
    end {}
}

[string]$outputFolder = Split-Path -Path $inputFile -Parent
[string]$outputFile = (Get-Item $inputFile).BaseName

$headerRow = Get-Content $inputFile | ConvertFrom-String -Delimiter "," | Select-Object -First 1
$headerRow

if ($headerRow -match "AuditData") {
    Write-Output "Starting recursive flattening of 'AuditData' field from UAL log. Recursive JSON flattening not recommended for log exports larger than around 10mb (5,000 records)..."

    if ($function -contains "iRon" -or $function -eq "all") {
        $sw = [Diagnostics.StopWatch]::StartNew()
        [string]$outputPath = $outputFolder + "\" + $outputFile + "_Processed-flatten.csv"
        Import-Csv -Path $inputFile | ForEach-Object { $_.AuditData } | ConvertFrom-Json | Flatten-Object | Sort-Object "CreationTime" | Export-Csv -Path "$outputPath" -NoTypeInformation
        Write-Output "`n$outputPath written."
        Write-Output "Seconds elapsed for CSV processing (Flatten-Object - slow): $($sw.elapsed.totalseconds)"
    }
    if ($function -contains "EvotecIT" -or $function -eq "all") {
        $sw = [Diagnostics.StopWatch]::StartNew()
        [string]$outputPath = $outputFolder + "\" + $outputFile + "_Processed-FlatObject1.csv"
        Import-Csv -Path $inputFile | ForEach-Object { $_.AuditData } | ConvertFrom-Json | ConvertTo-FlatObject | Sort-Object "CreationTime" | Export-Csv -Path "$outputPath" -NoTypeInformation
        Write-Output "`n$outputPath written."
        Write-Output "Seconds elapsed for CSV processing (ConvertTo-FlatObject - fast): $($sw.elapsed.totalseconds)"
    }
    if ($function -contains "RamblingCookieMonster" -or $function -eq "all") {
        $sw = [Diagnostics.StopWatch]::StartNew()
        [string]$outputPath = $outputFolder + "\" + $outputFile + "_Processed-FlatObject2.csv"
        Import-Csv -Path $inputFile | ForEach-Object { $_.AuditData } | ConvertFrom-Json | ConvertTo-FlatObject2 | Sort-Object "CreationTime" | Export-Csv -Path "$outputPath" -NoTypeInformation
        Write-Output "`n$outputPath written."
        Write-Output "Seconds elapsed for CSV processing (ConvertTo-FlatObject2 - slowest): $($sw.elapsed.totalseconds)"
    }
    if ($function -contains "proxb" -or $function -eq "all") {
        $sw = [Diagnostics.StopWatch]::StartNew()
        [string]$outputPath = $outputFolder + "\" + $outputFile + "_Processed-OutputForCsv.csv"
        Import-Csv -Path $inputFile | ForEach-Object { $_.AuditData } | ConvertFrom-Json | Convert-OutputForCSV | Sort-Object "CreationTime" | Export-Csv -Path "$outputPath" -NoTypeInformation
        Write-Output "`n$outputPath written."
        Write-Output "Seconds elapsed for CSV processing (Convert-OutputForCSV - fast): $($sw.elapsed.totalseconds)"
    }

    # One-level JSON to CSV export - very fast but loses all nested properties:
    # $sw = [Diagnostics.StopWatch]::StartNew()
    # [string]$outputPath = $outputFolder + "\" + $outputFile + "_Lossy_single_level_Processed.csv"
    # Import-Csv -Path $inputFile | ForEach-Object { $_.AuditData } | ConvertFrom-Json | Sort-Object "CreationTime" | Export-Csv -Path "$outputPath" -NoTypeInformation
    # Write-Output "`n$outputPath written."
    # Write-Output "Seconds elapsed for CSV processing (lossy non-recursive json conversion): $($sw.elapsed.totalseconds)"

    Write-Output "Done!"
    Write-Output "If you now have multiple columns with IP information they can be consolidated in Excel with a formula like:"
    Write-Output "=IF(ISBLANK(A2),IF(ISBLANK(B2),IF(ISBLANK(C2),"",C2),B2),A2)"
    Write-Output "(The outermost cell listed in the nested IF that contains data is preferred)"
} else {
    Write-Output "'AuditData' field not found. Please try again with exported UAL log containing this field."
}

exit
