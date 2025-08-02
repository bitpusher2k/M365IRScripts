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
# Join-Object function created by iRon
# Flatten-Object function created by iRon, ConvertTo-FlatObject function created by EvotecIT,
# ConvertTo-FlatObject2 function created by RamblingCookieMonster, Convert-OutputForCSV function created by proxb,
# Flatten-PsCustomObject function created by Kelly Jolly (not yet working).
# v3.1 last updated 2025-07-26
# Processes an exported CSV of Unified Audit Log entries that contains cells with arrays/hash tables/objects and flattens it for ease of manual processing.
#
# Appends flattened set of columns to the original CSV log data in the export to ensure no information is absent in result.
#
# Includes several functions for flattening complex objects found online. The one from EvotecIT is currently the best for this application.
#
# Usage:
# powershell -executionpolicy bypass -f .\05-ProcessUnifiedAuditLogFlatten.ps1 -inputFile "Path\to\input\log.csv" -function "EvotecIT"
#
# Use with DropShim.bat to allow drag-and-drop processing of downloaded logs, either singly or in bulk.
#
#comp #m365 #security #bec #script #json #csv #unified #audit #log #irscript #powershell

#Requires -Version 5.1

param(
    [string[]]$inputFiles = @("UALexport.csv"),
    [string]$outputFile = "UALexport_Processed.csv",
    [string]$function = "EvotecIT,simple", # Can be "iRon", "EvotecIT", "RamblingCookieMonster", "proxb", "simple", "solidstate888" (not yet working), "all" (to process using every function), or a comma-separated list
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
    [int]$logFileRetentionDays = 30,
    [string]$Encoding = "utf8bom" # PS 5 & 7: "Ascii" (7-bit), "BigEndianUnicode" (UTF-16 big-endian), "BigEndianUTF32", "Oem", "Unicode" (UTF-16 little-endian), "UTF32" (little-endian), "UTF7", "UTF8" (PS 5: BOM, PS 7: NO BOM). PS 7: "ansi", "utf8BOM", "utf8NoBOM"
)

#region initialization
if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }
#endregion initialization

#region functions

<#PSScriptInfo
.VERSION 3.8.3
.GUID 54688e75-298c-4d4b-a2d0-d478e6069126
.AUTHOR Ronald Bode (iRon)
.DESCRIPTION Join-Object combines two object lists based on a related property between them.
.COMPANYNAME PowerSnippets.com
.COPYRIGHT Ronald Bode (iRon)
.TAGS Join-Object Join InnerJoin LeftJoin RightJoin FullJoin OuterJoin CrossJoin Update Merge Difference Combine Table
.LICENSEURI https://github.com/iRon7/Join-Object/LICENSE
.PROJECTURI https://github.com/iRon7/Join-Object
.ICONURI https://raw.githubusercontent.com/iRon7/Join-Object/master/Join-Object.png
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES To install the new Join module equivalent: Install-Module -Name JoinModule
.PRIVATEDATA
#>

<#
.SYNOPSIS
    Combines two object lists based on a related property between them.

.DESCRIPTION
    Combines properties from one or more objects. It creates a set that can be saved as a new object or used as it is.
    An object join is a means for combining properties from one (self-join) or more object lists by using values common
    to each.

    Main features:
    * An intuitive idiomatic PowerShell syntax
    * SQL like joining features
    * Smart property merging
    * Predefined join commands for updating, merging and specific join types
    * Well defined pipeline for the (left) input objects and output objects (streaming preserves memory)
    * Performs about twice as fast as Compare-Object on large object lists
    * Supports a list of (custom) objects, strings or primitives and dictionaries (e.g. hash tables) and data tables for input
    * Smart properties and calculated property expressions
    * Custom relation expressions
    * Module (Install-Module -Name JoinModule) or (dot-sourcing) Script version (`Install-Script -Name Join`)
    * Supports PowerShell for Windows (5.1) and PowerShell Core

    The Join-Object cmdlet reveals the following proxy commands with their own ([-JoinType] and [-Property]) defaults:
    * `InnerJoin-Object` (Alias `InnerJoin` or `Join`), combines the related objects
    * `LeftJoin-Object` (Alias `LeftJoin`), combines the related objects and adds the rest of the left objects
    * `RightJoin-Object` (Alias `RightJoin`), combines the related objects and adds the rest of the right objects
    * `OuterJoin-Object` (Alias `OuterJoin`), returns the symmetric difference of the unrelated objects
    * `FullJoin-Object` (Alias `FullJoin`), combines the related objects and adds the rest of the left and right objects
    * `CrossJoin-Object` (Alias `CrossJoin`), combines each left object with each right object
    * `Update-Object` (Alias `Update`), updates the left object with the related right object
    * `Merge-Object` (Alias `Merge`), updates the left object with the related right object and adds the rest of the
      new (unrelated) right objects
    * `Get-Difference` (Alias `Differs`), returns the symmetric different objects and their properties

.PARAMETER LeftObject
    The left object list, usually provided through the pipeline, to be joined.

    > **Note:** a self-join on the `LeftObject` list will be performed if the `RightObject` is omitted.

.PARAMETER RightObject
    The right object list, provided by the first argument, to be joined.

    > **Note:** a self-join on the `RightObject` list will be performed if the `LeftObject` is omitted.

.PARAMETER On
    The [-On] parameter defines which objects should be joined together.\
    If the [-Equals] parameter is omitted, the value(s) of the properties listed by the -On parameter should be
    equal at both sides in order to join the left object with the right object.\
    If the [-On] parameter contains an expression, the expression will be evaluted where `$_`, `$PSItem` and
    `$Left` contains the currect object. The result of the expression will be compared to right object property
    defined by the [-Equals] parameter.

    > **Note 1:** The list of properties defined by the [-On] parameter will be complemented with the list of
    properties defined by the [-Equals] parameter and vice versa.

    > **Note 2:** Related properties will be merged to a single property by default (see also the [-Property]
    parameter).

    > **Note 3:** If the [-On] and the [-Using] parameter are omitted, a side-by-side join is returned unless
    `OuterJoin` is performed where the default [-On] parameter value is * (all properties).

    > **Note 4:** if the left object is a scalar array, the [-On] parameters is used to name the scalar array

.PARAMETER Equals
    If the [-Equals] parameter is supplied, the value(s) of the left object properties listed by the [-On]
    parameter should be equal to the value(s)of the right object listed by the [-Equals] parameter in order to
    join the left object with the right object.\
    If the [-Equals] parameter contains an expression, the expression will be evaluted where `$_`, `$PSItem` and
    `$Right` contains the currect object. The result of the expression will be compared to left object property
    defined by the [-On] parameter.

    > **Note 1:** The list of properties defined by the [-Equal] parameter will be complemented with the list of
    properties defined by the -On parameter and vice versa. This means that by default value of the [-Equals]
    parameter is equal to the value supplied to the [-On] parameter

    > **Note 2:** A property will be omitted in the results if it exists on both sides and if the property at the
    other side is related to another property.

    > **Note 3:** The [-Equals] parameter can only be used with the [-On] parameter.

    > **Note 4:** if the right object is a scalar array, the [-Equals] parameters is used to name the scalar array

.PARAMETER Strict
    If the [-Strict] switch is set, the comparison between the related properties defined by the [-On] Parameter
    (and the [-Equals] parameter) is based on a strict equality (both type and value need to be equal).

.PARAMETER MatchCase
    If the [-MatchCase] (alias `-CaseSensitive`) switch is set, the comparison between the related properties
    defined by the [-On] Parameter (and the [-Equals] parameter) will case sensitive.

.PARAMETER Using
    Any conditional expression that requires to evaluate to true in order to join the left object with the
    right object.

    The following variables are exposed for a (ScriptBlock) expression:
    * `$_`: iterates each property name
    * `$Left`: a hash table representing the current left object (each self-contained [-LeftObject]).
      The hash table will be empty (`@{}`) in the outer part of a left join or full join.
    * `$LeftIndex`: the index of the left object (`$Null` in the outer part of a right- or full join)
    * `$Right`: a hash table representing the current right object (each self-contained [-RightObject])
      The hash table will be empty (`@{}`) in the outer part of a right join or full join.
    * `$RightIndex`: the index of the right object (`$Null` in the outer part of a left- or full join)


    > **Note 1:** The -Using parameter has the most complex comparison possibilities but is considerable slower
    than the [-On] parameter.

    > **Note 2:** The [-Using] parameter cannot be used with the [-On] parameter.

.PARAMETER Where
    An expression that defines the condition to be met for the objects to be returned. See the [-Using]
    parameter for available expression variables.

.PARAMETER Discern
    By default unrelated properties with the same name will be collected in a single object property.
    The [-Discern] parameter (alias [-NameItems])  defines how to rename the object properties and divide
    them over multiple properties. If a given name pattern contains an asterisks (`*`), the asterisks
    will be replaced with the original property name. Otherwise, the property name for each property
    item will be prefixed with the given name pattern.

    The property collection of multiple (chained) join commands can be divided in once from the last join
    command in the change. The rename patterns are right aligned, meaning that the last renamed pattern
    will be applied to the last object joined. If there are less rename patterns than property items,
    the rest of the (left most) property items will be put in a fixed array under the original property name.

    > **Note 1:** Only properties with the same name on both sides will not be renamed.

    > **Note 2:** Related properties (with an equal value defined by the [-On] parameter) will be merged to a single
    item.

.PARAMETER Property
    A hash table or list of property names (strings) and/or hash tables that define a new selection of
    property names and values

    Hash tables should be in the format `@{<PropertyName> = <Expression>}` where the `<Expression>` is a
    ScriptBlock or a smart property (string) and defines how the specific left and right properties should be
    merged. See the [-Using] parameter for available expression variables.

    The following smart properties are available:
    * A general property: '<Property Name>', where `<Property Name>` represents the property name of the left
      and/or right property, e.g. `@{ MyProperty = 'Name' }`. If the property exists on both sides, an array
      holding both values will be returned. In the outer join, the value of the property will be `$Null`.
      This smart property is similar to the expression: `@{ MyProperty = { @($Left['Name'], $Right['Name']) } }`
    * A general wildcard property: `'*'`, where `* `represents the property name of the current property, e.g.
      `MyProperty` in `@{ MyProperty = '*' }`. If the property exists on both sides:
      - and the properties are unrelated, an array holding both values will be returned
      - and the properties are related to each other, the (equal) values will be merged in one property value
      - and the property at the other side is related to an different property, the property is omitted
      The argument: `-Property *`, will apply a general wildcard on all left and right properties.
    * A left property: `;Left.<Property Name>'`, or right property: `;Right.<Property Name>'`, where
      `<Property Name>` represents the property name of the either the left or right property. If the property
      doesn't exist, the value of the property will be `$Null`.
    * A left wildcard property: `'Left.*'`, or right wildcard property: `Right.*`, where `*` represents the
      property name of the current the left or right property, e.g. `MyProperty` in `@{ MyProperty = 'Left.*' }`.
      If the property doesn't exist (in an outer join), the property with the same name at the other side will
      be taken. If the property doesn't exist on either side, the value of the property will be `$Null`.
      The argument: `-Property 'Left.*'`, will apply a left wildcard property on all the left object properties.

    If the [-Property] parameter and the [-Discern] parameter are omitted, a general wildcard property is applied
    on all the left and right properties.

    The last defined expression or smart property will overrule any previous defined properties.

.PARAMETER ValueName
    Defines the name of the added property in case a scalar array is joined with an object array.
    The default property name for each scalar is: `<Value>`.

    > **Note:** if two scalar (or collection) arrays are joined, an array of (psobject) collections is returned.
    Each collection is a concatenation of the left item (collection) and the right item (collection).

.PARAMETER JoinType
    Defines which unrelated objects should be included (see: [Description]).
    Valid values are: `Inner`, `Left`, `Right`, `Full` or `Cross`. The default is `Inner`.

    > **Note:** it is recommended to use the related proxy commands (`... |<JoinType>-Object ...`) instead.

.EXAMPLE
    # Common (inner) join
    The following example will show an inner join based on the `country` property.\
    Given the following object lists:

    PS C:\> $Employee

        Id Name    Country Department  Age ReportsTo
        -- ----    ------- ----------  --- ---------
         1 Aerts   Belgium Sales        40         5
         2 Bauer   Germany Engineering  31         4
         3 Cook    England Sales        69         1
         4 Duval   France  Engineering  21         5
         5 Evans   England Marketing    35
         6 Fischer Germany Engineering  29         4

    PS C:\> $Department

        Name        Country
        ----        -------
        Engineering Germany
        Marketing   England
        Sales       France
        Purchase    France


    PS C:\> $Employee |Join $Department -On Country |Format-Table

        Id Name                   Country Department  Age ReportsTo
        -- ----                   ------- ----------  --- ---------
         2 {Bauer, Engineering}   Germany Engineering  31         4
         3 {Cook, Marketing}      England Sales        69         1
         4 {Duval, Sales}         France  Engineering  21         5
         4 {Duval, Purchase}      France  Engineering  21         5
         5 {Evans, Marketing}     England Marketing    35
         6 {Fischer, Engineering} Germany Engineering  29         4

.EXAMPLE
    # Full join overlapping column names

    The example below does a full join of the tables mentioned in the first example based
    on the `department` name and splits the duplicate (`country`) names over differend properties.

    PS C:\> $Employee |InnerJoin $Department -On Department -Equals Name -Discern Employee, Department |Format-Table

        Id Name    EmployeeCountry DepartmentCountry Department  Age ReportsTo
        -- ----    --------------- ----------------- ----------  --- ---------
         1 Aerts   Belgium         France            Sales        40         5
         2 Bauer   Germany         Germany           Engineering  31         4
         3 Cook    England         France            Sales        69         1
         4 Duval   France          Germany           Engineering  21         5
         5 Evans   England         England           Marketing    35
         6 Fischer Germany         Germany           Engineering  29         4

.EXAMPLE
    # merge a table with updates

    This example merges the following `$Changes` list into the `$Employee` list of the first example.

    PS C:\> $Changes

        Id Name    Country Department  Age ReportsTo
        -- ----    ------- ----------  --- ---------
         3 Cook    England Sales        69         5
         6 Fischer France  Engineering  29         4
         7 Geralds Belgium Sales        71         1

    PS C:\> # Apply the changes to the employees
    PS C:\> $Employee |Merge $Changes -On Id |Format-Table

        Id Name    Country Department  Age ReportsTo
        -- ----    ------- ----------  --- ---------
         1 Aerts   Belgium Sales        40         5
         2 Bauer   Germany Engineering  31         4
         3 Cook    England Sales        69         5
         4 Duval   France  Engineering  21         5
         5 Evans   England Marketing    35
         6 Fischer France  Engineering  29         4
         7 Geralds Belgium Sales        71         1

.EXAMPLE
    # Self join

    This example shows a (self)join where each employee is connected with another employee on the country.

    PS C:\> $Employee | Join -On Country -Discern *1,*2 |Format-Table *

        Id1 Id2 Name1   Name2   Country Department1 Department2 Age1 Age2 ReportsTo1 ReportsTo2
        --- --- -----   -----   ------- ----------- ----------- ---- ---- ---------- ----------
          2   6 Bauer   Fischer Germany Engineering Engineering   31   29          4          4
          3   5 Cook    Evans   England Sales       Marketing     69   35          1
          5   3 Evans   Cook    England Marketing   Sales         35   69                     1
          6   2 Fischer Bauer   Germany Engineering Engineering   29   31          4          4

.EXAMPLE
    # Join a scalar array

    This example adds an Id to the department list.\
    note that the default column name of (nameless) scalar array is `<Value>` this will show when the [-ValueName] parameter is ommited.

    PS C:\> 1..9 |Join $Department -ValueName Id

        Id Name        Country
        -- ----        -------
         1 Engineering Germany
         2 Marketing   England
         3 Sales       France
         4 Purchase    France

.EXAMPLE
    # Transpose arrays

    The following example, the `join-Object` cmdlet (`... |Join`) joins multiple arrays to a collection array.\
    The [Foreach-Object] cmdlet iterates over the rows and the `-Join` operator concatinates the item collections

    PS C:\> $a = 'a1', 'a2', 'a3', 'a4'
    PS C:\> $b = 'b1', 'b2', 'b3', 'b4'
    PS C:\> $c = 'c1', 'c2', 'c3', 'c4'
    PS C:\> $d = 'd1', 'd2', 'd3', 'd4'

    PS C:\> $a |Join $b |Join $c |Join $d |% { $_ -Join '|' }

        a1|b1|c1|d1
        a2|b2|c2|d2
        a3|b3|c3|d3
        a4|b4|c4|d4

.EXAMPLE
    # Arrays to objects

    This example will change the collections of the previous example into objects with named properties.

    PS C:\> $a |Join $b |Join $c |Join $d -Name a, b, c, d

        a  b  c  d
        -  -  -  -
        a1 b1 c1 d1
        a2 b2 c2 d2
        a3 b3 c3 d3
        a4 b4 c4 d4

.LINK
    https://www.powershellgallery.com/packages/Join
    https://www.powershellgallery.com/packages/JoinModule
    https://github.com/iRon7/Join-Object
    https://github.com/PowerShell/PowerShell/issues/14994 (Please give a thumbs up if you like to support the proposal to "Add a Join-Object cmdlet to the standard PowerShell equipment")
#>

function Join-Object {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionRisk.Create', '', Scope = 'Function')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('InjectionRisk.ForeachObjectInjection', '', Scope = 'Function')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseLiteralInitializerForHashtable', '', Scope = 'Function')]
    [CmdletBinding(DefaultParameterSetName = 'Default')][OutputType([Object[]])] param(

        [Parameter(ValueFromPipeLine = $True, ParameterSetName = 'Default')]
        [Parameter(ValueFromPipeLine = $True, ParameterSetName = 'On')]
        [Parameter(ValueFromPipeLine = $True, ParameterSetName = 'Using')]
        $LeftObject,

        [Parameter(Position = 0, ParameterSetName = 'Default')]
        [Parameter(Position = 0, ParameterSetName = 'On')]
        [Parameter(Position = 0, ParameterSetName = 'Using')]
        $RightObject,

        [Parameter(Position = 1, ParameterSetName = 'On')]
        [array]$On = @(),

        [Parameter(Position = 1, ParameterSetName = 'Using')]
        [scriptblock]$Using,

        [Parameter(ParameterSetName = 'On')]
        [Alias('Eq')][array]$Equals = @(),

        [Parameter(Position = 2, ParameterSetName = 'Default')]
        [Parameter(Position = 2, ParameterSetName = 'On')]
        [Parameter(Position = 2, ParameterSetName = 'Using')]
        [Alias('NameItems')][AllowEmptyString()][String[]]$Discern,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'On')]
        [Parameter(ParameterSetName = 'Using')]
        $Property,

        [Parameter(Position = 3, ParameterSetName = 'Default')]
        [Parameter(Position = 3, ParameterSetName = 'On')]
        [Parameter(Position = 3, ParameterSetName = 'Using')]
        [scriptblock]$Where,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'On')]
        [Parameter(ParameterSetName = 'Using')]
        [ValidateSet('Inner', 'Left', 'Right', 'Full', 'Outer', 'Cross')][String]$JoinType = 'Inner',

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'On')]
        [Parameter(ParameterSetName = 'Using')]
        [string]$ValueName = '<Value>',

        [Parameter(ParameterSetName = 'On')]
        [switch]$Strict,

        [Parameter(ParameterSetName = 'On')]
        [Alias('CaseSensitive')][switch]$MatchCase
    )
    begin {
        $Esc = "`u{1B}``"
        function StopError($Exception, $Id = 'IncorrectArgument', $Group = [Management.Automation.ErrorCategory]::SyntaxError, $Object){
            if ($Exception -isnot [Exception]) { $Exception = [ArgumentException]$Exception }
            $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new($Exception, $Id, $Group, $Object))
        }
        function AsDictionary {
            param(
                [Parameter(ValueFromPipeLine = $True)]$Object,
                $ValueName
            )
            begin {
                $Keys = $Null
            }
            process {
                if ($Null -eq $Keys) {
                    $Keys =
                        if ($Null -eq $Object) { ,@() }
                        elseif ($Object.GetType().GetElementType() -and $Object.get_Count() -eq 0) { $Null }
                        else {
                            $1 = $Object |Select-Object -First 1
                            if ($1 -is [string] -or $1 -is [ValueType] -or $1 -is [Array]) { $Null }
                            elseif ($1 -is [Collections.ObjectModel.Collection[psobject]]) { $Null }
                            elseif ($1 -is [Data.DataRow]) { ,@($1.Table.Columns.ColumnName) }
                            elseif ($1 -is [System.Collections.IDictionary]) { ,@($1.Get_Keys()) }
                            elseif ($1) { ,@($1.PSObject.Properties.Name) }
                        }
                }
                foreach ($Item in $Object) {
                    if ($Item -is [Collections.IDictionary]) { $Object; Break }
                    elseif ( $Null -eq $Keys ) { [ordered]@{ $ValueName = $Item } }
                    else {
                        $Dictionary = [ordered]@{}
                        if ($Null -ne $Item) {
                            foreach ($Key in @($Keys)) {
                                if ($Null -eq $Key) { $Key = $ValueName }
                                $Dictionary.Add($Key, $Item.psobject.properties[$Key].Value)
                            }
                        }
                        $Dictionary
                    }
                }
            }
        }
        function SetExpression ($Key = '*', $Keys, $Expression) {
            $Wildcard = if ($Key -is [ScriptBlock]) { $Keys } else {
                if (!$Keys.Contains($Key)) {
                    if ($Key.Trim() -eq '*') { $Keys }
                    else {
                        $Side, $Asterisks = $Key.Split('.', 2)
                        if ($Null -ne $Asterisks -and $Asterisks.Trim() -eq '*') {
                            if ($Side -eq 'Left') { $LeftKeys } elseif ($Side -eq 'Right') { $RightKeys }
                        }
                    }
                }
            }
            if ($Null -ne $Wildcard) {
                if ($Null -eq $Expression) { $Expression = $Key }
                foreach ($Key in $Wildcard) {
                    if ($Null -ne $Key -and !$Expressions.Contains($Key)) {
                        $Expressions[$Key] = $Expression
                    }
                }
            }
            else { $Expressions[$Key] = if ($Expression) { $Expression } else { ' * ' } }
        }
        function Combine {
            param(
                [Parameter(ValueFromPipeLine = $True)]$Item,
                $Where,
                $Expressions,
                $Discern,
                $ValueName,
                $LeftRight,
                $RightLeft
            )
            begin {
                if ($Where) { $Where = [ScriptBlock]::Create($Where) } # Pull into the current (module) scope
            }
            process {
                $Left = $Item.Left
                $Right = $Item.Right
                $LeftIndex = $Item.LeftIndex
                $RightIndex = $Item.RightIndex

                if (!$Where -or (& $Where)) {
                    $Nodes = [Ordered]@{}
                    foreach ($Name in $Expressions.Get_Keys()) {
                        $Tuple =
                            if ($Expressions[$Name] -is [ScriptBlock]) { @{ 0 = $Name.foreach{&$Expressions[$Name]}[0] } }
                            else {
                                $Key = $Expressions[$Name]
                                if ($Left.Contains($Key) -or $Right.Contains($Key)) {
                                    if ($Left.Contains($Key) -and $Right.Contains($Key)) { @{ 0 = $Left[$Key]; 1 = $Right[$Key] } }
                                    elseif ($Left.Contains($Key)) { @{ 0 = $Left[$Key] } }
                                    else { @{ 0 = $Right[$Key] } } # if($Right.Contains($Name))
                                }
                                elseif ($Key.Trim() -eq '*') {
                                    if ($Left.Contains($Name) -and $Right.Contains($Name)) {
                                        if ($LeftRight.Contains($Name) -and $LeftRight[$Name] -eq $Name) {
                                            if ($Null -ne $LeftIndex -and $Left.Contains($Name)) { @{ 0 = $Left[$Name] } } else { @{ 0 = $Right[$Name] } }
                                        }
                                        elseif (!$LeftRight.Contains($Name) -and $RightLeft.Contains($Name)) { @{ 0 = $Left[$Name] } }
                                        elseif ($LeftRight.Contains($Name) -and !$RightLeft.Contains($Name)) { @{ 0 = $Right[$Name] } }
                                        else { @{ 0 = $Left[$Name]; 1 = $Right[$Name] } }
                                    }
                                    elseif ($Left.Contains($Name))  {
                                        if ($Null -ne $LeftIndex -and $Left.Contains($Name)) { @{ 0 = $Left[$Name] } }
                                        elseif ($LeftRight.Contains($Name)) { @{ 0 = $Right[$LeftRight[$Name]] } }
                                    }
                                    elseif ($Right.Contains($Name)) {
                                        if ($Null -ne $RightIndex -and $Right.Contains($Name)) { @{ 0 = $Right[$Name] } }
                                        elseif ($RightLeft.Contains($Name)) { @{ 0 = $Left[$RightLeft[$Name]] } }
                                    }
                                }
                                else {
                                    $Side, $Key = $Key.Split('.', 2)
                                    if ($Null -ne $Key) {
                                        if ($Side[0] -eq 'L') {
                                            if ($Left.Contains($Key)) { @{ 0 = $Left[$Key] } }
                                            elseif ($Key -eq '*') {
                                                if ($Null -ne $LeftIndex -and $Left.Contains($Name)) { @{ 0 = $Left[$Name] } }
                                                elseif ($Null -ne $RightIndex -and $Right.Contains($Name)) { @{ 0 = $Right[$Name] } }
                                            }
                                        }
                                        if ($Side[0] -eq 'R') {
                                            if ($Right.Contains($Key)) { @{ 0 = $Right[$Key] } }
                                            elseif ($Key -eq '*') {
                                                if ($Null -ne $RightIndex -and $Right.Contains($Name)) { @{ 0 = $Right[$Name] } }
                                                elseif ($Null -ne $LeftIndex -and $Left.Contains($Name)) { @{ 0 = $Left[$Name] } }
                                            }
                                        }
                                    } else { StopError "The property '$Key' doesn't exists" 'MissingProperty' }
                                }
                            }
                        if ($Tuple -isnot [Collections.IDictionary] ) { $Node = $Null }
                        elseif ($Tuple.Count -eq 1) { $Node = $Tuple[0] }
                        else {
                            $Node = [Collections.ObjectModel.Collection[psobject]]::new()
                            if ($Tuple[0] -is [Collections.ObjectModel.Collection[psobject]]) { foreach ($Value in $Tuple[0]) { $Node.Add($Value) } } else { $Node.Add($Tuple[0]) }
                            if ($Tuple[1] -is [Collections.ObjectModel.Collection[psobject]]) { foreach ($Value in $Tuple[1]) { $Node.Add($Value) } } else { $Node.Add($Tuple[1]) }
                        }
                        if ($Null -ne $Discern -and $Node -is [Collections.ObjectModel.Collection[psobject]]) {
                            if ($Node.get_Count() -eq $Discern.Count + 1) { $Nodes[$Name] = $Node[$Node.get_Count() - $Discern.Count - 1] }
                            if ($Node.get_Count() -gt $Discern.Count + 1) { $Nodes[$Name] = $Node[0..($Node.get_Count() - $Discern.Count - 1)] }
                            for ($i = [math]::Min($Node.get_Count(), $Discern.Count); $i -gt 0; $i--) {
                                $Rename = $Discern[$Discern.Count - $i]
                                $Rename = if ($Rename.Contains('*')) { ([regex]"\*").Replace($Rename, $Name, 1) } elseif ($Name -eq $ValueName) { $Rename } else { $Rename + $Name }
                                if (!$Rename) { $Rename = $ValueName}
                                $Nodes[$Rename] = if ($Nodes.Contains($Rename)) { @($Nodes[$Rename]) + $Node[$Node.get_Count() - $i] } else { $Node[$Node.get_Count() - $i] }
                            }
                        } elseif ($Null -ne $Discern -and $Name -eq $ValueName) {
                            $Nodes[$Discern[0]] = $Node
                        } else {
                            $Nodes[$Name] = $Node
                        }
                    }
                    if ($Nodes.get_Count()) {
                        if ($Nodes.get_Count() -eq 1 -and $Nodes.Contains($ValueName)) { ,$Nodes[$ValueName] } # return scalar array
                        else { [PSCustomObject]$Nodes }
                    }
                }
            }
        }
        function ProcessObject {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Discern', Justification = 'False positive as rule does not scan child scopes')]
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Where',   Justification = 'False positive as rule does not scan child scopes')]
            param(
                $RightObject,
                [array]$On = @(),
                $Using,
                [array]$Equals = @(),
                $Discern,
                $Property,
                $Where,
                $JoinType,
                $ValueName,
                [switch]$Strict,
                [switch]$MatchCase,
                [Switch]$SkipSameIndex,
                [Parameter(ValueFromPipeLine = $True)]$LeftObject
            )
            begin {
                $Expressions = [Ordered]@{}
                $StringComparer = if ($MatchCase) { [StringComparer]::Ordinal } Else { [StringComparer]::OrdinalIgnoreCase }
                $Keys, $LeftKeys, $RightKeys, $Pipeline, $LeftList, $AsDictionary = $Null
                $InnerRight = [System.Collections.Generic.HashSet[int]]::new()
                $RightIndices = [Collections.Generic.Dictionary[string, object]]::new($StringComparer)
                $LeftRight = @{}; $RightLeft = @{}; $LeftNull = [ordered]@{}; $RightNull = [ordered]@{}
                $LeftIndex = 0
                if ($RightObject -is [Collections.IDictionary]) { $RightList = @($RightObject) }
                else {
                    $RightName = if ($Equals.Count -eq 0 -and $On.Count -eq 1  -and "$($On[0])".Trim() -ne '*') { $On[0] }
                                 elseif ($Equals.Count -eq 1 -and "$($Equals[0])".Trim() -ne '*') { $Equals[0] } else { $ValueName }
                    $RightList = @(AsDictionary $RightObject -ValueName $RightName)
                }
                if ($RightList.Count) { $RightKeys = $RightList[0].get_Keys() } else { $RightKeys = @() }
                if ($Using) { $Using = [ScriptBlock]::Create($Using) } # Pull into the current (module) scope
                $Combine = $null
            }
            process {
                if (!$AsDictionary) {
                    $LeftName = if ($On.Count -eq 1 -and "$($On[0])".Trim() -ne '*') { $On[0] } else { $ValueName }
                    $AsDictionary = { AsDictionary -ValueName $LeftName }.GetSteppablePipeline()
                    $AsDictionary.Begin($True)
                }
                $Left = if ($LeftObject -is[Collections.IDictionary]) { $LeftObject }elseif ($Null -ne $LeftObject) { $AsDictionary.Process((,$LeftObject))[0] }
                if (!$LeftKeys) {
                    if ($Null -ne $Left) { $LeftKeys = $Left.get_Keys() } else { $LeftKeys = @() }
                    $Keys = [System.Collections.Generic.HashSet[string]]::new([string[]](@($LeftKeys) + @($RightKeys)), [StringComparer]::InvariantCultureIgnoreCase)
                }
                if ($Null -eq $Combine) {
                    if ($On.Count) {
                        $OnWildCard     = $On.Count     -eq 1 -and "$($On[0])".Trim()     -eq '*' # Use e.g. -On ' * ' if there exists an '*' property
                        $EqualsWildCard = $Equals.Count -eq 1 -and "$($Equals[0])".Trim() -eq '*'
                        if ($OnWildCard) {
                            if ($Equals.Count -and !$EqualsWildCard) { $On = $Equals }
                            else { $On = $LeftKeys.Where{ $RightKeys -eq $_ } }
                        }
                        elseif ($EqualsWildCard) { $Equals = $On }
                        if     ($On.Count -gt $Equals.Count) { $Equals += $On[($Equals.Count)..($On.Count - 1)] }
                        elseif ($On.Count -lt $Equals.Count) { $On     += $Equals[($On.Count)..($Equals.Count - 1)] }
                        if ($Null -ne $Left) {
                            for ($i = 0; $i -lt $On.Count; $i++) {
                                if ( $On[$i] -is [ScriptBlock] ) { if ( $On[$i] -Like '*$Right*' ) { Write-Warning 'Use the -Using parameter for comparison expressions' } }
                                else {
                                    if ($On[$i] -notin $LeftKeys) { StopError "The property $($On[$i]) cannot be found on the left object." 'MissingLeftProperty' }
                                    $LeftRight[$On[$i]] = $Equals[$i]
                                }
                                if ( $Equals[$i] -is [ScriptBlock] ) { if ( $On[$i] -Like '*$Left*' ) { Write-Warning 'Use the -Using parameter for comparison expressions' } }
                                else {
                                    if ($Equals[$i] -notin $RightKeys) { StopError "The property $($Equals[$i]) cannot be found on the right object." 'MissingRightProperty' }
                                    $RightLeft[$Equals[$i]] = $On[$i]
                                }
                            }
                        }
                        $RightIndex = 0
                        foreach ($Right in $RightList) {
                            $Dictionary = $RightIndices # $Dictionary references the $RightList
                            $Count = $Equals.Count
                            foreach ($Name in $Equals) {
                                $Value = if ($Name -is [ScriptBlock]) { $Right |ForEach-Object $Name } else { $Right[$Name] }
                                $Key = # WET performance: https://github.com/orgs/PowerShell/discussions/19322
                                    if ( $Null -eq $Value ) { "$Esc`$Null" }
                                    else {
                                        $Type = if ($Strict) { "$($Value.GetType())" }
                                        if ($Value -is [String]) { $Value }
                                        elseif ($Value -is [ValueType]) { "$Type$Value" }
                                        elseif ($Value -is [System.MarshalByRefObject]) { "$Esc$Type[$($Value |Select-Object *)]" }
                                        elseif ($Value -is [PSCustomObject]) { "$Esc$Type[$Value]" }
                                        elseif ($Value -is [System.Collections.IDictionary]) { "$Esc$Type{$($Value.GetEnumerator())}" }
                                        elseif ($Value -is [Array]) { "$Esc$Type($Value)" }
                                        else { "$Esc$Type$Value" }
                                    }
                                if (-Not --$Count) { break }
                                if (!$Dictionary.ContainsKey($Key)) { $Dictionary[$Key] = [Collections.Generic.Dictionary[string, object]]::new($StringComparer) }
                                $Dictionary = $Dictionary[$Key]
                            }
                            if ($Dictionary.ContainsKey($Key)) { $Dictionary[$Key].Add($RightIndex++) }
                            else { $Dictionary[$Key] = [Collections.Generic.List[Int]]$RightIndex++ }
                        }
                    }
                    foreach ($Key in $LeftKeys) {
                        if ($Left[$Key] -isnot [Collections.ObjectModel.Collection[psobject]]) { $LeftNull[$Key] = $Null }
                        else { $LeftNull[$Key] = [Collections.ObjectModel.Collection[psobject]]( ,$Null * $Left[$Key].Count) }
                    }
                    foreach ($Key in $RightKeys) {
                        $RightNull[$Key] = if ($RightList) {
                            if ($RightList[0][$Key] -isnot [Collections.ObjectModel.Collection[psobject]]) { $Null }
                            else { [Collections.ObjectModel.Collection[psobject]]( ,$Null * $Left[$Key].Count) }
                        }
                    }
                    if ($Property) {
                        foreach ($Item in @($Property)) {
                            if ($Item -is [System.Collections.IDictionary]) { foreach ($Key in $Item.Get_Keys()) { SetExpression -Key $Key -Keys $Keys -Expression $Item[$Key] } }
                            else { SetExpression -Key $Item -Keys $Keys }
                        }
                    } else { SetExpression -Keys $Keys }
                    foreach ($Key in @($Expressions.get_Keys())) {
                        if ($Expressions[$Key] -is [ScriptBlock]) { $Expressions[$Key] = [scriptblock]::Create($Expressions[$Key]) }
                    }
                    $Combine = { Combine -LeftRight $LeftRight -RightLeft $RightLeft -Where $Where -Expression $Expressions -Discern $Discern -ValueName $ValueName }.GetSteppablePipeline()
                    $Combine.Begin($True)
                }
                if ($Null -ne $Left) {
                    $InnerLeft = $False
                    $Indices =
                        if ($On.Count) {
                            $Dictionary = $RightIndices
                            foreach ($Name in $On) {
                                $Value = if ($Name -is [ScriptBlock]) { $Left |ForEach-Object $Name } else { $Left[$Name] }
                                $Key = # WET performance: https://github.com/orgs/PowerShell/discussions/19322
                                    if ( $Null -eq $Value ) { "$Esc`$Null" }
                                    else {
                                        $Type = if ($Strict) { "$($Value.GetType())" }
                                        if ($Value -is [String]) { $Value }
                                        elseif ($Value -is [ValueType]) { "$Type$Value" }
                                        elseif ($Value -is [System.MarshalByRefObject]) { "$Esc$Type[$($Value |Select-Object *)]" }
                                        elseif ($Value -is [PSCustomObject]) { "$Esc$Type[$Value]" }
                                        elseif ($Value -is [System.Collections.IDictionary]) { "$Esc$Type{$($Value.GetEnumerator())}" }
                                        elseif ($Value -is [Array]) { "$Esc$Type($Value)" }
                                        else { "$Esc$Type$Value" }                            }
                                $Dictionary = if ($Dictionary.ContainsKey($Key)) { $Dictionary[$Key] }
                                if ($Null -eq $Dictionary) { break }
                            }
                            if ($Null -ne $Dictionary) { $Dictionary }
                        }
                        elseif ($Using) {
                            if ($JoinType -eq 'Cross') { StopError 'The Using parameter cannot be used on a cross join.' 'CrossUsing' }
                            for ($RightIndex = 0; $RightIndex -lt $RightList.Count; $RightIndex++) {
                                $Right = $RightList[$RightIndex]
                                if (& $Using) { $RightIndex }
                            }
                        }
                        elseif ($JoinType -eq 'Cross') { 0..($RightList.Length - 1) }
                        elseif ($LeftIndex -lt $RightList.Count) { $LeftIndex } else { $Null }
                    foreach ($RightIndex in $Indices) {
                        if ($SkipSameIndex -and $LeftIndex -eq $RightIndex) {
                            $InnerLeft = $True
                            $Null = $InnerRight.Add($RightIndex)
                        }
                        else {
                            $Object = $Combine.Process(@{ Left = $Left; Right = $RightList[$RightIndex]; LeftIndex = $LeftIndex; RightIndex = $RightIndex })
                            if ($Null -ne $Object -and $Object.get_Count() -gt 0) {
                                if ($JoinType -ne 'Outer') { $Object }
                                $InnerLeft = $True
                                $Null = $InnerRight.Add($RightIndex)
                            }
                        }
                    }
                }
                else {
                    $InnerLeft = $True
                    for ($RightIndex = 0; $RightIndex -lt $RightList.Count; $RightIndex++) {
                        if (!$InnerRight.Contains($RightIndex)) {
                            $Combine.Process(@{ Left = $LeftNull; Right = $RightList[$RightIndex]; LeftIndex = $Null; RightIndex = $RightIndex })
                        }
                    }
                }
                if (!$InnerLeft -and ($JoinType -in 'Left', 'Full', 'Outer')) {
                    $Combine.Process(@{ Left = $Left; Right = $RightNull; LeftIndex = $LeftIndex; RightIndex = $Null })
                }
                $LeftIndex++
            }
            end {
                if ($AsDictionary) { $AsDictionary.End() }
                if($Combine) { $Combine.End() }
            }
        }

        $Parameters = [System.Collections.Generic.Dictionary[String,Object]]::new($PSBoundParameters)
        $Parameters['ValueName']     = $ValueName
        if ($Parameters.TryGetValue('OutBuffer', [ref]$Null))          { $Parameters['OutBuffer']   = 1   }
        if ($Parameters.ContainsKey('Discern') -and !$Discern)         { $Parameters['Discern']     = @() }
        if ($JoinType -eq 'Outer' -and !$Parameters.ContainsKey('On')) { $Parameters['On']          = '*' }

        $LeftList, $Pipeline = $Null
    }

    process {
        # The Process block is invoked (once) if the pipeline is omitted but not if it is empty: @()
        # if ($Null -eq $LeftKeys) { $LeftKeys = GetKeys $LeftObject }

        if ($Null -eq $Pipeline) {
            if ($Null -ne $_ -and $Parameters.ContainsKey('RightObject')) {
                $Pipeline = { ProcessObject @Parameters }.GetSteppablePipeline()
                $Pipeline.Begin($PSCmdlet)
            }
            else {
                $Pipeline = $False
                $LeftList = [Collections.Generic.List[Object]]::New()
            }
        }
        if ($Pipeline) { $Pipeline.Process($_) }  else { $LeftList.Add($_) }
    }
    end {
        if (!($Parameters.ContainsKey('LeftObject') -or $LeftList) -and !$Parameters.ContainsKey('RightObject')) {
             StopError 'A value for either the LeftObject, pipeline or the RightObject is required.' 'MissingObject'
        }
        if ($Pipeline -eq $False) { # Not yet streamed/processed
            if (!$LeftList) {
                if ($Parameters.ContainsKey('LeftObject'))   {
                    $LeftList = $LeftObject
                }
                else { # Right self-join
                    if ($Parameters.ContainsKey('On') -and !$Parameters.ContainsKey('Equal')) { $Parameters['SkipSameIndex'] = $True }
                    $LeftList = $RightObject
                }
            }
            if ($Parameters.ContainsKey('LeftObject')) { $Null = $Parameters.remove('LeftObject') }
            if (!$Parameters.ContainsKey('RightObject')) { # Left self-join
                if ($Parameters.ContainsKey('On') -and !$Parameters.ContainsKey('Equal')) { $Parameters['SkipSameIndex'] = $True }
                $Parameters['RightObject'] = $LeftList
            }
            $Pipeline = { ProcessObject @Parameters }.GetSteppablePipeline()
            $Pipeline.Begin($True)
            foreach ($Left in $LeftList) { $Pipeline.Process($Left) }
        }
        if ('Right', 'Full', 'Outer' -eq $JoinType) {
            if ($Null -eq $Pipeline) {
                if ($Parameters.ContainsKey('LeftObject')) { $Null = $Parameters.remove('LeftObject') }
                $Pipeline = { ProcessObject @Parameters }.GetSteppablePipeline()
                $PipeLine.Begin($True)
            }
            $Pipeline.Process($Null)
        }
        if ($Pipeline) { $Pipeline.End() }
    }
}; Set-Alias Join Join-Object

$JoinCommand = Get-Command Join-Object
$MetaData = [System.Management.Automation.CommandMetadata]$JoinCommand
$ProxyCommand = [System.Management.Automation.ProxyCommand]::Create($MetaData)
$ParamBlock, $ScriptBlock = $ProxyCommand -Split '\r?\n(?=begin\r?\n)', 2

$Proxies =
    @{ Name = 'InnerJoin-Object'; Alias = 'InnerJoin'; Default = "JoinType = 'Inner'" },
    @{ Name = 'LeftJoin-Object';  Alias = 'LeftJoin';  Default = "JoinType = 'Left'" },
    @{ Name = 'RightJoin-Object'; Alias = 'RightJoin'; Default = "JoinType = 'Right'" },
    @{ Name = 'FullJoin-Object';  Alias = 'FullJoin';  Default = "JoinType = 'Full'" },
    @{ Name = 'OuterJoin-Object'; Alias = 'OuterJoin'; Default = "JoinType = 'Outer'" },
    @{ Name = 'CrossJoin-Object'; Alias = 'CrossJoin'; Default = "JoinType = 'Cross'" },
    @{ Name = 'Update-Object';    Alias = 'Update';    Default = "JoinType = 'Left'",  "Property = @{ '*' = 'Right.*' }" },
    @{ Name = 'Merge-Object';     Alias = 'Merge';     Default = "JoinType = 'Full'",  "Property = @{ '*' = 'Right.*' }" },
    @{ Name = 'Get-Difference';   Alias = 'Differs';   Default = "JoinType = 'Outer'", "Property = @{ '*' = 'Right.*' }" }

foreach ($Proxy in $Proxies) {
    $ProxyCommand = @(
        $ParamBlock
        'DynamicParam  {'
        foreach ($Default in @($Proxy.Default)) { '    $PSBoundParameters.' + $Default }
        '}'
        $ScriptBlock
    ) -Join [Environment]::NewLine
    $Null = New-Item -Path Function:\ -Name $Proxy.Name -Value $ProxyCommand -Force
    Set-Alias $Proxy.Alias $Proxy.Name
}


<#

Flatten-Object https://stackoverflow.com/questions/45829754/convert-nested-json-array-into-separate-columns-in-csv-file/
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
    <# https://evotec.xyz/powershell-converting-advanced-object-to-flat-object/
    .SYNOPSIS
    Flattens a nested object into a single level object.

    .DESCRIPTION
    Flattens a nested object into a single level object.

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
    The properties to be excluded from the output.

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
                #Write-Output -Message "ConvertTo-FlatObject - Object is null"
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
    <# https://github.com/RamblingCookieMonster/PowerShell/blob/master/ConvertTo-FlatObject.ps1
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
                        Write-Output "Excluding default properties for $($obj.gettype().Fullname):`n$($DefaultTypeProps | Out-String)"
                    }
                } catch {
                    Write-Output "Failed to extract properties from $($obj.gettype().Fullname): $_"
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
            Write-Output "Working in path $Path at depth $depth"
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
                    Write-Output "Adding member '$ThisPath'"
                }

                #Handle null...
                if ($ChildValue -eq $null) {
                    Write-Output "Skipping NULL $ChildName"
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
                    Write-Output "Skipping $ChildName with type $($ChildValue.GetType().fullname)"
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
                        Write-Output "Working on hashtable $CurrentPath"
                        foreach ($key in $HashKeys) {
                            Write-Output "Adding value from hashtable $CurrentPath['$key']"
                            $Output | Add-Member -MemberType NoteProperty -Name "$CurrentPath['$key']" -Value $ChildValue["$key"]
                            $Output = Recurse-Object -Object $ChildValue["$key"] -Path "$CurrentPath['$key']" -Output $Output -Depth $depth
                        }
                    }
                    #Sub children?  Recurse!
                    else {
                        if ($IsArray) {
                            foreach ($item in @($ChildValue)) {
                                Write-Output "Recursing through array node '$CurrentPath'"
                                $Output = Recurse-Object -Object $item -Path "$CurrentPath[$count]" -Output $Output -Depth $depth
                                $Count++
                            }
                        } else {
                            Write-Output "Recursing through node '$CurrentPath'"
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
    <# https://github.com/proxb/PowerShell_Scripts/blob/master/Convert-OutputForCSV.ps1
        .SYNOPSIS
            Provides a way to expand collections in an object property prior
            to being sent to Export-Csv.

        .DESCRIPTION
            Provides a way to expand collections in an object property prior
            to being sent to Export-Csv. This helps to avoid the object type
            from being shown such as system.object[] in a spreadsheet.

        .PARAMETER InputObject
            The object that will be sent to Export-Csv

        .PARAMETER OutputPropertyType
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
            function which expands any property with a collection so it can be read properly prior
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
            Write-Output "$($_)"
        }
        $FirstRun = $True
    }
    process {
        if ($FirstRun) {
            $OutputOrder = $InputObject.PSObject.Properties.Name
            Write-Output "Output Order:`n $($OutputOrder -join ', ' )"
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
            Write-Output "Properties Found that have collections:`n $(($Properties_Collection) -join ', ')"
            Write-Output "Properties Found that have no collections:`n $(($Properties_NoCollection) -join ', ')"
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



<# https://github.com/solidstate888/JSON-ToCSV/blob/master/Convert-JsonToCsv.ps1
.SYNOPSIS
    "Flattens" a JSON file into a CSV formatted file.
 
.DESCRIPTION
    Uses the built-in function "ConvertFrom-Json" to convert the source JSON file to a PSCustomObject.
    Once the data is a PSCustomObject, calls the function "Flatten-PsCustomObject" to remove nesting.
    After nesting is removed, the data is sent to the built-in function "Export-Csv" for output.
 
.PARAMETERS
    (Function "Flatten-PsCustomObject": $parent, $sourceParam)
    $parent is required to create the CSV headers, and $sourceParam it the PSCustomObject input.  
 
.INPUTS
  $inputFile = "testA.json"
 
.OUTPUTS
  $outputFile = "testA.csv"
 
.NOTES
  Version:        1.0
  Author:         Kelly Jolly 
  Creation Date:  6/2/2017
  Purpose/Change: Initial Commit
#>
 
Function Flatten-PsCustomObject{
    param (
        [Parameter(ValueFromPipeLine)] #[Parameter(Mandatory=$true)]
        $sourceParam,
        [Parameter(Mandatory=$true)]
        $parent       
    )
 
    $parentFlat=$parent
    $parentNested=$parent
    $flat = [System.Collections.ArrayList]@()
    $nested = [System.Collections.ArrayList]@()
    $counter=$null
    $output = New-Object -TypeName pscustomobject
 
    #### Get the items in the PSCustomObject source that contain user data. ####
    if ($sourceParam){      
         $objects = Get-Member -InputObject $sourceParam -MemberType NoteProperty
    }
    else{
        $objects = $null
    }
 
    #### Separate the user data, based on whether each item has additional nested data or not. ####
    # "Nested" contains nested data. "Flat" contains flat data, ready for export.                 #
    foreach ($object in $objects) {
        if ($object.Definition -match "System.Object"){
            $nested+=$object
        }
        else{
             $flat+=$object
        }
    }
 
    #### Flat Data - Create CSV headers, and add the headers & flat data to the output variable. ####
    foreach($keyFlat in $flat){
        
        # Build the CSV headers. #
        $nameFlat = $parentFlat+"."+$keyFlat.Name
       
        # Using the object names, pull the values of those objects from the source, and save to a variable. #
        if ($keyFlat) {
            try{
                $valueFlat = $sourceParam | Select -ExpandProperty $keyFlat.Name -ErrorAction Stop
            }catch{
                write-host "Flat Data - Unable to populate the variable $keyFlat"
            }
        }else{
            $valueFlat = $null
        }
 
        # Some nested data was sneaking through - checks for that, and sends nested data recursively back to function. #
        # Otherwise, it adds the flat data to the output variable. #
        if ($valueFlat -and $valueFlat -match "@{"){
            Flatten-PsCustomObject $nameFlat $valueFlat
#
        }elseif (($valueFlat) -and $valueFlat -notmatch "@{"){
            $output | Add-Member -MemberType NoteProperty -Name $nameFlat -Value $valueFlat
        }else{
            $output | Add-Member -MemberType NoteProperty -Name $nameFlat -Value ""
        }
    }
 
    #### Nested Data - Sends the nested data recursively back through the function. ####
    foreach($keyNested in $Nested){
        # Creates CSV headers, gets the values of the nested data. #
        try{
            $nameNested = $parentNested+"."+$keyNested.Name
            $valueNested = $sourceParam | select -ExpandProperty $keyNested.Name -ErrorAction Stop
        }catch{
            write-host "Nested Data - Unable to populate the variable $keyNested"
        }
       
        # Sends non-null values recursively back through the function. Sends null values to the output variable. #
        If($valueNested) {
            foreach ($value in $valueNested){             
                Flatten-PsCustomObject "$nameNested$counter" $value
                $counter++       
            }
            $counter=$null
        }else{
            $output | Add-Member -MemberType NoteProperty -Name $nameNested -Value ""
        }
 
    }
    return $output
}
 
#endregion functions

#region main

$total = [Diagnostics.StopWatch]::StartNew()

foreach ($inputFile in $inputfiles) {
    [string]$outputFolder = Split-Path -Path $inputFile -Parent
    [string]$outputFile = (Get-Item $inputFile).BaseName

    Write-Output "`nLoading $inputFile..."

    $Data = Get-Content $inputFile
    Write-Output "Imported data is $(($Data | Measure-Object -Character).Characters) characters long."
    $headerRow = $Data | Select-Object -First 1 | ConvertFrom-String -Delimiter ","
    $headerRow

    if ($headerRow -match "AuditData") {
        Write-Output "Starting recursive flattening of 'AuditData' field from UAL log. Recursive JSON flattening not recommended for log exports larger than around 10mb (5,000 records, 10,000,000 characters)..."

        $CsvData = Import-Csv -Path $inputFile
        Write-Output "Imported CSV is $($CsvData.length) records long."
        Write-Output "Parsing with $function function(s)..."

        # Simple not-recursive JSON to CSV export - very fast but only flattens JSON data by one level:
        if ($function -match "simple" -or $function -eq "all") {
            $sw = [Diagnostics.StopWatch]::StartNew()
            $Audit = ""
            $Combined = ""
            [string]$outputPath = $outputFolder + "\" + $outputFile + "_Processed-SingleLevel.csv"
            $Audit = $CsvData | ForEach-Object { $_.AuditData } | ConvertFrom-Json
            if ($null -eq $CSVData[0].Identity) { $Combined = $Audit } else { $Combined = $CSVdata | InnerJoin $Audit -On Identity -Equals Id } # if ($($CSVData.Identity | Measure-Object).Count -eq 0)
            $Combined = $Combined | Sort-Object * -Unique
            $Combined = $Combined | Sort-Object "CreationTime"
            $Combined | Export-Csv -Path "$outputPath" -Encoding $Encoding -NoTypeInformation
            Write-Output "`n$outputPath written (simple)."
            Write-Output "Processed CSV is $($Combined.length) records long."
            Write-Output "Seconds elapsed for CSV processing (non-recursive json conversion): $($sw.elapsed.totalseconds)`n"
        }

        if ($function -match "iRon" -or $function -eq "all") {
            $sw = [Diagnostics.StopWatch]::StartNew()
            $Audit = ""
            $Combined = ""
            [string]$outputPath = $outputFolder + "\" + $outputFile + "_Processed-flatten.csv"
            $Audit = $CsvData | ForEach-Object { $_.AuditData } | ConvertFrom-Json | Flatten-Object -Base 1 -Depth 20 -Uncut 20
            if ($null -eq $CSVData[0].Identity) { $Combined = $Audit } else { $Combined = $CSVdata | InnerJoin $Audit -On Identity -Equals Id }
            $Combined = $Combined | Sort-Object * -Unique
            $Combined = $Combined | Sort-Object "CreationTime"
            $Combined | Export-Csv -Path "$outputPath" -Encoding $Encoding -NoTypeInformation
            Write-Output "`n$outputPath written (iRon)."
            Write-Output "Processed CSV is $($Combined.length) records long."
            Write-Output "Seconds elapsed for CSV processing (Flatten-Object - slow): $($sw.elapsed.totalseconds)`n"
        }
        if ($function -match "EvotecIT" -or $function -eq "all") {
            $sw = [Diagnostics.StopWatch]::StartNew()
            $Audit = ""
            $Combined = ""
            [string]$outputPath = $outputFolder + "\" + $outputFile + "_Processed-FlatObject.csv"
            $Audit = $CsvData | ForEach-Object { $_.AuditData } | ConvertFrom-Json | ConvertTo-FlatObject -Base 1 -Depth 20
            if ($null -eq $CSVData[0].Identity) { $Combined = $Audit } else { $Combined = $CSVdata | InnerJoin $Audit -On Identity -Equals Id }
            $Combined = $Combined | Sort-Object * -Unique
            $Combined = $Combined | Sort-Object "CreationTime"
            $Combined | Export-Csv -Path "$outputPath" -Encoding $Encoding -NoTypeInformation
            [io.file]::readalltext("$outputPath").replace("System.Object[]","") | Out-File "$outputPath" -Encoding utf8 –Force
            Write-Output "`n$outputPath written (EvotecIT)."
            Write-Output "Processed CSV is $($Combined.length) records long."
            Write-Output "Seconds elapsed for CSV processing (ConvertTo-FlatObject - fast): $($sw.elapsed.totalseconds)`n"
        }
        if ($function -match "RamblingCookieMonster" -or $function -eq "all") {
            $sw = [Diagnostics.StopWatch]::StartNew()
            $Audit = ""
            $Combined = ""
            [string]$outputPath = $outputFolder + "\" + $outputFile + "_Processed-FlatObject2.csv"
            $Audit = $CsvData | ForEach-Object { $_.AuditData } | ConvertFrom-Json | ConvertTo-FlatObject2 -MaxDepth 20
            if ($null -eq $CSVData[0].Identity) { $Combined = $Audit } else { $Combined = $CSVdata | InnerJoin $Audit -On Identity -Equals '$Object.Id' }
            $Combined = $Combined | Sort-Object * -Unique
            $Combined = $Combined | Sort-Object "CreationTime"
            $Combined | Export-Csv -Path "$outputPath" -Encoding $Encoding -NoTypeInformation
            Write-Output "`n$outputPath written (RamblingCookieMonster)."
            Write-Output "Processed CSV is $($Combined.length) records long."
            Write-Output "Seconds elapsed for CSV processing (ConvertTo-FlatObject2 - slowest): $($sw.elapsed.totalseconds)`n"
        }
        if ($function -match "proxb" -or $function -eq "all") {
            $sw = [Diagnostics.StopWatch]::StartNew()
            $Audit = ""
            $Combined = ""
            $CsvDataReplace = ""
            [string]$outputPath = $outputFolder + "\" + $outputFile + "_Processed-OutputForCsv.csv"
            $CsvDataReplace = $CsvData | ForEach-Object { $_.AuditData = $_.AuditData -replace '“', '' ; $_.AuditData = $_.AuditData -replace '”', '' ; $_ }
            $Audit = $CsvDataReplace | ForEach-Object { $_.AuditData } | ConvertFrom-Json | Convert-OutputForCSV -OutputPropertyType "Comma"
            if ($null -eq $CSVData[0].Identity) { $Combined = $Audit } else { $Combined = $CSVdata | InnerJoin $Audit -On Identity -Equals Id }
            $Combined = $Combined | Sort-Object * -Unique
            $Combined = $Combined | Sort-Object "CreationTime"
            $Combined | Export-Csv -Path "$outputPath" -Encoding $Encoding -NoTypeInformation
            Write-Output "`n$outputPath written (proxb)."
            Write-Output "Processed CSV is $($Combined.length) records long."
            Write-Output "Seconds elapsed for CSV processing (Convert-OutputForCSV - fast): $($sw.elapsed.totalseconds)`n"
        }

        # Not yet working
        if ($function -match "solidstate888" -or $function -eq "all") {
            $sw = [Diagnostics.StopWatch]::StartNew()
            $Audit = ""
            $Combined = ""
            [string]$outputPath = $outputFolder + "\" + $outputFile + "_Processed-FlattenObject.csv"
            ForEach ($Record in $CsvData) { $Audit += $Record.AuditData | ConvertFrom-Json | Flatten-PsCustomObject -Parent "AuditData" }
            if ($null -eq $CSVData[0].Identity) { $Combined = $Audit } else { $Combined = $CSVdata | InnerJoin $Audit -On Identity -Equals AuditData.Id } # function currently outputs flattened data another level lower and currently unable to join
            $Combined = $Combined | Sort-Object * -Unique
            $Combined = $Combined | Sort-Object "CreationTime"
            $Combined | Export-Csv -Path "$outputPath" -Encoding $Encoding -NoTypeInformation
            Write-Output "`n$outputPath written (solidstate888)."
            Write-Output "Processed CSV is $($Combined.length) records long."
            Write-Output "Seconds elapsed for CSV processing (Flatten-PsCustomObject - fast): $($sw.elapsed.totalseconds)`n"
        }

        Write-Output "`n`nDone!"
        Write-Output "`nIf you now have multiple columns with IP information they can be consolidated in Excel with a formula like:"
        Write-Output "=IF(ISBLANK(A2),IF(ISBLANK(B2),IF(ISBLANK(C2),"",C2),B2),A2)"
        Write-Output "(The outermost cell listed in the nested IF that contains data is preferred)"
    } else {
        Write-Output "'AuditData' field not found. Please try again with exported UAL log containing this field."
    }
}
Write-Output "`nTotal time for script execution: $($total.elapsed.totalseconds)"
Write-Output "Script complete!"
#endregion main

exit
