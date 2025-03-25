::           Bitpusher
::            \`._,'/
::            (_- -_)
::              \o/
::          The Digital
::              Fox
::          @VinceVulpes
::    https://theTechRelay.com
:: https://github.com/bitpusher2k
::
:: DropShim.bat - By Bitpusher/The Digital Fox
:: 
:: v2.1 last updated 2025-03-01
:: BAT-to-PS shim script allowing drag-and-drop of files to pass to PS script for processing.
::
:: Rename this BAT to be the same name as the PS1 script that you want to run, and place this BAT in same directory as PS1 script. 
:: Drag-and-drop a file onto this BAT to run the similarly named PS1 and pass the dropped file path(s) as parameter(s).
:: Can handle spaces in the path to PS script, in the path to drag-and-drop file, and in the name of the files themselves.
::
:: Can also just double-click the BAT to run PS1 script of the same name in current directory with no parameters.
::
:: Can now pass multiple files with path/name containing spaces properly to target PS script.
::
:: #psshim #powershell #shim #wrapper #powershell #bat #drag-and-drop


:: Argument is the full path to the file that was drag-and-dropped onto this bat:
@SET args=%1
:: Replace the automatic double-quotes around paths containing spaces with single-quotes -
:: Allows multiple files to be drag-and-dropped at the same time:
@SET args=%args:"='%
:: @echo ARGS: %args%

:: Path is the drive path to this bat script that also has the similarly named PS1 script next to it:
@SET path=%~dp0
:: @echo PATH: %path%

:: Script name is the same as the BAT name, but with ".ps1" extension:
@SET script=%~n0.ps1
:: @echo SCRIPT: %script%


:More
@SHIFT
@IF '%1' == '' GOTO Done
@SET args=%args%,'%1'
@GOTO More


:Done
:: Run with same permissions as current user the conservative way - change to directory of script and run from there:
:: @CD "%path%"
:: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noprofile -command ".\%script% '%args%'"

:: Another way to run with same permissions as current user (direct through drive-path-name variable): 
C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '%path%%script%' %args%"
:: For PowerShell Core use:
:: "C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -ExecutionPolicy Bypass -Command "& '%path%%script%' %args%"

:: If PowerShell is in your path you can remove the full directory location:
:: PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& '%path%%script%' '%args%'"

:: Run script as admin: 
:: C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -Verb RunAs powershell -ArgumentList '-NoExit -NoProfile -ExecutionPolicy Bypass -File \"%path%%script%\" \"%args%\"'"

@echo.
@pause