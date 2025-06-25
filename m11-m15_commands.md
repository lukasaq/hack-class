
PowerShell Object and Data Structure Commands
Custom Object
PowerShell
$newObject = [PSCustomObject]@{
    Property1 = $output.property1
    Property2 = $secondoutput.property2
}
Description: Creates a new custom object with properties.
Hash Table
PowerShell
$newHashTable = @{ key1 = $value1; key2 = "value2"; key3 = 3 }
Description: Creates a hash table (key-value pairs).
Add or Set Values
PowerShell
$hashTable.Foo = 'Bar'
$hashTable['Foo'] = 'Bar'
$hashTable.Add('Foo','Bar')
Function Syntax and Parameters
Basic Function
PowerShell
function Custom-Function {
    Write-Output "Hello World"
}
Parameters
PowerShell
function Example {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Variable
    )
}
Called as:
PowerShell
Example -Variable "DATA"
Pipeline Input
PowerShell
function PipeExample {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Variable
    )
    process {
        Write-Output $Variable
    }
}
@("DATA1", "DATA2", "DATA3") | PipeExample
Dynamic Parameters
PowerShell
dynamicparam {
    if ($Condition) {
        # code
    }
}
Begin/Process/End Statements
PowerShell
function Example {
    begin { # Runs once before pipeline input }
    process { # Runs for each piped item }
    end { # Runs once after all input processed }
}
Cmdlets and Module Loading
List Cmdlets
PowerShell
Get-Command -Type Cmdlet
Import Module
PowerShell
Import-Module <Module-Name>
Object and Member Discovery
List Object Members
PowerShell
Get-Item ".\Documents\" | Get-Member
Get Aliases
PowerShell
Get-Alias      # or
gal            # alias for Get-Alias
Pipelines
Use | to chain commands:
PowerShell
Get-Process | Where-Object {$_.CPU -gt 1}
Data Gathering Cmdlets
Get-Item
PowerShell
Get-Item -Path <Path>
Get-Item HKLM:\Software\Microsoft\Powershell\1\Shellids\Microsoft.Powershell\
Get-ItemProperty
PowerShell
Get-ItemProperty -Path <RegistryPath>
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
Get-ChildItem (dir, ls, gci)
PowerShell
Get-ChildItem -Path "C:\"
Get-ChildItem -Path "C:\Users\*\Downloads"
Get-ChildItem -Recurse -Include *.exe
Parameters:
-Path <string>
-Recurse
-Include <string[]>
Get-Content
PowerShell
Get-Content -Path "C:\path\to\file"
Get-Content -Path "C:\path\to\file" -Stream <StreamName>
Parameters:
-Path <string>
-Stream <string>
Get-Process (gps)
PowerShell
Get-Process
Get-Process -ProcessName "explorer" | Format-List *
Get-CimInstance (replacement for Get-WmiObject)
PowerShell
Get-CimInstance -ClassName Win32_Product
Get-CimInstance -ClassName Win32_Process
Get-CimInstance -ClassName Win32_ComputerSystem
Get-CimInstance -ClassName <ClassName> -Filter @{"property"=VALUE} -Property Name
Get-CimInstance -Query "<WQL query>"
Parameters:
-ClassName <string>
-Filter <hashtable>
-Property <string[]>
-Query <string>
Get-Service
PowerShell
Get-Service
Get-Service -DisplayName "DNS Client" | Format-List *
Get-NetTCPConnection
PowerShell
Get-NetTCPConnection
Get-NetTCPConnection -LocalPort 139 | Format-List *
Parameters:
-LocalPort <int>
Get-ScheduledTask
PowerShell
Get-ScheduledTask
Get-ScheduledTask -TaskName Proxy | Format-List *
Parameters:
-TaskName <string>
Data Manipulation Cmdlets
Select-Object (select)
PowerShell
Select-Object -Property Property1, Property2
Get-Process | Select-Object Name, ID, Description
Get-Process | Where-Object Name -eq explorer | Select-Object -ExpandProperty Modules
Parameters:
-Property <string[]>
-ExpandProperty <string>
Where-Object (where)
PowerShell
Where-Object { $_.Property -eq 'Value' }
Get-Process | Where-Object {($_.ProcessName -like "*host*") -and ($_.CPU -lt 5) -and ($_.CPU -gt 0.01)}
Operators:
-contains, -notcontains, -in, -notin
-like, -notlike, -match, -notmatch
-eq, -ne, -gt, -ge, -lt, -le
Select-String
PowerShell
Select-String -Path "C:\path\to\file" -Pattern "pattern"
<Data-Object> | Select-String -Pattern "pattern"
<Data-Object> | Select-String -InputObject ($_.Property) -Pattern "pattern"
Parameters:
-Path <string>
-Pattern <string>
-InputObject <object>
Format-List (fl)
PowerShell
Format-List -Property Property1, Property2
Get-Process | Where-Object Name -match "explorer" | Format-List Name, Description, Path, ID
Parameters:
-Property <string[]>
Format-Table (ft)
PowerShell
Format-Table -Property Property1, Property2
Format-Table -AutoSize
Format-Table -Wrap
Get-Process | Where-Object Name -match "explorer" | Format-Table Name, Description, Path, ID
Parameters:
-Property <string[]>
-AutoSize
-Wrap
Sort-Object
PowerShell
Sort-Object -Property PropertyName -Descending
Get-Process | Sort-Object -Property WS -Descending
Parameters:
-Property <string>
-Descending
-Ascending
-Unique
ForEach-Object (foreach, %)
PowerShell
<Data-Object> | ForEach-Object -Begin {commands} -Process {command1; command2} -End {commands}
Foreach ($object in $collection) {
    Example-Cmdlet -Input $object
}
Parameters:
-Begin <scriptblock>
-Process <scriptblock>
-End <scriptblock>
Input and Output Cmdlets
Invoke-Command
PowerShell
Invoke-Command -ComputerName TEST001 -Credential Domain\User -ScriptBlock {Command1; Command2}
Invoke-Command -Session $sessionName -ScriptBlock {Command1; Command2}
Parameters:
-ComputerName <string>
-Credential <pscredential>
-ScriptBlock <scriptblock>
-Session <PSSession>
Write-Output
PowerShell
Write-Output "The time and date is $(Get-Date)"
Out-File
PowerShell
<Data> | Out-File -Path "C:\path\to\out\file" -Append
Parameters:
-Path <string>
-Append
Common Cmdlet Parameters
ErrorAction
Syntax: -ErrorAction <value>
Values: Stop, Continue, SilentlyContinue, Ignore, Inquire
Force
Syntax: -Force
Purpose: Overrides restrictions (e.g., deleting read-only files, accessing hidden files).
Active Directory Cmdlets
Get-ADDomain
PowerShell
Get-ADDomain
Get-ADForest
PowerShell
Get-ADForest
Get-ADOrganizationalUnit
PowerShell
Get-ADOrganizationalUnit -Filter *
Parameter:
-Filter <string>
Get-ADGroup
PowerShell
Get-ADGroup -Filter *
Get-ADGroup -Identity Administrators -Properties *
Parameters:
-Filter <string>
-Identity <string>
-Properties <string[]>
Get-ADGroupMember
PowerShell
Get-ADGroupMember -Identity Administrators
Parameter:
-Identity <string>
Example Situational Awareness Script Commands
PowerShell
Get-Process
Get-Service
Get-ScheduledTask
Get-NetTCPConnection
Get-CimInstance -ClassName Win32_Product
Get-ChildItem -Path C:\Users\*\Downloads
Get-ChildItem -Path C:\Users\AppData\Local\Temp
Get-ChildItem -Path C:\ProgramFiles
Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
# ... other registry keys as shown above ...
