
1 reference
Copilot said: Here are some of the most useful
Here are some of the most useful and critical PowerShell syntax and concepts pulled from your m11-m15.md notes in the lukasaq/hack-class repository:

1. Creating Custom Objects and Hash Tables
PowerShell
# Custom object
$newObject = [PSCustomObject]@{
    Property1 = $output.property1
    Property2 = $secondoutput.property2
}

# Hash table
$newHashTable = @{ key1 = $value1; key2 = "value2"; key3 = 3 }

# Adding values to a hash table
$hashTable = @{}
$hashTable.Foo = 'Bar'
$hashTable['Foo'] = 'Bar'
$hashTable.Add('Foo','Bar')
2. Writing Functions and Using Parameters
PowerShell
function Custom-Function {
    Write-Output "Hello World"
}

# With parameters
[CmdletBinding()]
param(
    [Parameter()]
    [string]$Variable
)

# Calling with a parameter
Custom-Function -Variable "DATA"

# Accepting pipeline input
[CmdletBinding()]
param(
    [Parameter(Mandatory, ValueFromPipeline)]
    [string]$Variable
)
@("DATA1", "DATA2", "DATA3") | Custom-Function
3. Function Blocks: begin, process, end
PowerShell
begin {
    # Initialization code
}
process {
    # Code for each piped object
}
end {
    # Cleanup code
}
4. PowerShell Cmdlets for System Information
List all cmdlets:

PowerShell
Get-Command -Type Cmdlet
Get properties/methods of an object:

PowerShell
Get-Member
List all aliases:

PowerShell
Get-Alias
# or gal
Use pipelines:

PowerShell
Cmdlet1 | Cmdlet2
5. Common Data Gathering Cmdlets
PowerShell
Get-Item -Path "C:\*"
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
Get-ChildItem -Path "C:\"
Get-ChildItem -Recurse -Include *.exe
Get-Content -Path "C:\path\to\file"
Get-Content -Path "C:\path\to\file" -Stream MaliciousStreamName
Get-Process
Get-Process -ProcessName "explorer" | Format-List *
Get-CimInstance -ClassName Win32_Product
Get-Service
Get-Service -DisplayName "DNS Client" | Format-List *
Get-NetTCPConnection
Get-NetTCPConnection -LocalPort 139 | Format-List *
Get-ScheduledTask
Get-ScheduledTask -TaskName Proxy | Format-List *
6. Data Manipulation Cmdlets
Select specific properties:

PowerShell
Cmdlet | Select-Object Property1, Property2
Filter objects:

PowerShell
Cmdlet | Where-Object { $_.Property -eq "Value" }
Containment/matching/equality operators: -contains, -notcontains, -in, -notin, -like, -notlike, -match, -notmatch, -eq, -ne, -gt, -ge, -lt, -le

Example: Filter processes:

PowerShell
Get-Process | Where-Object { ($_.ProcessName -like "*host*") -and ($_.CPU -lt 5) -and ($_.CPU -gt 0.01) }
Select-String to search for patterns:

PowerShell
Select-String -Path "C:\path\to\file" -Pattern "pattern"
Format output:

PowerShell
Cmdlet | Format-List -Property Property1, Property2
Cmdlet | Format-Table -Property Property1, Property2
Sorting:

PowerShell
Get-Process | Sort-Object -Property WS -Descending
Foreach-Object:

PowerShell
Data | Foreach-Object -Begin {commands} -Process {command1; command2} -End {commands}
7. Input/Output Cmdlets
Invoke-Command (remote execution):

PowerShell
Invoke-Command -ComputerName TEST001 -Credential Domain\User -ScriptBlock {Command1; Command2}
Write output:

PowerShell
Write-Output "The time and date is $(Get-Date)"
Output to file:

PowerShell
Data | Out-File -Path "C:\path\to\out\file" -Append
8. Common Cmdlet Parameters
ErrorAction: Stop, Continue, SilentlyContinue, Ignore, Inquire
Force: Forces potentially dangerous actions
9. PowerShell ISE (Integrated Scripting Environment)
Script pane for editing .ps1 files
Console pane for running/test scripts
F8 to run selected code
F1 for context-sensitive help
10. Situational Awareness Script Example
Collects:

Running processes (Get-Process)
Active services (Get-Service)
Scheduled jobs/tasks (Get-ScheduledTask)
Active network connections (Get-NetTCPConnection)
Installed software (Get-CimInstance -ClassName Win32_Product)
Directory listings of sensitive folders (Get-ChildItem)
Contents of registry keys used for persistence (Get-Item on registry paths)
11. Active Directory Cmdlets (from later sections)
High-level: Get-ADDomain, Get-ADForest, Get-ADGroup, Get-ADGroupMember, Get-ADOrganizationalUnit
Low-level: Get-ADUser, Get-ADComputer, Get-ADDomainController
Use -Filter to efficiently query AD objects:

PowerShell
Get-ADUser -Filter "(Name -like '*joe*') -and (TrustedForDelegation -eq 'False')"
If you want a summary of a specific section or details on a specific cmdlet, let me know!
